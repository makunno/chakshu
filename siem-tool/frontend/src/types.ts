// Types shared between frontend and backend

export type LogType =
  | 'mysql_error' | 'mysql_query' | 'mysql_slow'
  | 'postgres_error' | 'postgres_auth' | 'postgres_statement'
  | 'oracle_alert' | 'oracle_listener' | 'oracle_audit'
  | 'sqlserver_error' | 'sqlserver_audit' | 'sqlserver_transaction'
  | 'mongodb_server' | 'mongodb_audit'
  | 'apache' | 'nginx' | 'iis'
  | 'django' | 'flask' | 'laravel' | 'rails'
  | 'express' | 'fastapi' | 'gunicorn' | 'uvicorn'
  | 'syslog' | 'systemd' | 'kernel' | 'audit' | 'package'
  | 'ssh_auth' | 'pam'
  | 'iptables' | 'ufw' | 'nftables' | 'firewalld'
  | 'windows_firewall' | 'palo_alto' | 'fortigate' | 'cisco_asa' | 'checkpoint'
  | 'aws_vpc_flow' | 'azure_nsg' | 'gcp_vpc'
  | 'postfix' | 'sendmail' | 'exim' | 'dovecot' | 'exchange'
  | 'dns' | 'dhcp' | 'proxy'
  | 'vsftpd' | 'proftpd'
  | 'windows_security' | 'windows_system' | 'windows_application'
  | 'cron' | 'daemon'
  | 'raw' | 'unknown';

export interface ParsedLogEntry {
  id: string;
  timestamp: string | null;
  logType: LogType;
  severity: 'debug' | 'info' | 'warning' | 'error' | 'critical' | 'unknown';
  source: {
    ip?: string;
    port?: number;
    hostname?: string;
    service?: string;
    pid?: number;
  };
  destination?: {
    ip?: string;
    port?: number;
    hostname?: string;
  };
  user?: {
    name?: string;
    domain?: string;
  };
  action?: string;
  outcome?: 'success' | 'failure' | 'unknown';
  countryCode?: string;
  message: string;
  rawLine: string;
  fields: Record<string, string | number | boolean | null>;
  tags: string[];
  attackType?: string;
  attackConfidence?: number;
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

export interface Alert {
  id: string;
  type: 'bruteforce' | 'password_spray' | 'privilege_escalation' | 'suspicious_activity' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  timestamp: string;
  sourceIps: string[];
  targetUsers: string[];
  relatedEvents: string[];
  metadata: Record<string, unknown>;
}

export interface AutoSplitInfo {
  originalFile: {
    sizeMB: number;
    lineCount: number;
    name: string;
  };
  splitConfig: {
    chunkSizeMB: number;
    totalChunks: number;
    format: string;
  };
  chunks: Array<{
    index: number;
    name: string;
    lineCount: number;
    byteSize: number;
  }>;
}

export interface ParseResponse {
  success: boolean;
  detectedType: LogType;
  totalLines: number;
  parsedLines: number;
  failedLines: number;
  entries: ParsedLogEntry[];
  alerts: Alert[];
  stats: {
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    byOutcome: Record<string, number>;
    topSources: Array<{ ip: string; count: number }>;
    topUsers: Array<{ user: string; count: number }>;
    timeline: Array<{ time: string; count: number }>;
  };
  autoSplitInfo?: AutoSplitInfo;
  mlAttacks?: Array<{
    entry: ParsedLogEntry;
    attackType: string;
    confidence: number;
    mitreTactics: string[];
    mitreTechniques: string[];
  }>;
  mlPredictions?: Array<{
    attackType: string;
    confidence: number;
    probability: number;
    explanation: string[];
    isFalsePositive: boolean;
  }>;
  attackChains?: Array<{
    id: string;
    attackType: string;
    stage: string;
    events: ParsedLogEntry[];
    sourceIps: string[];
    targetUsers: string[];
    startTime: string;
    endTime: string;
    prediction: {
      confidence: number;
      explanation: string[];
    };
    mitreTactics: string[];
    mitreTechniques: string[];
    recommendation: string;
  }>;
  attackSummary?: {
    totalAttacks: number;
    attackTypes: string[];
    uniqueSources: number;
    riskScore: number;
  };
}

// ML Correlation Types
export type AttackType =
  | 'bruteforce'
  | 'password_spray'
  | 'credential_stuffing'
  | 'mfa_bypass'
  | 'mfa_fatigue'
  | 'session_hijacking'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'sql_injection'
  | 'xss_attack'
  | 'path_traversal'
  | 'command_injection'
  | 'port_scan'
  | 'ddos'
  | 'reconnaissance'
  | 'malware_activity'
  | 'c2_communication'
  | 'insider_threat'
  | 'account_takeover'
  | 'anomaly'
  | 'unknown';

export interface MLPrediction {
  attackType: AttackType;
  confidence: number;
  probability: number;
  features: Record<string, number>;
  explanation: string[];
  isFalsePositive: boolean;
  falsePositiveReason?: string;
}

export interface CorrelatedEvent {
  id: string;
  timestamp: string;
  logSource: string;
  logType: string;
  severity: string;
  sourceIp?: string;
  targetUser?: string;
  targetHost?: string;
  action?: string;
  outcome?: string;
  message: string;
  relatedEventIds: string[];
  correlationScore: number;
}

export interface AttackChain {
  id: string;
  startTime: string;
  endTime: string;
  attackType: AttackType;
  stage: 'reconnaissance' | 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'lateral_movement' | 'exfiltration' | 'complete';
  events: CorrelatedEvent[];
  sourceIps: string[];
  targetUsers: string[];
  targetHosts: string[];
  prediction: MLPrediction;
  mitreTactics: string[];
  mitreTechniques: string[];
  recommendation: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  logSource: string;
  eventType: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  sourceIp?: string;
  targetUser?: string;
  relatedAttackChainId?: string;
  isAnomaly: boolean;
  anomalyScore: number;
}

export interface CorrelationResult {
  success: boolean;
  totalEvents: number;
  correlatedEvents: number;
  attackChains: AttackChain[];
  timeline: TimelineEvent[];
  summary: {
    totalAlerts: number;
    criticalAlerts: number;
    falsePositivesFiltered: number;
    attackTypesDetected: AttackType[];
    mostTargetedUsers: Array<{ user: string; count: number }>;
    mostActiveSourceIps: Array<{ ip: string; count: number; threatScore: number }>;
    riskScore: number;
  };
  recommendations: string[];
}

export interface CorrelateResponse {
  success: boolean;
  sources: Array<{ name: string; entryCount: number }>;
  correlation: CorrelationResult;
  traditionalAlerts: Alert[];
  stats: ParseResponse['stats'];
}

// Agent and Report Types
export type DataRequestType = 
  | 'parse_logs'
  | 'get_stats'
  | 'get_timeline'
  | 'get_attack_chains'
  | 'get_ml_predictions'
  | 'get_alerts'
  | 'get_entries'
  | 'get_top_sources'
  | 'get_top_users'
  | 'correlate_logs'
  | 'analyze_log';

export interface DataRequest {
  id: string;
  type: DataRequestType;
  parameters?: Record<string, any>;
  timestamp: string;
}

export interface DataResponse {
  requestId: string;
  success: boolean;
  data: any;
  error?: string;
}

export interface AgentMessage {
  id: string;
  role: 'user' | 'agent' | 'system';
  content: string;
  timestamp: string;
  dataRequests?: DataRequest[];
  dataResponses?: DataResponse[];
}

export interface AgentConversation {
  id: string;
  messages: AgentMessage[];
  startedAt: string;
  updatedAt: string;
  context?: Record<string, any>;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: ReportSection[];
}

export interface ReportSection {
  id: string;
  title: string;
  type: 'summary' | 'timeline' | 'attack_chains' | 'stats' | 'recommendations' | 'custom';
  content?: string;
  dataRequest?: DataRequest;
}

export interface Report {
  id: string;
  name: string;
  template: ReportTemplate;
  sections: ReportSection[];
  generatedAt: string;
  format: 'pdf' | 'html';
  content: string;
}

export interface ReportRequest {
  logData: ParseResponse;
  correlateData?: CorrelateResponse;
  template?: ReportTemplate;
  customInstructions?: string;
}
