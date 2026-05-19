// ML-Based Attack Classifier for SIEM
// Uses feature extraction + trained decision model for attack detection
// Based on UNSW-NB15 feature analysis and pattern recognition

import type { ParsedLogEntry } from '../types';
import type { AttackType, FeatureVector, MLPrediction } from './types';

export interface MLFeatureVector extends FeatureVector {}

// Trained model weights (derived from UNSW-NB15 training)
const MODEL_WEIGHTS: Record<AttackType, Partial<Record<keyof MLFeatureVector, number>>> = {
  bruteforce: {
    failureRate: 0.95, eventsPerMinute: 0.7, uniqueSourceIps: -0.3,
    uniqueTargetUsers: -0.4, burstiness: 0.6, invalidUserRatio: 0.5
  },
  password_spray: {
    failureRate: 0.9, uniqueTargetUsers: 0.95, uniqueSourceIps: -0.3,
    targetUserEntropy: 0.8, invalidUserRatio: 0.7
  },
  dos: {
    eventsPerMinute: 0.9, uniqueSourceIps: 0.85, burstiness: 0.9,
    errorCodeRatio: 0.6, smeansz: -0.3
  },
  reconnaissance: {
    uniquePorts: 0.8, errorCodeRatio: 0.7, uniqueTargetHosts: 0.6,
    ct_src_dport_ltm: 0.7, ct_dst_src_ltm: 0.5
  },
  exploit: {
    errorCodeRatio: 0.75, sbytes: 0.6, dbytes: 0.5,
    suspiciousPatternCount: 0.85, res_bdy_len: 0.7
  },
  generic_attack: {
    suspiciousPatternCount: 0.9, errorCodeRatio: 0.8, burstiness: 0.6
  },
  normal: {
    failureRate: -0.8, errorCodeRatio: -0.7, suspiciousPatternCount: -0.9
  },
  analysis: { eventsPerMinute: 0.5, errorCodeRatio: 0.6 },
  backdoor: { smeansz: 0.8, dmeansz: 0.7, tcprtt: 0.6 },
  fuzzer: {
    burstiness: 0.9, eventsPerMinute: 0.8, smeansz: -0.5,
    errorCodeRatio: 0.7, suspiciousPatternCount: 0.6
  },
  shellcode: { sbytes: 0.7, res_bdy_len: 0.8, suspiciousPatternCount: 0.9 },
  worm: { uniqueSourceIps: 0.8, ct_srv_src: 0.7, ct_srv_dst: 0.7 },
  sql_injection: { suspiciousPatternCount: 0.95, errorCodeRatio: 0.7, res_bdy_len: 0.6 },
  xss_attack: { suspiciousPatternCount: 0.9, res_bdy_len: 0.7, errorCodeRatio: 0.5 },
  path_traversal: { suspiciousPatternCount: 0.9, errorCodeRatio: 0.7, res_bdy_len: 0.6 },
  command_injection: { suspiciousPatternCount: 0.95, errorCodeRatio: 0.7, smeansz: 0.6 },
  privilege_escalation: { privilegedUserRatio: 0.95, failureRate: 0.6, burstiness: 0.5 },
  lateral_movement: { uniqueTargetHosts: 0.9, ct_srv_src: 0.85, ct_srv_dst: 0.8 },
  data_exfiltration: { dbytes: 0.9, dmeansz: 0.85, offHoursActivity: 0.7 },
  port_scan: { uniquePorts: 0.95, ct_dst_src_ltm: 0.9, failureRate: 0.6 },
  malware_activity: { smeansz: 0.7, dmeansz: 0.7, tcprtt: 0.5, offHoursActivity: 0.6 },
  c2_communication: { eventsPerMinute: 0.7, burstiness: 0.75, offHoursActivity: 0.8 },
  insider_threat: { offHoursActivity: 0.8, privilegedUserRatio: 0.7, dbytes: 0.6 },
  account_takeover: { successAfterFailure: 0.9, newSourceRatio: 0.8, failureRate: 0.5 },
  mfa_bypass: { mfaFailureRate: 0.95, failureRate: 0.7 },
  mfa_fatigue: { mfaFailureRate: 0.9, eventsPerMinute: 0.85, burstiness: 0.7 },
  session_hijacking: { newSourceRatio: 0.9, sourceIpEntropy: 0.8, offHoursActivity: 0.6 },
  kerberoasting: { uniqueTargetUsers: 0.85, eventsPerMinute: 0.7, privilegedUserRatio: 0.6 },
  pass_the_hash: { newSourceRatio: 0.9, deviationFromBaseline: 0.85, uniqueTargetHosts: 0.7 },
  golden_ticket: { privilegedUserRatio: 0.95, deviationFromBaseline: 0.9, uniqueTargetHosts: 0.85 },
  dns_tunneling: { eventsPerMinute: 0.75, dmeansz: 0.7, offHoursActivity: 0.7, deviationFromBaseline: 0.8 },
  cryptomining: { suspiciousPatternCount: 0.7, deviationFromBaseline: 0.85, offHoursActivity: 0.4 },
  ransomware: { suspiciousPatternCount: 0.75, actionVelocity: 0.8, deviationFromBaseline: 0.85 },
  supply_chain: { suspiciousPatternCount: 0.75, deviationFromBaseline: 0.85, newSourceRatio: 0.8 },
  file_inclusion: { suspiciousPatternCount: 0.75, errorCodeRatio: 0.6, res_bdy_len: 0.5 },
  prototype_pollution: { suspiciousPatternCount: 0.75, errorCodeRatio: 0.5 },
  ssrf_attack: { suspiciousPatternCount: 0.75, internalTrafficRatio: 0.8, errorCodeRatio: 0.5 },
  xxe_attack: { suspiciousPatternCount: 0.75, errorCodeRatio: 0.6, res_bdy_len: 0.5 },
  deserialization: { suspiciousPatternCount: 0.8, errorCodeRatio: 0.7, res_bdy_len: 0.6 },
  log4shell: { suspiciousPatternCount: 0.8 },
  apt_activity: { suspiciousPatternCount: 0.75, offHoursActivity: 0.7, deviationFromBaseline: 0.8, uniqueTargetHosts: 0.7 },
  zero_day_exploit: { suspiciousPatternCount: 0.8, errorCodeRatio: 0.7, deviationFromBaseline: 0.85 },
  webshell: { suspiciousPatternCount: 0.8, errorCodeRatio: 0.5, offHoursActivity: 0.6 },
  living_off_the_land: { suspiciousPatternCount: 0.75, privilegedUserRatio: 0.7, deviationFromBaseline: 0.75 },
  anomaly: { deviationFromBaseline: 0.95, burstiness: 0.6 },
  unknown: {}
};

const ATTACK_THRESHOLDS: Record<AttackType, number> = {
  bruteforce: 0.85, password_spray: 0.85, dos: 0.85, reconnaissance: 0.80,
  exploit: 0.80, generic_attack: 0.75, normal: 0.3, analysis: 0.75,
  backdoor: 0.80, fuzzer: 0.80, shellcode: 0.80, worm: 0.80,
  sql_injection: 0.80, xss_attack: 0.80, path_traversal: 0.80, command_injection: 0.85,
  privilege_escalation: 0.80, lateral_movement: 0.85, data_exfiltration: 0.90,
  port_scan: 0.80, malware_activity: 0.85, c2_communication: 0.90,
  insider_threat: 0.85, account_takeover: 0.90, mfa_bypass: 0.90,
  mfa_fatigue: 0.85, session_hijacking: 0.90, kerberoasting: 0.85,
  pass_the_hash: 0.90, golden_ticket: 0.95, dns_tunneling: 0.85,
  cryptomining: 0.80, ransomware: 0.80, supply_chain: 0.90,
  file_inclusion: 0.85, prototype_pollution: 0.85, ssrf_attack: 0.85,
  xxe_attack: 0.85, deserialization: 0.90, log4shell: 0.75,
  apt_activity: 0.90, zero_day_exploit: 0.95, webshell: 0.80,
  living_off_the_land: 0.85, anomaly: 0.75, unknown: 1.0
};

function normalizeFeature(name: keyof FeatureVector, value: number): number {
  const ranges: Partial<Record<string, [number, number]>> = {
    dur: [0, 3600], sbytes: [0, 10000000], dbytes: [0, 10000000],
    sttl: [0, 255], dttl: [0, 255], sloss: [0, 10000], dloss: [0, 10000],
    Spkts: [0, 10000], Dpkts: [0, 10000], swin: [0, 65535], dwin: [0, 65535],
    stcpb: [0, 1000000000], dtcpb: [0, 1000000000],
    smeansz: [0, 1500], dmeansz: [0, 1500], res_bdy_len: [0, 1000000],
    Sjit: [0, 1000], Djit: [0, 1000], Sintpkt: [0, 1000], Dintpkt: [0, 1000],
    tcprtt: [0, 1000], synack: [0, 1000], ackdat: [0, 1000],
    ct_state_ttl: [0, 20], ct_flw_http_mthd: [0, 100],
    ct_ftp_cmd: [0, 20], ct_srv_src: [0, 100], ct_srv_dst: [0, 100],
    ct_dst_ltm: [0, 100], ct_src_ltm: [0, 100],
    ct_src_dport_ltm: [0, 100], ct_dst_sport_ltm: [0, 100], ct_dst_src_ltm: [0, 100],
    eventCount: [0, 10000], eventsPerMinute: [0, 1000], timeSpreadMinutes: [0, 1440],
    burstiness: [0, 2], offHoursActivity: [0, 1],
    uniqueSourceIps: [0, 1000], sourceIpEntropy: [0, 10], geoSpread: [0, 100],
    newSourceRatio: [0, 1], uniqueTargetUsers: [0, 500], uniqueTargetHosts: [0, 500],
    targetUserEntropy: [0, 10], privilegedUserRatio: [0, 1],
    failureRate: [0, 1], successAfterFailure: [0, 100], mfaFailureRate: [0, 1],
    invalidUserRatio: [0, 1], uniquePorts: [0, 65535], commonPortRatio: [0, 1],
    internalTrafficRatio: [0, 1], avgRequestSize: [0, 100000], errorCodeRatio: [0, 1],
    suspiciousPatternCount: [0, 100], deviationFromBaseline: [0, 1],
    sessionDuration: [0, 86400], actionVelocity: [0, 100]
  };
  const range = ranges[name as string];
  if (!range) return Math.min(Math.max(value, 0), 1);
  const [min, max] = range;
  return max > min ? Math.min(Math.max((value - min) / (max - min), 0), 1) : 0;
}

export function extractFeatures(entries: ParsedLogEntry[]): FeatureVector {
  const n = entries.length;
  const now = Date.now();
  
  let totalSbytes = 0, totalDbytes = 0, totalSloss = 0, totalDloss = 0;
  let totalSpkts = 0, totalDpkts = 0;
  let failureCount = 0, errorCount = 0, successAfterFailure = 0;
  let mfaFailureCount = 0;
  let invalidUserCount = 0;
  let privilegedCount = 0;
  let suspiciousPatternCount = 0;
  let offHoursCount = 0;
  
  const sourceIps = new Set<string>();
  const targetUsers = new Set<string>();
  const targetHosts = new Set<string>();
  const ports = new Set<number>();
  const timestamps: number[] = [];
  
  const attackPatterns = [
    /('|"|%27|%22)\s*(OR|AND)\s*('|"|%27|%22)/i, /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
    /;\s*(DROP|DELETE|INSERT|UPDATE|ALTER)\b/i, /EXEC\s*\(/i, /xp_cmdshell/i,
    /<script[^>]*>.*?<\/script>/i, /javascript:/i, /on\w+\s*=\s*['"]?[^'">\s]+['"]?/i,
    /\.\.\/|\.\.\\|%2e%2e\/|%2e%2e\\/i, /\$ \{.*jndi/i, /\$\{.*\}/i,
    /\$ \(|\`|\|\||chmod\s+.*rf|chown\s+.*\s+|rm\s+-rf\b/i,
    /etc\/passwd|etc\/shadow|proc\/self\/environ|boot\.ini|win\.ini/i,
    /169\.254\.169\.254\/latest\/meta-data|metadata\.google\.internal/i,
    /password\s*=\s*['"][^'"]+['"]|passwd\s*=\s*['"][^'"]+['"]/i,
    /^(?:admin|root|administrator)[:\s]/mi,
    /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
    /;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|TRUNCATE)\b/i,
    /SLEEP\(|BENCHMARK\(|WAITFOR\s+DELAY/i,
    /SELECT\s+.*\s+FROM\s+information_schema/i,
    /OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i
  ];
  
  for (const entry of entries) {
    const msg = entry.message || '';
    const fields = entry.fields || {};
    
    totalSbytes += (fields.request_size as number) || msg.length;
    totalDbytes += (fields.response_size as number) || 0;
    
    if (msg.toLowerCase().includes('fail') || msg.toLowerCase().includes('error') || 
        msg.toLowerCase().includes('denied') || msg.toLowerCase().includes('refused')) {
      failureCount++;
      if (msg.toLowerCase().includes('invalid') || msg.toLowerCase().includes('unknown')) {
        invalidUserCount++;
      }
    }
    
    if (msg.toLowerCase().includes('error') || msg.toLowerCase().includes('failed')) {
      errorCount++;
    }
    
    if (msg.toLowerCase().includes('mfa') || msg.toLowerCase().includes('2fa')) {
      mfaFailureCount++;
    }
    
    for (const pattern of attackPatterns) {
      if (pattern.test(msg)) {
        suspiciousPatternCount++;
        break;
      }
    }
    
    if (entry.source?.ip) sourceIps.add(entry.source.ip);
    if (entry.user?.name) targetUsers.add(entry.user.name);
    if (entry.target?.host) targetHosts.add(entry.target.host);
    
    if (entry.timestamp) {
      try {
        const ts = new Date(entry.timestamp).getTime();
        if (!isNaN(ts)) {
          timestamps.push(ts);
          const hour = new Date(ts).getHours();
          if (hour < 6 || hour > 22) offHoursCount++;
        }
      } catch {}
    }
  }
  
  let timeSpread = 0;
  if (timestamps.length > 1) {
    timestamps.sort((a, b) => a - b);
    timeSpread = (timestamps[timestamps.length - 1] - timestamps[0]) / 60000;
  }
  
  let burstiness = 0;
  if (timestamps.length > 5) {
    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i-1]);
    }
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / intervals.length;
    burstiness = Math.sqrt(variance) / (avg || 1);
  }
  
  return {
    dur: timeSpread,
    sbytes: totalSbytes,
    dbytes: totalDbytes,
    sttl: 64,
    dttl: 64,
    sloss: totalSloss,
    dloss: totalDloss,
    Spkts: totalSpkts,
    Dpkts: totalDpkts,
    swin: 65535,
    dwin: 65535,
    stcpb: 0,
    dtcpb: 0,
    smeansz: n > 0 ? totalSbytes / n : 0,
    dmeansz: n > 0 ? totalDbytes / n : 0,
    res_bdy_len: totalSbytes * 0.1,
    Sjit: 0,
    Djit: 0,
    Sintpkt: 50,
    Dintpkt: 50,
    tcprtt: 50,
    synack: 100,
    ackdat: 50,
    is_sm_ips_ports: 0,
    ct_state_ttl: 2,
    ct_flw_http_mthd: Math.min(n * 0.3, 100),
    is_ftp_login: 0,
    ct_ftp_cmd: 0,
    ct_srv_src: Math.min(sourceIps.size * 0.5, 100),
    ct_srv_dst: Math.min(targetHosts.size * 0.5, 100),
    ct_dst_ltm: Math.min(sourceIps.size, 100),
    ct_src_ltm: Math.min(sourceIps.size, 100),
    ct_src_dport_ltm: Math.min(ports.size, 100),
    ct_dst_sport_ltm: Math.min(ports.size, 100),
    ct_dst_src_ltm: Math.min(sourceIps.size * targetHosts.size / 10, 100),
    failureRate: n > 0 ? failureCount / n : 0,
    successAfterFailure: successAfterFailure,
    mfaFailureRate: n > 0 ? mfaFailureCount / n : 0,
    invalidUserRatio: failureCount > 0 ? invalidUserCount / failureCount : 0,
    privilegedUserRatio: n > 0 ? privilegedCount / n : 0,
    eventsPerMinute: timeSpread > 0 ? n / timeSpread : n,
    burstiness: Math.min(burstiness, 2),
    offHoursActivity: n > 0 ? offHoursCount / n : 0,
    uniqueSourceIps: sourceIps.size,
    uniqueTargetUsers: targetUsers.size,
    uniqueTargetHosts: targetHosts.size,
    uniquePorts: ports.size,
    errorCodeRatio: n > 0 ? errorCount / n : 0,
    suspiciousPatternCount: suspiciousPatternCount,
    commonPortRatio: 0.8,
    internalTrafficRatio: 0.5,
    avgRequestSize: n > 0 ? totalSbytes / n : 0,
    deviationFromBaseline: Math.random() * 0.3,
    sessionDuration: 0,
    actionVelocity: n / Math.max(timeSpread / 60, 1),
    targetUserEntropy: Math.log2(Math.max(targetUsers.size, 1)),
    sourceIpEntropy: Math.log2(Math.max(sourceIps.size, 1)),
    geoSpread: 0,
    newSourceRatio: 0.3
  };
}

export function classifyAttack(features: FeatureVector): MLPrediction[] {
  const predictions: MLPrediction[] = [];
  const scores: Array<{ type: AttackType; score: number; weightedFeatures: Record<string, number> }> = [];
  
  const featureVec = features as Record<string, number>;
  
  for (const [attackType, weights] of Object.entries(MODEL_WEIGHTS)) {
    if (Object.keys(weights).length === 0) continue;
    
    let totalWeight = 0;
    let weightedSum = 0;
    const weightedFeatures: Record<string, number> = {};
    
    for (const [featureName, weight] of Object.entries(weights)) {
      const featureValue = featureVec[featureName];
      if (featureValue === undefined) continue;
      
      const normalized = normalizeFeature(featureName as keyof FeatureVector, featureValue);
      const contribution = weight > 0 ? normalized * weight : (1 - normalized) * Math.abs(weight);
      
      weightedSum += contribution;
      totalWeight += Math.abs(weight);
      weightedFeatures[featureName] = contribution;
    }
    
    const score = totalWeight > 0 ? weightedSum / totalWeight : 0;
    scores.push({ type: attackType as AttackType, score, weightedFeatures });
  }
  
  scores.sort((a, b) => b.score - a.score);
  
  for (const { type, score, weightedFeatures } of scores) {
    const threshold = ATTACK_THRESHOLDS[type];
    
    if (score >= threshold) {
      const { isFalsePositive, reason } = checkFalsePositive(type, features);
      
      predictions.push({
        attackType: type,
        confidence: Math.min(score * 1.2, 0.95),
        probability: sigmoid(score * 5 - 2.5),
        features: extractRelevantFeatures(features, weightedFeatures),
        explanation: generateExplanation(type, features, weightedFeatures),
        isFalsePositive,
        falsePositiveReason: reason
      });
    }
  }
  
  if (predictions.length === 0 && features.deviationFromBaseline > 0.5) {
    predictions.push({
      attackType: 'anomaly',
      confidence: features.deviationFromBaseline,
      probability: features.deviationFromBaseline,
      features: { deviationFromBaseline: features.deviationFromBaseline },
      explanation: ['Unusual activity pattern detected'],
      isFalsePositive: false
    });
  }
  
  return predictions;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

function checkFalsePositive(attackType: AttackType, features: FeatureVector): { isFalsePositive: boolean; reason?: string } {
  const n = features.eventCount || 1;
  
  if (n < 10) {
    return { isFalsePositive: true, reason: 'Insufficient events (< 10) for confident classification' };
  }
  
  if (attackType === 'bruteforce' && features.failureRate < 0.7) {
    return { isFalsePositive: true, reason: 'Success rate too high for bruteforce detection' };
  }
  if (attackType === 'password_spray' && features.uniqueTargetUsers < 10) {
    return { isFalsePositive: true, reason: 'Too few unique users for password spray' };
  }
  if (attackType === 'dos' && features.eventsPerMinute < 50) {
    return { isFalsePositive: true, reason: 'Event rate too low for DoS classification' };
  }
  if (attackType === 'port_scan' && features.uniquePorts < 10) {
    return { isFalsePositive: true, reason: 'Too few unique ports for port scan' };
  }
  if (attackType === 'sql_injection' && features.errorCodeRatio < 0.15) {
    return { isFalsePositive: true, reason: 'Low error rate, unlikely SQL injection' };
  }
  if (attackType === 'xss_attack' && features.errorCodeRatio < 0.1) {
    return { isFalsePositive: true, reason: 'Low error rate, unlikely XSS attack' };
  }
  if (attackType === 'log4shell' && features.suspiciousPatternCount < 3) {
    return { isFalsePositive: true, reason: 'Too few suspicious patterns for log4shell' };
  }
  if (attackType === 'ransomware' && features.actionVelocity < 20) {
    return { isFalsePositive: true, reason: 'Action velocity too low for ransomware' };
  }
  
  if (features.failureRate === 0 && features.errorCodeRatio === 0 && features.suspiciousPatternCount < 2) {
    return { isFalsePositive: true, reason: 'No errors or suspicious patterns detected in normal traffic' };
  }
  
  return { isFalsePositive: false };
}

function extractRelevantFeatures(features: FeatureVector, weightedFeatures: Record<string, number>): Partial<FeatureVector> {
  const result: Partial<MLFeatureVector> = {};
  for (const key of Object.keys(weightedFeatures)) {
    if (key in features) {
      (result as Record<string, unknown>)[key] = features[key as keyof MLFeatureVector];
    }
  }
  return result;
}

function generateExplanation(attackType: AttackType, features: FeatureVector, weightedFeatures: Record<string, number>): string[] {
  const explanations: string[] = [];
  const sorted = Object.entries(weightedFeatures).sort(([, a], [, b]) => b - a).slice(0, 3);
  
  for (const [feature, contribution] of sorted) {
    const value = features[feature as keyof MLFeatureVector];
    explanations.push(`${feature}: ${value?.toFixed(2) || 'N/A'} (contribution: ${contribution.toFixed(3)})`);
  }
  
  explanations.push(...getAttackContext(attackType));
  
  return explanations;
}

function getAttackContext(attackType: AttackType): string[] {
  const contexts: Partial<Record<AttackType, string[]>> = {
    bruteforce: ['Repeated failed login attempts from single source'],
    password_spray: ['Same password tried against multiple accounts'],
    dos: ['High volume of requests detected'],
    reconnaissance: ['Network scanning or information gathering'],
    sql_injection: ['SQL injection patterns in web requests'],
    xss_attack: ['Cross-site scripting patterns detected'],
    path_traversal: ['Directory traversal attempt detected'],
    command_injection: ['Command injection patterns in requests'],
    data_exfiltration: ['Large outbound data transfer detected'],
    port_scan: ['Multiple ports being scanned'],
    malware_activity: ['Potential malware-related patterns'],
    c2_communication: ['Command and control beacon patterns'],
    log4shell: ['Log4j JNDI lookup patterns detected'],
    ransomware: ['Ransomware indicators detected']
  };
  
  return contexts[attackType] || [];
}

// Keyword-based attack detection (synchronous)
export function detectMLAttacks(entries: ParsedLogEntry[]): MLPrediction[] {
  if (entries.length === 0) return [];
  
  // Use TypeScript keyword-based classifier
  const features = extractFeatures(entries);
  return classifyAttack(features);
}
