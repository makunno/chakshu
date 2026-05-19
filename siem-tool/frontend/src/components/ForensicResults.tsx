import { 
  AlertTriangle, Shield, Clock, FileSearch, HardDrive, FolderOpen, 
  Download, Loader2, FileX, Trash2, FileText, Key, 
  Activity, CheckCircle2, XCircle, AlertCircle, 
  Info, Sparkles, Target, Eye, Lightbulb
} from 'lucide-react';
import { downloadForensicPdf } from '../api';
import { useState } from 'react';

export interface ForensicFinding {
  technique: string;
  severity: string;
  evidence: string;
  explanation: string;
  recommendation: string;
  confidence: number;
}

export interface ForensicResults {
  task_id: string;
  status: string;
  output_dir: string;
  findings: ForensicFinding[];
  summary: string;
  risk_level: string;
  recommendations: string[];
  timestamp: string;
  model: string;
  analysis_time_seconds: number;
}

interface ForensicResultsProps {
  results: ForensicResults;
  onReset: () => void;
}

const SEVERITY_COLORS: Record<string, { 
  bg: string; 
  text: string; 
  border: string;
  gradient: string;
  iconBg: string;
}> = {
  CRITICAL: { 
    bg: 'rgba(220, 38, 38, 0.15)', 
    text: '#ef4444', 
    border: '#dc2626',
    gradient: 'linear-gradient(135deg, rgba(220, 38, 38, 0.2) 0%, rgba(239, 68, 68, 0.1) 100%)',
    iconBg: 'rgba(220, 38, 38, 0.25)'
  },
  HIGH: { 
    bg: 'rgba(234, 88, 12, 0.15)', 
    text: '#ea580c', 
    border: '#ea580c',
    gradient: 'linear-gradient(135deg, rgba(234, 88, 12, 0.2) 0%, rgba(251, 146, 60, 0.1) 100%)',
    iconBg: 'rgba(234, 88, 12, 0.25)'
  },
  MEDIUM: { 
    bg: 'rgba(202, 138, 4, 0.15)', 
    text: '#ca8a04', 
    border: '#ca8a04',
    gradient: 'linear-gradient(135deg, rgba(202, 138, 4, 0.2) 0%, rgba(234, 179, 8, 0.1) 100%)',
    iconBg: 'rgba(202, 138, 4, 0.25)'
  },
  LOW: { 
    bg: 'rgba(22, 163, 74, 0.15)', 
    text: '#16a34a', 
    border: '#16a34a',
    gradient: 'linear-gradient(135deg, rgba(22, 163, 74, 0.2) 0%, rgba(34, 197, 94, 0.1) 100%)',
    iconBg: 'rgba(22, 163, 74, 0.25)'
  },
  UNKNOWN: { 
    bg: 'rgba(107, 114, 128, 0.15)', 
    text: '#6b7280', 
    border: '#6b7280',
    gradient: 'linear-gradient(135deg, rgba(107, 114, 128, 0.2) 0%, rgba(148, 163, 184, 0.1) 100%)',
    iconBg: 'rgba(107, 114, 128, 0.25)'
  },
};

const TECHNIQUE_ICONS: Record<string, React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }>> = {
  timestomping: Clock,
  shadow_deletion: Trash2,
  ads: FileText,
  deletion: FileX,
  log_clearing: FileText,
  registry_tampering: Key,
  other: Activity,
};

const TECHNIQUE_LABELS: Record<string, string> = {
  timestomping: 'Timestamp Manipulation',
  shadow_deletion: 'Shadow Copy Deletion',
  ads: 'Alternate Data Streams',
  deletion: 'File Deletion/Wiping',
  log_clearing: 'Log Clearing',
  registry_tampering: 'Registry Tampering',
  other: 'Other Activity',
};

const SEVERITY_ICONS: Record<string, React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }>> = {
  CRITICAL: XCircle,
  HIGH: AlertTriangle,
  MEDIUM: AlertCircle,
  LOW: CheckCircle2,
  UNKNOWN: Info,
};

export function ForensicResults({ results, onReset }: ForensicResultsProps) {
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  
  const riskColor = SEVERITY_COLORS[results.risk_level] || SEVERITY_COLORS.UNKNOWN;
  
  const handleDownloadPdf = async () => {
    setPdfDownloading(true);
    setPdfError(null);
    try {
      await downloadForensicPdf(results.task_id);
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : 'Failed to download PDF');
    } finally {
      setPdfDownloading(false);
    }
  };
  
  const findingsBySeverity = results.findings.reduce((acc, finding) => {
    const sev = finding.severity || 'UNKNOWN';
    if (!acc[sev]) acc[sev] = [];
    acc[sev].push(finding);
    return acc;
  }, {} as Record<string, ForensicFinding[]>);

  const criticalCount = findingsBySeverity['CRITICAL']?.length || 0;
  const highCount = findingsBySeverity['HIGH']?.length || 0;
  const mediumCount = findingsBySeverity['MEDIUM']?.length || 0;
  const lowCount = findingsBySeverity['LOW']?.length || 0;

  return (
    <div className="forensic-results fade-in">
      <div className="forensic-toolbar">
        <button className="btn btn-secondary" onClick={onReset}>
          <HardDrive size={16} />
          New Analysis
        </button>
        <button 
          className="btn btn-primary" 
          onClick={handleDownloadPdf}
          disabled={pdfDownloading}
        >
          {pdfDownloading ? (
            <Loader2 size={16} className="spin" />
          ) : (
            <Download size={16} />
          )}
          Export PDF Report
        </button>
      </div>
      {pdfError && (
        <div className="error-banner">
          {pdfError}
        </div>
      )}

      <div className="forensic-header">
        <div className="forensic-title-section">
          <FileSearch size={32} className="forensic-icon" />
          <div>
            <h1>Forensic Analysis Report</h1>
            <p className="forensic-meta">
              <Clock size={14} />
              {results.timestamp ? new Date(results.timestamp).toLocaleString() : 'N/A'}
              <span className="meta-separator">•</span>
              Analysis time: {results.analysis_time_seconds?.toFixed(1) || 0}s
              <span className="meta-separator">•</span>
              Model: {results.model || 'N/A'}
            </p>
          </div>
        </div>
        <div className="risk-badge-container">
          <div 
            className="risk-badge-large"
            style={{ 
              background: riskColor.bg, 
              borderColor: riskColor.border,
              color: riskColor.text 
            }}
          >
            <AlertTriangle size={20} />
            <span>{results.risk_level}</span>
          </div>
        </div>
      </div>

      <div className="forensic-output-dir">
        <FolderOpen size={18} />
        <span className="output-label">Artifacts saved to:</span>
        <code className="output-path">{results.output_dir}</code>
      </div>

      <div className="forensic-summary card">
        <h3>Summary</h3>
        <p>{results.summary}</p>
      </div>

      <div className="forensic-stats-grid">
        <div className="forensic-stat-card critical">
          <span className="stat-value">{criticalCount}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="forensic-stat-card high">
          <span className="stat-value">{highCount}</span>
          <span className="stat-label">High</span>
        </div>
        <div className="forensic-stat-card medium">
          <span className="stat-value">{mediumCount}</span>
          <span className="stat-label">Medium</span>
        </div>
        <div className="forensic-stat-card low">
          <span className="stat-value">{lowCount}</span>
          <span className="stat-label">Low</span>
        </div>
      </div>

      <div className="forensic-findings-section">
        <div className="findings-section-header">
          <div className="findings-header-left">
            <Sparkles size={24} className="findings-header-icon" />
            <div>
              <h3>AI Analysis Findings</h3>
              <p className="findings-subtitle">
                {results.findings.length} {results.findings.length === 1 ? 'finding' : 'findings'} detected by AI analysis
              </p>
            </div>
          </div>
          <div className="findings-header-stats">
            {criticalCount > 0 && (
              <div className="finding-stat-badge critical">
                <XCircle size={14} />
                <span>{criticalCount} Critical</span>
              </div>
            )}
            {highCount > 0 && (
              <div className="finding-stat-badge high">
                <AlertTriangle size={14} />
                <span>{highCount} High</span>
              </div>
            )}
          </div>
        </div>
        
        {results.findings.length === 0 ? (
          <div className="no-findings">
            <div className="no-findings-icon-wrapper">
              <Shield size={64} />
            </div>
            <h4>No Anti-Forensic Activity Detected</h4>
            <p>The analysis did not find evidence of anti-forensic techniques in this image.</p>
          </div>
        ) : (
          <div className="findings-list">
            {results.findings.map((finding, index) => {
              const sevColor = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.UNKNOWN;
              const TechniqueIcon = TECHNIQUE_ICONS[finding.technique] || Activity;
              const SeverityIcon = SEVERITY_ICONS[finding.severity] || Info;
              
              return (
                <div 
                  key={index} 
                  className="finding-card-enhanced"
                  style={{ 
                    '--severity-border': sevColor.border,
                    '--severity-bg': sevColor.bg,
                    '--severity-gradient': sevColor.gradient,
                    '--severity-icon-bg': sevColor.iconBg,
                  } as React.CSSProperties & Record<string, string>}
                >
                  <div className="finding-card-header">
                    <div className="finding-icon-wrapper" style={{ background: sevColor.iconBg }}>
                      <TechniqueIcon size={20} style={{ color: sevColor.text }} />
                    </div>
                    <div className="finding-title-group">
                      <h4 className="finding-technique-title">
                        {TECHNIQUE_LABELS[finding.technique] || finding.technique}
                      </h4>
                      <div className="finding-meta">
                        <span className="finding-index">#{index + 1}</span>
                        <span className="finding-separator">•</span>
                        <span className="finding-confidence-badge">
                          <Target size={12} />
                          {(finding.confidence * 100).toFixed(0)}% confidence
                        </span>
                      </div>
                    </div>
                    <div className="finding-severity-badge" style={{ 
                      background: sevColor.gradient,
                      borderColor: sevColor.border,
                      color: sevColor.text 
                    }}>
                      <SeverityIcon size={16} />
                      <span>{finding.severity}</span>
                    </div>
                  </div>
                  
                  <div className="finding-content-enhanced">
                    <div className="finding-field-card">
                      <div className="finding-field-header">
                        <Eye size={16} />
                        <span className="finding-field-label">Evidence</span>
                      </div>
                      <p className="finding-field-content">{finding.evidence}</p>
                    </div>
                    
                    <div className="finding-field-card">
                      <div className="finding-field-header">
                        <Info size={16} />
                        <span className="finding-field-label">Analysis</span>
                      </div>
                      <p className="finding-field-content">{finding.explanation}</p>
                    </div>
                    
                    <div className="finding-field-card recommendation">
                      <div className="finding-field-header">
                        <Lightbulb size={16} />
                        <span className="finding-field-label">Recommendation</span>
                      </div>
                      <p className="finding-field-content">{finding.recommendation}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {results.recommendations && results.recommendations.length > 0 && (
        <div className="forensic-recommendations card">
          <h3>Investigator Recommendations</h3>
          <ul>
            {results.recommendations.map((rec, index) => (
              <li key={index}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
