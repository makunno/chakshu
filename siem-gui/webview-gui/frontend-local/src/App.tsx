import { useState, useCallback } from 'react';
import { 
   Upload, Shield, AlertTriangle, Activity, FileText, 
   Download, RefreshCw, ChevronDown, X, Search, Terminal,
   Layers, Clock, Target, Zap, TrendingUp, Scissors, File, Archive
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import JSZip from 'jszip';
import { parseLogsFromFile, parseLogsFromText, correlateMultipleFiles, EVTXUploadError, isEVTXFile, type SplitFileResult } from './api';
import type { ParseResponse, ParsedLogEntry, CorrelateResponse, AttackChain, TimelineEvent } from './types';
import { DynamicTable } from './DynamicTable';
import { EVTXTutorial } from './EVTXTutorial';
import './App.css';

const SEVERITY_COLORS = {
  debug: '#64748b',
  info: '#3b82f6',
  warning: '#eab308',
  error: '#ef4444',
  critical: '#a855f7',
  unknown: '#94a3b8',
  low: '#22c55e',
  medium: '#f59e0b',
  high: '#ef4444',
};

const ATTACK_TYPE_ICONS: Record<string, string> = {
  bruteforce: '🔓',
  password_spray: '💨',
  credential_stuffing: '🔑',
  mfa_bypass: '🛡️',
  mfa_fatigue: '😴',
  session_hijacking: '🎭',
  privilege_escalation: '⬆️',
  lateral_movement: '↔️',
  data_exfiltration: '📤',
  sql_injection: '💉',
  xss_attack: '🌐',
  path_traversal: '📁',
  command_injection: '⌨️',
  port_scan: '🔍',
  ddos: '🌊',
  reconnaissance: '👁️',
  malware_activity: '🦠',
  c2_communication: '📡',
  insider_threat: '👤',
  account_takeover: '🔐',
  anomaly: '📊',
  unknown: '❓',
};

const STAGE_COLORS: Record<string, string> = {
  reconnaissance: '#64748b',
  initial_access: '#3b82f6',
  execution: '#8b5cf6',
  persistence: '#f59e0b',
  privilege_escalation: '#ef4444',
  lateral_movement: '#ec4899',
  exfiltration: '#dc2626',
  complete: '#7c3aed',
};

const ATTACK_TYPE_OPTIONS = [
  { type: 'sql_injection', label: 'SQL Injection' },
  { type: 'xss_attack', label: 'XSS' },
  { type: 'command_injection', label: 'Command Injection' },
  { type: 'path_traversal', label: 'Path Traversal' },
  { type: 'file_inclusion', label: 'File Inclusion' },
  { type: 'bruteforce', label: 'Brute Force' },
  { type: 'password_spray', label: 'Password Spray' },
  { type: 'credential_stuffing', label: 'Credential Stuffing' },
  { type: 'port_scan', label: 'Port Scan' },
  { type: 'ddos', label: 'DDoS' },
  { type: 'reconnaissance', label: 'Reconnaissance' },
  { type: 'privilege_escalation', label: 'Privilege Escalation' },
  { type: 'lateral_movement', label: 'Lateral Movement' },
  { type: 'data_exfiltration', label: 'Data Exfiltration' },
  { type: 'c2_communication', label: 'C2 Communication' },
  { type: 'malware_activity', label: 'Malware Activity' },
  { type: 'insider_threat', label: 'Insider Threat' },
  { type: 'account_takeover', label: 'Account Takeover' },
];

function App() {
  const [mode, setMode] = useState<'single' | 'multi'>('single');
  const [data, setData] = useState<ParseResponse | null>(null);
  const [correlationData, setCorrelationData] = useState<CorrelateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [evtxTutorialFile, setEvtxTutorialFile] = useState<string | null>(null);
  const [splitFileResult, setSplitFileResult] = useState<SplitFileResult | null>(null);
  const [activeTab, setActiveTab] = useState<'logs' | 'alerts' | 'attacks' | 'timeline' | 'stats'>('logs');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedEntry, setSelectedEntry] = useState<ParsedLogEntry | null>(null);
  const [selectedEntryFeedback, setSelectedEntryFeedback] = useState<{ [entryId: string]: 'safe' | 'unsafe' | 'attack_pattern' }>({});
  const [selectedEntryAttackType, setSelectedEntryAttackType] = useState<string>('');
  const [showAttackTypeDropdown, setShowAttackTypeDropdown] = useState(false);
  const [selectedChain, setSelectedChain] = useState<AttackChain | null>(null);
  const [displayedEntryCount, setDisplayedEntryCount] = useState(500);
  const [isLoadingMore, setIsLoadingMore] = useState(false);

  // Get unique attack types from entries for filter
  const attackTypesInData = [...new Set((data?.entries || []).filter(e => e.attackType).map(e => e.attackType))].sort();

  const filteredEntries = (data?.entries || []).filter(entry => {
    const matchesSearch = searchQuery === '' || 
      entry.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.source.ip?.includes(searchQuery) ||
      entry.user?.name?.toLowerCase().includes(searchQuery.toLowerCase());
    
    if (severityFilter === 'all') return matchesSearch;
    
    // Check if severity filter is an attack type
    if (attackTypesInData.includes(severityFilter)) {
      return matchesSearch && entry.attackType === severityFilter;
    }
    
    return matchesSearch && entry.severity === severityFilter;
  });

  const exportToCSV = useCallback(() => {
    if (!data && !correlationData) return;
    
    const entries = data?.entries || [];
    const headers = ['timestamp', 'logType', 'severity', 'source_ip', 'user', 'action', 'outcome', 'message'];
    const rows = entries.map(e => [
      e.timestamp || '',
      e.logType,
      e.severity,
      e.source.ip || '',
      e.user?.name || '',
      e.action || '',
      e.outcome || '',
      `"${e.message.replace(/"/g, '""')}"`,
    ]);
    
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
  }, [data, correlationData]);

  const exportToJSON = useCallback(() => {
    const exportData = correlationData || data;
    if (!exportData) return;
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-analysis-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
  }, [data, correlationData]);

  const hasData = data || correlationData;
  const attackChains = correlationData?.correlation?.attackChains || [];
  const timeline = correlationData?.correlation?.timeline || [];

  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

  const CLIENT_SPLIT_THRESHOLD = 200 * 1024; // 200KB

  const handleFileUpload = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    console.log('handleFileUpload called');
    const files = Array.from(e.target.files || []);
    if (files.length === 0) {
      console.log('No files selected');
      return;
    }

    console.log('Files selected:', files.map(f => ({ name: f.name, size: f.size })));

    // Single file mode
    if (mode === 'multi' || files.length > 1) {
      // Check for large files
      const largeFiles = files.filter(f => f.size > CLIENT_SPLIT_THRESHOLD);
      if (largeFiles.length > 0) {
        const fileNames = largeFiles.map(f => `${f.name} (${(f.size / 1024 / 1024).toFixed(1)} MB)`).join(', ');
        setError(`Files too large for multi-file upload: ${fileNames}. Files over 200KB will cause 413 errors. Please upload smaller files or use single file mode.`);
        return;
      }
      setUploadedFiles(prev => [...prev, ...files]);
      return;
    }

    const file = files[0];
    setError(null);
    setSplitFileResult(null);

    console.log('File upload:', { name: file.name, size: file.size, mode, threshold: CLIENT_SPLIT_THRESHOLD });

    if (isEVTXFile(file)) {
      setEvtxTutorialFile(file.name);
      return;
    }

    // DISABLED: File splitting - master worker handles distribution
    // Master worker distributes large files equally among all workers
    /*
    if (file.size > CLIENT_SPLIT_THRESHOLD) {
      console.log('Large file detected, splitting...');
      setLoading(true);
      try {
        const result = await splitFileClient(file);
        setSplitFileResult(result);
        setData(null);
        setLoading(false);
        return;
      } catch (err) {
        console.error('Split error:', err);
        setError('Failed to split file. Try a smaller file or use the CLI tool.');
        setLoading(false);
        return;
      }
    }
    */

    // Send file to master worker - it handles distribution
    console.log('Sending file to master worker...');
    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromFile(file);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      if (err instanceof EVTXUploadError) {
        setEvtxTutorialFile(file.name);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to parse logs');
      }
    } finally {
      setLoading(false);
    }
  }, [mode]);

  const handleRunCorrelation = useCallback(async () => {
    if (uploadedFiles.length === 0) return;

    // File size check - prevent very large files
    const largeFiles = uploadedFiles.filter(f => f.size > CLIENT_SPLIT_THRESHOLD);
    if (largeFiles.length > 0) {
      const fileNames = largeFiles.map(f => f.name).join(', ');
      setError(`Files too large (${largeFiles.length} file(s) > 200KB): ${fileNames}. Please split large files or upload smaller files.`);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const result = await correlateMultipleFiles(uploadedFiles);
      setCorrelationData(result);
      setData(null);
      setActiveTab('attacks');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to correlate logs');
    } finally {
      setLoading(false);
    }
  }, [uploadedFiles]);

  const handleDrop = useCallback(async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files || []);
    if (files.length === 0) return;

    if (mode === 'multi' || files.length > 1) {
      // File size check for multi-file mode
      const largeFiles = files.filter(f => f.size > CLIENT_SPLIT_THRESHOLD);
      if (largeFiles.length > 0) {
        const fileNames = largeFiles.map(f => `${f.name} (${(f.size / 1024 / 1024).toFixed(1)} MB)`).join(', ');
        setError(`Files too large for multi-file upload: ${fileNames}. Files over 200KB will cause 413 errors. Please upload smaller files or use single file mode.`);
        return;
      }
      setUploadedFiles(prev => [...prev, ...files]);
      return;
    }

    const file = files[0];
    setError(null);
    setSplitFileResult(null);

    if (isEVTXFile(file)) {
      setEvtxTutorialFile(file.name);
      return;
    }

    // DISABLED: File splitting in drop handler - master worker handles distribution
    /*
    if (file.size > CLIENT_SPLIT_THRESHOLD) {
      console.log('Large file detected in drop, splitting...');
      setLoading(true);
      try {
        const result = await splitFileClient(file);
        setSplitFileResult(result);
        setData(null);
        setLoading(false);
        return;
      } catch (err) {
        console.error('Split error:', err);
        setError('Failed to split file. Try a smaller file or use the CLI tool.');
        setLoading(false);
        return;
      }
    }
    */

    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromFile(file);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      if (err instanceof EVTXUploadError) {
        setEvtxTutorialFile(file.name);
      } else {
        setError(err instanceof Error ? err.message : 'Failed to parse logs');
      }
    } finally {
      setLoading(false);
    }
  }, [mode]);

  const handlePaste = useCallback(async (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text');
    if (!text || text.length < 10) return;

    setLoading(true);
    setError(null);

    try {
      const result = await parseLogsFromText(text);
      setData(result);
      setCorrelationData(null);
      setActiveTab('logs');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse logs');
    } finally {
      setLoading(false);
    }
  }, []);

  const removeFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const resetAll = () => {
    setData(null);
    setCorrelationData(null);
    setUploadedFiles([]);
    setSelectedEntry(null);
    setSelectedEntryFeedback({});
    setSelectedEntryAttackType('');
    setShowAttackTypeDropdown(false);
    setSelectedChain(null);
    setError(null);
  };
  const summary = correlationData?.correlation?.summary;

  return (
    <div className="app" onPaste={handlePaste}>
      {/* Header */}
      <header className="header">
        <div className="header-content container">
          <div className="logo">
            <Shield size={28} />
            <span>Cyber Chakshu SIEM</span>
          </div>
          <div className="header-stats">
            {hasData && (
              <>
                {summary && (
                  <>
                    <div className="stat risk-stat" style={{ 
                      borderColor: summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e' 
                    }}>
                      <span className="stat-value">{summary.riskScore}</span>
                      <span className="stat-label">Risk Score</span>
                    </div>
                    <div className="stat">
                      <span className="stat-value" style={{ color: attackChains.length > 0 ? '#ef4444' : 'inherit' }}>
                        {attackChains.length}
                      </span>
                      <span className="stat-label">Attack Chains</span>
                    </div>
                  </>
                )}
                {data && (
                  <>
                    <div className="stat">
                      <span className="stat-value">{data.totalLines}</span>
                      <span className="stat-label">Total Lines</span>
                    </div>
                    <div className="stat">
                      <span className="stat-value">{data.parsedLines}</span>
                      <span className="stat-label">Parsed</span>
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </header>

      <main className="main container">
        {/* Upload Section */}
        {!hasData && (
          <div className="upload-wrapper fade-in">
            {/* Mode Toggle */}
            <div className="mode-toggle">
              <button 
                className={`mode-btn ${mode === 'single' ? 'active' : ''}`}
                onClick={() => setMode('single')}
              >
                <FileText size={18} />
                Single Log
              </button>
              <button 
                className={`mode-btn ${mode === 'multi' ? 'active' : ''}`}
                onClick={() => setMode('multi')}
              >
                <Layers size={18} />
                Multi-Log Correlation
              </button>
            </div>

            <div 
              className="upload-section card"
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
            >
              <div className="upload-icon">
                {mode === 'single' ? <Upload size={48} /> : <Layers size={48} />}
              </div>
              <h2>{mode === 'single' ? 'Upload Log File' : 'Upload Multiple Log Files'}</h2>
              <p>
                {mode === 'single' 
                  ? 'Drag & drop your log file here, paste log content, or click to browse'
                  : 'Upload auth, web, database, firewall, and system logs for cross-correlation analysis'
                }
              </p>
              <p className="supported-types">
                Supports: Database, Webserver, System, SSH, Firewall, Network, Mail logs (56+ formats)
              </p>
              
              <input
                type="file"
                id="file-upload"
                onChange={handleFileUpload}
                accept=".log,.txt,.json,.jsonl,.csv,.xml,.evtx,.evt,.raw,.gz,.zip"
                multiple={mode === 'multi'}
                hidden
              />
              <label htmlFor="file-upload" className="btn btn-primary">
                <FileText size={18} />
                {mode === 'single' ? 'Choose File' : 'Add Files'}
              </label>

              {/* Multi-file list */}
              {mode === 'multi' && uploadedFiles.length > 0 && (
                <div className="uploaded-files">
                  <h4>Uploaded Files ({uploadedFiles.length})</h4>
                  <div className="file-list">
                    {uploadedFiles.map((file, index) => (
                      <div key={index} className="file-item">
                        <FileText size={16} />
                        <span>{file.name}</span>
                        <span className="file-size">{(file.size / 1024).toFixed(1)} KB</span>
                        <button onClick={() => removeFile(index)} className="remove-btn">
                          <X size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                  <button 
                    className="btn btn-primary run-correlation-btn"
                    onClick={handleRunCorrelation}
                    disabled={loading}
                  >
                    <Zap size={18} />
                    Run ML Correlation Analysis
                  </button>
                </div>
              )}

              {loading && (
                <div className="loading">
                  <RefreshCw size={24} className="spin" />
                  <span>{mode === 'multi' ? 'Running ML correlation analysis...' : 'Parsing logs...'}</span>
                </div>
              )}
              {error && (
                <div className="error-message">
                  <AlertTriangle size={18} />
                  {error}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Dashboard */}
        {hasData && (
          <div className="dashboard fade-in">
            {/* Toolbar */}
            <div className="toolbar">
              <div className="tabs">
                {correlationData && (
                  <>
                    <button 
                      className={`tab ${activeTab === 'attacks' ? 'active' : ''}`}
                      onClick={() => setActiveTab('attacks')}
                    >
                      <Target size={16} />
                      Attack Chains ({attackChains.length})
                    </button>
                    <button 
                      className={`tab ${activeTab === 'timeline' ? 'active' : ''}`}
                      onClick={() => setActiveTab('timeline')}
                    >
                      <Clock size={16} />
                      Timeline
                    </button>
                  </>
                )}
                {data && (
                  <>
                    <button 
                      className={`tab ${activeTab === 'logs' ? 'active' : ''}`}
                      onClick={() => setActiveTab('logs')}
                    >
                      <Terminal size={16} />
                      Logs ({data?.entries?.length || 0})
                    </button>
                    <button 
                      className={`tab ${activeTab === 'alerts' ? 'active' : ''}`}
                      onClick={() => setActiveTab('alerts')}
                    >
                      <AlertTriangle size={16} />
                      Alerts ({(data?.entries?.filter(e => e.attackType).length || 0) + (data?.alerts?.length || 0)})
                    </button>
                  </>
                )}
                <button 
                  className={`tab ${activeTab === 'stats' ? 'active' : ''}`}
                  onClick={() => setActiveTab('stats')}
                >
                  <Activity size={16} />
                  Analytics
                </button>
              </div>
              <div className="toolbar-actions">
                <button className="btn btn-secondary" onClick={resetAll}>
                  <Upload size={16} />
                  New Analysis
                </button>
                <div className="dropdown">
                  <button className="btn btn-secondary">
                    <Download size={16} />
                    Export
                    <ChevronDown size={14} />
                  </button>
                  <div className="dropdown-menu">
                    <button onClick={exportToCSV}>Export as CSV</button>
                    <button onClick={exportToJSON}>Export as JSON</button>
                  </div>
                </div>
              </div>
            </div>

            {/* Summary KPIs for Correlation */}
            {summary && (
              <div className="kpi-grid correlation-kpis">
                <div className="kpi-card risk-card" style={{ 
                  borderLeft: `4px solid ${summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e'}` 
                }}>
                  <div className="kpi-icon" style={{ 
                    background: summary.riskScore > 70 ? 'rgba(239, 68, 68, 0.2)' : summary.riskScore > 40 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(34, 197, 94, 0.2)' 
                  }}>
                    <TrendingUp size={24} color={summary.riskScore > 70 ? '#ef4444' : summary.riskScore > 40 ? '#f59e0b' : '#22c55e'} />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.riskScore}/100</div>
                    <div className="kpi-label">Risk Score</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(239, 68, 68, 0.2)' }}>
                    <Target size={24} color="#ef4444" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.criticalAlerts}</div>
                    <div className="kpi-label">Critical Alerts</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(34, 197, 94, 0.2)' }}>
                    <Shield size={24} color="#22c55e" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{summary.falsePositivesFiltered}</div>
                    <div className="kpi-label">False Positives Filtered</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(59, 130, 246, 0.2)' }}>
                    <Activity size={24} color="#3b82f6" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{correlationData?.correlation?.totalEvents || 0}</div>
                    <div className="kpi-label">Total Events</div>
                  </div>
                </div>
              </div>
            )}

            {/* KPI Cards for single file */}
            {data && !correlationData && (
              <div className="kpi-grid">
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(59, 130, 246, 0.2)' }}>
                    <FileText size={24} color="#3b82f6" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data.detectedType}</div>
                    <div className="kpi-label">Detected Log Type</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(34, 197, 94, 0.2)' }}>
                    <Activity size={24} color="#22c55e" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{Math.round((data.parsedLines / data.totalLines) * 100)}%</div>
                    <div className="kpi-label">Parse Success Rate</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(239, 68, 68, 0.2)' }}>
                    <AlertTriangle size={24} color="#ef4444" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data?.stats?.bySeverity?.error || 0}</div>
                    <div className="kpi-label">Errors</div>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon" style={{ background: 'rgba(245, 158, 11, 0.2)' }}>
                    <Target size={24} color="#f59e0b" />
                  </div>
                  <div className="kpi-content">
                    <div className="kpi-value">{data?.entries?.filter(e => e.attackType).length || 0}</div>
                    <div className="kpi-label">ML Detected Attacks</div>
                  </div>
                </div>
              </div>
            )}

            {/* Attack Chains Tab */}
            {activeTab === 'attacks' && correlationData && (
              <div className="attacks-section">
                {attackChains.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={48} />
                    <h3>No Attack Chains Detected</h3>
                    <p>The ML analysis did not identify any coordinated attack patterns across your logs.</p>
                  </div>
                ) : (
                  <>
                    {/* Recommendations */}
                    {correlationData.correlation?.recommendations?.length > 0 && (
                      <div className="recommendations-panel">
                        <h3>Recommendations</h3>
                        <ul>
                          {correlationData.correlation.recommendations.slice(0, 5).map((rec, i) => (
                            <li key={i}>{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="attack-chains-list">
                      {attackChains.map((chain) => (
                        <div 
                          key={chain.id} 
                          className={`attack-chain-card severity-${chain.prediction.confidence >= 0.8 ? 'critical' : chain.prediction.confidence >= 0.6 ? 'high' : 'medium'}`}
                          onClick={() => setSelectedChain(chain)}
                        >
                          <div className="chain-header">
                            <span className="attack-icon">{ATTACK_TYPE_ICONS[chain.attackType] || '?'}</span>
                            <div className="chain-title">
                              <h4>{chain.attackType.replace(/_/g, ' ').toUpperCase()}</h4>
                              <span className="chain-stage" style={{ background: STAGE_COLORS[chain.stage] }}>
                                {chain.stage.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <div className="chain-confidence">
                              <div className="confidence-bar">
                                <div 
                                  className="confidence-fill" 
                                  style={{ 
                                    width: `${chain.prediction.confidence * 100}%`,
                                    background: chain.prediction.confidence >= 0.8 ? '#ef4444' : chain.prediction.confidence >= 0.6 ? '#f59e0b' : '#3b82f6'
                                  }}
                                ></div>
                              </div>
                              <span>{(chain.prediction.confidence * 100).toFixed(0)}% confidence</span>
                            </div>
                          </div>
                          
                          <div className="chain-details">
                            <div className="chain-meta">
                              <div className="meta-item">
                                <span className="meta-label">Events</span>
                                <span className="meta-value">{chain.events.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Source IPs</span>
                                <span className="meta-value">{chain.sourceIps.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Target Users</span>
                                <span className="meta-value">{chain.targetUsers.length}</span>
                              </div>
                              <div className="meta-item">
                                <span className="meta-label">Duration</span>
                                <span className="meta-value">
                                  {formatDuration(new Date(chain.endTime).getTime() - new Date(chain.startTime).getTime())}
                                </span>
                              </div>
                            </div>

                            <div className="chain-explanation">
                              {chain.prediction.explanation.slice(0, 2).map((exp, i) => (
                                <p key={i}>{exp}</p>
                              ))}
                            </div>

                            <div className="chain-mitre">
                              <span className="mitre-label">MITRE ATT&CK:</span>
                              {chain.mitreTactics.slice(0, 2).map((tactic, i) => (
                                <span key={i} className="mitre-tag">{tactic}</span>
                              ))}
                            </div>
                          </div>

                          <div className="chain-recommendation">
                            <AlertTriangle size={14} />
                            {chain.recommendation.substring(0, 150)}...
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Timeline Tab */}
            {activeTab === 'timeline' && correlationData && (
              <div className="timeline-section">
                <div className="timeline-chart">
                  <h3>Event Timeline</h3>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={aggregateTimelineData(timeline)}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip 
                        contentStyle={{ background: '#1e293b', border: '1px solid #334155' }}
                        labelStyle={{ color: '#f1f5f9' }}
                      />
                      <Bar dataKey="normal" fill="#3b82f6" stackId="a" name="Normal" />
                      <Bar dataKey="anomaly" fill="#ef4444" stackId="a" name="Anomaly" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="timeline-list">
                  {timeline.slice(0, 100).map((event) => (
                    <div 
                      key={event.id} 
                      className={`timeline-item ${event.isAnomaly ? 'anomaly' : ''}`}
                    >
                      <div className="timeline-time">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </div>
                      <div className={`timeline-dot severity-${event.severity}`}></div>
                      <div className="timeline-content">
                        <div className="timeline-header">
                          <span className={`timeline-source badge-${event.logSource}`}>{event.logSource}</span>
                          <span className="timeline-title">{event.title}</span>
                          {event.isAnomaly && (
                            <span className="anomaly-badge">
                              Anomaly ({(event.anomalyScore * 100).toFixed(0)}%)
                            </span>
                          )}
                        </div>
                        <p className="timeline-desc">{event.description.substring(0, 100)}</p>
                        {event.sourceIp && <span className="timeline-ip">{event.sourceIp}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Logs Tab */}
            {activeTab === 'logs' && data && (
              <div className="logs-section">
                {/* Filters */}
                <div className="filters">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search logs..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    {searchQuery && (
                      <button onClick={() => setSearchQuery('')}>
                        <X size={16} />
                      </button>
                    )}
                  </div>
                    <select 
                      value={severityFilter} 
                      onChange={(e) => setSeverityFilter(e.target.value)}
                    >
                      <option value="all">All Entries</option>
                      <optgroup label="Severity">
                        <option value="critical">Critical</option>
                        <option value="error">Error</option>
                        <option value="warning">Warning</option>
                        <option value="info">Info</option>
                        <option value="debug">Debug</option>
                      </optgroup>
                      {attackTypesInData.length > 0 && (
                        <optgroup label="ML Detected Attacks">
                          {attackTypesInData.map(type => (
                            <option key={type} value={type}>{type?.replace(/_/g, ' ')}</option>
                          ))}
                        </optgroup>
                      )}
                    </select>
                </div>

                {/* Dynamic Logs Table */}
                <DynamicTable
                  entries={filteredEntries.slice(0, displayedEntryCount)}
                  detectedType={data?.detectedType || 'unknown'}
                  onEntryClick={setSelectedEntry}
                />
                {filteredEntries.length > displayedEntryCount && (
                  <div className="load-more-container">
                    {isLoadingMore ? (
                      <div className="loading-more">
                        <div className="buffering-dots">
                          <span></span>
                          <span></span>
                          <span></span>
                        </div>
                        <span>Loading more entries...</span>
                      </div>
                    ) : (
                      <button 
                        className="btn btn-secondary load-more-btn"
                        onClick={async () => {
                          setIsLoadingMore(true);
                          await new Promise(resolve => setTimeout(resolve, 500));
                          setDisplayedEntryCount(prev => Math.min(prev + 500, filteredEntries.length));
                          setIsLoadingMore(false);
                        }}
                      >
                        Load More Entries
                      </button>
                    )}
                    <div className="table-info">
                      Showing {Math.min(displayedEntryCount, filteredEntries.length)} of {filteredEntries.length} entries
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Alerts Tab */}
            {activeTab === 'alerts' && data && (
              <div className="alerts-section">
                {/* Get all suspicious entries (ML-detected attacks) */}
                {(() => {
                  // Use mlAttacks array directly for more accurate data
                  const mlAttacksFromApi = data?.mlAttacks || [];
                  const mlAttacks = (data?.entries || []).filter(e => e.attackType).map(entry => {
                    const fromApi = mlAttacksFromApi.find((a: any) => a.entry?.id === entry.id);
                    return {
                      ...entry,
                      _confidence: fromApi?.confidence || entry.attackConfidence || 0
                    };
                  });
                  const totalAlerts = (data?.alerts?.length || 0) + mlAttacks.length;

                  if (totalAlerts === 0) {
                    return (
                      <div className="empty-state">
                        <Shield size={48} />
                        <h3>No Suspicious Activity Detected</h3>
                        <p>The analysis did not find any security concerns or ML-detected attacks in the provided logs.</p>
                      </div>
                    );
                  }

                  return (
                    <>
                      {/* Attack Pattern Stats */}
                      {(() => {
                        const attackTypeCounts: Record<string, number> = {};
                        mlAttacks.forEach((e: any) => {
                          const type = e.attackType?.replace(/_/g, ' ') || 'Unknown';
                          attackTypeCounts[type] = (attackTypeCounts[type] || 0) + 1;
                        });
                        const sortedAttackTypes = Object.entries(attackTypeCounts)
                          .sort(([, a], [, b]) => b - a)
                          .slice(0, 3);

                        return (
                          <div className="alerts-stats-section">
                            {sortedAttackTypes.length > 0 && (
                              <div className="attack-frequency-card">
                                <h4 className="attack-frequency-title">Top Attack Patterns</h4>
                                <div className="attack-frequency-list">
                                  {sortedAttackTypes.map(([type, count], idx) => (
                                    <div key={type} className="attack-frequency-item">
                                      <span className="attack-frequency-rank">#{idx + 1}</span>
                                      <span className="attack-frequency-type">{type}</span>
                                      <span className="attack-frequency-count">{count} occurrences</span>
                                      <div className="attack-frequency-bar">
                                        <div
                                          className="attack-frequency-fill"
                                          style={{
                                            width: `${(count / mlAttacks.length) * 100}%`,
                                            background: idx === 0 ? '#ef4444' : idx === 1 ? '#f59e0b' : '#3b82f6'
                                          }}
                                        />
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Source IPs with most attacks */}
                            {(() => {
                              const ipCounts: Record<string, number> = {};
                              mlAttacks.forEach((e: any) => {
                                if (e.source?.ip) {
                                  ipCounts[e.source.ip] = (ipCounts[e.source.ip] || 0) + 1;
                                }
                              });
                              const topIps = Object.entries(ipCounts)
                                .sort(([, a], [, b]) => b - a)
                                .slice(0, 5);

                              if (topIps.length > 0) {
                                return (
                                  <div className="attack-source-card">
                                    <h4 className="attack-frequency-title">Top Attacker IPs</h4>
                                    <div className="attack-frequency-list">
                                      {topIps.map(([ip, count], idx) => (
                                        <div key={ip} className="attack-frequency-item">
                                          <span className="attack-frequency-rank">#{idx + 1}</span>
                                          <span className="attack-frequency-type mono">{ip}</span>
                                          <span className="attack-frequency-count">{count} attacks</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              }
                              return null;
                            })()}
                          </div>
                        );
                      })()}

                      {/* ML-Detected Attacks Section */}
                      {mlAttacks.length > 0 && (
                        <div className="ml-attacks-section">
                          <h3 className="section-title">
                            <span className="ml-badge">ML</span>
                            ML-Detected Attacks ({mlAttacks.length})
                          </h3>
                          <div className="ml-attacks-grid">
                            {mlAttacks.map((entryWithConf: any) => (
                              <div
                                key={entryWithConf.id}
                                className="ml-attack-card"
                                onClick={() => setSelectedEntry(entryWithConf)}
                              >
                                <div className="ml-attack-header">
                                  <span className="ml-attack-icon">🎯</span>
                                  <span className="ml-attack-type">
                                    {entryWithConf.attackType?.replace(/_/g, ' ').toUpperCase()}
                                  </span>
                                  <span className="ml-attack-confidence" style={{
                                    color: entryWithConf._confidence >= 0.8 ? '#22c55e' : entryWithConf._confidence >= 0.5 ? '#f59e0b' : '#ef4444'
                                  }}>
                                    {(entryWithConf._confidence * 100).toFixed(0)}%
                                  </span>
                                </div>
                                <p className="ml-attack-message">
                                  {(entryWithConf.message || '').substring(0, 150)}
                                  {(entryWithConf.message || '').length > 150 ? '...' : ''}
                                </p>
                                <div className="ml-attack-meta">
                                  {entryWithConf.source?.ip && (
                                    <span className="ml-attack-ip">Source: {entryWithConf.source.ip}</span>
                                  )}
                                  <span className="ml-attack-time">{entryWithConf.timestamp}</span>
                                </div>
                                {entryWithConf.mitreTactics && entryWithConf.mitreTactics.length > 0 && (
                                  <div className="ml-attack-mitre">
                                    {entryWithConf.mitreTactics.slice(0, 2).map((tactic: string, i: number) => (
                                      <span key={i} className="mitre-tag">{tactic}</span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Traditional Alerts Section */}
                      {data.alerts.length > 0 && (
                        <div className="traditional-alerts-section">
                          <h3 className="section-title">Rule-Based Alerts ({data.alerts.length})</h3>
                          <div className="alerts-list">
                            {data.alerts.map((alert) => (
                              <div key={alert.id} className={`alert-card severity-${alert.severity}`}>
                                <div className="alert-header">
                                  <span className="alert-icon">{ATTACK_TYPE_ICONS[alert.type] || '?'}</span>
                                  <span className="alert-title">{alert.title}</span>
                                  <span className={`badge badge-${alert.severity === 'high' || alert.severity === 'critical' ? 'error' : 'warning'}`}>
                                    {alert.severity}
                                  </span>
                                </div>
                                <p className="alert-description">{alert.description}</p>
                                <div className="alert-meta">
                                  <span>Confidence: {alert.confidence}</span>
                                  {alert.sourceIps.length > 0 && (
                                    <span>Sources: {alert.sourceIps.join(', ')}</span>
                                  )}
                                  {alert.targetUsers.length > 0 && (
                                    <span>Users: {alert.targetUsers.join(', ')}</span>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>
            )}

            {/* Stats Tab */}
            {activeTab === 'stats' && (
              <div className="stats-section">
                {/* Quick Stats Row */}
                <div className="quick-stats-row">
                  <div className="quick-stat-card">
                    <span className="quick-stat-value">{data?.totalLines || 0}</span>
                    <span className="quick-stat-label">Total Lines</span>
                  </div>
                  <div className="quick-stat-card">
                    <span className="quick-stat-value">{data?.parsedLines || 0}</span>
                    <span className="quick-stat-label">Parsed</span>
                  </div>
                  <div className="quick-stat-card">
                    <span className="quick-stat-value">{data?.entries.filter(e => e.attackType).length || 0}</span>
                    <span className="quick-stat-label">Attacks</span>
                  </div>
                  <div className="quick-stat-card">
                    <span className="quick-stat-value">{data?.alerts.length || 0}</span>
                    <span className="quick-stat-label">Alerts</span>
                  </div>
                  <div className="quick-stat-card">
                    <span className="quick-stat-value">{data?.attackSummary?.riskScore || 0}</span>
                    <span className="quick-stat-label">Risk Score</span>
                  </div>
                </div>

                {/* Attack Types Overview */}
                {data?.attackSummary?.attackTypes && data.attackSummary.attackTypes.length > 0 && (
                  <div className="analytics-section">
                    <h3 className="analytics-section-title">Attack Types Overview</h3>
                    <div className="attack-types-overview">
                      {(data?.attackSummary?.attackTypes || []).map((type) => {
                        const count = (data?.entries || []).filter(e => e.attackType === type).length;
                        const totalEntries = data?.entries?.length || 1;
                        const percent = Math.round((count / totalEntries) * 100);
                        return (
                          <div key={type} className="attack-type-overview-item">
                            <div className="attack-type-overview-header">
                              <span className="attack-type-icon">{ATTACK_TYPE_ICONS[type] || '⚠️'}</span>
                              <span className="attack-type-name">{type.replace(/_/g, ' ')}</span>
                              <span className="attack-type-count">{count}</span>
                            </div>
                            <div className="attack-type-overview-bar">
                              <div
                                className="attack-type-overview-fill"
                                style={{
                                  width: `${percent}%`,
                                  background: percent > 50 ? '#ef4444' : percent > 25 ? '#f59e0b' : '#22c55e'
                                }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Timeline and Severity Row */}
                <div className="analytics-row">
                  {/* Timeline Chart */}
                  {(data?.stats.timeline || []).length > 0 && (
                    <div className="chart-card">
                      <h3>Event Timeline</h3>
                      <ResponsiveContainer width="100%" height={200}>
                        <LineChart data={data?.stats.timeline}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                          <YAxis stroke="#94a3b8" tick={{ fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{ background: '#1e293b', border: '1px solid #334155' }}
                            labelStyle={{ color: '#f1f5f9' }}
                          />
                          <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  {/* Severity Distribution */}
                  {Object.keys(data?.stats.bySeverity || {}).length > 0 && (
                    <div className="chart-card">
                      <h3>Severity Distribution</h3>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie
                            data={Object.entries(data?.stats.bySeverity || {}).map(([name, value]) => ({ name, value }))}
                            cx="50%"
                            cy="50%"
                            innerRadius={40}
                            outerRadius={70}
                            paddingAngle={2}
                            dataKey="value"
                          >
                            {Object.entries(data?.stats.bySeverity || {}).map(([severity]) => (
                              <Cell key={severity} fill={SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] || '#94a3b8'} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="legend compact">
                        {Object.entries(data?.stats.bySeverity || {}).map(([severity, count]) => (
                          <div key={severity} className="legend-item">
                            <span className="legend-color" style={{ background: SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] }}></span>
                            <span>{severity}: {count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Top Sources and Users Row */}
                <div className="analytics-row">
                  {/* Top Source IPs */}
                  <div className="chart-card">
                    <h3>Top Source IPs</h3>
                    <div className="top-list compact">
                      {(data?.stats.topSources || []).slice(0, 8).map((item, i) => {
                        const ip = item.ip || '';
                        return (
                          <div key={ip || i} className="top-item">
                            <span className="rank">{i + 1}</span>
                            <span className="mono">{ip || '-'}</span>
                            <span className="count">{item.count}</span>
                          </div>
                        );
                      })}
                      {(data?.stats.topSources || []).length === 0 && (
                        <div className="empty-list">No IP addresses found</div>
                      )}
                    </div>
                  </div>

                  {/* Top Users */}
                  <div className="chart-card">
                    <h3>Top Target Users</h3>
                    <div className="top-list compact">
                      {(data?.stats.topUsers || []).slice(0, 8).map((item, i) => (
                        <div key={item.user} className="top-item">
                          <span className="rank">{i + 1}</span>
                          <span>{item.user || '-'}</span>
                          <span className="count">{item.count}</span>
                        </div>
                      ))}
                      {(data?.stats.topUsers || []).length === 0 && (
                        <div className="empty-list">No users found</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Detail Modal for Log Entry */}
      {selectedEntry && (
        <div className="modal-overlay" onClick={() => setSelectedEntry(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Log Entry Details</h3>
              <button onClick={() => setSelectedEntry(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="detail-grid">
                <div className="detail-item">
                  <label>Timestamp</label>
                  <span className="mono">{selectedEntry.timestamp || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Log Type</label>
                  <span className="badge badge-info">{selectedEntry.logType}</span>
                </div>
                <div className="detail-item">
                  <label>Severity</label>
                  <span className={`badge badge-${selectedEntry.severity === 'error' || selectedEntry.severity === 'critical' ? 'error' : selectedEntry.severity === 'warning' ? 'warning' : 'info'}`}>
                    {selectedEntry.severity}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Outcome</label>
                  <span className={`badge ${selectedEntry.outcome === 'success' ? 'badge-success' : selectedEntry.outcome === 'failure' ? 'badge-error' : 'badge-info'}`}>
                    {selectedEntry.outcome || 'unknown'}
                  </span>
                </div>
                <div className="detail-item">
                  <label>Source IP</label>
                  <span className="mono">{selectedEntry.source.ip || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Source Host</label>
                  <span>{selectedEntry.source.hostname || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Service</label>
                  <span>{selectedEntry.source.service || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>User</label>
                  <span>{selectedEntry.user?.name || 'N/A'}</span>
                </div>
                <div className="detail-item">
                  <label>Action</label>
                  <span>{selectedEntry.action || 'N/A'}</span>
                </div>
                {selectedEntry.attackType && (
                  <div className="detail-item">
                    <label>ML Detection</label>
                    <span className="attack-badge">{selectedEntry.attackType.replace(/_/g, ' ')}</span>
                  </div>
                )}
                <div className="detail-item full-width">
                  <label>Tags</label>
                  <div className="tags">
                    {selectedEntry.tags.map(tag => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                </div>
                <div className="detail-item full-width">
                  <label>Message</label>
                  <pre className="mono">{selectedEntry.message}</pre>
                </div>
                <div className="detail-item full-width">
                  <label>Raw Log</label>
                  <pre className="mono raw-log">{selectedEntry.rawLine}</pre>
                </div>
                {Object.keys(selectedEntry.fields).length > 0 && (
                  <div className="detail-item full-width">
                    <label>Parsed Fields</label>
                    <pre className="mono">{JSON.stringify(selectedEntry.fields, null, 2)}</pre>
                  </div>
                )}

                {/* Feedback Section */}
                <div className="detail-item full-width modal-feedback-section">
                  <label>Classification Feedback</label>
                  <div className="modal-feedback-actions">
                    <button
                      className="modal-feedback-btn safe"
                      onClick={async () => {
                        if (!selectedEntry?.id) return;
                        try {
                          const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/feedback`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                              entry_id: selectedEntry.id,
                              user_label: 'safe',
                              original_prediction: selectedEntry.attackType || 'normal',
                              confidence: selectedEntry.attackConfidence || 0,
                              log_message: selectedEntry.message,
                              source_ip: selectedEntry.source?.ip || '',
                              log_type: selectedEntry.logType,
                              mitre_tactics: selectedEntry.mitreTactics || [],
                              mitre_techniques: selectedEntry.mitreTechniques || [],
                            }),
                          });
                          const data = await response.json();
                          if (data.success) {
                            setSelectedEntryFeedback(prev => ({ ...prev, [selectedEntry.id]: 'safe' }));
                          }
                        } catch (error) {
                          console.error('Feedback error:', error);
                        }
                      }}
                      disabled={selectedEntryFeedback[selectedEntry.id] === 'safe'}
                    >
                      {selectedEntryFeedback[selectedEntry.id] === 'safe' ? '✓ Marked Safe' : 'Mark as Safe (False Positive)'}
                    </button>
                    <button
                      className="modal-feedback-btn unsafe"
                      onClick={async () => {
                        if (!selectedEntry?.id) return;
                        try {
                          const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/feedback`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                              entry_id: selectedEntry.id,
                              user_label: 'unsafe',
                              original_prediction: selectedEntry.attackType || 'normal',
                              confidence: selectedEntry.attackConfidence || 0,
                              log_message: selectedEntry.message,
                              source_ip: selectedEntry.source?.ip || '',
                              log_type: selectedEntry.logType,
                              mitre_tactics: selectedEntry.mitreTactics || [],
                              mitre_techniques: selectedEntry.mitreTechniques || [],
                            }),
                          });
                          const data = await response.json();
                          if (data.success) {
                            setSelectedEntryFeedback(prev => ({ ...prev, [selectedEntry.id]: 'unsafe' }));
                          }
                        } catch (error) {
                          console.error('Feedback error:', error);
                        }
                      }}
                      disabled={selectedEntryFeedback[selectedEntry.id] === 'unsafe'}
                    >
                      {selectedEntryFeedback[selectedEntry.id] === 'unsafe' ? '✓ Marked Unsafe' : 'Mark as Unsafe (Confirmed Attack)'}
                    </button>
                    <div className="modal-attack-pattern-dropdown">
                      <button
                        className="modal-feedback-btn attack-pattern"
                        onClick={() => setShowAttackTypeDropdown(!showAttackTypeDropdown)}
                        disabled={selectedEntryFeedback[selectedEntry.id] === 'attack_pattern'}
                      >
                        {selectedEntryFeedback[selectedEntry.id] === 'attack_pattern' ? '✓ Marked as Attack' : 'Mark as Attack Pattern'}
                      </button>
                      {showAttackTypeDropdown && (
                        <div className="modal-attack-type-dropdown">
                          {ATTACK_TYPE_OPTIONS.map(option => (
                            <button
                              key={option.type}
                              className="modal-attack-type-option"
                              onClick={async () => {
                                if (!selectedEntry?.id) return;
                                try {
                                  const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/feedback`, {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({
                                      entry_id: selectedEntry.id,
                                      user_label: 'attack_pattern',
                                      original_prediction: selectedEntry.attackType || 'normal',
                                      confidence: selectedEntry.attackConfidence || 0,
                                      log_message: selectedEntry.message,
                                      source_ip: selectedEntry.source?.ip || '',
                                      log_type: selectedEntry.logType,
                                      mitre_tactics: selectedEntry.mitreTactics || [],
                                      mitre_techniques: selectedEntry.mitreTechniques || [],
                                      feedback_metadata: { corrected_attack_type: option.type },
                                    }),
                                  });
                                  const data = await response.json();
                                  if (data.success) {
                                    setSelectedEntryFeedback(prev => ({ ...prev, [selectedEntry.id]: 'attack_pattern' }));
                                    setSelectedEntryAttackType(option.label);
                                    setShowAttackTypeDropdown(false);
                                  }
                                } catch (error) {
                                  console.error('Feedback error:', error);
                                }
                              }}
                            >
                              {option.label}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  {selectedEntryFeedback[selectedEntry.id] && (
                    <span className={`modal-feedback-status ${selectedEntryFeedback[selectedEntry.id]}`}>
                      {selectedEntryFeedback[selectedEntry.id] === 'safe'
                        ? '✓ Log marked as safe - will help reduce false positives'
                        : selectedEntryFeedback[selectedEntry.id] === 'unsafe'
                        ? '✓ Log marked as unsafe - will help improve detection'
                        : `✓ Log marked as ${selectedEntryAttackType || 'attack'} pattern - will help detect similar attacks`}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Attack Chain Detail Modal */}
      {selectedChain && (
        <div className="modal-overlay" onClick={() => setSelectedChain(null)}>
          <div className="modal modal-large" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>
                <span className="attack-icon">{ATTACK_TYPE_ICONS[selectedChain.attackType]}</span>
                Attack Chain Details
              </h3>
              <button onClick={() => setSelectedChain(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="chain-detail-header">
                <div className="chain-type">
                  <h4>{selectedChain.attackType.replace(/_/g, ' ').toUpperCase()}</h4>
                  <span className="chain-stage" style={{ background: STAGE_COLORS[selectedChain.stage] }}>
                    {selectedChain.stage.replace(/_/g, ' ')}
                  </span>
                </div>
                <div className="chain-confidence-large">
                  <span className="confidence-value">{(selectedChain.prediction.confidence * 100).toFixed(0)}%</span>
                  <span className="confidence-label">Confidence</span>
                </div>
              </div>

              <div className="chain-info-grid">
                <div className="info-section">
                  <h5>Time Range</h5>
                  <p>{new Date(selectedChain.startTime).toLocaleString()} - {new Date(selectedChain.endTime).toLocaleString()}</p>
                </div>
                <div className="info-section">
                  <h5>Source IPs ({selectedChain.sourceIps.length})</h5>
                  <div className="ip-list">
                    {selectedChain.sourceIps.map(ip => (
                      <span key={ip} className="ip-tag">{ip}</span>
                    ))}
                  </div>
                </div>
                <div className="info-section">
                  <h5>Target Users ({selectedChain.targetUsers.length})</h5>
                  <div className="user-list">
                    {selectedChain.targetUsers.map(user => (
                      <span key={user} className="user-tag">{user}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="chain-explanation-section">
                <h5>ML Analysis</h5>
                <ul>
                  {selectedChain.prediction.explanation.map((exp, i) => (
                    <li key={i}>{exp}</li>
                  ))}
                </ul>
              </div>

              <div className="chain-mitre-section">
                <h5>MITRE ATT&CK Mapping</h5>
                <div className="mitre-tags">
                  {selectedChain.mitreTactics.map((tactic, i) => (
                    <span key={i} className="mitre-tactic">{tactic}</span>
                  ))}
                </div>
                <div className="mitre-tags">
                  {selectedChain.mitreTechniques.map((tech, i) => (
                    <span key={i} className="mitre-technique">{tech}</span>
                  ))}
                </div>
              </div>

              <div className="chain-recommendation-section">
                <h5>Recommendation</h5>
                <p>{selectedChain.recommendation}</p>
              </div>

              <div className="chain-events-section">
                <h5>Related Events ({selectedChain.events.length})</h5>
                <div className="events-list">
                  {selectedChain.events.slice(0, 20).map(event => (
                    <div key={event.id} className="event-item">
                      <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
                      <span className={`event-source badge-${event.logSource}`}>{event.logSource}</span>
                      <span className="event-message">{event.message.substring(0, 80)}</span>
                      <span className="event-score">{(event.correlationScore * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      {/* EVTX Tutorial Modal */}
      {/* EVTX Tutorial Modal */}
      {evtxTutorialFile && (
        <EVTXTutorial
          fileName={evtxTutorialFile}
          onClose={() => setEvtxTutorialFile(null)}
          onUploadAnother={() => {
            setEvtxTutorialFile(null);
            resetAll();
          }}
        />
      )}
      {/* Split File Modal */}
      {splitFileResult && (
        <div className="modal-overlay" onClick={() => setSplitFileResult(null)}>
          <div className="modal-content large-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <Scissors size={24} />
              <h2>File Split Complete</h2>
              <button className="close-btn" onClick={() => setSplitFileResult(null)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="split-info">
                <div className="info-card">
                  <File size={20} />
                  <div>
                    <strong>Original:</strong> {splitFileResult.originalFile.name}
                    <br />
                    <span className="file-size">{(splitFileResult.originalFile.sizeMB).toFixed(2)} MB</span>
                    <span className="line-count">{splitFileResult.originalFile.lineCount.toLocaleString()} lines</span>
                  </div>
                </div>
                
                <div className="split-summary">
                  <div className="split-stat">
                    <span className="stat-value">{splitFileResult.totalChunks}</span>
                    <span className="stat-label">Total Chunks</span>
                  </div>
                  <div className="split-stat">
                    <span className="stat-value">{splitFileResult.chunkSizeMB} MB</span>
                    <span className="stat-label">Per Chunk</span>
                  </div>
                </div>
              </div>

              <div className="chunk-list">
                <h4>Split Chunks:</h4>
                <div className="chunk-items">
                  {splitFileResult.chunks.map((chunk) => (
                    <div key={chunk.index} className="chunk-item">
                      <span className="chunk-name">{chunk.name}</span>
                      <span className="chunk-lines">{chunk.lineCount.toLocaleString()} lines</span>
                      <span className="chunk-size">{(chunk.size / 1024 / 1024).toFixed(2)} MB</span>
                      <button 
                        className="btn btn-small"
                        onClick={() => {
                          const blob = new Blob([chunk.content], { type: 'text/plain' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = chunk.name;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        <Download size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="split-actions">
                <button 
                  className="btn btn-primary"
                  onClick={async () => {
                    console.log('Download ZIP clicked');
                    const zip = new JSZip();
                    splitFileResult.chunks.forEach(chunk => {
                      zip.file(chunk.name, chunk.content);
                    });
                    const content = await zip.generateAsync({ type: 'blob' });
                    const url = URL.createObjectURL(content);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${splitFileResult.originalFile.name.replace(/\.[^/.]+$/, '')}_chunks.zip`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <Archive size={16} />
                  Download All (ZIP)
                </button>
                
                <button 
                  className="btn btn-secondary"
                  onClick={() => {
                    setSplitFileResult(null);
                    setError(null);
                  }}
                >
                  <Upload size={16} />
                  Upload One by One
                </button>
                
                <button 
                  className="btn btn-outline"
                  onClick={() => setSplitFileResult(null)}
                >
                  Close
                </button>
              </div>

              <div className="upload-hint">
                <p>💡 Download the ZIP or individual chunks, then upload each chunk one by one (max 1MB each).</p>
                <p>Each chunk is ~1MB and safe for the backend to process.</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper functions
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(0)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(0)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

function aggregateTimelineData(timeline: TimelineEvent[]): Array<{ time: string; normal: number; anomaly: number }> {
  const grouped = new Map<string, { normal: number; anomaly: number }>();
  
  for (const event of timeline) {
    const minute = event.timestamp.substring(0, 16);
    if (!grouped.has(minute)) {
      grouped.set(minute, { normal: 0, anomaly: 0 });
    }
    const data = grouped.get(minute)!;
    if (event.isAnomaly) {
      data.anomaly++;
    } else {
      data.normal++;
    }
  }
  
  return Array.from(grouped.entries())
    .map(([time, data]) => ({ time: time.substring(11), ...data }))
    .sort((a, b) => a.time.localeCompare(b.time));
}

export default App;
