import { useState, useRef, useCallback, useEffect } from 'react';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { Download, FileText, BarChart3, AlertTriangle, Shield, Clock, Target, CheckCircle2, User, Globe, Activity, Info, Wrench, X, ChevronDown } from 'lucide-react';
import type { ParseResponse, CorrelateResponse, AttackChain } from '../types';

interface SmartReportGeneratorProps {
  data: ParseResponse | CorrelateResponse | null;
  onClose: () => void;
  logType: 'single' | 'correlation';
}

export function SmartReportGenerator({ data, onClose, logType }: SmartReportGeneratorProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [showFormatDropdown, setShowFormatDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowFormatDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);
  const reportRef = useRef<HTMLDivElement>(null);

  // Comprehensive suggestion mapping for 40+ attack patterns
  const getRec = (t: string): string => {
    const r: Record<string, string> = {
      // Authentication Attacks
      bruteforce: 'Implement account lockout policies (e.g., 5 failed attempts locks account for 15 mins). Use CAPTCHA after 3 attempts.',
      password_spray: 'Enforce strong password policies (min 12 chars, complexity). Implement MFA for all external access.',
      credential_stuffing: 'Block known breached passwords. Implement rate limiting on authentication endpoints.',
      mfa_bypass: 'Review MFA implementation. Enforce phishing-resistant MFA (FIDO2/WebAuthn). Check for MFA fatigue attacks.',
      account_takeover: 'Monitor for impossible travel scenarios. Implement step-up authentication for sensitive actions.',
      
      // Web Application Attacks
      sql_injection: 'Use parameterized queries/prepared statements. Implement input validation and sanitization. Use WAF.',
      xss_attack: 'Implement output encoding (HTML, JS, CSS). Use Content Security Policy (CSP) headers. Validate input.',
      path_traversal: 'Validate file paths. Use absolute paths. Sanitize user input. Implement file permission restrictions.',
      command_injection: 'Avoid shell commands. Use safe APIs. Validate and sanitize all user input. Use allowlists.',
      file_inclusion: 'Disable remote file inclusion. Validate file paths. Use absolute paths only.',
      
      // Network Attacks
      port_scan: 'Implement firewall rules to block scanning IPs. Use intrusion detection systems (IDS).',
      ddos: 'Implement rate limiting. Use DDoS protection services (Cloudflare, AWS Shield). Enable SYN cookies.',
      reconnaissance: 'Minimize attack surface. Use security headers. Disable unnecessary services. Implement port security.',
      
      // Malware & C2
      malware_activity: 'Implement endpoint protection (EDR). Regular scanning. Isolate infected hosts. Block malicious domains.',
      c2_communication: 'Block known C2 domains/IPs. Monitor outbound connections. Use DNS filtering.',
      
      // Internal Threats
      insider_threat: 'Implement user behavior analytics (UBA). Review access logs. Use least privilege principle.',
      privilege_escalation: 'Review user permissions. Implement least privilege. Monitor for sudo/group membership changes.',
      lateral_movement: 'Segment network (VLANs). Monitor internal traffic. Use micro-segmentation.',
      data_exfiltration: 'Implement DLP solutions. Monitor outbound traffic. Block unauthorized data transfers.',
      
      // Session Attacks
      session_hijacking: 'Use HTTPS everywhere. Implement secure session cookies (HttpOnly, Secure, SameSite). Rotate session IDs.',
      
      // Generic/Default
      default: 'Review security controls and implement best practices. Conduct regular security audits.'
    };
    return r[t] || r.default;
  };

  // Get detailed explanation for attack type
  const getAttackExplanation = (t: string): string => {
    const explanations: Record<string, string> = {
      bruteforce: 'Brute force attacks involve systematically attempting all possible combinations of passwords or encryption keys to gain unauthorized access.',
      sql_injection: 'SQL injection occurs when malicious SQL code is inserted into application queries, potentially allowing attackers to view or modify database data.',
      xss_attack: 'Cross-Site Scripting (XSS) attacks inject malicious scripts into web pages viewed by other users.',
      ddos: 'Distributed Denial of Service (DDoS) attacks overwhelm systems with traffic from multiple sources, making services unavailable.',
      port_scan: 'Port scanning is used to identify open ports and services on a target system, often as a reconnaissance step before an attack.',
      default: 'This attack type involves unauthorized actions that compromise system security.'
    };
    return explanations[t] || explanations.default;
  };

  const formatDur = (ms: number): string => {
    const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60);
    return h > 0 ? h + 'h ' + (m % 60) + 'm' : m + 'm ' + (s % 60) + 's';
  };

  const generateStats = useCallback((): any => {
    if (!data) return {};
    const isCorr = logType === 'correlation';
    
    // Get entries based on log type
    let entries: any[] = [];
    if (isCorr) {
      const correlation = (data as CorrelateResponse).correlation;
      entries = correlation?.attackChains?.flatMap(c => c.events) || [];
    } else {
      entries = (data as ParseResponse).entries || [];
    }
    
    // Log type counts
    const typeCounts: Record<string, number> = {};
    entries.forEach(e => { 
      const logType = e.logType || 'unknown';
      typeCounts[logType] = (typeCounts[logType] || 0) + 1; 
    });
    const logTypes = Object.entries(typeCounts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count);
    
    // Severity counts
    const sevCounts: Record<string, number> = { debug: 0, info: 0, warning: 0, error: 0, critical: 0, unknown: 0 };
    entries.forEach(e => { 
      const severity = e.severity || 'unknown';
      sevCounts[severity] = (sevCounts[severity] || 0) + 1; 
    });
    const totalEntries = entries.length || 1;
    const severityBreakdown = Object.entries(sevCounts).filter(([_, c]) => c > 0).map(([s, c]) => ({ severity: s, count: c, percentage: Math.round((c / totalEntries) * 100) }));
    
    // IP statistics
    const ipCounts: Record<string, number> = {};
    entries.forEach(e => { 
      let ip: string | undefined;
      if ('source' in e && e.source?.ip) {
        ip = e.source.ip;
      } else if ('sourceIp' in e && e.sourceIp) {
        ip = e.sourceIp;
      }
      if (ip) ipCounts[ip] = (ipCounts[ip] || 0) + 1; 
    });
    const topSourceIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, c]) => ({ ip, count: c, percentage: Math.round((c / totalEntries) * 100) }));
    
    // User statistics
    const userCounts: Record<string, number> = {};
    entries.forEach(e => { 
      let user: string | undefined;
      if ('user' in e && e.user?.name) {
        user = e.user.name;
      } else if ('targetUser' in e && e.targetUser) {
        user = e.targetUser;
      }
      if (user) userCounts[user] = (userCounts[user] || 0) + 1; 
    });
    const topUsers = Object.entries(userCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([user, c]) => ({ user, count: c, percentage: Math.round((c / totalEntries) * 100) }));
    
    // ML Attacks - handle both direct entries and mlAttacks array
    const mlAttacks = !isCorr ? (data as ParseResponse).mlAttacks || [] : [];
    
    // Also check for attackType in entries
    const entryAttacks = entries.filter(e => e.attackType && e.attackType !== 'normal').map(e => ({
      entry: e,
      attackType: e.attackType,
      confidence: e.attackConfidence || 0.8,
      mitreTactics: e.mitreTactics || [],
      mitreTechniques: e.mitreTechniques || []
    }));
    
    // Combine both sources of attacks
    const allAttacks = [...mlAttacks, ...entryAttacks];
    
    const attackTypeCounts: Record<string, { count: number; totalConfidence: number; entries: any[] }> = {};
    allAttacks.forEach(a => { 
      const type = a.attackType || 'unknown'; 
      if (!attackTypeCounts[type]) attackTypeCounts[type] = { count: 0, totalConfidence: 0, entries: [] }; 
      attackTypeCounts[type].count += 1; 
      attackTypeCounts[type].totalConfidence += a.confidence;
      attackTypeCounts[type].entries.push(a);
    });
    const attackTypes = Object.entries(attackTypeCounts).sort((a, b) => b[1].count - a[1].count).map(([type, d]) => ({ 
      type, 
      count: d.count, 
      confidence: d.totalConfidence / d.count,
      entries: d.entries
    }));
    
    // Anomalies (ML attacks + critical/error logs)
    const criticalErrorEntries = entries.filter(e => e.severity === 'critical' || e.severity === 'error');
    const mlAnomalies = allAttacks.slice(0, 100).map((a, i) => { 
      const entry = a.entry;
      let sourceIp = 'Unknown';
      let user = 'Unknown';
      
      if (entry) {
        if ('source' in entry && entry.source?.ip) {
          sourceIp = entry.source.ip;
        } else if ('sourceIp' in entry && entry.sourceIp) {
          sourceIp = entry.sourceIp;
        }
        
        if ('user' in entry && entry.user?.name) {
          user = entry.user.name;
        } else if ('targetUser' in entry && entry.targetUser) {
          user = entry.targetUser;
        }
      }
      
      return { 
        id: entry?.id || 'anom-' + i, 
        timestamp: entry?.timestamp || 'Unknown', 
        type: a.attackType || 'Unknown', 
        severity: entry?.severity || 'unknown', 
        confidence: a.confidence, 
        description: entry?.message || '', 
        sourceIp: sourceIp, 
        user: user, 
        recommendation: getRec(a.attackType || ''),
        explanation: getAttackExplanation(a.attackType || ''),
        isMlAttack: true
      };
    });
    
    const criticalAnomalies = criticalErrorEntries.slice(0, 50).map((e, i) => {
      let sourceIp = 'Unknown';
      let user = 'Unknown';
      
      if ('source' in e && e.source?.ip) {
        sourceIp = e.source.ip;
      } else if ('sourceIp' in e && e.sourceIp) {
        sourceIp = e.sourceIp;
      }
      
      if ('user' in e && e.user?.name) {
        user = e.user.name;
      } else if ('targetUser' in e && e.targetUser) {
        user = e.targetUser;
      }
      
      return {
        id: e.id || 'crit-' + i,
        timestamp: e.timestamp || 'Unknown',
        type: e.logType || 'Unknown',
        severity: e.severity,
        confidence: 0.8,
        description: e.message || '',
        sourceIp: sourceIp,
        user: user,
        recommendation: getRec('default'),
        explanation: getAttackExplanation('default'),
        isMlAttack: false
      };
    });
    
    const anomalies = [...mlAnomalies, ...criticalAnomalies].slice(0, 150);
    
    // Attack chains
    const attackChains: AttackChain[] = isCorr ? (data as CorrelateResponse).correlation?.attackChains || [] : [];
    const formattedChains = attackChains.map(chain => ({ 
      id: chain.id, 
      attackType: chain.attackType, 
      stage: chain.stage, 
      eventCount: chain.events.length, 
      sourceIps: chain.sourceIps, 
      targetUsers: chain.targetUsers, 
      duration: formatDur(new Date(chain.endTime).getTime() - new Date(chain.startTime).getTime()), 
      confidence: chain.prediction.confidence, 
      mitreTactics: chain.mitreTactics 
    }));
    
    // Timeline data aggregation
    const timelineMap = new Map<string, { normal: number; anomaly: number; critical: number }>();
    for (const entry of entries) {
      if (!entry.timestamp) continue;
      const minute = entry.timestamp.substring(0, 16);
      if (!timelineMap.has(minute)) {
        timelineMap.set(minute, { normal: 0, anomaly: 0, critical: 0 });
      }
      const data = timelineMap.get(minute)!;
      if (entry.severity === 'critical') {
        data.critical++;
      } else if (anomalies.some(a => a.id === entry.id || a.timestamp === entry.timestamp)) {
        data.anomaly++;
      } else {
        data.normal++;
      }
    }
    const timelineData = Array.from(timelineMap.entries())
      .map(([time, data]) => ({ time: time.substring(11), ...data }))
      .sort((a, b) => a.time.localeCompare(b.time))
      .slice(-20);
    
    // Risk score calculation
    const riskScore = isCorr 
      ? (data as CorrelateResponse).correlation?.summary?.riskScore || 0 
      : Math.round((attackTypes.length * 10) + (severityBreakdown.find(s => s.severity === 'critical')?.count || 0) * 5);
    
    return { 
      totalLogs: entries.length, 
      parsedLogs: (data as ParseResponse).parsedLines || entries.length, 
      failedLogs: (data as ParseResponse).failedLines || 0, 
      logTypes, 
      severityBreakdown, 
      topSourceIPs, 
      topUsers, 
      attackTypes, 
      anomalies, 
      attackChains: formattedChains, 
      riskScore,
      criticalCount: sevCounts.critical || 0,
      errorCount: sevCounts.error || 0,
      timelineData
    };
  }, [data, logType]);

  const stats = generateStats();

  const generatePDF = async () => {
    if (!reportRef.current) {
      console.error('Report ref is null');
      return;
    }
    setIsGenerating(true);
    try {
      const canvas = await html2canvas(reportRef.current, { scale: 2, logging: false, useCORS: true, backgroundColor: '#ffffff' });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const imgWidth = canvas.width;
      const imgHeight = canvas.height;
      const ratio = Math.min(pdfWidth / imgWidth, pdfHeight / imgHeight);
      const imgX = (pdfWidth - imgWidth * ratio) / 2;
      let heightLeft = imgHeight * ratio;
      let position = 0;
      
      pdf.addImage(imgData, 'PNG', imgX, position, imgWidth * ratio, imgHeight * ratio);
      heightLeft -= pdfHeight;
      
      while (heightLeft > 0) { 
        position = heightLeft - imgHeight * ratio; 
        pdf.addPage(); 
        pdf.addImage(imgData, 'PNG', imgX, position, imgWidth * ratio, imgHeight * ratio); 
        heightLeft -= pdfHeight; 
      }
      
      pdf.save('siem-report-' + new Date().toISOString().split('T')[0] + '.pdf');
    } catch (error) { 
      console.error('PDF error:', error);
      alert('Failed to generate PDF. Try HTML format instead.');
    }
    setIsGenerating(false);
  };

  const generateHTML = () => {
    try {
      // Build grouped attack details for separate pages/sections
      let attackDetailsHtml = '';
      stats.attackTypes.forEach((attack: { type: string; count: number; confidence: number; entries: any[] }) => {
        attackDetailsHtml += `
          <div class="attack-group">
            <h4>${attack.type.replace(/_/g, ' ').toUpperCase()}</h4>
            <p><strong>Occurrences:</strong> ${attack.count}</p>
            <p><strong>Average Confidence:</strong> ${(attack.confidence * 100).toFixed(0)}%</p>
            <p><strong>Explanation:</strong> ${getAttackExplanation(attack.type)}</p>
            <p><strong>Recommendation:</strong> ${getRec(attack.type)}</p>
            <details>
              <summary>View Log Entries (${attack.entries.length})</summary>
              <div class="log-entries">
                ${attack.entries.slice(0, 10).map((a: any) => `
                  <div class="log-entry">
                    <span class="timestamp">${a.entry?.timestamp || 'Unknown'}</span>
                    <span class="message">${a.entry?.message || 'No message'}</span>
                    <span class="source">Source: ${a.entry?.source?.ip || 'Unknown'}</span>
                  </div>
                `).join('')}
              </div>
            </details>
          </div>
        `;
      });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>SIEM Security Report</title>
        <style>
          body { 
            font-family: Arial, sans-serif; 
            padding: 20px; 
            background-color: #f5f5f5; 
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
          }
          .report-container { 
            background: white; 
            padding: 30px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
          }
          h1 { color: #1e3a8a; border-bottom: 2px solid #1e3a8a; padding-bottom: 10px; }
          h2 { color: #1e40af; margin-top: 25px; }
          h3 { color: #1e40af; }
          .summary-box { 
            background: #e0f2fe; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0;
            border-left: 4px solid #0284c7;
          }
          .risk-high { color: #dc2626; font-weight: bold; }
          .risk-medium { color: #f59e0b; font-weight: bold; }
          .risk-low { color: #16a34a; font-weight: bold; }
          .attack-group { 
            background: #fef3c7; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px;
            border-left: 4px solid #f59e0b;
          }
          .log-entries { 
            background: #f3f4f6; 
            padding: 10px; 
            margin-top: 10px;
            font-family: monospace;
            font-size: 12px;
          }
          .log-entry { 
            padding: 5px; 
            border-bottom: 1px solid #ddd;
          }
          .timestamp { color: #6b7280; }
          .recommendations-list { 
            background: #d1fae5; 
            padding: 15px; 
            border-radius: 5px;
            border-left: 4px solid #10b981;
          }
          .recommendations-list li { margin: 8px 0; }
          .timeline-chart {
            background: white;
            padding: 10px;
            margin: 15px 0;
            border: 1px solid #ddd;
          }
          details { margin: 10px 0; }
          summary { cursor: pointer; color: #1e40af; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="report-container">
          <h1>🔒 SIEM Security Analysis Report</h1>
          <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
          
          <div class="summary-box">
            <h2>Executive Summary</h2>
            <p><strong>Total Events Analyzed:</strong> ${stats.totalLogs}</p>
            <p><strong>Risk Score:</strong> <span class="risk-${conclusion.riskLevel.toLowerCase()}">${conclusion.riskScore}/100 (${conclusion.riskLevel})</span></p>
            <p><strong>Detected Anomalies:</strong> ${stats.anomalies.length}</p>
            <p><strong>Attack Types Found:</strong> ${stats.attackTypes.length}</p>
          </div>

          <h2>📊 Attack Analysis</h2>
          ${attackDetailsHtml || '<p>No attacks detected.</p>'}

          <h2>📈 Timeline Overview</h2>
          <div class="timeline-chart">
            ${stats.timelineData && stats.timelineData.length > 0 ? `
              <svg width="100%" height="180" viewBox="0 0 800 180">
                <defs>
                  <linearGradient id="normalGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#3b82f6;stop-opacity:0.8"/>
                    <stop offset="100%" style="stop-color:#3b82f6;stop-opacity:0.3"/>
                  </linearGradient>
                  <linearGradient id="anomalyGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#ef4444;stop-opacity:0.8"/>
                    <stop offset="100%" style="stop-color:#ef4444;stop-opacity:0.3"/>
                  </linearGradient>
                </defs>
                <g transform="translate(40, 10)">
                  ${(function() {
                    const maxVal = Math.max(...stats.timelineData.map((d: any) => d.normal + d.anomaly + d.critical), 1);
                    const chartWidth = 720;
                    const chartHeight = 120;
                    const barWidth = Math.max(8, (chartWidth / stats.timelineData.length) - 4);
                    const scale = chartHeight / maxVal;
                    
                    return stats.timelineData.map((d: any, i: number) => {
                      const x = (i / stats.timelineData.length) * chartWidth;
                      const normalH = d.normal * scale;
                      const anomalyH = d.anomaly * scale;
                      const criticalH = d.critical * scale;
                      return `
                        <g>
                          <rect x="${x}" y="${chartHeight - normalH}" width="${barWidth}" height="${normalH}" fill="url(#normalGrad)" />
                          <rect x="${x}" y="${chartHeight - normalH - anomalyH}" width="${barWidth}" height="${anomalyH}" fill="url(#anomalyGrad)" />
                          <rect x="${x}" y="${chartHeight - normalH - anomalyH - criticalH}" width="${barWidth}" height="${criticalH}" fill="#dc2626" />
                          <text x="${x + barWidth/2}" y="${chartHeight + 15}" font-size="9" fill="#6b7280" text-anchor="middle" transform="rotate(45, ${x + barWidth/2}, ${chartHeight + 15})">${d.time.substring(0, 5)}</text>
                        </g>
                      `;
                    }).join('');
                  })()}
                  <line x1="0" y1="120" x2="720" y2="120" stroke="#e5e7eb" stroke-width="1"/>
                </g>
                <g transform="translate(10, 30)">
                  <rect x="0" y="0" width="16" height="16" fill="#3b82f6"/>
                  <text x="22" y="13" font-size="11" fill="#374151">Normal</text>
                  <rect x="80" y="0" width="16" height="16" fill="#ef4444"/>
                  <text x="102" y="13" font-size="11" fill="#374151">Anomaly</text>
                  <rect x="170" y="0" width="16" height="16" fill="#dc2626"/>
                  <text x="192" y="13" font-size="11" fill="#374151">Critical</text>
                </g>
              </svg>
              <p><strong>Total Events:</strong> ${stats.totalLogs} | <strong>Critical:</strong> ${stats.criticalCount} | <strong>Anomalies:</strong> ${stats.anomalies.length}</p>
            ` : `
              <p>No timeline data available.</p>
              <p><strong>Critical Events:</strong> ${stats.criticalCount}</p>
              <p><strong>Error Events:</strong> ${stats.errorCount}</p>
            `}
          </div>

          <h2>🛡️ Recommendations</h2>
          <div class="recommendations-list">
            <h3>Immediate Actions:</h3>
            <ul>
              ${conclusion.actions.map((action: string) => `<li>${action}</li>`).join('')}
            </ul>
          </div>

          <h2>ℹ️ Additional Information</h2>
          <p><strong>Log Types Detected:</strong> ${stats.logTypes.map((lt: any) => `${lt.type} (${lt.count})`).join(', ')}</p>
          <p><strong>Top Source IPs:</strong> ${stats.topSourceIPs.slice(0, 10).map((ip: any, i: number) => `#${i + 1} ${ip.ip} (${ip.count} events)`).join(', ') || 'None'}</p>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #6b7280;">
            <p>Generated by Cyber Chakshu SIEM Tool</p>
            <p>Report ID: ${Math.random().toString(36).substr(2, 9).toUpperCase()}</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'siem-report-' + new Date().toISOString().split('T')[0] + '.html';
    a.click();
    URL.revokeObjectURL(url);
    } catch (error) {
      console.error('HTML generation error:', error);
      alert('Failed to generate HTML report.');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'error': return '#ef4444';
      case 'warning': return '#f59e0b';
      case 'info': return '#3b82f6';
      case 'debug': return '#64748b';
      default: return '#94a3b8';
    }
  };

  // Dynamic Conclusion Generation
  const generateConclusion = () => {
    const detectedAttackTypes = stats.attackTypes.map((a: { type: string }) => a.type);
    const uniqueAttacks = Array.from(new Set(detectedAttackTypes)) as string[];
    
    if (stats.anomalies.length === 0) {
      return {
        summary: `The analysis scanned ${stats.totalLogs} log entries and detected no security anomalies or attack patterns. All events were classified as normal activity.`,
        riskLevel: "LOW",
        riskScore: stats.riskScore,
        actions: [
          "Continue regular monitoring of log files.",
          "Ensure all security patches are up to date.",
          "Maintain current security controls.",
          `Analyzed ${stats.logTypes.length} log types: ${stats.logTypes.map((lt: any) => lt.type).join(', ')}`,
          `Top source IPs: ${stats.topSourceIPs.slice(0, 3).map((ip: any) => ip.ip).join(', ') || 'None detected'}`
        ]
      };
    }

    let riskLevel = "LOW";
    if (stats.riskScore > 70) riskLevel = "HIGH";
    else if (stats.riskScore > 40) riskLevel = "MEDIUM";

    // Generate specific recommendations based on detected attacks
    const specificRecommendations = uniqueAttacks.map((attack: string) => getRec(attack));
    
    return {
      summary: `The analysis detected ${stats.anomalies.length} security anomalies including ${uniqueAttacks.length} unique attack types across ${stats.totalLogs} log entries.`,
      riskLevel: riskLevel,
      riskScore: stats.riskScore,
      actions: [
        ...specificRecommendations,
        `Review ${stats.criticalCount} critical events immediately.`,
        `Investigate ${stats.errorCount} error events for potential issues.`,
        "Monitor source IPs with high event counts."
      ]
    };
  };

  const conclusion = generateConclusion();

  // Check if data exists for specific sections
  const hasIPs = stats.topSourceIPs && stats.topSourceIPs.length > 0;
  const hasAttackTypes = stats.attackTypes && stats.attackTypes.length > 0;
  const hasAnomalies = stats.anomalies && stats.anomalies.length > 0;
  const hasAttackChains = stats.attackChains && stats.attackChains.length > 0;



  return (
    <div className="smart-report-modal">
      <div className="report-header">
        <h2><BarChart3 size={24} /> Security Intelligence Report</h2>
        <div className="report-actions">
          <div className="dropdown-container" ref={dropdownRef}>
            <button className="tab-btn" onClick={() => setShowFormatDropdown(!showFormatDropdown)}>
              <Download size={16} /> Download <ChevronDown size={14} />
            </button>
            {showFormatDropdown && (
              <div className="dropdown-menu">
                <button onClick={() => { generateHTML(); setShowFormatDropdown(false); }}>
                  <FileText size={14} /> HTML
                </button>
                <button onClick={() => { generatePDF(); setShowFormatDropdown(false); }} disabled={isGenerating}>
                  <Download size={14} /> PDF {isGenerating && '...'}
                </button>
              </div>
            )}
          </div>
          <button className="close-btn" onClick={onClose}><X size={16} /></button>
        </div>
      </div>
      
      <div className="report-content" ref={reportRef}>
        <div className="report-section report-header-section">
          <div className="report-title">
            <h1>SIEM Security Analysis Report</h1>
            <p className="report-date">Generated: {new Date().toLocaleString()}</p>
          </div>
          <div className="report-summary">
            <div className="summary-item">
              <div className="summary-value">{stats.totalLogs}</div>
              <div className="summary-label">Total Events</div>
            </div>
            <div className="summary-item">
              <div className="summary-value" style={{ color: stats.riskScore > 70 ? '#ef4444' : stats.riskScore > 40 ? '#f59e0b' : '#22c55e' }}>
                {stats.riskScore}
              </div>
              <div className="summary-label">Risk Score</div>
            </div>
            <div className="summary-item">
              <div className="summary-value" style={{ color: '#ef4444' }}>{stats.criticalCount}</div>
              <div className="summary-label">Critical</div>
            </div>
            <div className="summary-item">
              <div className="summary-value" style={{ color: '#ef4444' }}>{stats.errorCount}</div>
              <div className="summary-label">Errors</div>
            </div>
            <div className="summary-item">
              <div className="summary-value">{stats.anomalies.length}</div>
              <div className="summary-label">Anomalies</div>
            </div>
          </div>
        </div>

        {/* Overview Section */}
        <div className="report-section">
          <h3><Activity size={18} /> Overview</h3>
          <p>This report provides a comprehensive analysis of security events detected in your log data.</p>
          
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-icon" style={{ background: 'rgba(59, 130, 246, 0.2)' }}>
                <FileText size={20} color="#3b82f6" />
              </div>
              <div className="stat-info">
                <div className="stat-value">{stats.parsedLogs}</div>
                <div className="stat-label">Parsed Logs</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon" style={{ background: 'rgba(239, 68, 68, 0.2)' }}>
                <AlertTriangle size={20} color="#ef4444" />
              </div>
              <div className="stat-info">
                <div className="stat-value">{stats.failedLogs}</div>
                <div className="stat-label">Failed Parses</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon" style={{ background: 'rgba(34, 197, 94, 0.2)' }}>
                <CheckCircle2 size={20} color="#22c55e" />
              </div>
              <div className="stat-info">
                <div className="stat-value">{Math.round((stats.parsedLogs / (stats.parsedLogs + stats.failedLogs)) * 100)}%</div>
                <div className="stat-label">Success Rate</div>
              </div>
            </div>
            <div className="stat-card">
              <div className="stat-icon" style={{ background: 'rgba(245, 158, 11, 0.2)' }}>
                <Target size={20} color="#f59e0b" />
              </div>
              <div className="stat-info">
                <div className="stat-value">{stats.attackTypes.length}</div>
                <div className="stat-label">Attack Types</div>
              </div>
            </div>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="report-section">
          <h3><Shield size={18} /> Severity Distribution</h3>
          <div className="severity-list">
            {stats.severityBreakdown.map((sev: { severity: string; count: number; percentage: number }, i: number) => (
              <div key={i} className="severity-item">
                <div className="severity-info">
                  <span className="severity-badge" style={{ background: getSeverityColor(sev.severity) }}>
                    {sev.severity}
                  </span>
                  <span className="severity-count">{sev.count} events</span>
                </div>
                <div className="severity-bar">
                  <div 
                    className="severity-fill" 
                    style={{ width: `${sev.percentage}%`, background: getSeverityColor(sev.severity) }}
                  ></div>
                </div>
                <span className="severity-percentage">{sev.percentage}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Log Types */}
        <div className="report-section">
          <h3><FileText size={18} /> Log Types</h3>
          <div className="log-types-grid">
            {stats.logTypes.map((lt: { type: string; count: number }, i: number) => (
              <div key={i} className="log-type-item">
                <span className="log-type-name">{lt.type}</span>
                <span className="log-type-count">{lt.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Source IPs - Conditionally Rendered */}
        {hasIPs && (
          <div className="report-section">
            <h3><Globe size={18} /> Top Source IPs</h3>
            <div className="ip-list">
              {stats.topSourceIPs.map((ip: { ip: string; count: number }, i: number) => (
                <div key={i} className="ip-item">
                  <span className="ip-rank">#{i + 1}</span>
                  <span className="ip-address">{ip.ip}</span>
                  <span className="ip-count">{ip.count} events</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack Types - Conditionally Rendered */}
        {hasAttackTypes && (
          <div className="report-section">
            <h3><Target size={18} /> ML-Detected Attack Types</h3>
            <div className="attack-types-list">
              {stats.attackTypes.map((attack: { type: string; count: number; confidence: number }, i: number) => (
                <div key={i} className="attack-type-item">
                  <div className="attack-type-header">
                    <span className="attack-type-name">{attack.type.replace(/_/g, ' ')}</span>
                    <span className="attack-type-count">{attack.count} occurrences</span>
                  </div>
                  <div className="attack-type-confidence">
                    <div 
                      className="confidence-bar" 
                      style={{ width: `${attack.confidence * 100}%` }}
                    ></div>
                    <span>{(attack.confidence * 100).toFixed(0)}% avg confidence</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Anomalies Section - Conditionally Rendered */}
        {hasAnomalies && (
          <div className="report-section">
            <h3><AlertTriangle size={18} /> Anomalies & Critical Events</h3>
            <p className="section-description">Detailed list of ML-detected attacks and critical/error severity logs.</p>
            
            <div className="anomalies-list">
              {stats.anomalies.map((anomaly: { id: string; type: string; severity: string; isMlAttack: boolean; description: string; timestamp: string; sourceIp: string; user: string; recommendation: string }, i: number) => (
                <div key={i} className={`anomaly-item ${anomaly.isMlAttack ? 'ml-attack' : 'critical-log'}`}>
                  <div className="anomaly-header">
                    <span className="anomaly-type">
                      {anomaly.isMlAttack ? '🎯' : '⚠️'} {anomaly.type.replace(/_/g, ' ')}
                    </span>
                    <span className="anomaly-severity" style={{ background: getSeverityColor(anomaly.severity) }}>
                      {anomaly.severity}
                    </span>
                  </div>
                  <p className="anomaly-description">{anomaly.description}</p>
                  <div className="anomaly-meta">
                    <span><Clock size={12} /> {anomaly.timestamp}</span>
                    <span><Globe size={12} /> {anomaly.sourceIp}</span>
                    <span><User size={12} /> {anomaly.user}</span>
                  </div>
                  <div className="anomaly-recommendation">
                    <Wrench size={12} /> <strong>Recommendation:</strong> {anomaly.recommendation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack Chains (Correlation Mode) - Conditionally Rendered */}
        {hasAttackChains && (
          <div className="report-section">
            <h3><Target size={18} /> Attack Chains</h3>
            <div className="attack-chains-list">
              {stats.attackChains.map((chain: { id: string; attackType: string; stage: string; eventCount: number; sourceIps: string[]; targetUsers: string[]; duration: string; confidence: number }, i: number) => (
                <div key={i} className="attack-chain-item">
                  <div className="chain-header">
                    <span className="chain-type">{chain.attackType.replace(/_/g, ' ')}</span>
                    <span className="chain-stage">{chain.stage.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="chain-stats">
                    <span>Events: {chain.eventCount}</span>
                    <span>Source IPs: {chain.sourceIps.length}</span>
                    <span>Target Users: {chain.targetUsers.length}</span>
                    <span>Duration: {chain.duration}</span>
                  </div>
                  <div className="chain-confidence">
                    <div 
                      className="confidence-bar" 
                      style={{ width: `${chain.confidence * 100}%` }}
                    ></div>
                    <span>{(chain.confidence * 100).toFixed(0)}% confidence</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Dynamic Conclusion & Recommendations */}
        <div className="report-section conclusion-section">
          <h3><Info size={18} /> Conclusion & Recommendations</h3>
          <div className="conclusion-content">
            <p>
              <strong>Summary:</strong> {conclusion.summary}
            </p>
            <p>
              <strong>Risk Level:</strong> 
              <span style={{ 
                color: conclusion.riskLevel === 'HIGH' ? '#ef4444' : conclusion.riskLevel === 'MEDIUM' ? '#f59e0b' : '#22c55e',
                fontWeight: 'bold',
                marginLeft: '8px'
              }}>
                {conclusion.riskLevel} ({conclusion.riskScore}/100)
              </span>
            </p>
            
            <h4>Recommended Actions:</h4>
            <ul className="recommendations-list">
              {conclusion.actions.map((action: string, i: number) => (
                <li key={i}>{action}</li>
              ))}
            </ul>
            
            <div className="report-footer">
              <p>Generated by Cyber Chakshu SIEM Tool</p>
              <p>Report ID: {Math.random().toString(36).substr(2, 9).toUpperCase()}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default SmartReportGenerator;
