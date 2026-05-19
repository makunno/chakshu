import { useState } from 'react';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { Download, FileText, X, ShieldCheck } from 'lucide-react';
import type { ParseResponse, CorrelateResponse } from '../types';
import { generateSiemReport } from '../api';

interface ReportGeneratorProps {
  data: ParseResponse | CorrelateResponse | null;
  logType: 'single' | 'correlation';
  onClose: () => void;
}

export function ReportGenerator({ data, logType, onClose }: ReportGeneratorProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [isGeneratingOfficial, setIsGeneratingOfficial] = useState(false);

  const handleGenerateOfficial = async () => {
    if (!data || logType !== 'single') return;
    setIsGeneratingOfficial(true);
    try {
      await generateSiemReport(data as ParseResponse);
      onClose();
    } catch (err) {
      console.error('Failed to generate official report:', err);
      alert('Failed to generate official PDF report. Please try again.');
    } finally {
      setIsGeneratingOfficial(false);
    }
  };

  const getRec = (t: string): string => {
    const r: Record<string, string> = {
      bruteforce: 'Implement account lockout policies (e.g., 5 failed attempts locks account for 15 mins). Use CAPTCHA after 3 attempts.',
      password_spray: 'Enforce strong password policies (min 12 chars, complexity). Implement MFA for all external access.',
      credential_stuffing: 'Block known breached passwords. Implement rate limiting on authentication endpoints.',
      mfa_bypass: 'Review MFA implementation. Enforce phishing-resistant MFA (FIDO2/WebAuthn). Check for MFA fatigue attacks.',
      account_takeover: 'Monitor for impossible travel scenarios. Implement step-up authentication for sensitive actions.',
      sql_injection: 'Use parameterized queries/prepared statements. Implement input validation and sanitization. Use WAF.',
      xss_attack: 'Implement output encoding (HTML, JS, CSS). Use Content Security Policy (CSP) headers. Validate input.',
      path_traversal: 'Validate file paths. Use absolute paths. Sanitize user input. Implement file permission restrictions.',
      command_injection: 'Avoid shell commands. Use safe APIs. Validate and sanitize all user input. Use allowlists.',
      file_inclusion: 'Disable remote file inclusion. Validate file paths. Use absolute paths only.',
      port_scan: 'Implement firewall rules to block scanning IPs. Use intrusion detection systems (IDS).',
      ddos: 'Implement rate limiting. Use DDoS protection services (Cloudflare, AWS Shield). Enable SYN cookies.',
      reconnaissance: 'Minimize attack surface. Use security headers. Disable unnecessary services. Implement port security.',
      malware_activity: 'Implement endpoint protection (EDR). Regular scanning. Isolate infected hosts. Block malicious domains.',
      c2_communication: 'Block known C2 domains/IPs. Monitor outbound connections. Use DNS filtering.',
      insider_threat: 'Implement user behavior analytics (UBA). Review access logs. Use least privilege principle.',
      privilege_escalation: 'Review user permissions. Implement least privilege. Monitor for sudo/group membership changes.',
      lateral_movement: 'Segment network (VLANs). Monitor internal traffic. Use micro-segmentation.',
      data_exfiltration: 'Implement DLP solutions. Monitor outbound traffic. Block unauthorized data transfers.',
      session_hijacking: 'Use HTTPS everywhere. Implement secure session cookies (HttpOnly, Secure, SameSite). Rotate session IDs.',
      default: 'Review security controls and implement best practices. Conduct regular security audits.'
    };
    return r[t] || r.default;
  };

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

  const generateStats = () => {
    if (!data) return null;
    const isCorr = logType === 'correlation';
    
    let entries: any[] = [];
    if (isCorr) {
      const correlation = (data as CorrelateResponse).correlation;
      entries = correlation?.attackChains?.flatMap(c => c.events) || [];
    } else {
      entries = (data as ParseResponse).entries || [];
    }
    
    const typeCounts: Record<string, number> = {};
    entries.forEach(e => { 
      const lt = e.logType || 'unknown';
      typeCounts[lt] = (typeCounts[lt] || 0) + 1; 
    });
    const logTypes = Object.entries(typeCounts).map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count);
    
    const sevCounts: Record<string, number> = { debug: 0, info: 0, warning: 0, error: 0, critical: 0, unknown: 0 };
    entries.forEach(e => { 
      const severity = e.severity || 'unknown';
      sevCounts[severity] = (sevCounts[severity] || 0) + 1; 
    });
    const totalEntries = entries.length || 1;
    const severityBreakdown = Object.entries(sevCounts).filter(([_, c]) => c > 0).map(([s, c]) => ({ severity: s, count: c, percentage: Math.round((c / totalEntries) * 100) }));
    
    const ipCounts: Record<string, number> = {};
    entries.forEach(e => { 
      let ip: string | undefined;
      if ('source' in e && e.source?.ip) ip = e.source.ip;
      else if ('sourceIp' in e && e.sourceIp) ip = e.sourceIp;
      if (ip) ipCounts[ip] = (ipCounts[ip] || 0) + 1; 
    });
    const topSourceIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, c]) => ({ ip, count: c }));
    
    const userCounts: Record<string, number> = {};
    entries.forEach(e => { 
      let user: string | undefined;
      if ('user' in e && e.user?.name) user = e.user.name;
      else if ('targetUser' in e && e.targetUser) user = e.targetUser;
      if (user) userCounts[user] = (userCounts[user] || 0) + 1; 
    });
    const topUsers = Object.entries(userCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([user, c]) => ({ user, count: c }));
    
    // Timeline data - group events by hour
    const timelineCounts: Record<string, { normal: number; anomaly: number }> = {};
    entries.forEach(e => {
      if (e.timestamp) {
        // Extract hour from timestamp
        const hour = e.timestamp.substring(0, 13) + ':00:00';
        if (!timelineCounts[hour]) timelineCounts[hour] = { normal: 0, anomaly: 0 };
        const isAnomaly = e.severity === 'critical' || e.severity === 'error' || (e as any).attackType;
        if (isAnomaly) {
          timelineCounts[hour].anomaly++;
        } else {
          timelineCounts[hour].normal++;
        }
      }
    });
    const timeline = Object.entries(timelineCounts)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(0, 24)
      .map(([time, counts]) => ({ time, ...counts }));
    
    const mlAttacks = !isCorr ? (data as ParseResponse).mlAttacks || [] : [];
    const entryAttacks = entries.filter(e => e.attackType && e.attackType !== 'normal').map(e => ({
      entry: e,
      attackType: e.attackType,
      confidence: e.attackConfidence || 0.8,
    }));
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
    
    const criticalErrorEntries = entries.filter(e => e.severity === 'critical' || e.severity === 'error');
    
    const anomalies = allAttacks.slice(0, 100).map((a, i) => { 
      const entry = a.entry;
      let sourceIp = 'Unknown';
      let user = 'Unknown';
      if (entry) {
        if ('source' in entry && entry.source?.ip) sourceIp = entry.source.ip;
        else if ('sourceIp' in entry && entry.sourceIp) sourceIp = entry.sourceIp;
        if ('user' in entry && entry.user?.name) user = entry.user.name;
        else if ('targetUser' in entry && entry.targetUser) user = entry.targetUser;
      }
      return { 
        id: entry?.id || 'anom-' + i, 
        timestamp: entry?.timestamp || 'Unknown', 
        type: a.attackType || 'Unknown', 
        severity: entry?.severity || 'unknown', 
        confidence: a.confidence, 
        description: entry?.message || '', 
        sourceIp, 
        user, 
        recommendation: getRec(a.attackType || ''),
        explanation: getAttackExplanation(a.attackType || ''),
      };
    });
    
    const criticalAnomalies = criticalErrorEntries.slice(0, 50).map((e, i) => {
      let sourceIp = 'Unknown';
      let user = 'Unknown';
      if ('source' in e && e.source?.ip) sourceIp = e.source.ip;
      else if ('sourceIp' in e && e.sourceIp) sourceIp = e.sourceIp;
      if ('user' in e && e.user?.name) user = e.user.name;
      else if ('targetUser' in e && e.targetUser) user = e.targetUser;
      return {
        id: e.id || 'crit-' + i,
        timestamp: e.timestamp || 'Unknown',
        type: e.logType || 'Unknown',
        severity: e.severity,
        description: e.message || '',
        sourceIp,
        user,
        recommendation: getRec('default'),
        explanation: getAttackExplanation('default'),
      };
    });
    
    const allAnomalies = [...anomalies, ...criticalAnomalies].slice(0, 150);
    
    const riskScore = isCorr 
      ? (data as CorrelateResponse).correlation?.summary?.riskScore || 0 
      : Math.round((attackTypes.length * 10) + (sevCounts.critical || 0) * 5);
    
    return { 
      totalLogs: entries.length, 
      parsedLogs: (data as ParseResponse).parsedLines || entries.length, 
      failedLogs: (data as ParseResponse).failedLines || 0, 
      logTypes, 
      severityBreakdown, 
      topSourceIPs, 
      topUsers, 
      attackTypes, 
      anomalies: allAnomalies, 
      riskScore,
      criticalCount: sevCounts.critical || 0,
      errorCount: sevCounts.error || 0,
      timeline
    };
  };

  const stats = generateStats();

  const generateConclusion = () => {
    if (!stats) return { summary: '', riskLevel: 'LOW', riskScore: 0, actions: [] };
    
    const detectedAttackTypes = stats.attackTypes.map((a: { type: string }) => a.type);
    const uniqueAttacks = Array.from(new Set(detectedAttackTypes)) as string[];
    
    if (stats.anomalies.length === 0) {
      return {
        summary: `The analysis scanned ${stats.totalLogs} log entries and detected no security anomalies or attack patterns. All events were classified as normal activity.`,
        riskLevel: 'LOW',
        riskScore: stats.riskScore,
        actions: [
          'Continue regular monitoring of log files.',
          'Ensure all security patches are up to date.',
          'Maintain current security controls.',
          `Analyzed ${stats.logTypes.length} log types: ${stats.logTypes.map((lt: any) => lt.type).join(', ')}`,
          `Top source IPs: ${stats.topSourceIPs.slice(0, 3).map((ip: any) => ip.ip).join(', ') || 'None detected'}`
        ]
      };
    }

    let riskLevel = 'LOW';
    if (stats.riskScore > 70) riskLevel = 'HIGH';
    else if (stats.riskScore > 40) riskLevel = 'MEDIUM';

    const specificRecommendations = uniqueAttacks.map((attack: string) => getRec(attack));
    
    return {
      summary: `The analysis detected ${stats.anomalies.length} security anomalies including ${uniqueAttacks.length} unique attack types across ${stats.totalLogs} log entries.`,
      riskLevel: riskLevel,
      riskScore: stats.riskScore,
      actions: [
        ...specificRecommendations,
        `Review ${stats.criticalCount} critical events immediately.`,
        `Investigate ${stats.errorCount} error events for potential issues.`,
        'Monitor source IPs with high event counts.'
      ]
    };
  };

  const conclusion = generateConclusion();

  const generateHTML = () => {
    if (!stats) return;
    
    // Build severity bar visualization
    const maxSeverity = Math.max(...stats.severityBreakdown.map((s: any) => s.count), 1);
    let severityBarHtml = '';
    stats.severityBreakdown.forEach((sev: any) => {
      const barWidth = (sev.count / maxSeverity) * 100;
      const color = sev.severity === 'critical' ? '#dc2626' : 
                    sev.severity === 'error' ? '#ef4444' : 
                    sev.severity === 'warning' ? '#f59e0b' : 
                    sev.severity === 'info' ? '#3b82f6' : '#64748b';
      severityBarHtml += `
        <div style="margin: 10px 0;">
          <span style="background: ${color}; color: white; padding: 3px 10px; border-radius: 3px; font-size: 12px;">${sev.severity}</span>
          <span style="margin-left: 15px; font-weight: bold;">${sev.count} events (${sev.percentage}%)</span>
          <div style="background: #e5e7eb; height: 14px; width: 300px; margin-top: 5px; border-radius: 3px; display: inline-block; vertical-align: middle; margin-left: 10px;">
            <div style="background: ${color}; height: 100%; width: ${barWidth}%; border-radius: 3px;"></div>
          </div>
        </div>
      `;
    });

    // Build attack details
    let attackDetailsHtml = '';
    stats.attackTypes.forEach((attack: { type: string; count: number; confidence: number; entries: any[] }) => {
      attackDetailsHtml += `
        <div style="background: #fef3c7; padding: 15px; margin: 10px 0; border-left: 4px solid #f59e0b; border-radius: 5px;">
          <h4 style="margin: 0 0 10px 0; color: #000;">${attack.type.replace(/_/g, ' ').toUpperCase()}</h4>
          <p style="margin: 5px 0; color: #000;"><strong>Occurrences:</strong> ${attack.count}</p>
          <p style="margin: 5px 0; color: #000;"><strong>Average Confidence:</strong> ${(attack.confidence * 100).toFixed(0)}%</p>
          <p style="margin: 5px 0; color: #000;"><strong>Explanation:</strong> ${getAttackExplanation(attack.type)}</p>
          <p style="margin: 5px 0; color: #065f46;"><strong>Recommendation:</strong> ${getRec(attack.type)}</p>
        </div>
      `;
    });

    // Build IP table
    const ipTableHtml = stats.topSourceIPs.slice(0, 10).map((ip: any, i: number) => 
      `<tr><td style="border: 1px solid #ddd; padding: 8px;">#${i+1}</td><td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;">${ip.ip}</td><td style="border: 1px solid #ddd; padding: 8px; text-align: right;">${ip.count}</td></tr>`
    ).join('');

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>SIEM Security Report</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5; color: #000; max-width: 1200px; margin: 0 auto; }
          .report-container { background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          h1 { color: #000; border-bottom: 3px solid #000; padding-bottom: 15px; }
          h2 { color: #000; margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
          p { color: #000; font-size: 14px; }
          .summary-box { background: #e0f2fe; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 5px solid #0284c7; }
          .risk-high { color: #dc2626; font-weight: bold; }
          .risk-medium { color: #f59e0b; font-weight: bold; }
          .risk-low { color: #16a34a; font-weight: bold; }
          .attack-group { background: #fef3c7; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #f59e0b; }
          .recommendations-list { background: #d1fae5; padding: 20px; border-radius: 5px; border-left: 5px solid #10b981; margin: 15px 0; }
          .recommendations-list li { color: #000; margin: 10px 0; font-size: 14px; }
          table { width: 100%; border-collapse: collapse; margin: 15px 0; }
          th { background: #f3f4f6; border: 1px solid #ddd; padding: 10px; text-align: left; color: #000; }
          td { border: 1px solid #ddd; padding: 8px; color: #000; }
        </style>
      </head>
      <body>
        <div class="report-container">
          <h1>SIEM SECURITY ANALYSIS REPORT</h1>
          <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
          
          <div class="summary-box">
            <h2 style="margin-top: 0;">EXECUTIVE SUMMARY</h2>
            <p><strong>Total Events Analyzed:</strong> ${stats.totalLogs}</p>
            <p><strong>Parsed Logs:</strong> ${stats.parsedLogs} | <strong>Failed:</strong> ${stats.failedLogs}</p>
            <p><strong>Risk Score:</strong> <span class="risk-${conclusion.riskLevel.toLowerCase()}" style="font-size: 18px; font-weight: bold;">${conclusion.riskScore}/100 (${conclusion.riskLevel})</span></p>
            <p><strong>Detected Anomalies:</strong> ${stats.anomalies.length}</p>
            <p><strong>Attack Types Found:</strong> ${stats.attackTypes.length}</p>
          </div>

          <h2>SEVERITY DISTRIBUTION</h2>
          ${severityBarHtml}

          <h2>LOG TYPES</h2>
          <table>
            <tr><th>Log Type</th><th style="text-align: right;">Count</th></tr>
            ${stats.logTypes.map((lt: any) => `<tr><td>${lt.type}</td><td style="text-align: right;">${lt.count}</td></tr>`).join('')}
          </table>

          <h2>TOP SOURCE IPs</h2>
          <table>
            <tr><th style="width: 60px;">Rank</th><th>IP Address</th><th style="width: 100px; text-align: right;">Events</th></tr>
            ${ipTableHtml}
          </table>

          <h2>TOP USERS</h2>
          <table>
            <tr><th style="width: 60px;">Rank</th><th>Username</th><th style="width: 100px; text-align: right;">Events</th></tr>
            ${stats.topUsers.slice(0, 10).map((u: any, i: number) => `<tr><td>#${i+1}</td><td>${u.user}</td><td style="text-align: right;">${u.count}</td></tr>`).join('')}
          </table>

          <h2>ML-DETECTED ATTACKS</h2>
          ${attackDetailsHtml || '<p>No ML-detected attacks found in the analyzed logs.</p>'}

          <h2>RECOMMENDATIONS</h2>
          <div class="recommendations-list">
            <ul>
              ${conclusion.actions.map((action: string) => `<li>${action}</li>`).join('')}
            </ul>
          </div>

          <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #000; text-align: center; color: #000;">
            <p style="font-weight: bold;">Generated by Cyber Chakshu SIEM Tool</p>
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
    onClose();
  };

  const generatePDF = async () => {
    if (!stats) return;
    setIsGenerating(true);
    
    // Create a temporary div to render the report with DARK text
    const tempDiv = document.createElement('div');
    tempDiv.style.position = 'absolute';
    tempDiv.style.left = '-9999px';
    tempDiv.style.width = '800px';
    tempDiv.style.background = 'white';
    tempDiv.style.padding = '40px';
    tempDiv.style.color = '#000000';
    tempDiv.style.fontFamily = 'Arial, sans-serif';
    tempDiv.style.fontSize = '14px';
    
    // Build attack details
    let attackDetailsHtml = '';
    stats.attackTypes.forEach((attack: { type: string; count: number; confidence: number }) => {
      attackDetailsHtml += `
        <div style="background: #fef3c7; padding: 12px; margin: 8px 0; border-left: 4px solid #f59e0b;">
          <strong>${attack.type.replace(/_/g, ' ').toUpperCase()}</strong><br/>
          Occurrences: ${attack.count} | Confidence: ${(attack.confidence * 100).toFixed(0)}%<br/>
          <em>${getRec(attack.type)}</em>
        </div>
      `;
    });

    // Build severity bar visualization
    const maxSeverity = Math.max(...stats.severityBreakdown.map((s: any) => s.count), 1);
    let severityBarHtml = '';
    stats.severityBreakdown.forEach((sev: any) => {
      const barWidth = (sev.count / maxSeverity) * 100;
      const color = sev.severity === 'critical' ? '#dc2626' : 
                    sev.severity === 'error' ? '#ef4444' : 
                    sev.severity === 'warning' ? '#f59e0b' : 
                    sev.severity === 'info' ? '#3b82f6' : '#64748b';
      severityBarHtml += `
        <div style="margin: 8px 0;">
          <span style="background: ${color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px;">${sev.severity}</span>
          <span style="margin-left: 10px;">${sev.count} events (${sev.percentage}%)</span>
          <div style="background: #e5e7eb; height: 12px; width: 200px; margin-top: 4px; border-radius: 2px;">
            <div style="background: ${color}; height: 100%; width: ${barWidth}%; border-radius: 2px;"></div>
          </div>
        </div>
      `;
    });

    // Build IP table
    const ipTableHtml = stats.topSourceIPs.slice(0, 10).map((ip: any, i: number) => 
      `<tr><td style="border: 1px solid #ddd; padding: 6px;">#${i+1}</td><td style="border: 1px solid #ddd; padding: 6px;">${ip.ip}</td><td style="border: 1px solid #ddd; padding: 6px;">${ip.count}</td></tr>`
    ).join('');

    tempDiv.innerHTML = `
      <div style="color: #000000;">
        <h1 style="color: #000000; border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px;">SIEM SECURITY ANALYSIS REPORT</h1>
        <p style="color: #000;"><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
        
        <div style="background: #e0f2fe; padding: 15px; margin: 15px 0; border-left: 4px solid #0284c7;">
          <h2 style="color: #000; margin-top: 0;">EXECUTIVE SUMMARY</h2>
          <p style="color: #000;"><strong>Total Events Analyzed:</strong> ${stats.totalLogs}</p>
          <p style="color: #000;"><strong>Risk Score:</strong> <span style="font-weight: bold; color: ${conclusion.riskLevel === 'HIGH' ? '#dc2626' : conclusion.riskLevel === 'MEDIUM' ? '#f59e0b' : '#16a34a'};">${conclusion.riskScore}/100 (${conclusion.riskLevel})</span></p>
          <p style="color: #000;"><strong>Parsed Logs:</strong> ${stats.parsedLogs} | <strong>Failed:</strong> ${stats.failedLogs}</p>
          <p style="color: #000;"><strong>Detected Anomalies:</strong> ${stats.anomalies.length}</p>
          <p style="color: #000;"><strong>Attack Types Found:</strong> ${stats.attackTypes.length}</p>
        </div>

        <h2 style="color: #000;">SEVERITY DISTRIBUTION</h2>
        ${severityBarHtml}

        <h2 style="color: #000;">LOG TYPES</h2>
        <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
          <tr style="background: #f3f4f6;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Log Type</th><th style="border: 1px solid #ddd; padding: 8px; text-align: right;">Count</th></tr>
          ${stats.logTypes.map((lt: any) => `<tr><td style="border: 1px solid #ddd; padding: 6px;">${lt.type}</td><td style="border: 1px solid #ddd; padding: 6px; text-align: right;">${lt.count}</td></tr>`).join('')}
        </table>

        <h2 style="color: #000;">TOP SOURCE IPs</h2>
        <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
          <tr style="background: #f3f4f6;"><th style="border: 1px solid #ddd; padding: 8px;">Rank</th><th style="border: 1px solid #ddd; padding: 8px;">IP Address</th><th style="border: 1px solid #ddd; padding: 8px;">Events</th></tr>
          ${ipTableHtml}
        </table>

        <h2 style="color: #000;">ML-DETECTED ATTACKS</h2>
        ${attackDetailsHtml || '<p>No attacks detected.</p>'}

        <h2 style="color: #000;">RECOMMENDATIONS</h2>
        <ul style="background: #d1fae5; padding: 15px 15px 15px 35px; margin: 10px 0;">
          ${conclusion.actions.map((action: string) => `<li style="color: #000; margin: 8px 0;">${action}</li>`).join('')}
        </ul>

        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #000; text-align: center; color: #000;">
          <p style="color: #000;">Generated by Cyber Chakshu SIEM Tool</p>
          <p style="color: #000;">Report ID: ${Math.random().toString(36).substr(2, 9).toUpperCase()}</p>
        </div>
      </div>
    `;
    document.body.appendChild(tempDiv);
    
    try {
      const canvas = await html2canvas(tempDiv, { 
        scale: 3, 
        backgroundColor: '#ffffff',
        useCORS: true,
        logging: false
      });
      document.body.removeChild(tempDiv);
      
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const imgWidth = canvas.width;
      const imgHeight = canvas.height;
      const ratio = Math.min(pdfWidth / imgWidth, pdfHeight / imgHeight);
      const imgX = (pdfWidth - imgWidth * ratio) / 2;
      
      pdf.addImage(imgData, 'PNG', imgX, 0, imgWidth * ratio, imgHeight * ratio);
      pdf.save('siem-report-' + new Date().toISOString().split('T')[0] + '.pdf');
    } catch (error) {
      console.error('PDF error:', error);
      if (tempDiv.parentNode) document.body.removeChild(tempDiv);
    }
    setIsGenerating(false);
    onClose();
  };

  return (
    <div className="smart-report-modal">
      <div className="report-header">
        <h2>Generate Security Report</h2>
        <button className="close-btn" onClick={onClose}><X size={16} /></button>
      </div>
      <div className="report-content">
        <div className="format-selection-dialog">
          <h3>Choose Report Format</h3>
          <p>Select your preferred format for the security report:</p>
          <div className="format-options">
            <button className="format-option" onClick={handleGenerateOfficial} disabled={isGeneratingOfficial || logType !== 'single'}>
              {isGeneratingOfficial ? 'Generating...' : <ShieldCheck size={32} />}
              <span>Official PDF Report</span>
              <small>Professional Backend-generated PDF</small>
            </button>
            <button className="format-option" onClick={generateHTML}>
              <FileText size={32} />
              <span>HTML Report</span>
              <small>Download as HTML file</small>
            </button>
            <button className="format-option" onClick={generatePDF} disabled={isGenerating}>
              {isGenerating ? 'Generating...' : <Download size={32} />}
              <span>Legacy PDF Report</span>
              <small>Client-side generated PDF</small>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ReportGenerator;