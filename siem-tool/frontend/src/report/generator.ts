// Report Generator
import type { ReportTemplate, ReportSection, Report, ReportRequest } from '../types';

export class ReportGenerator {
  private templates: Map<string, ReportTemplate> = new Map();

  constructor() {
    this.registerDefaultTemplates();
  }

  // Register default report templates
  private registerDefaultTemplates() {
    // Security Incident Report
    this.templates.set('security_incident', {
      id: 'security_incident',
      name: 'Security Incident Report',
      description: 'Comprehensive report on security incidents',
      sections: [
        {
          id: 'executive_summary',
          title: 'Executive Summary',
          type: 'summary',
          dataRequest: { id: 'req_summary', type: 'get_stats', timestamp: new Date().toISOString() }
        },
        {
          id: 'timeline',
          title: 'Event Timeline',
          type: 'timeline',
          dataRequest: { id: 'req_timeline', type: 'get_timeline', timestamp: new Date().toISOString() }
        },
        {
          id: 'attack_analysis',
          title: 'Attack Analysis',
          type: 'attack_chains',
          dataRequest: { id: 'req_attacks', type: 'get_attack_chains', timestamp: new Date().toISOString() }
        },
        {
          id: 'recommendations',
          title: 'Recommendations',
          type: 'recommendations'
        }
      ]
    });

    // Compliance Report
    this.templates.set('compliance', {
      id: 'compliance',
      name: 'Compliance Report',
      description: 'Report for compliance auditing',
      sections: [
        {
          id: 'compliance_summary',
          title: 'Compliance Summary',
          type: 'summary'
        },
        {
          id: 'security_events',
          title: 'Security Events',
          type: 'timeline'
        },
        {
          id: 'access_logs',
          title: 'Access Logs',
          type: 'custom'
        }
      ]
    });

    // Forensic Analysis Report
    this.templates.set('forensic', {
      id: 'forensic',
      name: 'Forensic Analysis Report',
      description: 'Detailed forensic analysis',
      sections: [
        {
          id: 'incident_overview',
          title: 'Incident Overview',
          type: 'summary'
        },
        {
          id: 'evidence_timeline',
          title: 'Evidence Timeline',
          type: 'timeline'
        },
        {
          id: 'attack_chain',
          title: 'Attack Chain Analysis',
          type: 'attack_chains'
        },
        {
          id: 'findings',
          title: 'Findings',
          type: 'custom'
        }
      ]
    });
  }

  // Generate report
  generateReport(request: ReportRequest, templateId: string = 'security_incident'): Report {
    const template = this.templates.get(templateId);
    if (!template) {
      throw new Error(`Template not found: ${templateId}`);
    }

    const report: Report = {
      id: `report_${Date.now()}`,
      name: `${template.name} - ${new Date().toLocaleDateString()}`,
      template,
      sections: [],
      generatedAt: new Date().toISOString(),
      format: 'html',
      content: ''
    };

    // Generate content for each section
    for (const sectionTemplate of template.sections) {
      const section = this.generateSection(sectionTemplate, request);
      report.sections.push(section);
    }

    // Generate full report content
    report.content = this.compileReport(report, request);

    return report;
  }

  // Generate individual section
  private generateSection(sectionTemplate: ReportSection, request: ReportRequest): ReportSection {
    const section: ReportSection = {
      id: sectionTemplate.id,
      title: sectionTemplate.title,
      type: sectionTemplate.type
    };

    switch (sectionTemplate.type) {
      case 'summary':
        section.content = this.generateSummary(request);
        break;
      case 'timeline':
        section.content = this.generateTimeline(request);
        break;
      case 'attack_chains':
        section.content = this.generateAttackChains(request);
        break;
      case 'recommendations':
        section.content = this.generateRecommendations(request);
        break;
      case 'custom':
        section.content = this.generateCustomContent(request, sectionTemplate.title);
        break;
    }

    return section;
  }

  // Generate summary section
  private generateSummary(request: ReportRequest): string {
    const { logData } = request;
    
    if (!logData?.attackSummary) {
      return 'No security incidents detected.';
    }

    const { totalAttacks, riskScore, attackTypes, uniqueSources } = logData.attackSummary;

    return `
## Executive Summary

**Incident Overview:**
- Total Attacks Detected: ${totalAttacks}
- Risk Score: ${riskScore}/100
- Unique Source IPs: ${uniqueSources}
- Attack Types: ${attackTypes?.join(', ') || 'None'}

**Severity Distribution:**
${Object.entries(logData.stats.bySeverity || {})
  .map(([severity, count]) => `- ${severity}: ${count}`)
  .join('\n')}
`;
  }

  // Generate timeline section
  private generateTimeline(request: ReportRequest): string {
    const { logData, correlateData } = request;
    
    const timeline = correlateData?.correlation.timeline || logData?.stats.timeline || [];
    
    let content = `## Event Timeline\n\n`;
    
    if (timeline.length === 0) {
      content += 'No timeline data available.\n';
      return content;
    }

    content += `Total Events: ${timeline.length}\n\n`;
    
    // Show recent events
    const recentEvents = timeline.slice(-20);
    content += `Recent Events:\n`;
    
    recentEvents.forEach((event: any) => {
      const time = event.timestamp || event.time || 'Unknown';
      const count = event.count || 1;
      content += `- ${time}: ${count} event${count > 1 ? 's' : ''}\n`;
    });

    return content;
  }

  // Generate attack chains section
  private generateAttackChains(request: ReportRequest): string {
    const { logData, correlateData } = request;
    
    const attackChains = correlateData?.correlation.attackChains || logData?.attackChains || [];
    
    let content = `## Attack Analysis\n\n`;
    
    if (attackChains.length === 0) {
      content += 'No attack chains detected.\n';
      return content;
    }

    content += `Detected Attack Chains: ${attackChains.length}\n\n`;
    
    attackChains.forEach((chain: any, index: number) => {
      content += `### Attack Chain ${index + 1}\n`;
      content += `- **Type:** ${chain.attackType}\n`;
      content += `- **Stage:** ${chain.stage}\n`;
      content += `- **Source IPs:** ${chain.sourceIps?.join(', ') || 'Unknown'}\n`;
      content += `- **Target Users:** ${chain.targetUsers?.join(', ') || 'Unknown'}\n`;
      content += `- **MITRE Tactics:** ${chain.mitreTactics?.join(', ') || 'Unknown'}\n`;
      content += `- **Recommendation:** ${chain.recommendation || 'None'}\n\n`;
    });

    return content;
  }

  // Generate recommendations section
  private generateRecommendations(request: ReportRequest): string {
    const { logData, correlateData } = request;
    
    let content = `## Recommendations\n\n`;
    
    const recommendations = correlateData?.correlation.recommendations || [];
    
    if (recommendations.length > 0) {
      content += `Based on analysis:\n`;
      recommendations.forEach((rec: string) => {
        content += `- ${rec}\n`;
      });
    } else {
      content += `Based on the analysis:\n`;
      
      if ((logData?.attackSummary?.riskScore || 0) > 70) {
        content += `- **CRITICAL:** Immediate incident response required\n`;
      }
      
      if (logData?.stats?.topSources?.length > 0) {
        content += `- Investigate top source IPs for suspicious activity\n`;
      }
      
      content += `- Review and update security policies\n`;
      content += `- Implement additional monitoring for detected attack types\n`;
    }

    return content;
  }

  // Generate custom content
  private generateCustomContent(_request: ReportRequest, title: string): string {
    return `## ${title}\n\nCustom content for ${title.toLowerCase()}.`;
  }

  // Compile full report
  private compileReport(report: Report, _request: ReportRequest): string {
    let html = `
<!DOCTYPE html>
<html>
<head>
    <title>${report.name}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        h3 { color: #777; }
        .section { margin: 30px 0; }
        .summary { background: #f8f9fa; padding: 20px; border-left: 4px solid #007bff; }
        .critical { color: #dc2626; font-weight: bold; }
        .high { color: #ea580c; }
        .medium { color: #ca8a04; }
        .low { color: #16a34a; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f2f2f2; }
        ul { margin-left: 20px; }
        .metadata { font-size: 0.9em; color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>${report.name}</h1>
    <div class="metadata">
        Generated: ${new Date(report.generatedAt).toLocaleString()}<br>
        Template: ${report.template.name}
    </div>
`;

    // Add each section
    for (const section of report.sections) {
      html += `
    <div class="section" id="${section.id}">
        <h2>${section.title}</h2>
        <div class="content">
            ${this.markdownToHtml(section.content || '')}
        </div>
    </div>
`;
    }

    html += `
    <div class="section">
        <h2>Report Details</h2>
        <div class="content">
            <p><strong>Report ID:</strong> ${report.id}</p>
            <p><strong>Generated:</strong> ${new Date(report.generatedAt).toLocaleString()}</p>
        </div>
    </div>
</body>
</html>
`;

    return html;
  }

  // Convert markdown to HTML (simple implementation)
  private markdownToHtml(markdown: string): string {
    return markdown
      .replace(/^## (.*$)/gim, '<h3>$1</h3>')
      .replace(/^# (.*$)/gim, '<h2>$1</h2>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/^- (.*$)/gim, '<li>$1</li>')
      .replace(/\n/g, '<br>')
      .replace(/<br><li>/g, '<ul><li>')
      .replace(/<\/li><br>/g, '</li></ul>')
      .replace(/<br><h3>/g, '</div><div class="section"><h3>')
      .replace(/<br><h2>/g, '</div><div class="section"><h2>');
  }

  // Get available templates
  getTemplates(): ReportTemplate[] {
    return Array.from(this.templates.values());
  }

  // Get template by ID
  getTemplate(id: string): ReportTemplate | undefined {
    return this.templates.get(id);
  }

  // Register custom template
  registerTemplate(template: ReportTemplate) {
    this.templates.set(template.id, template);
  }
}

// Singleton instance
export const reportGenerator = new ReportGenerator();
