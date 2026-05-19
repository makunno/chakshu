// Main Agent Class
import type { AgentMessage, DataRequest, DataResponse, ParseResponse, CorrelateResponse } from '../types';
import { agentTools } from './tools';
import { agentMemory } from './memory';
import { SYSTEM_PROMPT } from './prompts';
import * as api from '../api';

export interface AgentConfig {
  model?: string;
  maxTokens?: number;
  temperature?: number;
  useTools?: boolean;
}

export class SOCAnalystAgent {
  private config: Required<AgentConfig>;
  private isProcessing: boolean = false;

  constructor(config: AgentConfig = {}) {
    this.config = {
      model: config.model || 'meta-llama/llama-3.1-8b-instruct:free',
      maxTokens: config.maxTokens || 1000,
      temperature: config.temperature || 0.3,
      useTools: config.useTools !== false
    };
    // Initialize agent with default conversation
    agentMemory.createConversation();
    // Use config to avoid unused variable warning
    void this.config;
  }

  // Initialize agent with parsed data
  initialize(parsedData: ParseResponse, correlateData?: CorrelateResponse) {
    agentTools.setParsedData(parsedData);
    if (correlateData) {
      agentTools.setCorrelateData(correlateData);
    }
    
    agentMemory.createConversation({
      logDataAvailable: true,
      totalEntries: parsedData.parsedLines,
      attackCount: parsedData.attackSummary?.totalAttacks || 0
    });
  }

  // Process user message
  async processMessage(userMessage: string): Promise<AgentMessage> {
    if (this.isProcessing) {
      throw new Error('Agent is already processing a message');
    }

    this.isProcessing = true;

    try {
      // Add user message to memory
      agentMemory.addMessage('user', userMessage);
      
      // Parse message for data requests
      const dataRequests = this.extractDataRequests(userMessage);
      
      // Execute data requests
      const dataResponses: DataResponse[] = [];
      for (const request of dataRequests) {
        const response = await agentTools.executeRequest(request);
        dataResponses.push(response);
      }

      // Generate agent response
      const agentResponse = await this.generateResponse(userMessage, dataResponses);
      
      // Add agent message to memory
      const agentMsg = agentMemory.addMessage('agent', agentResponse, dataRequests, dataResponses);
      
      return agentMsg;
    } finally {
      this.isProcessing = false;
    }
  }

  // Extract data requests from user message
  private extractDataRequests(message: string): DataRequest[] {
    const requests: DataRequest[] = [];
    
    // Simple keyword-based extraction (in production, use LLM for this)
    const lowerMessage = message.toLowerCase();
    
    // Check for common data request patterns
    if (lowerMessage.includes('stats') || lowerMessage.includes('statistics')) {
      requests.push({
        id: `req_${Date.now()}_stats`,
        type: 'get_stats',
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('timeline') || lowerMessage.includes('events timeline')) {
      requests.push({
        id: `req_${Date.now()}_timeline`,
        type: 'get_timeline',
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('attack') || lowerMessage.includes('threat')) {
      requests.push({
        id: `req_${Date.now()}_attacks`,
        type: 'get_attack_chains',
        timestamp: new Date().toISOString()
      });
      
      requests.push({
        id: `req_${Date.now()}_alerts`,
        type: 'get_alerts',
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('source') || lowerMessage.includes('ip')) {
      requests.push({
        id: `req_${Date.now()}_sources`,
        type: 'get_top_sources',
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('user') || lowerMessage.includes('username')) {
      requests.push({
        id: `req_${Date.now()}_users`,
        type: 'get_top_users',
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('entry') || lowerMessage.includes('log')) {
      requests.push({
        id: `req_${Date.now()}_entries`,
        type: 'get_entries',
        parameters: { limit: 10 },
        timestamp: new Date().toISOString()
      });
    }

    if (lowerMessage.includes('correlat')) {
      requests.push({
        id: `req_${Date.now()}_correlate`,
        type: 'correlate_logs',
        timestamp: new Date().toISOString()
      });
    }

    return requests;
  }

  // Generate response using SOC Analyst AI
  private async generateResponse(userMessage: string, dataResponses: DataResponse[]): Promise<string> {
    // Build context from data responses
    const context = this.buildContextFromData(dataResponses);
    
    // Build prompt for SOC Analyst AI
    const prompt = this.buildPrompt(userMessage, context);
    
    try {
      // Use SOC Analyst AI endpoint
      const response = await api.getSocAnalystChat(prompt, [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userMessage }
      ]);
      
      return response;
    } catch (error) {
      // Fallback to rule-based response
      return this.generateRuleBasedResponse(userMessage, context);
    }
  }

  // Build context from data responses
  private buildContextFromData(dataResponses: DataResponse[]): string {
    let context = '';
    
    for (const response of dataResponses) {
      if (!response.success) continue;
      
      const data = response.data;
      
      if (response.requestId.includes('stats')) {
        context += `\nStatistics:\n`;
        if (data.bySeverity) {
          context += `- Severity breakdown: ${JSON.stringify(data.bySeverity)}\n`;
        }
        if (data.byType) {
          context += `- Log types: ${JSON.stringify(data.byType)}\n`;
        }
      }
      
      if (response.requestId.includes('timeline')) {
        context += `\nTimeline: ${data.length} events\n`;
      }
      
      if (response.requestId.includes('attacks')) {
        context += `\nAttack Chains: ${data.length} detected\n`;
        data.slice(0, 3).forEach((ac: any) => {
          context += `- ${ac.attackType} (${ac.stage}) from ${ac.sourceIps?.[0] || 'unknown'}\n`;
        });
      }
      
      if (response.requestId.includes('alerts')) {
        context += `\nAlerts: ${data.length} total\n`;
        const critical = data.filter((a: any) => a.severity === 'critical').length;
        if (critical > 0) {
          context += `- Critical alerts: ${critical}\n`;
        }
      }
      
      if (response.requestId.includes('sources')) {
        context += `\nTop Sources:\n`;
        data.slice(0, 5).forEach((s: any) => {
          context += `- ${s.ip}: ${s.count} events\n`;
        });
      }
    }
    
    return context;
  }

  // Build prompt for LLM
  private buildPrompt(userMessage: string, context: string): string {
    const history = agentMemory.formatHistoryForPrompt();
    
    let prompt = SYSTEM_PROMPT;
    
    if (history) {
      prompt += `\n\nConversation History:\n${history}`;
    }
    
    if (context) {
      prompt += `\n\nAvailable Data:\n${context}`;
    }
    
    prompt += `\n\nUser Query: ${userMessage}\n\nAgent Response:`;
    
    return prompt;
  }

  // Rule-based fallback response
  private generateRuleBasedResponse(userMessage: string, context: string): string {
    const lowerMessage = userMessage.toLowerCase();
    
    if (lowerMessage.includes('stats') || lowerMessage.includes('statistics')) {
      return `Based on the available statistics:\n${context}\n\nWhat specific aspect would you like me to analyze further?`;
    }
    
    if (lowerMessage.includes('attack') || lowerMessage.includes('threat')) {
      return `I've analyzed the attack patterns and alerts.\n${context}\n\nWould you like me to generate a detailed report on these threats?`;
    }
    
    if (lowerMessage.includes('report') || lowerMessage.includes('generate')) {
      return `I can generate a comprehensive security report based on the available data.\n${context}\n\nWhat format would you prefer: PDF or HTML?`;
    }
    
    return `I've analyzed your query and the available data.\n${context}\n\nHow would you like me to proceed with this investigation?`;
  }

  // Generate report
  async generateReport(format: 'pdf' | 'html' = 'pdf', customInstructions?: string): Promise<string> {
    const conversation = agentMemory.getCurrentConversation();
    if (!conversation) {
      throw new Error('No active conversation. Initialize agent first.');
    }

    const context = conversation.context || {};
    void context;
    
    // Build report request
    const reportRequest = {
      logData: agentTools['parsedData'],
      correlateData: agentTools['correlateData'],
      customInstructions
    };

    // Generate report using API
    if (format === 'pdf') {
      // TODO: Implement PDF generation
      return 'PDF report generation coming soon';
    } else {
      // Generate HTML report
      return this.generateHTMLReport(reportRequest);
    }
  }

  // Generate HTML report
  private generateHTMLReport(request: any): string {
    // Use request to avoid unused variable warning
    void request;
    const { logData } = request;
    
    let html = `
<!DOCTYPE html>
<html>
<head>
    <title>Security Incident Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #666; margin-top: 30px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .stat { margin: 10px 0; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #ca8a04; }
        .low { color: #16a34a; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Security Incident Report</h1>
    <p>Generated: ${new Date().toLocaleString()}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
`;

    if (logData?.attackSummary) {
      html += `
        <p>Total Attacks Detected: <strong>${logData.attackSummary.totalAttacks}</strong></p>
        <p>Risk Score: <strong class="${logData.attackSummary.riskScore > 70 ? 'critical' : logData.attackSummary.riskScore > 40 ? 'high' : 'medium'}">${logData.attackSummary.riskScore}/100</strong></p>
        <p>Unique Sources: ${logData.attackSummary.uniqueSources}</p>
        <p>Attack Types: ${logData.attackSummary.attackTypes?.join(', ') || 'None detected'}</p>
`;
    }

    html += `
    </div>
    
    <h2>Statistics Overview</h2>
`;

    if (logData?.stats) {
      html += `
        <table>
            <tr><th>Metric</th><th>Count</th></tr>
`;

      for (const [severity, count] of Object.entries(logData.stats.bySeverity || {})) {
        html += `<tr><td>${severity}</td><td>${count}</td></tr>`;
      }

      html += `
        </table>
        
        <h3>Top Source IPs</h3>
        <table>
            <tr><th>IP Address</th><th>Event Count</th></tr>
`;

      (logData.stats.topSources || []).slice(0, 10).forEach((source: any) => {
        html += `<tr><td>${source.ip}</td><td>${source.count}</td></tr>`;
      });

      html += `
        </table>
`;
    }

    html += `
    <h2>Recommendations</h2>
    <ul>
        <li>Review critical alerts immediately</li>
        <li>Investigate suspicious source IPs</li>
        <li>Update security policies based on findings</li>
    </ul>
</body>
</html>
`;

    return html;
  }

  // Get conversation history
  getHistory(): AgentMessage[] {
    return agentMemory.getConversationHistory();
  }

  // Clear conversation
  clearConversation() {
    agentMemory.clearCurrentConversation();
  }
}

// Singleton instance
export const socAnalystAgent = new SOCAnalystAgent();
