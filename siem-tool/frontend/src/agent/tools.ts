// Agent Tools for Data Fetching
import type { DataRequest, DataResponse, ParseResponse, CorrelateResponse, ParsedLogEntry, Alert, AttackChain } from '../types';
import * as api from '../api';

export class AgentTools {
  private parsedData: ParseResponse | null = null;
  private correlateData: CorrelateResponse | null = null;

  // Set parsed data from frontend (avoid fetching if already available)
  setParsedData(data: ParseResponse) {
    this.parsedData = data;
  }

  setCorrelateData(data: CorrelateResponse) {
    this.correlateData = data;
  }

  // Main tool dispatcher
  async executeRequest(request: DataRequest): Promise<DataResponse> {
    const { type, parameters } = request;

    try {
      let data: any;

      switch (type) {
        case 'parse_logs':
          data = await this.parseLogs(parameters);
          break;
        case 'get_stats':
          data = await this.getStats(parameters);
          break;
        case 'get_timeline':
          data = await this.getTimeline(parameters);
          break;
        case 'get_attack_chains':
          data = await this.getAttackChains(parameters);
          break;
        case 'get_ml_predictions':
          data = await this.getMLPredictions(parameters);
          break;
        case 'get_alerts':
          data = await this.getAlerts(parameters);
          break;
        case 'get_entries':
          data = await this.getEntries(parameters);
          break;
        case 'get_top_sources':
          data = await this.getTopSources(parameters);
          break;
        case 'get_top_users':
          data = await this.getTopUsers(parameters);
          break;
        case 'correlate_logs':
          data = await this.correlateLogs(parameters);
          break;
        case 'analyze_log':
          data = await this.analyzeLog(parameters);
          break;
        default:
          return {
            requestId: request.id,
            success: false,
            data: null,
            error: `Unknown request type: ${type}`
          };
      }

      return {
        requestId: request.id,
        success: true,
        data
      };
    } catch (error) {
      return {
        requestId: request.id,
        success: false,
        data: null,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // 1. Parse Logs
  private async parseLogs(parameters?: Record<string, any>): Promise<ParseResponse> {
    // If we have parsed data in memory, use it
    if (this.parsedData) {
      return this.parsedData;
    }

    // Otherwise, parse from parameters or return empty
    if (parameters?.content) {
      return await api.parseLogsFromText(parameters.content);
    }
    
    throw new Error('No log data available. Please upload logs first.');
  }

  // 2. Get Statistics
  private async getStats(parameters?: Record<string, any>): Promise<any> {
    const data = await this.parseLogs();
    const stats = data.stats;

    // Filter by severity if specified
    if (parameters?.severity) {
      return {
        bySeverity: stats.bySeverity[parameters.severity] || 0,
        total: data.parsedLines
      };
    }

    // Filter by type if specified
    if (parameters?.type) {
      return {
        byType: stats.byType[parameters.type] || 0,
        total: data.parsedLines
      };
    }

    return stats;
  }

  // 3. Get Timeline
  private async getTimeline(_parameters?: Record<string, any>): Promise<any> {
    const data = await this.parseLogs();
    
    if (this.correlateData) {
      return this.correlateData.correlation.timeline;
    }

    return data.stats.timeline;
  }

  // 4. Get Attack Chains
  private async getAttackChains(_parameters?: Record<string, any>): Promise<AttackChain[]> {
    const data = await this.parseLogs();
    void _parameters;
    
    if (this.correlateData) {
      return this.correlateData.correlation.attackChains;
    }

    // Convert parseResponse attackChains to AttackChain format
    return (data.attackChains || []).map(ac => ({
      id: ac.id,
      startTime: ac.startTime,
      endTime: ac.endTime,
      attackType: ac.attackType as any,
      stage: ac.stage as any,
      events: ac.events.map(e => ({
        id: e.id,
        timestamp: e.timestamp || '',
        logSource: e.logType,
        logType: e.logType,
        severity: e.severity,
        sourceIp: e.source?.ip,
        targetUser: e.user?.name,
        message: e.message,
        relatedEventIds: [],
        correlationScore: 0.5
      })),
      sourceIps: ac.sourceIps,
      targetUsers: ac.targetUsers,
      targetHosts: [],
      prediction: {
        attackType: ac.attackType as any,
        confidence: ac.prediction.confidence,
        probability: ac.prediction.confidence,
        features: {},
        explanation: ac.prediction.explanation,
        isFalsePositive: false
      },
      mitreTactics: ac.mitreTactics,
      mitreTechniques: ac.mitreTechniques,
      recommendation: ac.recommendation
    }));
  }

  // 5. Get ML Predictions
  private async getMLPredictions(parameters?: Record<string, any>): Promise<any> {
    const data = await this.parseLogs();
    void parameters;
    
    if (parameters?.attackType) {
      return (data.mlPredictions || []).filter(p => p.attackType === parameters.attackType);
    }

    return data.mlPredictions || [];
  }

  // 6. Get Alerts
  private async getAlerts(parameters?: Record<string, any>): Promise<Alert[]> {
    const data = await this.parseLogs();
    void parameters;
    
    if (parameters?.severity) {
      return (data.alerts || []).filter(a => a.severity === parameters.severity);
    }

    return data.alerts || [];
  }

  // 7. Get Entries
  private async getEntries(parameters?: Record<string, any>): Promise<ParsedLogEntry[]> {
    const data = await this.parseLogs();
    void parameters;
    
    let entries = data.entries;

    // Filter by severity
    if (parameters?.severity) {
      entries = entries.filter(e => e.severity === parameters.severity);
    }

    // Filter by log type
    if (parameters?.logType) {
      entries = entries.filter(e => e.logType === parameters.logType);
    }

    // Filter by attack type
    if (parameters?.attackType) {
      entries = entries.filter(e => e.attackType === parameters.attackType);
    }

    // Limit results
    if (parameters?.limit) {
      entries = entries.slice(0, parameters.limit);
    }

    return entries;
  }

  // 8. Get Top Sources
  private async getTopSources(_parameters?: Record<string, any>): Promise<any> {
    const data = await this.parseLogs();
    void _parameters;
    return data.stats.topSources;
  }

  // 9. Get Top Users
  private async getTopUsers(_parameters?: Record<string, any>): Promise<any> {
    const data = await this.parseLogs();
    return data.stats.topUsers;
  }

  // 10. Correlate Logs
  private async correlateLogs(parameters?: Record<string, any>): Promise<CorrelateResponse> {
    void parameters;
    if (this.correlateData) {
      return this.correlateData;
    }

    // If we have parsed data, use it for correlation
    await this.parseLogs();
    
    // For correlation, we need multiple log sources
    // This would require the frontend to provide the sources
    throw new Error('No log sources available for correlation');
  }

  // 11. Analyze Log
  private async analyzeLog(parameters?: Record<string, any>): Promise<any> {
    if (!parameters?.logEntry) {
      throw new Error('No log entry provided for analysis');
    }

    const logType = parameters.logType || 'unknown';
    const result = await api.analyzeLogWithAI(parameters.logEntry, logType);
    
    return {
      analysis: result.analysis,
      attackDetected: result.attack_detected,
      severity: result.severity
    };
  }
}

// Singleton instance
export const agentTools = new AgentTools();
