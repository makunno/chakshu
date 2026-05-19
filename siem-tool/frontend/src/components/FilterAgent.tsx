import type { ParsedLogEntry, ParseResponse, CorrelateResponse, CorrelatedEvent } from '../types';

export interface FilterCriteria {
  column?: string;
  value?: string | number;
  operator?: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'greaterThan' | 'lessThan';
  attackType?: string;
  severity?: string;
  logType?: string;
  timeRange?: { start: string; end: string };
}

export interface FilterRequest {
  prompt: string;
  criteria?: FilterCriteria[];
  maxResults?: number;
}

export interface FilterResponse {
  entries: (ParsedLogEntry | CorrelatedEvent)[];
  totalCount: number;
  filteredCount: number;
  appliedFilters: FilterCriteria[];
}

export class FilterAgent {
  private allEntries: (ParsedLogEntry | CorrelatedEvent)[] = [];

  constructor(data: ParseResponse | CorrelateResponse | null, logType: 'single' | 'correlation') {
    if (!data) return;
    
    if (logType === 'single') {
      this.allEntries = (data as ParseResponse).entries || [];
    } else {
      const correlation = (data as CorrelateResponse).correlation;
      this.allEntries = correlation?.attackChains?.flatMap(c => c.events) || [];
    }
  }

  parsePrompt(prompt: string): FilterCriteria[] {
    const criteria: FilterCriteria[] = [];
    const lowerPrompt = prompt.toLowerCase();

    const ipMatch = prompt.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
    if (ipMatch) {
      criteria.push({
        column: 'source.ip',
        value: ipMatch[0],
        operator: 'equals'
      });
    }

    if (lowerPrompt.includes('attack') || lowerPrompt.includes('ml') || lowerPrompt.includes('detected')) {
      criteria.push({
        attackType: 'any'
      });
    }

    const severities = ['critical', 'error', 'warning', 'info', 'debug'];
    for (const severity of severities) {
      if (lowerPrompt.includes(severity)) {
        criteria.push({ severity });
        break;
      }
    }

    const logTypes = ['apache', 'nginx', 'ssh', 'mysql', 'postgresql', 'windows', 'firewall', 'dns'];
    for (const logType of logTypes) {
      if (lowerPrompt.includes(logType)) {
        criteria.push({ logType });
        break;
      }
    }

    if (lowerPrompt.includes('recent') || lowerPrompt.includes('latest')) {
      criteria.push({
        column: 'timestamp',
        operator: 'greaterThan',
        value: new Date(Date.now() - 3600000).toISOString()
      });
    }

    if (lowerPrompt.includes('user') || lowerPrompt.includes('username')) {
      const userMatch = prompt.match(/user\s+(\w+)/i) || prompt.match(/username\s+(\w+)/i);
      if (userMatch) {
        criteria.push({
          column: 'user.name',
          value: userMatch[1],
          operator: 'equals'
        });
      }
    }

    if (lowerPrompt.includes('failed') || lowerPrompt.includes('failure')) {
      criteria.push({
        column: 'outcome',
        value: 'failure',
        operator: 'equals'
      });
    }

    return criteria;
  }

  filterLogs(criteria: FilterCriteria[]): (ParsedLogEntry | CorrelatedEvent)[] {
    let filtered = [...this.allEntries];

    for (const criterion of criteria) {
      filtered = filtered.filter(entry => {
        if (criterion.attackType && 'attackType' in entry) {
          if (criterion.attackType === 'any') {
            return entry.attackType !== undefined && entry.attackType !== 'normal';
          }
          return entry.attackType === criterion.attackType;
        }

        if (criterion.severity) {
          return entry.severity === criterion.severity;
        }

        if (criterion.logType) {
          return entry.logType.toLowerCase().includes(criterion.logType.toLowerCase());
        }

        if (criterion.column && criterion.value !== undefined) {
          const value = this.getNestedValue(entry, criterion.column);
          if (value === undefined) return false;

          const strValue = String(value).toLowerCase();
          const criterionValue = String(criterion.value).toLowerCase();

          switch (criterion.operator) {
            case 'contains':
              return strValue.includes(criterionValue);
            case 'startsWith':
              return strValue.startsWith(criterionValue);
            case 'endsWith':
              return strValue.endsWith(criterionValue);
            case 'greaterThan':
              return Number(value) > Number(criterion.value);
            case 'lessThan':
              return Number(value) < Number(criterion.value);
            default:
              return strValue === criterionValue;
          }
        }

        return true;
      });
    }

    return filtered;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  }

  processQuery(prompt: string, maxResults: number = 100): FilterResponse {
    const criteria = this.parsePrompt(prompt);
    const filtered = this.filterLogs(criteria);

    filtered.sort((a, b) => {
      const timeA = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const timeB = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return timeB - timeA;
    });

    const limited = filtered.slice(0, maxResults);

    return {
      entries: limited,
      totalCount: this.allEntries.length,
      filteredCount: filtered.length,
      appliedFilters: criteria
    };
  }

  getMLDetectedAttacks(): (ParsedLogEntry | CorrelatedEvent)[] {
    return this.allEntries.filter(e => 'attackType' in e && e.attackType && e.attackType !== 'normal');
  }

  getByColumn(column: string, value: string | number, operator: string = 'equals'): (ParsedLogEntry | CorrelatedEvent)[] {
    return this.filterLogs([{ column, value, operator: operator as any }]);
  }

  getByAttackType(attackType: string): (ParsedLogEntry | CorrelatedEvent)[] {
    return this.filterLogs([{ attackType }]);
  }

  getBySeverity(severity: string): (ParsedLogEntry | CorrelatedEvent)[] {
    return this.filterLogs([{ severity }]);
  }
}

export default FilterAgent;
