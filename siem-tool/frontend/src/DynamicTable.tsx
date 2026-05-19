import { useRef, useEffect, useState, useCallback } from 'react';
import type { ParsedLogEntry } from './types';

interface FeedbackState {
  [entryId: string]: 'safe' | 'unsafe' | 'attack_pattern';
}

interface AttackTypeOption {
  type: string;
  label: string;
  description: string;
}

interface Column {
  key: string;
  label: string;
  width: number;
  visible: boolean;
  getValue: (entry: ParsedLogEntry) => string | React.ReactNode;
  sortable: boolean;
}

const API_URL = import.meta.env.VITE_API_URL || '';

const MIN_COLUMN_WIDTH = 100;

const ATTACK_TYPE_OPTIONS: AttackTypeOption[] = [
  { type: 'sql_injection', label: 'SQL Injection', description: 'SQL commands injected into application queries' },
  { type: 'xss_attack', label: 'XSS', description: 'Cross-site scripting attack' },
  { type: 'command_injection', label: 'Command Injection', description: 'OS commands injected through input' },
  { type: 'path_traversal', label: 'Path Traversal', description: 'Directory traversal attack' },
  { type: 'file_inclusion', label: 'File Inclusion', description: 'Remote/local file inclusion' },
  { type: 'bruteforce', label: 'Brute Force', description: 'Multiple failed login attempts' },
  { type: 'password_spray', label: 'Password Spray', description: 'Same password against multiple accounts' },
  { type: 'credential_stuffing', label: 'Credential Stuffing', description: 'Stolen credentials login' },
  { type: 'port_scan', label: 'Port Scan', description: 'Network port scanning' },
  { type: 'ddos', label: 'DDoS', description: 'Distributed denial of service' },
  { type: 'reconnaissance', label: 'Reconnaissance', description: 'Information gathering' },
  { type: 'privilege_escalation', label: 'Privilege Escalation', description: 'Elevated access attempts' },
  { type: 'lateral_movement', label: 'Lateral Movement', description: 'Movement between systems' },
  { type: 'data_exfiltration', label: 'Data Exfiltration', description: 'Unauthorized data transfer' },
  { type: 'c2_communication', label: 'C2 Communication', description: 'Command and control traffic' },
  { type: 'malware_activity', label: 'Malware Activity', description: 'Potential malware execution' },
  { type: 'insider_threat', label: 'Insider Threat', description: 'Authorized user suspicious activity' },
  { type: 'account_takeover', label: 'Account Takeover', description: 'Unauthorized account access' },
];

const formatFieldLabel = (key: string): string => {
  return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
};

const getColumnsForLogType = (_logType: string, sampleEntries: ParsedLogEntry[]): Column[] => {
  const hasAttacks = sampleEntries.some(e => e.attackType);
  const hasEntries = sampleEntries.length > 0;

  const columns: Column[] = [];

  if (hasEntries) {
    columns.push({
      key: 'select',
      label: '',
      width: 40,
      visible: true,
      sortable: false,
      getValue: () => 'checkbox'
    });
  }

  columns.push(
    { key: 'timestamp', label: 'Timestamp', width: 180, visible: true, sortable: true, getValue: (e) => e.timestamp || '-' },
    {
      key: 'country',
      label: 'Country',
      width: 80,
      visible: true,
      sortable: true,
      getValue: (e) => (
        <span 
          style={{ 
            backgroundColor: '#3b82f6', 
            color: '#ffffff',
            padding: '1px 6px',
            borderRadius: '3px',
            fontSize: '10px',
            fontWeight: 'bold'
          }}
        >
          {e.countryCode || '??'}
        </span>
      )
    },
    {
      key: 'severity',
      label: 'Severity',
      width: 100,
      visible: true,
      sortable: true,
      getValue: (e) => {
        if (e.attackType) {
          return (
            <div className="severity-with-indicator">
              <span className="severity-icon">⚠️</span>
              <span>{e.severity}</span>
            </div>
          );
        }
        return e.severity;
      }
    },
  );

  if (hasAttacks) {
    columns.push({
      key: 'attack',
      label: 'Attack',
      width: 150,
      visible: true,
      sortable: false,
      getValue: (e) => {
        const confidence = e.attackConfidence || 0;
        const attackType = e.attackType || 'safe';
        
        // For "normal" entries, show as safe (green) regardless of confidence
        // The confidence for "normal" means "confidence it's normal", not "confidence it's an attack"
        const isNormal = attackType === 'normal' || attackType === 'safe';
        
        let bgColor = '#22c55e'; // green - safe/normal
        let textColor = '#ffffff';
        let displayType = isNormal ? 'Safe' : attackType.replace(/_/g, ' ');
        
        if (!isNormal) {
          // For actual attacks: higher confidence = more dangerous = red
          if (confidence >= 0.8) {
            bgColor = '#dc2626'; // red - high confidence attack
          } else if (confidence >= 0.6) {
            bgColor = '#f97316'; // orange - medium-high confidence
          } else if (confidence >= 0.4) {
            bgColor = '#eab308'; // yellow - medium confidence
          } else {
            bgColor = '#84cc16'; // lime - low confidence attack
          }
        }
        
        return (
          <span 
            className="attack-badge" 
            style={{ 
              backgroundColor: bgColor, 
              color: textColor,
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: 'bold'
            }}
            title={`Confidence: ${(confidence * 100).toFixed(0)}%`}
          >
            {displayType} ({(confidence * 100).toFixed(0)}%)
          </span>
        );
      }
    });
  }

  const usedKeys = new Set<string>([
    'select', 'timestamp', 'severity', 'attack', 'message',
    'source', 'destination', 'user', 'action', 'outcome', 'fields', 
    'rawLine', 'id', 'logType', 'tags', 'attackType', 'attackConfidence'
  ]);

  const allFieldKeys = new Set<string>();
  
  sampleEntries.forEach(entry => {
    if (entry.fields) {
      Object.keys(entry.fields).forEach(key => {
        if (key === '_detected_fields') return;
        const value = entry.fields[key];
        if (value !== null && value !== undefined && value !== '') {
          allFieldKeys.add(key);
        }
      });
    }
  });

  const sortedFields = Array.from(allFieldKeys).sort();
  
  sortedFields.forEach(key => {
    columns.push({
      key: `fields_${key}`,
      label: formatFieldLabel(key),
      width: 150,
      visible: true,
      sortable: true,
      getValue: (e) => {
        const val = e.fields?.[key];
        if (val === null || val === undefined) return '-';
        if (typeof val === 'object') return JSON.stringify(val);
        return String(val);
      }
    });
    usedKeys.add(key);
  });

  return columns;
};

interface DynamicTableProps {
  entries: ParsedLogEntry[];
  detectedType: string;
  onEntryClick?: (entry: ParsedLogEntry) => void;
}

export function DynamicTable({ entries, detectedType, onEntryClick }: DynamicTableProps) {
  const [columns, setColumns] = useState<Column[]>([]);
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(new Set());
  const [feedbackState, setFeedbackState] = useState<FeedbackState>({});
  const [selectedEntries, setSelectedEntries] = useState<Set<string>>(new Set());
  const [showAttackTypeDropdown, setShowAttackTypeDropdown] = useState(false);
  const [bulkFeedbackStatus, setBulkFeedbackStatus] = useState<{ success: number; failed: number } | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);
  const [showContextAttackDropdown, setShowContextAttackDropdown] = useState(false);

  const tableContainerRef = useRef<HTMLDivElement>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);

  const submitBulkFeedback = useCallback(async (label: 'safe' | 'unsafe' | 'attack_pattern', attackType?: string) => {
    if (selectedEntries.size === 0) return;

    const entriesToSubmit = Array.from(selectedEntries);
    let success = 0;
    let failed = 0;

    for (const entryId of entriesToSubmit) {
      const entry = entries.find(e => e.id === entryId);
      if (!entry) {
        failed++;
        continue;
      }

      try {
        const response = await fetch(`${API_URL}/feedback/bulk`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            entries: [{ entry_id: entryId }],
            user_label: label,
            attack_type: attackType,
          }),
        });

        if (response.ok) {
          success++;
          setFeedbackState(prev => ({ ...prev, [entryId]: label }));
        } else {
          failed++;
        }
      } catch {
        failed++;
      }
    }

    setBulkFeedbackStatus({ success, failed });
    setSelectedEntries(new Set());
    setShowAttackTypeDropdown(false);
    setContextMenu(null);

    setTimeout(() => setBulkFeedbackStatus(null), 3000);
  }, [selectedEntries, entries]);

  const exportToCSV = useCallback(() => {
    if (selectedEntries.size === 0) return;

    const selectedData = entries.filter(e => selectedEntries.has(e.id));
    const headers = ['timestamp', 'logType', 'severity', 'source_ip', 'user', 'action', 'outcome', 'message', 'attackType'];
    const rows = selectedData.map(e => [
      e.timestamp || '',
      e.logType,
      e.severity,
      e.source?.ip || '',
      e.user?.name || '',
      e.action || '',
      e.outcome || '',
      `"${(e.message || '').replace(/"/g, '""')}"`,
      e.attackType || 'normal',
    ]);

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-logs-selected-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    setContextMenu(null);
  }, [selectedEntries, entries]);

  const exportToJSON = useCallback(() => {
    if (selectedEntries.size === 0) return;

    const selectedData = entries.filter(e => selectedEntries.has(e.id));
    const blob = new Blob([JSON.stringify(selectedData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-logs-selected-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setContextMenu(null);
  }, [selectedEntries, entries]);

  const exportToTXT = useCallback(() => {
    if (selectedEntries.size === 0) return;

    const selectedData = entries.filter(e => selectedEntries.has(e.id));
    const text = selectedData.map(e => e.rawLine || e.message).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-logs-selected-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setContextMenu(null);
  }, [selectedEntries, entries]);

  const toggleEntrySelection = useCallback((entryId: string) => {
    setSelectedEntries(prev => {
      const next = new Set(prev);
      if (next.has(entryId)) {
        next.delete(entryId);
      } else {
        next.add(entryId);
      }
      return next;
    });
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    if (selectedEntries.size > 0) {
      e.preventDefault();
      setContextMenu({ x: e.clientX, y: e.clientY });
      setShowContextAttackDropdown(false);
    }
  }, [selectedEntries.size]);

  const closeContextMenu = useCallback(() => {
    setContextMenu(null);
    setShowContextAttackDropdown(false);
  }, []);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        closeContextMenu();
      }
    };

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeContextMenu();
      }
    };

    document.addEventListener('click', handleClickOutside);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('click', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [closeContextMenu]);

  const toggleSelectAll = useCallback(() => {
    if (selectedEntries.size === entries.length) {
      setSelectedEntries(new Set());
    } else {
      setSelectedEntries(new Set(entries.map(e => e.id)));
    }
  }, [selectedEntries, entries]);

  useEffect(() => {
    const newColumns = getColumnsForLogType(detectedType, entries.slice(0, 10));
    setColumns(newColumns);
    setVisibleColumns(new Set(newColumns.filter(c => c.visible).map(c => c.key)));
  }, [detectedType, entries]);

  const handleSort = (columnKey: string) => {
    if (sortColumn === columnKey) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(columnKey);
      setSortDirection('asc');
    }
  };

  const handleResizeStart = (columnKey: string, startX: number) => {
    const handleMouseMove = (e: MouseEvent) => {
      const column = columns.find(c => c.key === columnKey);
      if (!column) return;

      const delta = startX - e.clientX;
      const newWidth = Math.max(MIN_COLUMN_WIDTH, column.width - delta);

      setColumns(prev => prev.map(c =>
        c.key === columnKey ? { ...c, width: newWidth } : c
      ));
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const getSortedEntries = useCallback(() => {
    if (!sortColumn) return entries;

    const column = columns.find(c => c.key === sortColumn);
    if (!column || !column.sortable) return entries;

    const sorted = [...entries].sort((a, b) => {
      const valueA = String(column.getValue(a) || '');
      const valueB = String(column.getValue(b) || '');

      const comparison = valueA.localeCompare(valueB);
      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return sorted;
  }, [sortColumn, sortDirection, columns, entries]);

  const visibleColumnList = columns.filter(c => visibleColumns.has(c.key));
  const sortedEntries = getSortedEntries();

  const getColumnContent = (column: Column, entry: ParsedLogEntry) => {
    if (column.key === 'select') {
      return (
        <input
          type="checkbox"
          checked={selectedEntries.has(entry.id)}
          onChange={() => toggleEntrySelection(entry.id)}
          onClick={e => e.stopPropagation()}
        />
      );
    }
    if (column.key === 'severity' && entry.attackType) {
      return (
        <div className="severity-with-indicator">
          <span className="severity-icon">⚠️</span>
          <span>{entry.severity}</span>
        </div>
      );
    }
    if (column.key === 'attack' && entry.attackType) {
      return (
        <span className="attack-badge" title={`Confidence: ${(entry.attackConfidence! * 100).toFixed(0)}%`}>
          {entry.attackType!.replace(/_/g, ' ')}
        </span>
      );
    }
    return column.getValue(entry);
  };

  const getHeaderContent = (column: Column) => {
    if (column.key === 'select') {
      return (
        <input
          type="checkbox"
          checked={selectedEntries.size === entries.length && entries.length > 0}
          ref={input => {
            if (input) {
              input.indeterminate = selectedEntries.size > 0 && selectedEntries.size < entries.length;
            }
          }}
          onChange={toggleSelectAll}
          onClick={e => e.stopPropagation()}
        />
      );
    }
    return (
      <div className="th-content">
        <span className="th-label">{column.label}</span>
        {sortColumn === column.key && (
          <span className={`sort-indicator ${sortDirection}`}>
            {sortDirection === 'asc' ? '▲' : '▼'}
          </span>
        )}
      </div>
    );
  };

  const getRowClassName = (entry: ParsedLogEntry) => {
    const feedback = feedbackState[entry.id];
    const hasAttack = !!entry.attackType;
    const isSelected = selectedEntries.has(entry.id);

    const classes: string[] = [];
    if (hasAttack) classes.push('attack-row');
    if (feedback) classes.push(`feedback-${feedback}`);
    if (isSelected) classes.push('selected-row');
    return classes.join(' ');
  };

  const getTdClassName = (column: Column, entry: ParsedLogEntry) => {
    const hasAttack = !!entry.attackType;
    const classes: string[] = ['data-cell'];
    if (hasAttack) classes.push('attack-cell');
    if (column.key === 'select') classes.push('select-cell');
    return classes.join(' ');
  };

  return (
    <div className="dynamic-table-container">
      {selectedEntries.size > 0 && (
        <div className="bulk-actions-bar">
          <span className="selected-count">{selectedEntries.size} selected</span>
          <button
            className="bulk-action-btn safe"
            onClick={() => submitBulkFeedback('safe')}
          >
            Mark Safe
          </button>
          <button
            className="bulk-action-btn unsafe"
            onClick={() => submitBulkFeedback('unsafe')}
          >
            Mark Unsafe
          </button>
          <div className="bulk-action-dropdown">
            <button
              className="bulk-action-btn attack-pattern"
              onClick={() => setShowAttackTypeDropdown(!showAttackTypeDropdown)}
            >
              Mark as Attack Pattern
            </button>
            {showAttackTypeDropdown && (
              <div className="attack-type-dropdown">
                {ATTACK_TYPE_OPTIONS.map(option => (
                  <button
                    key={option.type}
                    className="attack-type-option"
                    onClick={() => submitBulkFeedback('attack_pattern', option.type)}
                  >
                    <span className="attack-type-label">{option.label}</span>
                    <span className="attack-type-desc">{option.description}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            className="bulk-action-btn clear"
            onClick={() => setSelectedEntries(new Set())}
          >
            Clear Selection
          </button>
          {bulkFeedbackStatus && (
            <span className="bulk-feedback-status">
              {bulkFeedbackStatus.success} submitted
              {bulkFeedbackStatus.failed > 0 && `, ${bulkFeedbackStatus.failed} failed`}
            </span>
          )}
        </div>
      )}

      <div
        className="table-scroll-wrapper"
        ref={tableContainerRef}
        onContextMenu={handleContextMenu}
      >
        <table className="dynamic-table">
          <thead>
            <tr>
              {visibleColumnList.map(column => (
                <th
                  key={column.key}
                  style={{ width: `${column.width}px`, minWidth: `${MIN_COLUMN_WIDTH}px` }}
                  className={`sortable ${sortColumn === column.key ? 'sorted' : ''} ${column.key === 'select' ? 'select-column' : ''}`}
                  onClick={() => column.sortable && handleSort(column.key)}
                >
                  {getHeaderContent(column)}
                  <div
                    className="resize-handle"
                    onMouseDown={(e) => handleResizeStart(column.key, e.clientX)}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedEntries.map((entry) => (
              <tr
                key={entry.id}
                onClick={() => onEntryClick?.(entry)}
                className={getRowClassName(entry)}
              >
                {visibleColumnList.map(column => (
                  <td
                    key={column.key}
                    style={{ width: `${column.width}px` }}
                    className={getTdClassName(column, entry)}
                  >
                    {getColumnContent(column, entry)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="column-toggles">
        <button
          className="toggle-columns-btn"
          onClick={() => {
            if (visibleColumns.size === columns.filter(c => c.visible).length) {
              const minimalVisible = new Set(['select', 'timestamp', 'severity', 'message']);
              setVisibleColumns(minimalVisible);
            } else {
              setVisibleColumns(new Set(columns.filter(c => c.visible).map(c => c.key)));
            }
          }}
        >
          {visibleColumns.size > 4 ? 'Fewer Columns' : 'More Columns'}
        </button>
      </div>
      {visibleColumns.size < columns.filter(c => c.visible).length && (
        <div className="hidden-columns-indicator">
          {columns.filter(c => c.visible).length - visibleColumns.size} hidden columns
        </div>
      )}

      {/* Context Menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          className="context-menu"
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          <div className="context-menu-header">
            {selectedEntries.size} selected entries
          </div>
          <div className="context-menu-divider" />
          <div className="context-menu-section">
            <div className="context-menu-label">Classification</div>
            <button className="context-menu-item safe" onClick={() => submitBulkFeedback('safe')}>
              ✓ Mark as Safe
            </button>
            <button className="context-menu-item unsafe" onClick={() => submitBulkFeedback('unsafe')}>
              ✗ Mark as Unsafe
            </button>
            <div className="context-menu-dropdown">
              <button
                className="context-menu-item attack-pattern"
                onClick={() => setShowContextAttackDropdown(!showContextAttackDropdown)}
              >
                🎯 Mark as Attack Pattern ▾
              </button>
              {showContextAttackDropdown && (
                <div className="context-menu-subdropdown">
                  {ATTACK_TYPE_OPTIONS.map(option => (
                    <button
                      key={option.type}
                      className="context-menu-subitem"
                      onClick={() => submitBulkFeedback('attack_pattern', option.type)}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="context-menu-divider" />
          <div className="context-menu-section">
            <div className="context-menu-label">Export Selected</div>
            <button className="context-menu-item export" onClick={exportToCSV}>
              📄 Export as CSV
            </button>
            <button className="context-menu-item export" onClick={exportToJSON}>
              📋 Export as JSON
            </button>
            <button className="context-menu-item export" onClick={exportToTXT}>
              📝 Export as TXT
            </button>
          </div>
          <div className="context-menu-divider" />
          <button className="context-menu-item clear" onClick={() => { setSelectedEntries(new Set()); setContextMenu(null); }}>
            Clear Selection
          </button>
        </div>
      )}
    </div>
  );
}
