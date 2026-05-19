// API client for SIEM backend

import type { ParseResponse, CorrelateResponse, ParsedLogEntry, CorrelatedEvent } from './types';

// Read API URL from environment or injected window variable
// - VITE_API_URL: set during build for Cloudflare deployment
// - window.CYBERCHAKSHU_API_URL: injected by Flask for local development
const ENV_API_URL = import.meta.env.VITE_API_URL || '';
const INJECTED_API_URL = typeof window !== 'undefined' ? (window as any).CYBERCHAKSHU_API_URL : '';
const API_URL = ENV_API_URL || INJECTED_API_URL || '';

const CLIENT_SPLIT_THRESHOLD = 200 * 1024; // 200KB - split on frontend

function getApiUrl(path: string): string {
  // Use absolute URL if set, otherwise use relative URL
  if (API_URL) {
    return `${API_URL}${path.startsWith('/') ? path : '/' + path}`;
  }
  return path; // Relative URL for same-origin requests
}

export function isEVTXFile(file: File): boolean {
  const ext = file.name.toLowerCase().split('.').pop();
  return ext === 'evtx' || ext === 'evt';
}

export class EVTXUploadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EVTXUploadError';
  }
}

export interface ChunkInfo {
  index: number;
  name: string;
  content: string;
  size: number;
  lineCount: number;
}

export interface SplitFileResult {
  originalFile: {
    name: string;
    size: number;
    sizeMB: number;
    lineCount: number;
  };
  chunks: ChunkInfo[];
  totalChunks: number;
  chunkSizeMB: number;
}

export async function splitFileClient(file: File): Promise<SplitFileResult> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = () => {
      try {
        const content = reader.result as string;
        const lines = content.split('\n');
        
        const chunks: ChunkInfo[] = [];
        let currentChunk = '';
        let currentSize = 0;
        let chunkIndex = 1;
        let totalLines = 0;
        
        for (const line of lines) {
          const lineWithNewline = line + '\n';
          const lineSize = new Blob([lineWithNewline]).size;
          
          if (currentSize + lineSize > CLIENT_SPLIT_THRESHOLD && currentChunk.length > 0) {
            const trimmed = currentChunk.trimEnd();
            chunks.push({
              index: chunkIndex,
              name: `${file.name.replace(/\.[^/.]+$/, '')}_chunk_${String(chunkIndex).padStart(3, '0')}.log`,
              content: trimmed,
              size: new Blob([trimmed]).size,
              lineCount: trimmed.split('\n').length
            });
            chunkIndex++;
            currentChunk = lineWithNewline;
            currentSize = lineSize;
          } else {
            currentChunk += lineWithNewline;
            currentSize += lineSize;
          }
          totalLines++;
        }
        
        if (currentChunk.trimEnd().length > 0) {
          const trimmed = currentChunk.trimEnd();
          chunks.push({
            index: chunkIndex,
            name: `${file.name.replace(/\.[^/.]+$/, '')}_chunk_${String(chunkIndex).padStart(3, '0')}.log`,
            content: trimmed,
            size: new Blob([trimmed]).size,
            lineCount: trimmed.split('\n').length
          });
        }
        
        resolve({
          originalFile: {
            name: file.name,
            size: file.size,
            sizeMB: file.size / 1024 / 1024,
            lineCount: totalLines
          },
          chunks,
          totalChunks: chunks.length,
          chunkSizeMB: CLIENT_SPLIT_THRESHOLD / 1024 / 1024
        });
      } catch (err) {
        reject(err);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

export async function trainAnomaly(content: string, forceType?: string): Promise<{ success: boolean; detail: string }> {
  const formData = new FormData();
  formData.append('content', content);
  if (forceType) {
    formData.append('forceType', forceType);
  }

  const response = await fetch(getApiUrl('/train-anomaly'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to train anomaly detector: ${response.statusText}`);
  }

  return response.json();
}

export async function trainAnomalyFromFile(file: File, forceType?: string): Promise<{ success: boolean; detail: string }> {
  const formData = new FormData();
  formData.append('file', file);
  if (forceType) {
    formData.append('forceType', forceType);
  }

  const response = await fetch(getApiUrl('/train-anomaly'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to train anomaly detector: ${response.statusText}`);
  }

  return response.json();
}

export async function parseLogsFromFile(file: File): Promise<ParseResponse> {
  if (isEVTXFile(file)) {
    throw new EVTXUploadError(
      'EVTX files are not directly supported. Please export your Windows Event Log as TXT format using Event Viewer, then upload the TXT file.'
    );
  }

  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(getApiUrl('/parse'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  const data = await response.json();
  
  // Handle auto-split response - return special response that frontend can use
  if (data.status === 'auto_split') {
    return {
      success: true,
      detectedType: 'unknown',
      totalLines: data.originalFile?.lineCount || 0,
      parsedLines: 0,
      failedLines: 0,
      entries: [],
      alerts: [],
      stats: {
        byType: {},
        bySeverity: {},
        byOutcome: {},
        topSources: [],
        topUsers: [],
        timeline: []
      },
      autoSplitInfo: {
        originalFile: data.originalFile,
        splitConfig: data.splitConfig,
        chunks: data.chunks
      }
    } as unknown as ParseResponse;
  }

  return data;
}

export async function parseLogsFromChunkedFile(
  chunks: string[], 
  fileName: string
): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/parse/chunked'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chunks, fileName })
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function parseLogsFromText(content: string): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/parse'), {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: content,
  });

  if (!response.ok) {
    throw new Error(`Failed to parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function correlateMultipleFiles(files: File[]): Promise<CorrelateResponse> {
  const formData = new FormData();
  
  for (const file of files) {
    formData.append('files', file);
  }

  const response = await fetch(getApiUrl('/correlate'), {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Failed to correlate logs: ${response.statusText}`);
  }

  return response.json();
}

export async function correlateFromChunkedFiles(
  fileChunks: Array<{ name: string; chunks: string[] }>
): Promise<CorrelateResponse> {
  const logs = fileChunks.map(f => ({
    name: f.name,
    content: f.chunks.join('\n')
  }));

  const response = await fetch(getApiUrl('/correlate'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs })
  });

  if (!response.ok) {
    throw new Error(`Failed to correlate logs: ${response.statusText}`);
  }

  return response.json();
}

export async function detectLogType(content: string): Promise<{
  detectedType: string;
  sampleSize: number;
  totalLines: number;
}> {
  const response = await fetch(getApiUrl('/detect'), {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: content,
  });

  if (!response.ok) {
    throw new Error(`Failed to detect log type: ${response.statusText}`);
  }

  return response.json();
}

export async function streamParseLogs(lines: string[]): Promise<ParseResponse> {
  const response = await fetch(getApiUrl('/stream'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lines })
  });

  if (!response.ok) {
    throw new Error(`Failed to stream parse logs: ${response.statusText}`);
  }

  return response.json();
}

export async function getAvailableParsers(): Promise<{
  total: number;
  categories: Record<string, Array<{ name: string; logType: string }>>;
  all: Array<{ name: string; logType: string }>;
}> {
  const response = await fetch(getApiUrl('/parsers'));

  if (!response.ok) {
    throw new Error(`Failed to get parsers: ${response.statusText}`);
  }

  return response.json();
}

export async function getAttackTypes(): Promise<{
  attackTypes: Array<{ type: string; description: string }>;
  mitreTactics: string[];
}> {
  const response = await fetch(getApiUrl('/attacks'));

  if (!response.ok) {
    throw new Error(`Failed to get attack types: ${response.statusText}`);
  }

  return response.json();
}

// SOC Analyst LLM API
export interface LogAnalysisResponse {
  analysis: string;
  attack_detected: boolean;
  severity: string;
}

export interface ChatResponse {
  response: string;
}

export async function analyzeLogWithAI(logEntry: string, logType: string): Promise<LogAnalysisResponse> {
  const response = await fetch(getApiUrl('/soc-analyze'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_entry: logEntry, log_type: logType }),
  });

  if (!response.ok) {
    if (response.status === 503) {
      throw new Error('SOC Analyst AI is loading or not available. The model is being initialized. Please wait a moment and try again.');
    }
    throw new Error(`Failed to analyze log: ${response.statusText}`);
  }

  return response.json();
}

export async function getSocAnalystChat(message: string, context: Array<{role: string, content: string}> = [], analysisContext?: any): Promise<string> {
  const response = await fetch(getApiUrl('/soc-chat'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, context, analysis_context: analysisContext }),
  });

  if (!response.ok) {
    if (response.status === 503) {
      throw new Error('SOC Analyst AI is loading or not available. The model is being initialized. Please wait a moment and try again.');
    }
    throw new Error(`Failed to get chat response: ${response.statusText}`);
  }

  const data: ChatResponse = await response.json();
  return data.response;
}

export interface FeedbackRequest {
  message_id: string;
  rating: 1 | 5;
  feedback_text?: string;
  original_prompt: string;
  llm_response: string;
  log_context?: string;
}

export interface FeedbackResponse {
  status: string;
  message: string;
  training_examples_count: number;
}

export async function submitFeedback(feedback: FeedbackRequest): Promise<FeedbackResponse> {
  const response = await fetch(getApiUrl('/soc-feedback'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(feedback),
  });

  if (!response.ok) {
    throw new Error(`Failed to submit feedback: ${response.statusText}`);
  }

  return response.json();
}

export async function triggerTraining(epochs: number = 1): Promise<{status: string; message: string}> {
  const response = await fetch(getApiUrl('/soc-train'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ epochs }),
  });

  if (!response.ok) {
    throw new Error(`Failed to start training: ${response.statusText}`);
  }

  return response.json();
}

export async function getFeedbackStats(): Promise<{total_feedback: number; likes: number; dislikes: number}> {
  const response = await fetch(getApiUrl('/soc-feedback/stats'), {
    method: 'GET',
  });

  if (!response.ok) {
    throw new Error(`Failed to get feedback stats: ${response.statusText}`);
  }

  return response.json();
}

export async function checkSocAnalystHealth(): Promise<{status: string; llm_loaded: boolean}> {
  try {
    const response = await fetch(getApiUrl('/soc-analyze'), {
      method: 'GET',
    });
    
    if (response.ok) {
      return await response.json();
    }
    return { status: 'unavailable', llm_loaded: false };
  } catch {
    return { status: 'unavailable', llm_loaded: false };
  }
}

// Forensic Analysis API
export interface ForensicStartResponse {
  task_id: string;
  status: string;
  message: string;
}

export interface ForensicStatusResponse {
  task_id: string;
  status: string;
  progress: number;
  stage: string;
  message: string;
  output_dir: string | null;
  error: string | null;
}

export interface ForensicFinding {
  technique: string;
  severity: string;
  evidence: string;
  explanation: string;
  recommendation: string;
  confidence: number;
}

export interface ForensicResultsResponse {
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

export async function checkForensicHealth(): Promise<{
  status: string;
  pipeline_available: boolean;
  api_key_configured: boolean;
}> {
  try {
    const response = await fetch(getApiUrl('/forensics/health'));
    if (response.ok) {
      return await response.json();
    }
    return { status: 'unavailable', pipeline_available: false, api_key_configured: false };
  } catch {
    return { status: 'unavailable', pipeline_available: false, api_key_configured: false };
  }
}

export async function startForensicAnalysis(imagePath: string): Promise<ForensicStartResponse> {
  const response = await fetch(getApiUrl('/forensics/start'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ image_path: imagePath }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `Failed to start analysis: ${response.statusText}`);
  }

  return response.json();
}

export async function getForensicStatus(taskId: string): Promise<ForensicStatusResponse> {
  const response = await fetch(getApiUrl(`/forensics/status/${taskId}`));

  if (!response.ok) {
    throw new Error(`Failed to get status: ${response.statusText}`);
  }

  return response.json();
}

export async function getForensicResults(taskId: string): Promise<ForensicResultsResponse> {
  const response = await fetch(getApiUrl(`/forensics/results/${taskId}`));

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `Failed to get results: ${response.statusText}`);
  }

  return response.json();
}

export async function downloadForensicPdf(taskId: string): Promise<void> {
  const response = await fetch(getApiUrl(`/forensics/pdf/${taskId}`));

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `Failed to download PDF: ${response.statusText}`);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic_report_${taskId}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function generateSiemReport(data: ParseResponse, socSummary?: string): Promise<void> {
  console.log('Generating SIEM report...', { dataSize: data?.entries?.length, hasSocSummary: !!socSummary });
  
  const response = await fetch(getApiUrl('/generate-report'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, soc_summary: socSummary }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('Report generation failed:', response.status, errorText);
    throw new Error(`Failed to generate report: ${response.statusText}`);
  }

  console.log('Report generated successfully, downloading...');
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `siem_report_${new Date().getTime()}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Smart Filtering API for AI Agent
export interface FilterCriteria {
  column?: string;
  value?: string | number;
  operator?: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'greaterThan' | 'lessThan';
  attackType?: string;
  severity?: string;
  logType?: string;
}

export interface SmartFilterResponse {
  entries: (ParsedLogEntry | CorrelatedEvent)[];
  totalCount: number;
  filteredCount: number;
  appliedFilters: FilterCriteria[];
}

export function smartFilterLogs(
  data: ParseResponse | CorrelateResponse,
  logType: 'single' | 'correlation',
  criteria: FilterCriteria[]
): SmartFilterResponse {
  const entries = logType === 'single'
    ? (data as ParseResponse).entries || []
    : (data as CorrelateResponse).correlation?.attackChains?.flatMap(c => c.events) || [];

  let filtered = [...entries];

  for (const criterion of criteria) {
    filtered = filtered.filter(entry => {
      // Handle attack type filtering (only for ParsedLogEntry, not CorrelatedEvent)
      if (criterion.attackType && 'attackType' in entry) {
        if (criterion.attackType === 'any') {
          return entry.attackType !== undefined && entry.attackType !== 'normal';
        }
        return entry.attackType === criterion.attackType;
      }

      // Handle severity filtering
      if (criterion.severity) {
        return entry.severity === criterion.severity;
      }

      // Handle log type filtering
      if (criterion.logType) {
        return entry.logType.toLowerCase().includes(criterion.logType.toLowerCase());
      }

      // Handle column-based filtering
      if (criterion.column && criterion.value !== undefined) {
        const value = getNestedValue(entry, criterion.column);
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

  return {
    entries: filtered,
    totalCount: entries.length,
    filteredCount: filtered.length,
    appliedFilters: criteria
  };
}

function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((current, key) => {
    return current && current[key] !== undefined ? current[key] : undefined;
  }, obj);
}
