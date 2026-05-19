// SIEM Backend API - Cloudflare Workers with Hono
// Main entry point for the log parsing and analysis API

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { autoParse, detectLogType, allParsers, analyzeLogStructureAndSuggestLabels } from './parsers';
import { runDetections, generateStats } from './detectors/alerts';
import { correlateMultipleLogs as correlateMultipleLogsEnhanced, CorrelationResult, detectAttacksInEntries, enrichEntriesWithAttacks, detectMLAttacks, detectAnomaly, detectAnomaliesForAllTypes } from './ml';
import { correlateMultipleLogs as correlateMultipleLogsLegacy } from './ml/correlator';
import { EVTXParser, EVTXDetector } from './parsers/evtx';
import type { ParseResponse, LogType, ParsedLogEntry } from './types';

// Helper functions for MITRE ATT&CK mapping
function getMitreTacticsForAttack(attackType: string): string[] {
  const tacticMap: Record<string, string[]> = {
    bruteforce: ['TA0006 - Credential Access'],
    password_spray: ['TA0006 - Credential Access'],
    credential_stuffing: ['TA0006 - Credential Access'],
    mfa_bypass: ['TA0006 - Credential Access', 'TA0005 - Defense Evasion'],
    mfa_fatigue: ['TA0006 - Credential Access'],
    session_hijacking: ['TA0006 - Credential Access', 'TA0008 - Lateral Movement'],
    account_takeover: ['TA0006 - Credential Access', 'TA0001 - Initial Access'],
    sql_injection: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    xss_attack: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    path_traversal: ['TA0001 - Initial Access', 'TA0009 - Collection'],
    command_injection: ['TA0002 - Execution'],
    privilege_escalation: ['TA0004 - Privilege Escalation'],
    lateral_movement: ['TA0008 - Lateral Movement'],
    data_exfiltration: ['TA0010 - Exfiltration'],
    port_scan: ['TA0043 - Reconnaissance'],
    ddos: ['TA0040 - Impact'],
    reconnaissance: ['TA0043 - Reconnaissance'],
    malware_activity: ['TA0002 - Execution', 'TA0003 - Persistence'],
    c2_communication: ['TA0011 - Command and Control'],
    insider_threat: ['TA0009 - Collection', 'TA0010 - Exfiltration'],
    log4shell: ['TA0001 - Initial Access', 'TA0002 - Execution'],
    ransomware: ['TA0040 - Impact', 'TA0002 - Execution'],
    anomaly: ['TA0043 - Reconnaissance'],
  };
  return tacticMap[attackType] || ['Unknown'];
}

function getMitreTechniquesForAttack(attackType: string): string[] {
  const techniqueMap: Record<string, string[]> = {
    bruteforce: ['T1110.001 - Password Guessing'],
    password_spray: ['T1110.003 - Password Spraying'],
    credential_stuffing: ['T1110.004 - Credential Stuffing'],
    sql_injection: ['T1190 - Exploit Public-Facing Application'],
    xss_attack: ['T1189 - Drive-by Compromise'],
    path_traversal: ['T1083 - File and Directory Discovery'],
    command_injection: ['T1059 - Command and Scripting Interpreter'],
    privilege_escalation: ['T1068 - Exploitation for Privilege Escalation'],
    lateral_movement: ['T1021 - Remote Services'],
    data_exfiltration: ['T1041 - Exfiltration Over C2 Channel'],
    port_scan: ['T1046 - Network Service Discovery'],
    ddos: ['T1498 - Network Denial of Service'],
    reconnaissance: ['T1595 - Active Scanning'],
    malware_activity: ['T1204 - User Execution'],
    c2_communication: ['T1071 - Application Layer Protocol'],
    log4shell: ['T1190 - Exploit Public-Facing Application'],
    ransomware: ['T1486 - Data Encrypted for Impact'],
  };
  return techniqueMap[attackType] || ['Unknown'];
}

// Cloudflare Workers limits - reduced to 200KB to prevent CPU crashes
const MAX_TEXT_SIZE = 200 * 1024; // 200KB hard limit per request
const MAX_BINARY_SIZE = 200 * 1024; // 200KB for EVTX
const CHUNK_SIZE = 200 * 1024; // 200KB chunk size for splitting

// Types for Cloudflare Workers
type Bindings = {
  // Add any bindings here (KV, D1, etc.)
};

const app = new Hono<{ Bindings: Bindings }>();

// Enable CORS for frontend with specific origins
app.use('*', cors({
  origin: (origin) => {
    const allowedOrigins = [
      'https://cyberchakshu-frontend.pages.dev',
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5000',
      'http://127.0.0.1:5000',
    ];
    if (!origin) return '*';
    return allowedOrigins.includes(origin) ? origin : '*';
  },
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With', 'CF-Access-Client-Id', 'CF-Access-Client-Name', 'X-File-Name'],
  exposeHeaders: ['Content-Length', 'X-Custom-Header'],
  maxAge: 86400,
  credentials: false,
}));

// Handle preflight OPTIONS requests explicitly
app.options('*', (c) => {
  const origin = c.req.header('Origin');
  const allowedOrigins = [
    'https://cyberchakshu-frontend.pages.dev',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5000',
    'http://127.0.0.1:5000',
  ];
  const allowOrigin = (!origin || allowedOrigins.includes(origin)) ? origin || '*' : '*';
  
  return c.text('', 200, {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, Origin, X-Requested-With, CF-Access-Client-Id, CF-Access-Client-Name, X-File-Name',
    'Access-Control-Max-Age': '86400',
  });
});
 
// Health check
app.get('/', (c) => {
  return c.json({
    status: 'ok',
    name: 'Cyber Chakshu SIEM API',
    version: '2.0.0',
    features: [
      'Multi-log parsing (56+ log types)',
      'ML-based anomaly detection',
      'Cross-log correlation',
      'Attack chain detection',
      'False positive filtering',
      'MITRE ATT&CK mapping',
    ],
    endpoints: [
      'GET / - Health check',
      'GET /parsers - List available parsers',
      'POST /parse - Parse single log file',
      'POST /correlate - Multi-log correlation with ML',
      'POST /detect - Detect log type only',
      'POST /stream - Stream parsing (line by line)',
      'POST /analyze - Dynamic field detection and labeling',
    ],
  });
});

// List available parsers
app.get('/parsers', (c) => {
  const parsers = allParsers.map(p => ({
    name: p.name,
    logType: p.logType,
  }));
  
  // Group by category
  const categories = {
    database: parsers.filter(p => ['mysql_error', 'mysql_query', 'mysql_slow', 'postgres_error', 'postgres_auth', 'postgres_statement', 'oracle_alert', 'oracle_listener', 'oracle_audit', 'sqlserver_error', 'sqlserver_audit', 'sqlserver_transaction', 'mongodb_server', 'mongodb_audit'].includes(p.logType)),
    webserver: parsers.filter(p => ['apache', 'nginx', 'iis', 'django', 'flask', 'laravel', 'rails', 'express', 'fastapi', 'gunicorn', 'uvicorn'].includes(p.logType)),
    system: parsers.filter(p => ['syslog', 'systemd', 'kernel', 'audit', 'package', 'cron', 'daemon'].includes(p.logType)),
    auth: parsers.filter(p => ['ssh_auth', 'pam', 'vsftpd', 'proftpd'].includes(p.logType)),
    firewall: parsers.filter(p => ['iptables', 'ufw', 'nftables', 'firewalld', 'windows_firewall', 'palo_alto', 'fortigate', 'cisco_asa', 'checkpoint', 'aws_vpc_flow', 'azure_nsg', 'gcp_vpc'].includes(p.logType)),
    mail: parsers.filter(p => ['postfix', 'sendmail', 'exim', 'dovecot', 'exchange'].includes(p.logType)),
  };

  return c.json({
    total: parsers.length,
    categories,
    all: parsers,
  });
});

// Detect log type without full parsing
app.post('/detect', async (c) => {
  try {
    const body = await c.req.text();
    
    if (!body || body.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }

    const lines = body.split('\n').filter(l => l.trim());
    const detectedType = detectLogType(body);

    return c.json({
      detectedType,
      sampleSize: Math.min(lines.length, 50),
      totalLines: lines.length,
    });
  } catch (error) {
    return c.json({ error: 'Failed to detect log type', details: String(error) }, 500);
  }
});

// Main parse endpoint (single file)
app.post('/parse', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    let content: string;
    let binaryContent: ArrayBuffer | null = null;
    let forceType: LogType | undefined;
    let filename: string | undefined;

    // Handle different content types
    if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as File | null;
      const type = formData.get('type') as string | null;
      
      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }
      
      filename = file.name;
      
      // Check if it's a binary file (EVTX) - always check by filename extension
      if (filename?.toLowerCase().endsWith('.evtx')) {
        binaryContent = await file.arrayBuffer();
        console.log('EVTX file detected by extension:', filename, 'size:', binaryContent.byteLength);
      } else {
        content = await file.text();
      }
      
      if (type && type !== 'auto') {
        forceType = type as LogType;
      }
    } else if (contentType.includes('application/json')) {
      const json = await c.req.json();
      if (Array.isArray(json)) {
        content = JSON.stringify(json);
      } else {
        content = json.content || json.logs || '';
      }
      forceType = json.type;
    } else if (contentType.includes('application/octet-stream') || contentType.includes('binary')) {
      // Handle binary file upload (EVTX)
      const arrayBuffer = await c.req.arrayBuffer();
      filename = c.req.header('x-file-name') || c.req.header('X-File-Name');
      
      if (arrayBuffer.byteLength === 0) {
        return c.json({ error: 'Empty file provided' }, 400);
      }
      
      // Check if it's an EVTX file by signature or filename
      if (arrayBuffer.byteLength >= 4) {
        const view = new DataView(arrayBuffer);
        const signature = view.getUint32(0, true);
        
        if (signature === 0x46566C45 || filename?.toLowerCase().endsWith('.evtx')) {
          binaryContent = arrayBuffer;
          console.log('Binary EVTX upload detected:', filename, 'size:', arrayBuffer.byteLength);
        }
      }
      
      // If not detected as binary, decode as text
      if (!binaryContent) {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        try {
          content = decoder.decode(arrayBuffer);
        } catch {
          content = new TextDecoder('latin1').decode(arrayBuffer);
        }
      }
    } else {
      // Check if content might be binary (starts with EVTX magic bytes)
      const arrayBuffer = await c.req.arrayBuffer();
      
      // Check if arrayBuffer is empty or too small
      if (arrayBuffer.byteLength === 0) {
        return c.json({ error: 'No log content provided' }, 400);
      }
      
      const view = new DataView(arrayBuffer);
      
      // Need at least 4 bytes for signature check
      if (arrayBuffer.byteLength >= 4) {
        const signature = view.getUint32(0, true);
        
        // EVTX signature: 0x46566C45 ('ElfF')
        if (signature === 0x46566C45) {
          binaryContent = arrayBuffer;
          console.log('EVTX detected via signature, size:', arrayBuffer.byteLength);
        }
      }
      
      // If not binary, decode as text
      if (!binaryContent) {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        try {
          content = decoder.decode(arrayBuffer);
        } catch {
          // If decoding fails, try latin1 for 8-bit encodings
          content = new TextDecoder('latin1').decode(arrayBuffer);
        }
      }
    }

    // Check content size before processing
    if (binaryContent) {
      const sizeMB = (binaryContent.byteLength / (1024 * 1024)).toFixed(2);
      console.log(`Processing binary content: ${sizeMB} MB`);
      
      if (binaryContent.byteLength > MAX_BINARY_SIZE) {
        const sizeMB = (binaryContent.byteLength / (1024 * 1024)).toFixed(2);
        
        // Auto-split binary by extracting events in chunks
        const decoder = new TextDecoder('utf-8', { fatal: false });
        const content = decoder.decode(binaryContent);
        const lines = content.split('\n');
        
        // Find event boundaries and create text-based chunks
        const chunks: { index: number; content: string; size: number; lineCount: number }[] = [];
        let currentChunk = '';
        let currentSize = 0;
        let chunkIndex = 1;
        let lineCount = 0;
        
        for (const line of lines) {
          const lineWithNewline = line + '\n';
          const lineSize = new TextEncoder().encode(lineWithNewline).length;
          
          // Look for event boundaries (XML-like structure in EVTX text export)
          const isEventStart = line.includes('Event') || line.includes('<Event');
          
          if (currentSize + lineSize > CHUNK_SIZE && currentChunk.length > 0) {
            chunks.push({
              index: chunkIndex,
              content: currentChunk.trimEnd(),
              size: currentChunk.length,
              lineCount: lineCount
            });
            chunkIndex++;
            currentChunk = lineWithNewline;
            currentSize = lineSize;
            lineCount = 1;
          } else {
            currentChunk += lineWithNewline;
            currentSize += lineSize;
            lineCount++;
          }
        }
        
        if (currentChunk.trimEnd().length > 0) {
          chunks.push({
            index: chunkIndex,
            content: currentChunk.trimEnd(),
            size: currentChunk.length,
            lineCount
          });
        }
        
        return c.json({
          status: 'auto_split',
          message: 'Binary EVTX file converted to text and split (1MB limit)',
          originalFile: {
            sizeMB: parseFloat(sizeMB),
            format: 'EVTX binary',
            name: filename
          },
          splitConfig: {
            chunkSizeMB: CHUNK_SIZE / 1024 / 1024,
            totalChunks: chunks.length,
            format: 'text_export'
          },
          chunks: chunks.slice(0, 10).map(c => ({
            index: c.index,
            name: `chunk_${String(c.index).padStart(3, '0')}.log`,
            content: c.content, // Include content for frontend processing
            lineCount: c.lineCount,
            byteSize: c.size
          })),
          note: chunks.length > 10 ? `Showing 10 of ${chunks.length} chunks` : null,
          usage: {
            option1: 'File will be automatically processed in chunks',
            option2: 'Export EVTX to text using Windows Event Viewer, then upload',
          },
        }, 200);
      }
    } else if (content) {
      const sizeMB = (content.length / (1024 * 1024)).toFixed(2);
      console.log(`Processing text content: ${sizeMB} MB, ${content.split('\n').length} lines`);
      
      if (content.length > MAX_TEXT_SIZE) {
        const lineCount = content.split('\n').length;
        
        // AUTO-SPLIT: Split file into chunks and return all chunks
        const lines = content.split('\n');
        const chunks: { index: number; content: string; size: number; lineCount: number; byteSize: number }[] = [];
        let currentChunk = '';
        let currentSize = 0;
        let chunkIndex = 1;
        
        for (const line of lines) {
          const lineWithNewline = line + '\n';
          const lineSize = new TextEncoder().encode(lineWithNewline).length;
          
          if (currentSize + lineSize > CHUNK_SIZE && currentChunk.length > 0) {
            chunks.push({
              index: chunkIndex,
              content: currentChunk.trimEnd(),
              size: currentChunk.length,
              lineCount: currentChunk.split('\n').length,
              byteSize: currentSize
            });
            chunkIndex++;
            currentChunk = lineWithNewline;
            currentSize = lineSize;
          } else {
            currentChunk += lineWithNewline;
            currentSize += lineSize;
          }
        }
        
        if (currentChunk.trimEnd().length > 0) {
          chunks.push({
            index: chunkIndex,
            content: currentChunk.trimEnd(),
            size: currentChunk.length,
            lineCount: currentChunk.split('\n').length,
            byteSize: currentSize
          });
        }
        
        console.log(`Auto-split into ${chunks.length} chunks`);
        
        // If we have reasonable number of chunks, process them directly
        // Increase limit to handle larger files (up to ~2MB)
        if (chunks.length <= 10) {
          // Process each chunk and combine results
          const allEntries: any[] = [];
          const allAlerts: any[] = [];
          
          for (const chunk of chunks) {
            const { entries, stats } = autoParse(chunk.content);
            allEntries.push(...entries);
            const alerts = runDetections(entries);
            allAlerts.push(...alerts);
          }
          
          // Run ML-based attack detection on combined entries
          const enrichedEntries = enrichEntriesWithAttacks(allEntries);
          const detectedAttacks = detectAttacksInEntries(enrichedEntries);
          const mlPredictions = detectMLAttacks(allEntries);
          const multiLogAnomalies = detectAnomaliesForAllTypes(allEntries);
          
          // We no longer indiscriminately map file-level ML predictions to every single log entry
          // Individual log attacks are already identified via detectAttacksInEntries
          
          // Generate attack summary
          const attackTypes = [...new Set(detectedAttacks.map((a: any) => a.attack.attackType))];
          const mlAttackTypes = [...new Set(mlPredictions.map((p: any) => p.attackType))];
          const multiLogAttackTypes = multiLogAnomalies.flatMap((a: any) => a.detectedAttackTypes);
          const allAttackTypes = [...new Set([...attackTypes, ...mlAttackTypes, ...multiLogAttackTypes])];
          const attackSummary = {
            totalAttacks: detectedAttacks.length + mlPredictions.length + multiLogAnomalies.filter((a: any) => a.isAnomaly).length,
            attackTypes: allAttackTypes,
            uniqueSources: new Set(allEntries.map((e: any) => e.source.ip).filter(Boolean)).size,
            riskScore: Math.min(Math.max(detectedAttacks.length, mlPredictions.length) * 10, 100),
          };
          
          // Generate stats
          const uniqueIps = new Set(allEntries.map(e => e.source.ip).filter(Boolean));
          const stats = {
            byType: { [filename || 'logs']: allEntries.length },
            bySeverity: allEntries.reduce((acc: any, e: any) => {
              acc[e.severity] = (acc[e.severity] || 0) + 1;
              return acc;
            }, {}),
            byOutcome: allEntries.reduce((acc: any, e: any) => {
              acc[e.outcome || 'unknown'] = (acc[e.outcome || 'unknown'] || 0) + 1;
              return acc;
            }, {}),
            topSources: Array.from(uniqueIps).slice(0, 10).map(ip => ({ ip, count: 1 })),
            topUsers: [],
            timeline: []
          };
          
          return c.json({
            success: true,
            detectedType: 'auto_split_processed',
            totalLines: lineCount,
            parsedLines: allEntries.length,
            failedLines: lineCount - allEntries.length,
            entries: enrichedEntries,
            alerts: allAlerts,
            mlAttacks: detectedAttacks,
            mlPredictions,
            multiLogAnomalies,
            attackSummary,
            stats,
            chunkInfo: {
              processedChunks: chunks.length,
              message: 'File was automatically split and processed'
            }
          }, 200);
        }
        
        // For too many chunks, return chunk info for manual processing
        return c.json({
          status: 'auto_split',
          message: 'File was automatically split - too many chunks for auto-processing',
          originalFile: {
            sizeMB: parseFloat(sizeMB),
            lineCount,
            name: filename
          },
          splitConfig: {
            chunkSizeMB: CHUNK_SIZE / 1024 / 1024,
            totalChunks: chunks.length,
            format: 'line_based'
          },
          chunks: chunks.map(c => ({
            index: c.index,
            name: `chunk_${String(c.index).padStart(3, '0')}.log`,
            content: c.content, // Include content for frontend
            lineCount: c.lineCount,
            byteSize: c.byteSize
          })),
          usage: {
            option1: 'File will be processed in chunks if you upload via /parse/chunked',
            option2: 'Upload smaller files (<200KB) for immediate processing'
          }
        }, 200);
      }
    }

    // Handle EVTX binary files
    if (binaryContent) {
      console.log('Parsing EVTX binary, size:', binaryContent.byteLength, 'filename:', filename);
      const evtxEntries = EVTXParser.parse(binaryContent);
      console.log('EVTX entries parsed:', evtxEntries.length);
      
      if (evtxEntries.length === 0) {
        return c.json({ 
          error: 'No valid EVTX records found in file. The file may be empty, corrupted, or in an unsupported format.',
          debug: {
            fileSize: binaryContent.byteLength,
            filename,
            isValidEVTX: EVTXParser.canParse(binaryContent)
          }
        }, 400);
      }

      // Run detections
      const alerts = runDetections(evtxEntries);
      const enrichedEntries = enrichEntriesWithAttacks(evtxEntries);
      const detectedAttacks = detectAttacksInEntries(enrichedEntries);
      const mlPredictions = detectMLAttacks(evtxEntries);
      const multiLogAnomalies = detectAnomaliesForAllTypes(evtxEntries);
      
      // Generate attack summary
      const attackTypes = [...new Set(detectedAttacks.map(a => a.attack.attackType))];
      const mlAttackTypes = [...new Set(mlPredictions.map(p => p.attackType))];
      const multiLogAttackTypes = multiLogAnomalies.flatMap(a => a.detectedAttackTypes);
      const allAttackTypes = [...new Set([...attackTypes, ...mlAttackTypes, ...multiLogAttackTypes])];
      
      const attackSummary = {
        totalAttacks: detectedAttacks.length + mlPredictions.length + multiLogAnomalies.filter(a => a.isAnomaly).length,
        attackTypes: allAttackTypes,
        uniqueSources: new Set(evtxEntries.map(e => e.source.ip).filter(Boolean)).size,
        riskScore: Math.min(Math.max(detectedAttacks.length, mlPredictions.length) * 10, 100),
        multiLogRiskScore: Math.min(multiLogAnomalies.reduce((sum, a) => sum + a.anomalyScore, 0) * 20, 100),
      };

      const stats = generateStats(evtxEntries);

      return c.json({
        success: true,
        detectedType: 'windows_event' as LogType,
        totalLines: evtxEntries.length,
        parsedLines: evtxEntries.length,
        failedLines: 0,
        entries: enrichedEntries,
        alerts,
        stats,
        mlAttacks: detectedAttacks,
        mlPredictions,
        multiLogAnomalies,
        attackSummary,
      } as ParseResponse);
    }

    if (!content || content.trim().length === 0) {
      // Check if there might be binary content that wasn't detected
      console.log('Empty content check:', { hasContent: !!content, length: content?.length, contentType });
      return c.json({ 
        error: 'No log content provided',
        debug: {
          hasContent: !!content,
          contentLength: content?.length || 0,
          contentType
        }
      }, 400);
    }

    // Parse logs
    const { detectedType, entries, stats: parseStats } = autoParse(content);
    
    // Use forced type if provided
    const finalType = forceType || detectedType;

    // Run detections
    const alerts = runDetections(entries);
    
    // Run ML-based per-entry attack detection
    const enrichedEntries = enrichEntriesWithAttacks(entries);
    const detectedAttacks = detectAttacksInEntries(enrichedEntries);
    
    // Run ML-based feature extraction and classification
    const mlPredictions = detectMLAttacks(entries);
    
    // Also enrich entries with ML predictions for frontend display
    // We no longer indiscriminately map file-level ML predictions to every single log entry
    // Individual log attacks are already identified via detectAttacksInEntries
    
    // Run multi-log type anomaly detection
    const multiLogAnomalies = detectAnomaliesForAllTypes(entries);
    const multiLogAnomalyDetected = multiLogAnomalies.some(a => a.isAnomaly);
    const multiLogRiskScore = Math.min(
      multiLogAnomalies.reduce((sum, a) => sum + a.anomalyScore, 0) * 20, 
      100
    );
    
    // Generate attack summary
    const attackTypes = [...new Set(detectedAttacks.map(a => a.attack.attackType))];
    const mlAttackTypes = [...new Set(mlPredictions.map(p => p.attackType))];
    const multiLogAttackTypes = multiLogAnomalies.flatMap(a => a.detectedAttackTypes);
    const allAttackTypes = [...new Set([...attackTypes, ...mlAttackTypes, ...multiLogAttackTypes])];
    const attackSummary = {
      totalAttacks: detectedAttacks.length + mlPredictions.length + multiLogAnomalies.filter(a => a.isAnomaly).length,
      attackTypes: allAttackTypes,
      uniqueSources: new Set(entries.map(e => e.source.ip).filter(Boolean)).size,
      riskScore: Math.min(Math.max(detectedAttacks.length, mlPredictions.length, multiLogRiskScore) * 10, 100),
      multiLogRiskScore,
    };
    
    // Generate statistics
    const stats = generateStats(entries);

const response: ParseResponse = {
      success: true,
      detectedType: finalType,
      totalLines: parseStats.totalLines,
      parsedLines: parseStats.parsedLines,
      failedLines: parseStats.failedLines,
      successRate: parseStats.successRate !== undefined 
        ? parseStats.successRate 
        : (parseStats.totalLines > 0 ? Math.round(((parseStats.totalLines - (parseStats.failedLines || 0)) / parseStats.totalLines) * 100) : 0),
      totalEvents: parseStats.totalEvents,
      parsedEvents: parseStats.parsedEvents,
      failedEvents: parseStats.failedEvents,
      entries: enrichedEntries,
      alerts,
      stats,
      mlAttacks: detectedAttacks,
      mlPredictions,
      multiLogAnomalies,
      attackSummary,
    };

    return c.json(response);
  } catch (error) {
    console.error('Parse error:', error);
    const errorMsg = String(error);
    const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('CPU') || errorMsg.includes('execution') || errorMsg.includes('exceeded');
    const isMemory = errorMsg.includes('memory') || errorMsg.includes('heap');
    
    if (isTimeout) {
      return c.json({
        success: false,
        error: 'Processing timeout - file too large',
        details: 'The file exceeded the maximum CPU time limit for processing',
        suggestion: 'Try one of these solutions:',
        solutions: [
          'Split the file into smaller chunks (1-5 MB each)',
          'Use /parse/chunked endpoint with multiple smaller uploads',
          'Use /parse/stream for very large files with line-by-line processing',
          'Process the file locally using a CLI tool'
        ],
        seeAlso: 'GET /limits for current limits and recommendations'
      }, 413);
    }
    
    if (isMemory) {
      return c.json({
        success: false,
        error: 'Out of memory - file too large',
        details: 'The file exceeded available memory for processing',
        suggestion: 'Split the file into smaller parts and process separately',
        solutions: [
          'Split the file into smaller files (1-2 MB each)',
          'Use /parse/chunked for combined processing',
          'Process in smaller batches with /parse/stream'
        ]
      }, 507);
    }
    
    return c.json({ 
      success: false,
      error: 'Failed to parse logs', 
      details: errorMsg 
    }, 500);
  }
});

// Multi-log correlation endpoint with ML-based detection
app.post('/correlate', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    
    interface LogSource {
      name: string;
      entries: ParsedLogEntry[];
    }
    
    const logSources: LogSource[] = [];

    if (contentType.includes('multipart/form-data')) {
      // Handle multiple file uploads
      const formData = await c.req.formData();
      const files: File[] = [];
      
      // Try multiple files field
      const multipleFiles = formData.getAll('files');
      for (const f of multipleFiles) {
        if (typeof f !== 'string' && 'text' in f) {
          files.push(f as File);
        }
      }
      
      // Try single file field
      if (files.length === 0) {
        const singleFile = formData.get('file');
        if (singleFile && typeof singleFile !== 'string' && 'text' in singleFile) {
          files.push(singleFile as File);
        }
      }
      
      if (files.length === 0) {
        return c.json({ error: 'No files provided' }, 400);
      }

      // Parse each file
      for (const file of files) {
        const content = await file.text();
        if (!content.trim()) continue;
        
        const { entries } = autoParse(content);
        logSources.push({
          name: file.name || `file_${logSources.length + 1}`,
          entries,
        });
      }
    } else if (contentType.includes('application/json')) {
      // Handle JSON payload with multiple log sources
      const json = await c.req.json();
      
      if (Array.isArray(json.logs)) {
        // Array of log sources: [{ name: "auth", content: "..." }, ...]
        for (const source of json.logs) {
          if (!source.content) continue;
          
          const { entries } = autoParse(source.content);
          logSources.push({
            name: source.name || `source_${logSources.length + 1}`,
            entries,
          });
        }
      } else if (json.content) {
        // Single content with optional name
        const { entries } = autoParse(json.content);
        logSources.push({
          name: json.name || 'logs',
          entries,
        });
      }
    } else {
      // Plain text - treat as single source
      const content = await c.req.text();
      if (!content.trim()) {
        return c.json({ error: 'No log content provided' }, 400);
      }
      
      const { entries } = autoParse(content);
      logSources.push({
        name: 'logs',
        entries,
      });
    }

    if (logSources.length === 0 || logSources.every(s => s.entries.length === 0)) {
      return c.json({ error: 'No valid log entries found in provided sources' }, 400);
    }

    // Run ML-based correlation
    const correlationResult: CorrelationResult = correlateMultipleLogsEnhanced(logSources);

    // Also run traditional detections for comparison
    const allEntries = logSources.flatMap(s => s.entries);
    const traditionalAlerts = runDetections(allEntries);
    const stats = generateStats(allEntries);

    return c.json({
      success: true,
      sources: logSources.map(s => ({ name: s.name, entryCount: s.entries.length })),
      correlation: correlationResult,
      traditionalAlerts, // For comparison/fallback
      stats,
    });
  } catch (error) {
    console.error('Correlation error:', error);
    return c.json({ 
      success: false,
      error: 'Failed to correlate logs', 
      details: String(error) 
    }, 500);
  }
});

// Stream parsing - parse a single line or batch of lines
app.post('/stream', async (c) => {
  try {
    const json = await c.req.json();
    const lines: string[] = Array.isArray(json.lines) ? json.lines : [json.line || json.content];
    
    if (lines.length === 0 || !lines[0]) {
      return c.json({ error: 'No lines provided' }, 400);
    }

    const content = lines.join('\n');
    const { detectedType, entries, stats } = autoParse(content);
    
    // Run detections on the batch
    const alerts = runDetections(entries);

    const successRate = stats.successRate !== undefined 
      ? stats.successRate 
      : (stats.totalLines > 0 ? Math.round(((stats.totalLines - (stats.failedLines || 0)) / stats.totalLines) * 100) : 0);

    return c.json({
      success: true,
      detectedType,
      totalLines: stats.totalLines || entries.length,
      parsedLines: entries.length,
      failedLines: (stats.totalLines || entries.length) - entries.length,
      successRate,
      totalEvents: stats.totalEvents,
      parsedEvents: stats.parsedEvents,
      failedEvents: stats.failedEvents,
      entries,
      alerts,
      stats,
    });
  } catch (error) {
    return c.json({ 
      success: false,
      error: 'Failed to parse stream', 
      details: String(error) 
    }, 500);
  }
});

// Attack types reference endpoint
app.get('/attacks', (c) => {
  return c.json({
    attackTypes: [
      { type: 'bruteforce', description: 'Multiple failed login attempts to same account' },
      { type: 'password_spray', description: 'Same password tried against multiple accounts' },
      { type: 'credential_stuffing', description: 'Automated login attempts with stolen credentials' },
      { type: 'mfa_bypass', description: 'Attempts to circumvent multi-factor authentication' },
      { type: 'mfa_fatigue', description: 'Repeated MFA push notifications to exhaust user' },
      { type: 'session_hijacking', description: 'Unauthorized use of valid session tokens' },
      { type: 'privilege_escalation', description: 'Attempts to gain elevated access' },
      { type: 'lateral_movement', description: 'Movement between systems in network' },
      { type: 'data_exfiltration', description: 'Unauthorized data transfer out of network' },
      { type: 'sql_injection', description: 'SQL commands injected into application' },
      { type: 'xss_attack', description: 'Cross-site scripting attack' },
      { type: 'path_traversal', description: 'Directory traversal to access restricted files' },
      { type: 'command_injection', description: 'OS commands injected into application' },
      { type: 'port_scan', description: 'Network reconnaissance scanning ports' },
      { type: 'ddos', description: 'Distributed denial of service attack' },
      { type: 'reconnaissance', description: 'Information gathering activity' },
      { type: 'malware_activity', description: 'Potential malware execution detected' },
      { type: 'c2_communication', description: 'Command and control server communication' },
      { type: 'insider_threat', description: 'Suspicious activity from authorized user' },
      { type: 'account_takeover', description: 'Unauthorized account access' },
    ],
    mitreTactics: [
      'TA0001 - Initial Access',
      'TA0002 - Execution',
      'TA0003 - Persistence',
      'TA0004 - Privilege Escalation',
      'TA0005 - Defense Evasion',
      'TA0006 - Credential Access',
      'TA0007 - Discovery',
      'TA0008 - Lateral Movement',
      'TA0009 - Collection',
      'TA0010 - Exfiltration',
      'TA0011 - Command and Control',
      'TA0040 - Impact',
      'TA0043 - Reconnaissance',
    ],
  });
});

// Dynamic log analysis endpoint - analyze unknown logs and suggest field labels
app.post('/analyze', async (c) => {
  try {
    const contentType = c.req.header('Content-Type') || '';
    let content: string;

    if (contentType.includes('multipart/form-data')) {
      const formData = await c.req.formData();
      const file = formData.get('file') as File | null;

      if (!file) {
        return c.json({ error: 'No file provided' }, 400);
      }

      content = await file.text();
    } else if (contentType.includes('application/json')) {
      const json = await c.req.json();
      content = json.content || json.logs || '';
    } else {
      content = await c.req.text();
    }

    if (!content || content.trim().length === 0) {
      return c.json({ error: 'No log content provided' }, 400);
    }

    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) {
      return c.json({ error: 'No valid log lines found' }, 400);
    }

    // Analyze log structure and suggest labels
    const analysis = analyzeLogStructureAndSuggestLabels(lines);

    // Detect log type using existing parsers
    const detectedType = detectLogType(content);

    return c.json({
      success: true,
      detectedType,
      totalLines: lines.length,
      structure: {
        separator: analysis.structure.separator,
        columns: analysis.structure.columns,
        hasTimestamp: analysis.structure.hasTimestamp,
        timestampIndex: analysis.structure.timestampIndex,
        hasKeyPairs: analysis.structure.hasKeyPairs,
      },
      detectedFields: analysis.detectedFields,
      suggestedLabels: analysis.suggestedLabels,
      sampleFields: analysis.sampleFields.slice(0, 5),
      summary: {
        fieldCount: analysis.detectedFields.length,
        confidenceScore: analysis.suggestedLabels.reduce((sum: number, l: any) => sum + l.confidence, 0) / analysis.suggestedLabels.length,
        isStructured: analysis.structure.separator !== 'unknown' || analysis.structure.hasKeyPairs,
      },
    });
  } catch (error) {
    console.error('Analysis error:', error);
    return c.json({
      success: false,
      error: 'Failed to analyze logs',
      details: String(error)
    }, 500);
  }
});

// Submit feedback for a log entry
app.post('/feedback', async (c) => {
  try {
    const json = await c.req.json();

    if (!json.entry_id || !json.user_label) {
      return c.json({ error: 'Missing required fields: entry_id, user_label' }, 400);
    }

    if (!['safe', 'unsafe', 'attack_pattern'].includes(json.user_label)) {
      return c.json({ error: 'user_label must be "safe", "unsafe", or "attack_pattern"' }, 400);
    }

    // In a real implementation, this would store to a database
    // For now, we just acknowledge the feedback
    const feedbackId = `${json.entry_id}_${Date.now()}`;

    console.log(`Feedback received: ${json.user_label} - Entry ${json.entry_id}`);

    return c.json({
      success: true,
      message: `Feedback submitted: Entry ${json.entry_id} marked as ${json.user_label}`,
      feedback_id: feedbackId
    });
  } catch (error) {
    console.error('Feedback error:', error);
    return c.json({
      success: false,
      error: 'Failed to submit feedback',
      details: String(error)
    }, 500);
  }
});

// Submit bulk feedback for multiple entries
app.post('/feedback/bulk', async (c) => {
  try {
    const json = await c.req.json();

    if (!json.entries || !Array.isArray(json.entries)) {
      return c.json({ error: 'Missing or invalid entries array' }, 400);
    }

    const { entries, user_label, attack_type } = json;

    if (!['safe', 'unsafe', 'attack_pattern'].includes(user_label)) {
      return c.json({ error: 'user_label must be "safe", "unsafe", or "attack_pattern"' }, 400);
    }

    if (user_label === 'attack_pattern' && !attack_type) {
      return c.json({ error: 'attack_type is required when user_label is "attack_pattern"' }, 400);
    }

    const results: { id: string; success: boolean }[] = [];

    for (const entry of entries) {
      const feedbackId = `${entry.entry_id}_${Date.now()}_${Math.random().toString(36).slice(2)}`;

      results.push({
        id: entry.entry_id,
        success: true
      });

      console.log(`Bulk feedback: ${user_label} - Entry ${entry.entry_id} - Attack type: ${attack_type || 'N/A'}`);
    }

    return c.json({
      success: true,
      message: `Bulk feedback submitted for ${results.length} entries`,
      results
    });
  } catch (error) {
    console.error('Bulk feedback error:', error);
    return c.json({
      success: false,
      error: 'Failed to submit bulk feedback',
      details: String(error)
    }, 500);
  }
});

// Get available attack types for manual classification
app.get('/feedback/attack-types', (c) => {
  return c.json({
    attackTypes: [
      { type: 'sql_injection', label: 'SQL Injection', description: 'SQL commands injected into application queries' },
      { type: 'xss_attack', label: 'Cross-Site Scripting (XSS)', description: 'Malicious scripts injected into web pages' },
      { type: 'command_injection', label: 'Command Injection', description: 'OS commands injected through application input' },
      { type: 'path_traversal', label: 'Path Traversal', description: 'Directory traversal to access restricted files' },
      { type: 'file_inclusion', label: 'File Inclusion', description: 'Remote/local file inclusion attacks' },
      { type: 'bruteforce', label: 'Brute Force', description: 'Multiple failed login attempts to same account' },
      { type: 'password_spray', label: 'Password Spray', description: 'Same password tried against multiple accounts' },
      { type: 'credential_stuffing', label: 'Credential Stuffing', description: 'Automated login with stolen credentials' },
      { type: 'port_scan', label: 'Port Scan', description: 'Network reconnaissance scanning ports' },
      { type: 'ddos', label: 'DDoS', description: 'Distributed denial of service attack' },
      { type: 'reconnaissance', label: 'Reconnaissance', description: 'Information gathering activity' },
      { type: 'privilege_escalation', label: 'Privilege Escalation', description: 'Attempts to gain elevated access' },
      { type: 'lateral_movement', label: 'Lateral Movement', description: 'Movement between systems in network' },
      { type: 'data_exfiltration', label: 'Data Exfiltration', description: 'Unauthorized data transfer out of network' },
      { type: 'c2_communication', label: 'C2 Communication', description: 'Command and control server communication' },
      { type: 'malware_activity', label: 'Malware Activity', description: 'Potential malware execution detected' },
      { type: 'insider_threat', label: 'Insider Threat', description: 'Suspicious activity from authorized user' },
      { type: 'account_takeover', label: 'Account Takeover', description: 'Unauthorized account access' },
      { type: 'mfa_bypass', label: 'MFA Bypass', description: 'Attempts to circumvent multi-factor authentication' },
      { type: 'session_hijacking', label: 'Session Hijacking', description: 'Unauthorized use of valid session tokens' },
    ]
  });
});

// Get feedback statistics
app.get('/feedback/stats', (c) => {
  return c.json({
    success: true,
    stats: {
      total_feedback: 0,
      safe_count: 0,
      unsafe_count: 0,
      attack_pattern_count: 0,
      by_attack_type: {}
    }
  });
});

// Chunked upload for large files
app.post('/parse/chunked', async (c) => {
  try {
    const json = await c.req.json();
    const { chunks, fileName, forceType } = json;
    
    if (!chunks || !Array.isArray(chunks) || chunks.length === 0) {
      return c.json({ error: 'No chunks provided', format: 'Expected: { chunks: string[], fileName?: string }' }, 400);
    }
    
    const content = chunks.join('');
    
    if (!content || content.trim().length === 0) {
      return c.json({ error: 'No log content provided after combining chunks' }, 400);
    }

    const totalSize = content.length;
    const totalChunks = chunks.length;
    
    console.log(`Processing chunked upload: ${totalChunks} chunks, ${(totalSize / (1024 * 1024)).toFixed(2)} MB`);

    // Check if combined chunks exceed limits
    if (totalSize > MAX_TEXT_SIZE * 2) {
      return c.json({
        error: 'Combined chunks too large',
        details: `Total size (${(totalSize / 1024).toFixed(1)} KB) exceeds maximum allowed size (${(MAX_TEXT_SIZE * 2 / 1024).toFixed(0)} KB)`,
        suggestion: `Reduce chunk sizes or number of chunks. Each chunk should be under ${MAX_TEXT_SIZE / 1024}KB`,
        solutions: [
          'Use smaller chunks (64-256KB each)',
          'Process multiple smaller files separately',
          'Use CLI tool: node split-log-file.js <file>'
        ],
        limits: {
          maxTotalSizeKB: (MAX_TEXT_SIZE * 2) / 1024,
          recommendedChunkSizeKB: CHUNK_SIZE / 1024
        }
      }, 413);
    }
    
    const { detectedType, entries, stats: parseStats } = autoParse(content);
    const alerts = runDetections(entries);
    const enrichedEntries = enrichEntriesWithAttacks(entries);
    const detectedAttacks = detectAttacksInEntries(enrichedEntries);
    
    // Run ML-based feature extraction and classification
    const mlPredictions = detectMLAttacks(entries);
    
    // Add ML predictions to entries
    if (mlPredictions.length > 0) {
      const matchingPrediction = mlPredictions.find(p => 
        p.attackType !== 'safe' && 
        p.attackType !== 'anomaly' &&
        p.confidence >= 0.3
      );
      
      // Calculate average confidence
      const avgConfidence = mlPredictions.reduce((sum, p) => sum + p.confidence, 0) / mlPredictions.length;
      
      if (matchingPrediction) {
        for (const entry of enrichedEntries) {
          if (!entry.attackType) {
            entry.attackType = matchingPrediction.attackType;
            entry.attackConfidence = matchingPrediction.confidence;
            entry.mitreTactics = matchingPrediction.features ? getMitreTacticsForAttack(matchingPrediction.attackType) : undefined;
            entry.mitreTechniques = matchingPrediction.features ? getMitreTechniquesForAttack(matchingPrediction.attackType) : undefined;
          } else if (!entry.attackConfidence) {
            entry.attackConfidence = matchingPrediction.confidence;
          }
        }
      } else {
        // No attack detected - set normal with confidence
        for (const entry of enrichedEntries) {
          if (!entry.attackConfidence) {
            entry.attackConfidence = avgConfidence;
          }
          if (!entry.attackType) {
            entry.attackType = 'safe';
          }
        }
      }
    }
    
    const attackTypes = [...new Set(detectedAttacks.map(a => a.attack.attackType))];
    const mlAttackTypes = [...new Set(mlPredictions.map(p => p.attackType))];
    const allAttackTypes = [...new Set([...attackTypes, ...mlAttackTypes])];
    const attackSummary = {
      totalAttacks: detectedAttacks.length + mlPredictions.length,
      attackTypes: allAttackTypes,
      uniqueSources: new Set(entries.map(e => e.source.ip).filter(Boolean)).size,
      riskScore: Math.min(Math.max(detectedAttacks.length, mlPredictions.length) * 10, 100),
    };
    
    const stats = generateStats(entries);

    return c.json({
      success: true,
      detectedType: forceType || detectedType,
      totalLines: parseStats.totalLines,
      parsedLines: parseStats.parsedLines,
      failedLines: parseStats.failedLines,
      successRate: parseStats.successRate,
      totalEvents: parseStats.totalEvents,
      parsedEvents: parseStats.parsedEvents,
      failedEvents: parseStats.failedEvents,
      entries: enrichedEntries,
      alerts,
      stats,
      mlAttacks: detectedAttacks,
      mlPredictions,
      attackSummary,
      fileName,
      chunkInfo: {
        totalChunks,
        chunkSizeMB: (totalSize / chunks.length / (1024 * 1024)).toFixed(2)
      }
    });
  } catch (error) {
    console.error('Chunked parse error:', error);
    const errorMsg = String(error);
    const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('CPU') || errorMsg.includes('execution');
    
    return c.json({ 
      success: false,
      error: isTimeout ? 'Processing timeout - file too large' : 'Failed to parse logs',
      details: errorMsg,
      suggestion: isTimeout ? 'Split the file into smaller chunks and try again' : undefined,
      format: 'Expected: { chunks: string[], fileName?: string, forceType?: string }'
    }, isTimeout ? 413 : 500);
  }
});

// Streaming parse for very large files - processes line by line with partial results
app.post('/parse/stream', async (c) => {
  try {
    const json = await c.req.json();
    const { lines, batchSize = 1000, fileName } = json;
    
    if (!lines || !Array.isArray(lines) || lines.length === 0) {
      return c.json({ error: 'No lines provided', format: 'Expected: { lines: string[], batchSize?: number, fileName?: string }' }, 400);
    }

    const totalLines = lines.length;
    const batches = Math.ceil(totalLines / batchSize);
    
    console.log(`Streaming parse: ${totalLines} lines in ${batches} batches of ${batchSize}`);

    const allEntries: ParsedLogEntry[] = [];
    const allAlerts: any[] = [];
    let totalParsed = 0;
    let totalFailed = 0;
    let detectedType = 'unknown';

    // Process in batches to avoid memory issues
    for (let i = 0; i < batches; i++) {
      const start = i * batchSize;
      const end = Math.min(start + batchSize, totalLines);
      const batch = lines.slice(start, end);
      
      const batchContent = batch.join('\n');
      const result = autoParse(batchContent);
      
      if (i === 0) {
        detectedType = result.detectedType;
      }
      
      allEntries.push(...result.entries);
      const batchAlerts = runDetections(result.entries);
      allAlerts.push(...batchAlerts);
      
      totalParsed += result.stats.parsedLines || result.entries.length;
      totalFailed += result.stats.failedLines || 0;
    }

    // Run ML detection on all entries
    const enrichedEntries = enrichEntriesWithAttacks(allEntries);
    const detectedAttacks = detectAttacksInEntries(enrichedEntries);
    const mlPredictions = detectMLAttacks(allEntries);
    
    const attackTypes = [...new Set(detectedAttacks.map(a => a.attack.attackType))];
    const attackSummary = {
      totalAttacks: detectedAttacks.length + mlPredictions.length,
      attackTypes,
      uniqueSources: new Set(allEntries.map(e => e.source.ip).filter(Boolean)).size,
      riskScore: Math.min(detectedAttacks.length * 10, 100),
    };

    const stats = generateStats(allEntries);

    return c.json({
      success: true,
      detectedType,
      totalLines,
      parsedLines: totalParsed,
      failedLines: totalFailed,
      entries: enrichedEntries,
      alerts: allAlerts,
      stats,
      mlAttacks: detectedAttacks,
      mlPredictions,
      attackSummary,
      fileName,
      streamInfo: {
        totalLines,
        batchSize,
        totalBatches: batches,
        processedBatches: batches
      }
    });
  } catch (error) {
    console.error('Stream parse error:', error);
    const errorMsg = String(error);
    const isTimeout = errorMsg.includes('timeout') || errorMsg.includes('CPU') || errorMsg.includes('execution');
    
    return c.json({ 
      success: false,
      error: isTimeout ? 'Processing timeout - reduce batch size' : 'Failed to parse stream',
      details: errorMsg,
      suggestion: isTimeout ? 'Reduce the batchSize parameter (try 500 instead of 1000)' : undefined,
      format: 'Expected: { lines: string[], batchSize?: number, fileName?: string }'
    }, isTimeout ? 413 : 500);
  }
});

// Get processing limits and recommendations
app.get('/limits', (c) => {
  return c.json({
    limits: {
      maxTextSizeBytes: MAX_TEXT_SIZE,
      maxTextSizeMB: MAX_TEXT_SIZE / 1024 / 1024,
      maxBinarySizeBytes: MAX_BINARY_SIZE,
      maxBinarySizeMB: MAX_BINARY_SIZE / 1024 / 1024,
      autoSplitThreshold: 'Files > 1MB are automatically split',
      autoSplitChunkSizeMB: CHUNK_SIZE / 1024 / 1024
    },
    autoSplit: {
      enabled: true,
      description: 'Files exceeding 1MB are automatically split into 1MB chunks',
      format: 'Line-based splitting preserves log entries',
      response: {
        status: 'auto_split',
        chunks: 'Array of chunk metadata with content previews',
        downloadScript: 'Node.js script to save all chunks locally',
        usage: 'Upload chunks individually or send array to /parse/chunked'
      }
    },
    cloudflareLimits: {
      freeTierCPUMs: 10,
      paidTierCPUMs: 50,
      note: 'Worker terminates immediately when CPU limit reached'
    },
    endpoints: {
      parse: 'POST /parse - Auto-splits files > 1MB, processes smaller files directly',
      chunked: 'POST /parse/chunked - Process pre-split chunks',
      stream: 'POST /parse/stream - Line-by-line processing for very large files',
      limits: 'GET /limits - This endpoint'
    }
  });
});

// Export for Cloudflare Workers
export default app;
