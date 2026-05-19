// EVTX Parser - Parses Windows Event Log files (.evtx)
// Supports basic event record extraction from binary EVTX format

import { ParsedLogEntry, LogType } from '../types';
import { generateId } from '../utils/helpers';

export class EVTXParser {
  private static readonly EVTX_SIGNATURE = 0x46566C45; // 'ElfF' in little endian
  private static readonly CHUNK_SIGNATURE = 0x6B636E45; // 'ElfChnk' in little endian
  
  static canParse(content: ArrayBuffer): boolean {
    const view = new DataView(content);
    const signature = view.getUint32(0, true);
    return signature === this.EVTX_SIGNATURE;
  }

  static parse(content: ArrayBuffer): ParsedLogEntry[] {
    const entries: ParsedLogEntry[] = [];
    
    try {
      const view = new DataView(content);
      const totalSize = content.byteLength;
      
      // Check signature
      const signature = view.getUint32(0, true);
      console.log('EVTX: Signature 0x' + signature.toString(16).toUpperCase());
      
      if (signature !== this.EVTX_SIGNATURE) {
        console.log('EVTX: Invalid signature, trying XML format');
        return this.parseXmlFormat(content);
      }
      
      // Parse chunks starting at offset 128
      let offset = 128;
      let chunkNum = 0;
      
      while (offset + 512 <= totalSize) {
        chunkNum++;
        const chunkEntries = this.parseChunk(content, offset, chunkNum, totalSize);
        entries.push(...chunkEntries);
        offset += 4096;
      }
      
      console.log('EVTX: Parsed', entries.length, 'entries from', chunkNum, 'chunks');
      
    } catch (error) {
      console.error('EVTX parse error:', error);
    }
    
    return entries;
  }
  
  private static parseChunk(content: ArrayBuffer, chunkOffset: number, chunkNum: number, totalSize: number): ParsedLogEntry[] {
    const entries: ParsedLogEntry[] = [];
    const view = new DataView(content);
    
    let recordOffset = chunkOffset + 512;
    let recordNum = 0;
    
    while (recordOffset + 24 <= Math.min(chunkOffset + 4096, totalSize)) {
      const recordSize = view.getUint32(recordOffset, true);
      
      if (recordSize < 24 || recordSize > 65536) {
        recordOffset += 4;
        continue;
      }
      
      const magic = view.getUint32(recordOffset + 4, true);
      if (magic !== 0x0000002A) {
        recordOffset += 4;
        continue;
      }
      
      const recordId = view.getUint32(recordOffset + 8, true);
      
      // Parse timestamp
      let timestamp: string;
      try {
        const timestampBin = view.getBigUint64(recordOffset + 16, true);
        timestamp = this.parseTimestamp(timestampBin);
      } catch {
        timestamp = new Date().toISOString();
      }
      
      // Extract XML data
      let xmlData = '';
      try {
        const dataOffset = recordOffset + 24;
        if (dataOffset < recordOffset + recordSize) {
          const dataLength = Math.min(recordOffset + recordSize - dataOffset, 65536);
          const data = new Uint8Array(content, dataOffset, dataLength);
          xmlData = this.extractXmlContent(data);
        }
      } catch {
        xmlData = '';
      }
      
      const eventInfo = this.parseEventXml(xmlData, recordId, timestamp);
      const severity = this.getSeverity(eventInfo.level);
      const action = this.getAction(eventInfo.eventId, eventInfo.channel);
      
      const entry: ParsedLogEntry = {
        id: generateId(),
        timestamp: eventInfo.timestamp || timestamp,
        logType: 'windows_event' as LogType,
        severity,
        source: {
          hostname: eventInfo.computer,
          service: eventInfo.channel || 'Unknown',
          ip: eventInfo.ipAddress || undefined
        },
        action,
        outcome: eventInfo.status === 'failure' ? 'failure' : 'success',
        message: eventInfo.message || xmlData.substring(0, 500),
        rawLine: xmlData,
        fields: {
          record_id: recordId,
          event_id: eventInfo.eventId,
          channel: eventInfo.channel,
          level: eventInfo.level,
          provider: eventInfo.provider,
          chunk_num: chunkNum,
          record_num: recordNum,
          ip_address: eventInfo.ipAddress || null
        },
        tags: ['windows', 'evtx', eventInfo.channel?.toLowerCase() || 'event', severity]
      };
      
      entries.push(entry);
      recordNum++;
      recordOffset += recordSize;
    }
    
    return entries;
  }
  
  private static parseXmlFormat(content: ArrayBuffer): ParsedLogEntry[] {
    const entries: ParsedLogEntry[] = [];
    
    try {
      const decoder = new TextDecoder('utf-8');
      const text = decoder.decode(content);
      
      if (text.includes('<Event') && text.includes('</Event>')) {
        const eventRegex = /<Event[^>]*>([\s\S]*?)<\/Event>/g;
        let match;
        let count = 0;
        
        while ((match = eventRegex.exec(text)) !== null && count < 10000) {
          const entry = this.parseEventFromXml(match[0], count);
          if (entry) {
            entries.push(entry);
          }
          count++;
        }
        
        console.log('EVTX XML: Extracted', entries.length, 'events');
      }
    } catch (error) {
      console.error('EVTX XML parse error:', error);
    }
    
    return entries;
  }
  
  private static parseEventFromXml(xml: string, index: number): ParsedLogEntry | null {
    try {
      const eventIdMatch = xml.match(/<EventID[^>]*>(\d+)<\/EventID>/);
      const channelMatch = xml.match(/<Channel>([^<]+)<\/Channel>/);
      const levelMatch = xml.match(/<Level>([^<]+)<\/Level>/);
      const computerMatch = xml.match(/<Computer>([^<]+)<\/Computer>/);
      const timeMatch = xml.match(/<TimeCreated[^>]*SystemTime="([^"]+)"/);
      const providerMatch = xml.match(/<Provider Name="([^"]+)"[^>]*>/);
      const messageMatch = xml.match(/<Message>([^<]+)<\/Message>/);
      const ipMatch = xml.match(/<Data[^>]*Name="IpAddress"[^>]*>([^<]+)<\/Data>/i) 
                   || xml.match(/<IpAddress>([^<]+)<\/IpAddress>/i);
      const ipAddress = ipMatch ? ipMatch[1] : undefined;
      
      return {
        id: generateId(),
        timestamp: timeMatch?.[1] || new Date().toISOString(),
        logType: 'windows_event' as LogType,
        severity: this.getSeverity(levelMatch?.[1] || 'info'),
        source: {
          hostname: computerMatch?.[1],
          service: channelMatch?.[1] || 'Unknown',
          ip: ipAddress
        },
        action: this.getAction(eventIdMatch ? parseInt(eventIdMatch[1]) : 0, channelMatch?.[1]),
        outcome: 'success',
        message: messageMatch?.[1] || xml.substring(0, 500),
        rawLine: xml,
        fields: {
          event_id: eventIdMatch ? parseInt(eventIdMatch[1]) : 0,
          channel: channelMatch?.[1],
          level: levelMatch?.[1],
          provider: providerMatch?.[1],
          ip_address: ipAddress || null
        },
        tags: ['windows', 'xml', channelMatch?.[1]?.toLowerCase() || 'event']
      };
    } catch {
      return null;
    }
  }
  
  private static parseTimestamp(winTicks: bigint): string {
    try {
      const ticksPerSecond = BigInt(10000000);
      const epochOffset = BigInt(116444736000000000);
      const secondsSince1970 = (winTicks - epochOffset) / ticksPerSecond;
      return new Date(Number(secondsSince1970) * 1000).toISOString();
    } catch {
      return new Date().toISOString();
    }
  }
  
  private static extractXmlContent(data: Uint8Array): string {
    try {
      let text: string;
      if (data.length >= 2 && data[1] === 0) {
        const decoder = new TextDecoder('utf-16le');
        text = decoder.decode(data);
      } else {
        const decoder = new TextDecoder('utf-8');
        text = decoder.decode(data);
      }
      return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').trim();
    } catch {
      return '';
    }
  }
  
  private static parseEventXml(xml: string, recordId: number, fallbackTimestamp: string) {
    const result = {
      timestamp: fallbackTimestamp,
      eventId: 0,
      channel: '',
      level: 'info',
      provider: '',
      computer: '',
      message: '',
      status: 'success',
      ipAddress: ''
    };
    
    try {
      const eventIdMatch = xml.match(/<EventID[^>]*>(\d+)<\/EventID>/);
      if (eventIdMatch) result.eventId = parseInt(eventIdMatch[1]);
      
      const channelMatch = xml.match(/<Channel>([^<]+)<\/Channel>/);
      if (channelMatch) result.channel = channelMatch[1];
      
      const levelMatch = xml.match(/<Level>([^<]+)<\/Level>/);
      if (levelMatch) result.level = levelMatch[1].toLowerCase();
      
      const providerMatch = xml.match(/<Provider Name="([^"]+)"[^>]*>/);
      if (providerMatch) result.provider = providerMatch[1];
      
      const computerMatch = xml.match(/<Computer>([^<]+)<\/Computer>/);
      if (computerMatch) result.computer = computerMatch[1];
      
      const messageMatch = xml.match(/<Message>([^<]+)<\/Message>/);
      if (messageMatch) result.message = messageMatch[1];
      
      const timeMatch = xml.match(/<TimeCreated[^>]*SystemTime="([^"]+)"/);
      if (timeMatch) result.timestamp = timeMatch[1];
      
      const ipMatch = xml.match(/<Data[^>]*Name="IpAddress"[^>]*>([^<]+)<\/Data>/i) 
                   || xml.match(/<IpAddress>([^<]+)<\/IpAddress>/i)
                   || xml.match(/<Data[^>]*>([\d.]+)<\/Data>/);
      if (ipMatch) result.ipAddress = ipMatch[1];
      
      result.status = this.getEventStatus(result.eventId);
    } catch {}
    
    return result;
  }
  
  private static getSeverity(level: string): 'debug' | 'info' | 'warning' | 'error' | 'critical' {
    const lvl = level.toLowerCase();
    if (lvl === 'critical' || lvl === '1') return 'critical';
    if (lvl === 'error' || lvl === '2') return 'error';
    if (lvl === 'warning' || lvl === '3') return 'warning';
    if (lvl === 'info' || lvl === '4') return 'info';
    return 'info';
  }
  
  private static getAction(eventId: number, channel?: string): string {
    const events: Record<number, string> = {
      4624: 'logon_success', 4625: 'logon_failure', 4634: 'logoff',
      4648: 'explicit_logon', 4672: 'admin_logon', 4688: 'process_create',
      4689: 'process_exit', 4696: 'token_duplicate', 4720: 'user_created',
      4722: 'user_enabled', 4723: 'password_change', 4724: 'password_reset',
      4725: 'user_disabled', 4726: 'user_deleted', 4738: 'user_changed',
      4740: 'account_locked', 4767: 'account_unlocked', 4768: 'tgt_request',
      4769: 'tgs_request', 4771: 'preauth_failure', 4776: 'cred_validate',
    };
    if (channel?.toLowerCase().includes('security') && events[eventId]) {
      return events[eventId];
    }
    return 'event';
  }
  
  private static getEventStatus(eventId: number): string {
    const failureEvents = [4625, 4648, 4767, 4771, 4776];
    return failureEvents.includes(eventId) ? 'failure' : 'success';
  }
}

export class EVTXDetector {
  static isEVTXFile(filename: string): boolean {
    return filename.toLowerCase().endsWith('.evtx');
  }
  
  static isEVTX(content: string | ArrayBuffer, filename?: string): boolean {
    if (filename && this.isEVTXFile(filename)) return true;
    if (content instanceof ArrayBuffer) {
      const view = new DataView(content);
      return view.getUint32(0, true) === 0x46566C45;
    }
    if (typeof content === 'string') {
      return content.includes('<Event') && content.includes('<System>');
    }
    return false;
  }
}
