import { ParsedSyslogRfc } from './syslogRfcParser.js';
import { EventSeverity, CollectorType } from '../../collectors/collectorTypes.js';

export interface VendorParseResult {
  vendor: string;
  product: string;
  eventType: string;
  category: string;
  severity?: EventSeverity;
  host?: string;
  ip?: string;
  normalizedFields: Record<string, any>;
  tags: string[];
}

export interface SyslogVendorParser {
  name: string;
  vendor: string;
  product: string;
  canParse(header: ParsedSyslogRfc, raw: string): boolean;
  parse(header: ParsedSyslogRfc, raw: string): VendorParseResult;
}
