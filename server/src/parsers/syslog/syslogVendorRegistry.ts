import { SyslogVendorParser, VendorParseResult } from './syslogVendorParser.js';
import { ParsedSyslogRfc } from './syslogRfcParser.js';
import { LinuxSyslogParser } from './linuxParser.js';
import { CiscoSyslogParser } from './ciscoParser.js';
import { PaloAltoPanOsParser } from './paloAltoParser.js';
import { FortinetFortiGateParser } from './fortinetParser.js';

export class SyslogVendorRegistry {
  private parsers: SyslogVendorParser[] = [];

  constructor() {
    // Register built-in vendor parsers
    this.registerParser(new LinuxSyslogParser());
    this.registerParser(new CiscoSyslogParser());
    this.registerParser(new PaloAltoPanOsParser());
    this.registerParser(new FortinetFortiGateParser());
  }

  public registerParser(parser: SyslogVendorParser): void {
    this.parsers.push(parser);
  }

  public parse(header: ParsedSyslogRfc, raw: string): VendorParseResult {
    // Try vendor parsers in order
    for (const parser of this.parsers) {
      try {
        if (parser.canParse(header, raw)) {
          return parser.parse(header, raw);
        }
      } catch {
        // Fall to next parser if exception occurs
      }
    }

    // Generic Fallback Parser
    return {
      vendor: 'Generic',
      product: header.appName || 'syslog',
      eventType: 'SYSLOG_EVENT',
      category: 'System',
      severity: header.severity,
      host: header.hostname,
      normalizedFields: {
        facility: header.facility,
        procId: header.procId,
        message: header.message,
      },
      tags: ['syslog', 'generic'],
    };
  }

  public getRegisteredVendorNames(): string[] {
    return this.parsers.map((p) => p.name);
  }
}
