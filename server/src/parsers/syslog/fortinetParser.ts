import { SyslogVendorParser, VendorParseResult } from './syslogVendorParser.js';
import { ParsedSyslogRfc } from './syslogRfcParser.js';

export class FortinetFortiGateParser implements SyslogVendorParser {
  public name = 'Fortinet FortiGate Key-Value Parser';
  public vendor = 'Fortinet';
  public product = 'FortiGate';

  public canParse(header: ParsedSyslogRfc, raw: string): boolean {
    return (
      raw.includes('devname=') ||
      raw.includes('devid=') ||
      raw.includes('type=traffic') ||
      raw.includes('type=utm')
    );
  }

  public parse(header: ParsedSyslogRfc, raw: string): VendorParseResult {
    const kvMap: Record<string, string> = {};
    const kvRegex = /(\w+)=(?:"([^"]*)"|(\S+))/g;

    let match: RegExpExecArray | null;
    while ((match = kvRegex.exec(header.message)) !== null) {
      kvMap[match[1]] = match[2] !== undefined ? match[2] : match[3];
    }

    const result: VendorParseResult = {
      vendor: 'Fortinet',
      product: 'FortiGate NGFW',
      eventType: kvMap.subtype ? `FORTIGATE_${kvMap.subtype.toUpperCase()}` : 'FORTIGATE_LOG',
      category: kvMap.type === 'utm' ? 'Threat' : 'Network',
      severity: header.severity,
      host: kvMap.devname || header.hostname,
      ip: kvMap.srcip,
      normalizedFields: {
        deviceType: kvMap.devtype || 'FortiGate',
        action: kvMap.action || 'unknown',
        sourceIp: kvMap.srcip,
        sourcePort: kvMap.srcport ? parseInt(kvMap.srcport, 10) : undefined,
        destinationIp: kvMap.dstip,
        destinationPort: kvMap.dstport ? parseInt(kvMap.dstport, 10) : undefined,
        policyId: kvMap.policyid,
        service: kvMap.service,
        url: kvMap.url,
      },
      tags: ['fortinet', 'fortigate', 'firewall'],
    };

    return result;
  }
}
