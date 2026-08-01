import { SyslogVendorParser, VendorParseResult } from './syslogVendorParser.js';
import { ParsedSyslogRfc } from './syslogRfcParser.js';

export class CiscoSyslogParser implements SyslogVendorParser {
  public name = 'Cisco ASA & IOS Syslog Parser';
  public vendor = 'Cisco';
  public product = 'ASA/IOS';

  public canParse(header: ParsedSyslogRfc, raw: string): boolean {
    return (
      raw.includes('%ASA-') ||
      raw.includes('%IOS-') ||
      raw.includes('%LINK-') ||
      raw.includes('%PIX-') ||
      header.appName.startsWith('%')
    );
  }

  public parse(header: ParsedSyslogRfc, raw: string): VendorParseResult {
    const textToMatch = `${header.appName}: ${header.message} ${raw}`;
    const asaMatch = textToMatch.match(/%(ASA|IOS|PIX)-(\d)-(\d+):\s*(.*)/i);

    const result: VendorParseResult = {
      vendor: 'Cisco',
      product: 'ASA Firewall',
      eventType: 'FIREWALL_EVENT',
      category: 'Network',
      severity: header.severity,
      host: header.hostname,
      normalizedFields: {},
      tags: ['cisco', 'firewall'],
    };

    if (asaMatch) {
      const [, devType, severityNum, messageId, messageText] = asaMatch;
      result.product = devType === 'ASA' ? 'Cisco ASA' : 'Cisco IOS';
      result.eventType = `CISCO_${devType}_${messageId}`;

      // Parse ASA-6-302013 / 302014 (Built/Teardown connection)
      if (messageId === '302013' || messageId === '302014' || messageId === '302015') {
        const connMatch = messageText.match(/(Built|Teardown)\s+(\S+)?\s*(\S+)\s+connection\s+\d+\s+for\s+(\S+):(\S+)\/(\d+)/i);
        if (connMatch) {
          result.normalizedFields = {
            action: connMatch[1],
            direction: connMatch[2] || 'outbound',
            protocol: connMatch[3],
            srcInterface: connMatch[4],
            srcIp: connMatch[5],
            srcPort: parseInt(connMatch[6], 10),
          };
          result.ip = connMatch[5];
        }

        // Try extracting destination IP & Port
        const dstMatch = messageText.match(/to\s+(\S+):(\S+)\/(\d+)/i);
        if (dstMatch) {
          result.normalizedFields.dstInterface = dstMatch[1];
          result.normalizedFields.dstIp = dstMatch[2];
          result.normalizedFields.dstPort = parseInt(dstMatch[3], 10);
        }
      }
      // Parse ASA-1-105001 (Host unreachable / Attack)
      else if (messageId === '105001') {
        result.severity = 'Critical';
        result.category = 'Threat';
        result.tags.push('attack', 'denial-of-service');
      }
    }

    return result;
  }
}
