export class PaloAltoPanOsParser {
    name = 'Palo Alto PAN-OS CSV Syslog Parser';
    vendor = 'Palo Alto Networks';
    product = 'PAN-OS';
    canParse(header, raw) {
        return (raw.includes('1,202') ||
            raw.includes('TRAFFIC,') ||
            raw.includes('THREAT,') ||
            raw.includes('SYSTEM,') ||
            header.appName.toLowerCase().includes('pan'));
    }
    parse(header, raw) {
        const fields = header.message.split(',');
        const result = {
            vendor: 'Palo Alto Networks',
            product: 'PAN-OS Next-Gen Firewall',
            eventType: fields[3] ? `PAN_OS_${fields[3]}` : 'PAN_OS_LOG',
            category: 'Network',
            severity: header.severity,
            host: header.hostname,
            normalizedFields: {},
            tags: ['palo-alto', 'pan-os', 'firewall'],
        };
        // PAN-OS Traffic CSV layout: Domain, ReceiveTime, Serial, Type, Subtype, ...
        if (fields.length >= 10) {
            const logType = fields[3]; // TRAFFIC, THREAT, SYSTEM
            const srcIp = fields[7];
            const dstIp = fields[8];
            const srcPort = parseInt(fields[24] || '0', 10);
            const dstPort = parseInt(fields[25] || '0', 10);
            const action = fields[29] || 'allow';
            const app = fields[14] || 'any';
            result.category = logType === 'THREAT' ? 'Threat' : 'Network';
            if (logType === 'THREAT')
                result.severity = 'High';
            result.ip = srcIp;
            result.normalizedFields = {
                logType,
                sourceIp: srcIp,
                destinationIp: dstIp,
                sourcePort: srcPort,
                destinationPort: dstPort,
                action,
                application: app,
            };
        }
        return result;
    }
}
