import assert from 'assert';
import { test, describe } from 'node:test';
import { parseSyslogHeader } from '../parsers/syslog/syslogRfcParser.js';
import { SyslogVendorRegistry } from '../parsers/syslog/syslogVendorRegistry.js';
import { parseWindowsEventXml } from '../parsers/wef/wefXmlParser.js';
import { decodeNetflowBuffer } from '../parsers/netflow/netflowDecoder.js';
import { InMemoryMessageQueue } from '../queue/inMemoryQueue.js';
import { sanitizeRawLog, maskSensitivePii } from '../security/sanitize.js';
describe('Live Telemetry Data Collection Suite', () => {
    describe('1. Syslog RFC 3164 & 5424 Header Parser', () => {
        test('Should parse RFC 3164 BSD Syslog Header', () => {
            const raw = '<134>Jul 31 18:00:00 firewall1 sshd[4012]: Failed password for root from 192.168.1.50 port 54321';
            const parsed = parseSyslogHeader(raw);
            assert.strictEqual(parsed.pri, 134);
            assert.strictEqual(parsed.facility, 'local0');
            assert.strictEqual(parsed.severity, 'Info');
            assert.strictEqual(parsed.hostname, 'firewall1');
            assert.strictEqual(parsed.appName, 'sshd');
            assert.strictEqual(parsed.procId, '4012');
        });
        test('Should parse RFC 5424 Structured Syslog Header', () => {
            const raw = '<165>1 2026-08-01T00:00:00.000Z host-01 pan-os 1280 - [pan@1280 type="TRAFFIC"] 1,2026/08/01,10.0.0.5,8.8.8.8';
            const parsed = parseSyslogHeader(raw);
            assert.strictEqual(parsed.pri, 165);
            assert.strictEqual(parsed.isRfc5424, true);
            assert.strictEqual(parsed.hostname, 'host-01');
            assert.strictEqual(parsed.appName, 'pan-os');
            assert.strictEqual(parsed.procId, '1280');
        });
    });
    describe('2. Modular Syslog Vendor Parsers', () => {
        const registry = new SyslogVendorRegistry();
        test('Linux SSHD Authentication Failure Parser', () => {
            const raw = '<86>Aug 01 02:00:00 server01 sshd[1234]: Failed password for invalid user admin from 10.0.0.99 port 41234';
            const header = parseSyslogHeader(raw);
            const result = registry.parse(header, raw);
            assert.strictEqual(result.vendor, 'Linux');
            assert.strictEqual(result.eventType, 'SSH_AUTHENTICATION_FAILURE');
            assert.strictEqual(result.severity, 'High');
            assert.strictEqual(result.normalizedFields.targetUser, 'admin');
            assert.strictEqual(result.normalizedFields.sourceIp, '10.0.0.99');
        });
        test('Cisco ASA Firewall Connection Parser', () => {
            const raw = '<134>Aug 01 02:00:00 asa01 %ASA-6-302013: Built outbound TCP connection 987654 for outside:1.1.1.1/443 (1.1.1.1/443) to inside:192.168.1.10/50000';
            const header = parseSyslogHeader(raw);
            const result = registry.parse(header, raw);
            assert.strictEqual(result.vendor, 'Cisco');
            assert.strictEqual(result.eventType, 'CISCO_ASA_302013');
            assert.strictEqual(result.normalizedFields.action, 'Built');
            assert.strictEqual(result.normalizedFields.srcIp, '1.1.1.1');
            assert.strictEqual(result.normalizedFields.dstIp, '192.168.1.10');
        });
        test('Fortinet FortiGate Key-Value Parser', () => {
            const raw = '<13>date=2026-08-01 time=00:00:00 devname="FG-100D" type=traffic subtype=forward srcip=192.168.1.5 dstip=8.8.8.8 srcport=54321 dstport=53 action=allow';
            const header = parseSyslogHeader(raw);
            const result = registry.parse(header, raw);
            assert.strictEqual(result.vendor, 'Fortinet');
            assert.strictEqual(result.eventType, 'FORTIGATE_FORWARD');
            assert.strictEqual(result.host, 'FG-100D');
            assert.strictEqual(result.normalizedFields.sourceIp, '192.168.1.5');
            assert.strictEqual(result.normalizedFields.destinationIp, '8.8.8.8');
        });
    });
    describe('3. Windows Event Forwarding (WEF) XML Normalizer', () => {
        test('Should parse Security Event ID 4625 (Logon Failure)', () => {
            const xml = `
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4625</EventID>
            <Level>0</Level>
            <Task>12544</Task>
            <Channel>Security</Channel>
            <Computer>DC-01.corp.internal</Computer>
            <TimeCreated SystemTime="2026-08-01T00:00:00.000Z"/>
          </System>
          <EventData>
            <Data Name="TargetUserName">Administrator</Data>
            <Data Name="IpAddress">192.168.1.200</Data>
          </EventData>
        </Event>
      `;
            const parsed = parseWindowsEventXml(xml);
            assert.strictEqual(parsed.eventId, '4625');
            assert.strictEqual(parsed.computer, 'DC-01.corp.internal');
            assert.strictEqual(parsed.severity, 'High');
            assert.strictEqual(parsed.eventType, 'WINDOWS_LOGON_FAILURE');
            assert.strictEqual(parsed.eventData.TargetUserName, 'Administrator');
            assert.strictEqual(parsed.eventData.IpAddress, '192.168.1.200');
        });
    });
    describe('4. NetFlow v5 Binary Frame Decoder', () => {
        test('Should decode 24-byte header and 48-byte NetFlow v5 record', () => {
            const buf = Buffer.alloc(24 + 48);
            // Write Header (Version 5, Count 1)
            buf.writeUInt16BE(5, 0); // Version 5
            buf.writeUInt16BE(1, 2); // Count 1
            buf.writeUInt32BE(10000, 4); // SysUptime
            buf.writeUInt32BE(17000000, 8); // UnixSecs
            buf.writeUInt32BE(1, 16); // Sequence Number
            // Write Record 1 (Offset 24)
            buf.writeUInt8(10, 24);
            buf.writeUInt8(0, 25);
            buf.writeUInt8(0, 26);
            buf.writeUInt8(5, 27); // Src 10.0.0.5
            buf.writeUInt8(8, 28);
            buf.writeUInt8(8, 29);
            buf.writeUInt8(8, 30);
            buf.writeUInt8(8, 31); // Dst 8.8.8.8
            buf.writeUInt32BE(10, 40); // Packets 10
            buf.writeUInt32BE(1500, 44); // Bytes 1500
            buf.writeUInt16BE(54321, 56); // SrcPort 54321
            buf.writeUInt16BE(53, 58); // DstPort 53
            buf.writeUInt8(17, 62); // Protocol 17 (UDP)
            const records = decodeNetflowBuffer(buf, '192.168.1.1');
            assert.strictEqual(records.length, 1);
            assert.strictEqual(records[0].version, 5);
            assert.strictEqual(records[0].sourceIp, '10.0.0.5');
            assert.strictEqual(records[0].destinationIp, '8.8.8.8');
            assert.strictEqual(records[0].bytes, 1500);
            assert.strictEqual(records[0].protocol, 'UDP');
        });
    });
    describe('5. Message Queue Abstraction & Backpressure Watermarks', () => {
        test('Should enqueue and consume messages with watermark tracking', async () => {
            const queue = new InMemoryMessageQueue(10);
            const received = [];
            queue.subscribe('telemetry.test', async (msg) => {
                received.push(msg.payload);
            });
            const published = await queue.publish('telemetry.test', { data: 'sample-event', severity: 'High' });
            assert.strictEqual(published, true);
            // Wait for async loop
            await new Promise((res) => setTimeout(res, 50));
            assert.strictEqual(received.length, 1);
            assert.strictEqual(received[0].data, 'sample-event');
            const metrics = queue.getMetrics();
            assert.strictEqual(metrics.publishedCount, 1);
            assert.strictEqual(metrics.consumedCount, 1);
        });
    });
    describe('6. Security & Data Hygiene', () => {
        test('Should strip CRLF characters to prevent Log Injection', () => {
            const malicious = 'User login\r\n[SYSTEM ALERT] Admin password changed!';
            const sanitized = sanitizeRawLog(malicious);
            assert.strictEqual(sanitized.includes('\r'), false);
            assert.strictEqual(sanitized.includes('\n'), false);
            assert.strictEqual(sanitized, 'User login \\n [SYSTEM ALERT] Admin password changed!');
        });
        test('Should mask sensitive credentials and bearer tokens', () => {
            const logWithPass = 'POST /login password=SuperSecretPassword123 & token=Bearer eyJhbGciOi...';
            const { maskedText, hasPiiMasked } = maskSensitivePii(logWithPass);
            assert.strictEqual(hasPiiMasked, true);
            assert.strictEqual(maskedText.includes('SuperSecretPassword123'), false);
            assert.strictEqual(maskedText.includes('[MASKED_CREDENTIAL]'), true);
        });
    });
});
