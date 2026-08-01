export class LinuxSyslogParser {
    name = 'Linux Syslog & Auditd Parser';
    vendor = 'Linux';
    product = 'OS/Auditd';
    canParse(header, raw) {
        const app = header.appName.toLowerCase();
        return (app.includes('sshd') ||
            app.includes('sudo') ||
            app.includes('auditd') ||
            app.includes('su') ||
            app.includes('systemd') ||
            header.facility === 'auth' ||
            header.facility === 'authpriv');
    }
    parse(header, raw) {
        const msg = header.message;
        const app = header.appName.toLowerCase();
        const result = {
            vendor: 'Linux',
            product: app || 'systemd',
            eventType: 'SYSTEM_EVENT',
            category: 'System',
            severity: header.severity,
            host: header.hostname,
            normalizedFields: {},
            tags: ['linux', app],
        };
        // 1. SSHD Failed Password
        if (msg.includes('Failed password')) {
            const match = msg.match(/Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)/i);
            result.eventType = 'SSH_AUTHENTICATION_FAILURE';
            result.category = 'Identity';
            result.severity = 'High';
            if (match) {
                result.normalizedFields = {
                    targetUser: match[1],
                    sourceIp: match[2],
                    sourcePort: parseInt(match[3], 10),
                    authMethod: 'password',
                };
                result.ip = match[2];
            }
            result.tags.push('ssh', 'auth-failure', 'brute-force');
        }
        // 2. SSHD Accepted Password / Key
        else if (msg.includes('Accepted password') || msg.includes('Accepted publickey')) {
            const match = msg.match(/Accepted (\S+) for (\S+) from (\S+) port (\d+)/i);
            result.eventType = 'SSH_AUTHENTICATION_SUCCESS';
            result.category = 'Identity';
            result.severity = 'Info';
            if (match) {
                result.normalizedFields = {
                    authMethod: match[1],
                    targetUser: match[2],
                    sourceIp: match[3],
                    sourcePort: parseInt(match[4], 10),
                };
                result.ip = match[3];
            }
            result.tags.push('ssh', 'auth-success');
        }
        // 3. Sudo Privilege Escalation
        else if (app.includes('sudo')) {
            const match = msg.match(/(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/i);
            result.eventType = 'SUDO_PRIVILEGE_EXECUTION';
            result.category = 'Privilege Escalation';
            result.severity = 'Medium';
            if (match) {
                result.normalizedFields = {
                    executingUser: match[1],
                    tty: match[2],
                    pwd: match[3],
                    targetUser: match[4],
                    command: match[5],
                };
            }
            result.tags.push('sudo', 'privilege-escalation');
        }
        return result;
    }
}
