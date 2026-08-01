// Windows Event Forwarding (WEF) & Sysmon XML Event Normalizer
export function parseWindowsEventXml(xmlString) {
    const xml = xmlString.trim();
    // Extract <EventID>
    const eventIdMatch = xml.match(/<EventID[^>]*>(\d+)<\/EventID>/i);
    const eventId = eventIdMatch ? eventIdMatch[1] : '0';
    // Extract <Provider Name="...">
    const providerMatch = xml.match(/<Provider\s+Name=["']([^"']+)["']/i);
    const provider = providerMatch ? providerMatch[1] : 'Microsoft-Windows-Security-Auditing';
    // Extract <Channel>
    const channelMatch = xml.match(/<Channel>([^<]+)<\/Channel>/i);
    const channel = channelMatch ? channelMatch[1] : 'Security';
    // Extract <Computer>
    const computerMatch = xml.match(/<Computer>([^<]+)<\/Computer>/i);
    const computer = computerMatch ? computerMatch[1] : 'unknown-host';
    // Extract <Security UserID="...">
    const userSidMatch = xml.match(/<Security\s+UserID=["']([^"']+)["']/i);
    const userSid = userSidMatch ? userSidMatch[1] : '';
    // Extract <TimeCreated SystemTime="...">
    const timeMatch = xml.match(/<TimeCreated\s+SystemTime=["']([^"']+)["']/i);
    const timestamp = timeMatch ? new Date(timeMatch[1]).toISOString() : new Date().toISOString();
    // Extract <Level>
    const levelMatch = xml.match(/<Level>(\d+)<\/Level>/i);
    const level = levelMatch ? parseInt(levelMatch[1], 10) : 4; // 1: Critical, 2: Error, 3: Warning, 4: Info
    // Extract <Task>
    const taskMatch = xml.match(/<Task>(\d+)<\/Task>/i);
    const task = taskMatch ? parseInt(taskMatch[1], 10) : 0;
    // Extract <Keywords>
    const keywordsMatch = xml.match(/<Keywords>([^<]+)<\/Keywords>/i);
    const keywords = keywordsMatch ? keywordsMatch[1] : '';
    // Extract <Data Name="key">value</Data> key-value pairs
    const eventData = {};
    const dataRegex = /<Data\s+Name=["']([^"']+)["']\s*>(.*?)<\/Data>/gi;
    let dataMatch;
    while ((dataMatch = dataRegex.exec(xml)) !== null) {
        eventData[dataMatch[1]] = dataMatch[2].replace(/<!\[CDATA\[(.*?)\]\]>/gs, '$1').trim();
    }
    // Derive Severity & Category based on Event ID and Channel
    const { severity, eventType, category } = mapWefEventMetadata(eventId, provider, channel, level, eventData);
    return {
        eventId,
        provider,
        channel,
        computer,
        userSid,
        timestamp,
        level,
        task,
        keywords,
        rawXml: xml,
        eventData,
        severity,
        eventType,
        category,
    };
}
function mapWefEventMetadata(eventId, provider, channel, level, eventData) {
    // Sysmon Events
    if (provider.includes('Sysmon') || channel.includes('Sysmon')) {
        switch (eventId) {
            case '1':
                return { severity: 'Medium', eventType: 'SYSMON_PROCESS_CREATE', category: 'Execution' };
            case '3':
                return { severity: 'Low', eventType: 'SYSMON_NETWORK_CONNECT', category: 'Network' };
            case '7':
                return { severity: 'Medium', eventType: 'SYSMON_IMAGE_LOAD', category: 'Execution' };
            case '8':
                return { severity: 'High', eventType: 'SYSMON_CREATE_REMOTE_THREAD', category: 'Injection' };
            case '10':
                return { severity: 'High', eventType: 'SYSMON_PROCESS_ACCESS_LSASS', category: 'Credential Access' };
            case '11':
                return { severity: 'Low', eventType: 'SYSMON_FILE_CREATE', category: 'Persistence' };
            case '12':
            case '13':
            case '14':
                return { severity: 'Medium', eventType: 'SYSMON_REGISTRY_EVENT', category: 'Persistence' };
            default:
                return { severity: 'Info', eventType: `SYSMON_EVENT_${eventId}`, category: 'Endpoint' };
        }
    }
    // Windows Security Events
    switch (eventId) {
        case '4624':
            return { severity: 'Info', eventType: 'WINDOWS_LOGON_SUCCESS', category: 'Identity' };
        case '4625':
            return { severity: 'High', eventType: 'WINDOWS_LOGON_FAILURE', category: 'Identity' };
        case '4688':
            if (eventData.CommandLine?.toLowerCase().includes('-enc') || eventData.CommandLine?.toLowerCase().includes('-encodedcommand')) {
                return { severity: 'Critical', eventType: 'POWERSHELL_ENCODED_COMMAND', category: 'Execution' };
            }
            return { severity: 'Low', eventType: 'WINDOWS_PROCESS_CREATE', category: 'Execution' };
        case '4720':
            return { severity: 'High', eventType: 'WINDOWS_USER_CREATED', category: 'Persistence' };
        case '1102':
            return { severity: 'Critical', eventType: 'WINDOWS_AUDIT_LOG_CLEARED', category: 'Defense Evasion' };
        case '4104':
            return { severity: 'Medium', eventType: 'POWERSHELL_SCRIPT_BLOCK', category: 'Execution' };
        default:
            if (level === 1)
                return { severity: 'Critical', eventType: `WIN_EVENT_${eventId}`, category: 'System' };
            if (level === 2)
                return { severity: 'High', eventType: `WIN_EVENT_${eventId}`, category: 'System' };
            if (level === 3)
                return { severity: 'Medium', eventType: `WIN_EVENT_${eventId}`, category: 'System' };
            return { severity: 'Info', eventType: `WIN_EVENT_${eventId}`, category: 'System' };
    }
}
