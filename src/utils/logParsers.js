// Parser utility for CyberMind AI

export function parseWindowsEventLog(rawText) {
  const events = [];
  try {
    if (rawText.includes('<Event') || rawText.includes('<Events')) {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawText, "text/xml");
      const eventNodes = xmlDoc.getElementsByTagName("Event");

      for (let i = 0; i < eventNodes.length; i++) {
        const node = eventNodes[i];
        const eventId = node.getElementsByTagName("EventID")[0]?.textContent || "Unknown";
        const computer = node.getElementsByTagName("Computer")[0]?.textContent || "Unknown-Host";
        const timeCreated = node.getElementsByTagName("TimeCreated")[0]?.getAttribute("SystemTime") || new Date().toISOString();
        
        const dataMap = {};
        const dataNodes = node.getElementsByTagName("Data");
        for (let j = 0; j < dataNodes.length; j++) {
          const name = dataNodes[j].getAttribute("Name");
          if (name) {
            dataMap[name] = dataNodes[j].textContent;
          }
        }

        events.push({
          id: `WIN-${i+1}`,
          sourceType: "Windows Event Log",
          eventId,
          computer,
          timestamp: timeCreated,
          user: dataMap["TargetUserName"] || dataMap["SubjectUserName"] || "N/A",
          ip: dataMap["IpAddress"] || "N/A",
          process: dataMap["NewProcessName"] || dataMap["ProcessName"] || "N/A",
          commandLine: dataMap["CommandLine"] || "N/A",
          details: dataMap["FailureReason"] || dataMap["Message"] || `Event ID ${eventId} executed on ${computer}`,
          raw: node.outerHTML
        });
      }
    } else {
      // Fallback TXT / Line-by-line parser
      const lines = rawText.split('\n').filter(l => l.trim().length > 0);
      lines.forEach((line, idx) => {
        let eventId = "4625";
        if (line.includes("4688") || line.includes("powershell")) eventId = "4688";
        if (line.includes("4720") || line.includes("user")) eventId = "4720";
        if (line.includes("1102") || line.includes("cleared")) eventId = "1102";

        events.push({
          id: `WIN-TXT-${idx+1}`,
          sourceType: "Windows Event Log (TXT)",
          eventId,
          computer: "HOST-PC",
          timestamp: new Date().toISOString(),
          user: line.includes("User:") ? line.split("User:")[1].split(" ")[0] : "Admin",
          ip: line.includes("IP:") ? line.split("IP:")[1].split(" ")[0] : "192.168.1.155",
          process: line.includes("powershell") ? "powershell.exe" : "N/A",
          commandLine: line,
          details: line,
          raw: line
        });
      });
    }
  } catch (err) {
    console.error("Error parsing Windows Event Log:", err);
  }
  return events;
}

export function parseLinuxLog(rawText) {
  const logs = [];
  const lines = rawText.split('\n').filter(l => l.trim().length > 0);
  lines.forEach((line, idx) => {
    let action = "INFO";
    if (line.includes("Failed password")) action = "SSH_FAILED_LOGIN";
    if (line.includes("Accepted password")) action = "SSH_SUCCESS_LOGIN";
    if (line.includes("sudo")) action = "SUDO_PRIV_ESC";
    if (line.includes("Out of memory") || line.includes("Kill process")) action = "OOM_MINER";

    const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);

    logs.push({
      id: `LNX-${idx+1}`,
      sourceType: "Linux Syslog / Auth",
      timestamp: line.substring(0, 15) || new Date().toISOString(),
      action,
      ip: ipMatch ? ipMatch[0] : "185.220.101.5",
      user: line.includes("user") ? line.split("user")[1]?.trim().split(" ")[0] : "root",
      message: line,
      raw: line
    });
  });
  return logs;
}

export function parseFirewallLog(rawText) {
  const records = [];
  const lines = rawText.split('\n').filter(l => l.trim().length > 0);
  lines.forEach((line, idx) => {
    const isDeny = line.toLowerCase().includes("deny") || line.toLowerCase().includes("drop");
    const ipMatches = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || ["192.168.1.105", "185.220.101.5"];
    
    records.push({
      id: `FW-${idx+1}`,
      sourceType: line.includes("Cisco") ? "Cisco ASA Firewall" : "Palo Alto Firewall",
      action: isDeny ? "DENY / DROP" : "ALLOW",
      srcIp: ipMatches[0] || "192.168.1.105",
      dstIp: ipMatches[1] || "185.220.101.5",
      port: line.includes("dport=") ? line.split("dport=")[1].split(" ")[0] : "4444",
      rule: line.includes("rule=") ? line.split("rule=")[1].split(" ")[0] : "DEFAULT_BLOCK",
      raw: line
    });
  });
  return records;
}

export function parseNmapScan(rawText) {
  const openPorts = [];
  let host = "Target Host";
  let os = "Unknown OS";

  try {
    if (rawText.includes('<nmaprun')) {
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(rawText, "text/xml");
      const hostNode = xmlDoc.getElementsByTagName("host")[0];
      if (hostNode) {
        host = hostNode.getElementsByTagName("address")[0]?.getAttribute("addr") || "192.168.1.10";
        os = hostNode.getElementsByTagName("osmatch")[0]?.getAttribute("name") || "Windows / Linux";
        
        const portNodes = hostNode.getElementsByTagName("port");
        for (let i = 0; i < portNodes.length; i++) {
          const pNode = portNodes[i];
          const portId = pNode.getAttribute("portid");
          const proto = pNode.getAttribute("protocol");
          const state = pNode.getElementsByTagName("state")[0]?.getAttribute("state");
          const serviceNode = pNode.getElementsByTagName("service")[0];
          const serviceName = serviceNode?.getAttribute("name") || "unknown";
          const product = serviceNode?.getAttribute("product") || "";
          const version = serviceNode?.getAttribute("version") || "";
          const scripts = Array.from(pNode.getElementsByTagName("script")).map(s => s.getAttribute("output"));

          openPorts.push({
            port: parseInt(portId),
            protocol: proto,
            state: state,
            service: `${serviceName} ${product} ${version}`.trim(),
            vulns: scripts.length > 0 ? scripts.join("; ") : "No CVE script output"
          });
        }
      }
    } else {
      // Standard output parser
      const lines = rawText.split('\n');
      lines.forEach((l, idx) => {
        if (l.includes("/tcp") || l.includes("/udp")) {
          const parts = l.split(/\s+/).filter(Boolean);
          openPorts.push({
            port: parseInt(parts[0]),
            protocol: parts[0].includes("tcp") ? "tcp" : "udp",
            state: parts[1] || "open",
            service: parts.slice(2).join(" ") || "Unknown",
            vulns: l.includes("VULNERABLE") ? "Flagged Vulnerable Service" : "Normal"
          });
        }
      });
    }
  } catch (e) {
    console.error("Nmap parse error:", e);
  }

  return { host, os, openPorts };
}
