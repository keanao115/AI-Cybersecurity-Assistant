// Real Threat Intelligence Feed Integration
// Data sources:
//   1. Feodo Tracker (abuse.ch) — botnet C2 IP blocklist (free, no auth)
//   2. URLhaus (abuse.ch) — malicious URL feed (free, no auth)
//   3. Local known-bad seed list for offline operation

export interface IocEntry {
  indicator: string;
  type: 'IP' | 'DOMAIN' | 'URL' | 'HASH';
  malwareFamily: string;
  confidence: 'High' | 'Medium' | 'Low';
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  source: string;
}

// ─── In-memory blocklist store ────────────────────────────────────────────────
let feodoBlocklist: Map<string, IocEntry> = new Map();
let urlhausBlocklist: Map<string, IocEntry> = new Map();
let lastRefreshed: Date | null = null;
let isLoading = false;
const REFRESH_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours

// Known-bad seed list (offline fallback — real threat actors)
const SEED_BLOCKLIST: IocEntry[] = [
  { indicator: '185.220.101.5', type: 'IP', malwareFamily: 'Tor Exit Node / C2', confidence: 'High', firstSeen: '2023-01-01', lastSeen: new Date().toISOString(), tags: ['tor', 'c2', 'proxy'], source: 'seed' },
  { indicator: '185.220.101.47', type: 'IP', malwareFamily: 'Tor Exit Node', confidence: 'High', firstSeen: '2023-01-01', lastSeen: new Date().toISOString(), tags: ['tor', 'exit-node'], source: 'seed' },
  { indicator: '195.54.160.149', type: 'IP', malwareFamily: 'Emotet C2', confidence: 'High', firstSeen: '2023-06-01', lastSeen: new Date().toISOString(), tags: ['emotet', 'botnet', 'c2'], source: 'seed' },
  { indicator: '31.41.244.197', type: 'IP', malwareFamily: 'QakBot C2', confidence: 'High', firstSeen: '2023-09-01', lastSeen: new Date().toISOString(), tags: ['qakbot', 'banking-trojan', 'c2'], source: 'seed' },
  { indicator: '194.26.29.113', type: 'IP', malwareFamily: 'AsyncRAT C2', confidence: 'High', firstSeen: '2024-01-01', lastSeen: new Date().toISOString(), tags: ['asyncrat', 'rat', 'c2'], source: 'seed' },
];

// ─── Load Feodo Tracker IP Blocklist ─────────────────────────────────────────
async function loadFeodoBlocklist(): Promise<void> {
  const endpoints = [
    'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  ];
  for (const url of endpoints) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(8000),
        headers: { 'Accept': 'application/json' },
      });
      if (!res.ok) continue;
      const data = await res.json() as any[];

      for (const entry of data) {
        const ip = entry.ip_address;
        if (!ip) continue;
        feodoBlocklist.set(ip, {
          indicator: ip,
          type: 'IP',
          malwareFamily: entry.malware || 'Unknown Botnet',
          confidence: 'High',
          firstSeen: entry.first_seen || '',
          lastSeen: entry.last_seen || '',
          tags: ['botnet', 'c2', 'feodo'],
          source: 'feodotracker.abuse.ch',
        });
      }
      console.log(`[ThreatIntel] Feodo blocklist loaded: ${feodoBlocklist.size} C2 IPs`);
      return;
    } catch {
      // try next
    }
  }
  console.warn(`[ThreatIntel] Feodo feeds unreachable. Using seed IP blocklist (${SEED_BLOCKLIST.length} IPs).`);
}

// ─── Load URLhaus URL Blocklist ────────────────────────────────────────────────
async function loadUrlhausFeed(): Promise<void> {
  try {
    const res = await fetch('https://urlhaus.abuse.ch/downloads/json_online/', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as any;
    const urls = Object.values(data) as any[];

    for (const entry of urls.slice(0, 250)) {
      const url = entry.url;
      if (!url) continue;
      urlhausBlocklist.set(url, {
        indicator: url,
        type: 'URL',
        malwareFamily: entry.threat || 'Malware Download',
        confidence: 'High',
        firstSeen: entry.date_added || '',
        lastSeen: entry.date_added || '',
        tags: entry.tags || ['malware', 'download'],
        source: 'urlhaus.abuse.ch',
      });
    }
    console.log(`[ThreatIntel] URLhaus feed loaded: ${urlhausBlocklist.size} malicious URLs`);
  } catch (err: any) {
    console.warn(`[ThreatIntel] URLhaus feed offline or unreachable (${err.message}).`);
  }
}

// ─── Initialize feeds ──────────────────────────────────────────────────────────
export async function loadThreatIntelFeeds(): Promise<void> {
  if (isLoading) return;
  isLoading = true;

  // Seed the local fallback immediately
  for (const entry of SEED_BLOCKLIST) {
    feodoBlocklist.set(entry.indicator, entry);
  }

  await Promise.allSettled([loadFeodoBlocklist(), loadUrlhausFeed()]);

  lastRefreshed = new Date();
  isLoading = false;

  // Auto-refresh every 4 hours
  setInterval(async () => {
    await Promise.allSettled([loadFeodoBlocklist(), loadUrlhausFeed()]);
    lastRefreshed = new Date();
  }, REFRESH_INTERVAL_MS);
}

// ─── Public Lookup API ────────────────────────────────────────────────────────
export function checkIpReputation(ip: string): { isKnownBad: boolean; ioc?: IocEntry } {
  const entry = feodoBlocklist.get(ip);
  return { isKnownBad: !!entry, ioc: entry };
}

export function checkUrlReputation(url: string): { isKnownBad: boolean; ioc?: IocEntry } {
  const entry = urlhausBlocklist.get(url);
  return { isKnownBad: !!entry, ioc: entry };
}

export function enrichWithThreatIntel(ip: string): string | null {
  const rep = checkIpReputation(ip);
  if (rep.isKnownBad && rep.ioc) {
    return `Known Bad IP — ${rep.ioc.malwareFamily} [Source: ${rep.ioc.source}]`;
  }
  return null;
}

export function getActiveIocList(type?: 'IP' | 'URL'): IocEntry[] {
  const allIocs: IocEntry[] = [
    ...Array.from(feodoBlocklist.values()),
    ...Array.from(urlhausBlocklist.values()),
  ];
  return type ? allIocs.filter(i => i.type === type) : allIocs;
}

export function getThreatIntelStats() {
  return {
    totalIocs: feodoBlocklist.size + urlhausBlocklist.size,
    ipBlocklist: feodoBlocklist.size,
    urlBlocklist: urlhausBlocklist.size,
    lastRefreshed: lastRefreshed?.toISOString() || null,
    sources: ['feodotracker.abuse.ch', 'urlhaus.abuse.ch', 'local-seed'],
  };
}
