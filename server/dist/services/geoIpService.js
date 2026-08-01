// Real GeoIP Lookup via ip-api.com (free, no API key, 45 req/min)
// Automatically skips private RFC1918 and special-use addresses
const GEO_API = 'http://ip-api.com/json';
const BATCH_API = 'http://ip-api.com/batch';
const FIELDS = 'status,country,countryCode,city,org,isp,query,mobile,proxy,hosting';
// ─── Session-level LRU cache ───────────────────────────────────────────────────
const geoCache = new Map();
const CACHE_MAX = 500;
// RFC1918 + special-use IP ranges
const PRIVATE_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^fd[0-9a-f]{2}:/i,
    /^169\.254\./,
    /^0\./,
];
export function isPrivateIp(ip) {
    return PRIVATE_RANGES.some(r => r.test(ip));
}
const PRIVATE_GEO = {
    ip: '', country: 'INTERNAL', countryCode: 'INT', city: 'LAN',
    org: 'Private Network', isp: 'RFC1918', isProxy: false, isHosting: false, isMobile: false,
    source: 'RFC1918',
};
// ─── Single IP Lookup ──────────────────────────────────────────────────────────
export async function lookupIpGeo(ip) {
    if (isPrivateIp(ip))
        return { ...PRIVATE_GEO, ip };
    const cached = geoCache.get(ip);
    if (cached)
        return { ...cached, source: 'CACHE' };
    try {
        const res = await fetch(`${GEO_API}/${ip}?fields=${FIELDS}`, {
            signal: AbortSignal.timeout(4000),
        });
        if (!res.ok)
            throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (data.status !== 'success')
            throw new Error(data.message || 'lookup failed');
        const result = {
            ip,
            country: data.country || 'Unknown',
            countryCode: data.countryCode || 'XX',
            city: data.city || 'Unknown',
            org: data.org || 'Unknown',
            isp: data.isp || 'Unknown',
            isProxy: data.proxy || false,
            isHosting: data.hosting || false,
            isMobile: data.mobile || false,
            source: 'API',
        };
        // Maintain cache size
        if (geoCache.size >= CACHE_MAX) {
            const firstKey = geoCache.keys().next().value;
            if (firstKey)
                geoCache.delete(firstKey);
        }
        geoCache.set(ip, result);
        return result;
    }
    catch (err) {
        console.warn(`[GeoIP] Lookup failed for ${ip}: ${err.message}`);
        return {
            ip, country: 'Unknown', countryCode: 'XX', city: 'Unknown',
            org: 'Unknown', isp: 'Unknown', isProxy: false, isHosting: false, isMobile: false,
            source: 'FAIL',
        };
    }
}
// ─── Batch IP Lookup (up to 100 IPs per request) ─────────────────────────────
export async function batchLookupGeo(ips) {
    const results = new Map();
    const toFetch = [];
    for (const ip of ips) {
        if (isPrivateIp(ip)) {
            results.set(ip, { ...PRIVATE_GEO, ip });
        }
        else if (geoCache.has(ip)) {
            results.set(ip, { ...geoCache.get(ip), source: 'CACHE' });
        }
        else {
            toFetch.push(ip);
        }
    }
    if (toFetch.length === 0)
        return results;
    try {
        const uniqueIps = [...new Set(toFetch)].slice(0, 100);
        const body = JSON.stringify(uniqueIps.map(ip => ({ query: ip, fields: FIELDS })));
        const res = await fetch(BATCH_API, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
            signal: AbortSignal.timeout(8000),
        });
        if (!res.ok)
            throw new Error(`Batch API HTTP ${res.status}`);
        const dataArray = await res.json();
        for (const data of dataArray) {
            const ip = data.query;
            if (data.status === 'success') {
                const result = {
                    ip, country: data.country || 'Unknown', countryCode: data.countryCode || 'XX',
                    city: data.city || 'Unknown', org: data.org || 'Unknown', isp: data.isp || 'Unknown',
                    isProxy: data.proxy || false, isHosting: data.hosting || false, isMobile: data.mobile || false,
                    source: 'API',
                };
                geoCache.set(ip, result);
                results.set(ip, result);
            }
            else {
                results.set(ip, {
                    ip, country: 'Unknown', countryCode: 'XX', city: 'Unknown',
                    org: 'Unknown', isp: 'Unknown', isProxy: false, isHosting: false, isMobile: false,
                    source: 'FAIL',
                });
            }
        }
    }
    catch (err) {
        console.warn(`[GeoIP] Batch lookup failed: ${err.message}`);
        for (const ip of toFetch) {
            if (!results.has(ip)) {
                results.set(ip, {
                    ip, country: 'Unknown', countryCode: 'XX', city: 'Unknown',
                    org: 'Unknown', isp: 'Unknown', isProxy: false, isHosting: false, isMobile: false,
                    source: 'FAIL',
                });
            }
        }
    }
    return results;
}
export function getGeoCacheStats() {
    return { cachedEntries: geoCache.size, maxEntries: CACHE_MAX };
}
