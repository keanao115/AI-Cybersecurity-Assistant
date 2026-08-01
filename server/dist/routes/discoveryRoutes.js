import { Router } from 'express';
import { getDiscoveryScopeConfig, updateDiscoveryScopeConfig, runAuthorizedAssetSweep, getDiscoveryJobs, scheduleDiscoveryJob } from '../services/assetDiscoveryService.js';
import { buildRealAssetList, getArpTable, getActiveConnections } from '../services/osNetworkDiscovery.js';
export const discoveryRouter = Router();
discoveryRouter.get('/scope', (req, res) => {
    const config = getDiscoveryScopeConfig();
    return res.json(config);
});
discoveryRouter.post('/scope', (req, res) => {
    const updated = updateDiscoveryScopeConfig(req.body);
    return res.json({ message: 'Discovery CIDR scope updated', config: updated });
});
// POST /api/discovery/sweep — standard sweep (authorized CIDRs)
discoveryRouter.post('/sweep', async (req, res) => {
    const { targetCidr, scanSpeed } = req.body;
    try {
        const sweepResult = await runAuthorizedAssetSweep(targetCidr || '192.168.1.0/24', scanSpeed || 'Normal');
        return res.json(sweepResult);
    }
    catch (err) {
        return res.status(403).json({ error: 'Scope Authorization Violation', message: err.message });
    }
});
// GET /api/discovery/localhost — REAL OS-based local network discovery
discoveryRouter.get('/localhost', async (req, res) => {
    try {
        const result = await buildRealAssetList();
        return res.json({
            message: 'Real local network discovery complete (ARP table + active connections)',
            hostname: result.rawDiscovery.hostname,
            platform: result.rawDiscovery.platform,
            networkInterfaces: result.rawDiscovery.networkInterfaces,
            arpEntries: result.rawDiscovery.arpEntries,
            activeConnectionCount: result.rawDiscovery.activeConnections.length,
            activeConnections: result.rawDiscovery.activeConnections.slice(0, 30),
            discoveredAssets: result.assets,
            runAt: result.rawDiscovery.runAt,
        });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// GET /api/discovery/arp — Raw ARP table
discoveryRouter.get('/arp', async (req, res) => {
    try {
        const entries = await getArpTable();
        return res.json({ total: entries.length, entries });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
// GET /api/discovery/netstat — Real active connections
discoveryRouter.get('/netstat', async (req, res) => {
    try {
        const conns = await getActiveConnections();
        const listening = conns.filter(c => c.state === 'LISTENING' || c.state === 'LISTEN');
        const established = conns.filter(c => c.state === 'ESTABLISHED');
        return res.json({
            total: conns.length,
            listening: listening.length,
            established: established.length,
            connections: conns,
        });
    }
    catch (err) {
        return res.status(500).json({ error: err.message });
    }
});
discoveryRouter.get('/jobs', (req, res) => {
    const jobs = getDiscoveryJobs();
    return res.json({ total: jobs.length, jobs });
});
discoveryRouter.post('/jobs/schedule', (req, res) => {
    const { targetCidr, intervalMin, scanSpeed } = req.body;
    if (!targetCidr) {
        return res.status(400).json({ error: 'targetCidr is required' });
    }
    try {
        const job = scheduleDiscoveryJob(targetCidr, intervalMin || 60, scanSpeed || 'Normal');
        return res.status(201).json({ message: 'Discovery job scheduled', job });
    }
    catch (err) {
        return res.status(403).json({ error: err.message });
    }
});
