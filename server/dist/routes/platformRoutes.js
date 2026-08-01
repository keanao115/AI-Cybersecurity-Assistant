import { Router } from 'express';
import { loadPlatformConfig, updatePlatformConfigOverride } from '../config/platformConfig.js';
import { recordAuditLog, getAuditLogs } from '../services/auditService.js';
import { SyntheticFlowGenerator } from '../demo/syntheticFlowGenerator.js';
import { seedDemoData } from '../demo/seedDataService.js';
export const platformRouter = Router();
const serverStartTime = Date.now();
// GET /api/platform/status — Returns current operating mode & data policy
platformRouter.get('/status', (_req, res) => {
    const config = loadPlatformConfig();
    const uptimeSeconds = Math.floor((Date.now() - serverStartTime) / 1000);
    const status = {
        platformMode: config.platformMode,
        syntheticDataEnabled: config.enableSyntheticData,
        seedDataEnabled: config.enableSeedData,
        attackSimulationEnabled: config.enableAttackSimulation,
        runtimeModeSwitchAllowed: config.allowRuntimeModeSwitch,
        dataPolicy: {
            allowSyntheticInCurrentMode: config.platformMode === 'DEMO' && config.enableSyntheticData,
            defaultIncludeSynthetic: config.platformMode === 'DEMO',
            allowSeedInCurrentMode: config.platformMode === 'DEMO' && config.enableSeedData,
        },
        uptimeSeconds,
    };
    return res.json(status);
});
// POST /api/platform/mode — Controlled Runtime Operating Mode Switching
platformRouter.post('/mode', async (req, res) => {
    const currentConfig = loadPlatformConfig();
    if (!currentConfig.allowRuntimeModeSwitch) {
        return res.status(403).json({
            error: 'Runtime mode switching is disabled by server configuration (ALLOW_RUNTIME_MODE_SWITCH=false).',
        });
    }
    const { targetMode, enableSynthetic, enableSeed } = req.body;
    if (!targetMode || (targetMode !== 'LIVE' && targetMode !== 'DEMO')) {
        return res.status(400).json({ error: 'Invalid targetMode. Must be "LIVE" or "DEMO".' });
    }
    const prevMode = currentConfig.platformMode;
    const newMode = targetMode;
    const updatedConfig = updatePlatformConfigOverride({
        platformMode: newMode,
        enableSyntheticData: newMode === 'DEMO' ? (enableSynthetic ?? true) : false,
        enableSeedData: newMode === 'DEMO' ? (enableSeed ?? true) : false,
    });
    const generator = SyntheticFlowGenerator.getInstance();
    if (newMode === 'DEMO') {
        if (updatedConfig.enableSyntheticData) {
            generator.start();
        }
        if (updatedConfig.enableSeedData) {
            seedDemoData();
        }
    }
    else {
        // Leaving DEMO mode -> stop synthetic generators immediately
        generator.stop();
    }
    await recordAuditLog({
        userId: req.user?.username || 'admin',
        action: 'PLATFORM_MODE_CHANGE',
        previousValue: prevMode,
        newValue: newMode,
        sourceIp: req.ip || req.socket.remoteAddress || '127.0.0.1',
        result: 'SUCCESS',
    });
    return res.json({
        message: `Platform mode successfully changed to ${newMode}`,
        config: updatedConfig,
    });
});
// GET /api/platform/audit-logs — Audit log history
platformRouter.get('/audit-logs', (_req, res) => {
    return res.json({ auditLogs: getAuditLogs() });
});
