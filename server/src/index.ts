import express from 'express';
import http from 'http';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { initDbConnection } from './db/client.js';
import { apiRateLimiter, ingestRateLimiter } from './middleware/rateLimiter.js';
import { authenticateJwt } from './middleware/auth.js';
import { authRouter } from './routes/authRoutes.js';
import { assetRouter } from './routes/assetRoutes.js';
import { ingestRouter } from './routes/ingestRoutes.js';
import { vulnerabilityRouter } from './routes/vulnerabilityRoutes.js';
import { reportRouter } from './routes/reportRoutes.js';
import { threatRouter } from './routes/threatRoutes.js';
import { networkFlowRouter } from './routes/networkFlowRoutes.js';
import { packetRouter } from './routes/packetRoutes.js';
import { discoveryRouter } from './routes/discoveryRoutes.js';
import { siemRouter } from './routes/siemRoutes.js';
import { aiRouter } from './routes/aiRoutes.js';
import { initWebSocketServer } from './services/websocketService.js';
import { startSyslogReceiver, getSyslogStats } from './services/syslogReceiverService.js';
import { loadThreatIntelFeeds, getThreatIntelStats, getActiveIocList } from './services/threatIntelService.js';
import { getSystemHealth } from './services/systemHealthService.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Security Middlewares ────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Global Rate Limiting ────────────────────────────────────────────────────
app.use('/api/', apiRateLimiter);

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const systemHealth = await getSystemHealth();
  const syslogStats = getSyslogStats();
  const threatIntelStats = getThreatIntelStats();
  const geminiEnabled = !!process.env.GEMINI_API_KEY;

  res.json({
    status: 'HEALTHY',
    system: 'Intelligent Enterprise Security Operations Platform Engine',
    version: '3.0.0',
    timestamp: new Date().toISOString(),
    modules: [
      'Auth', 'Assets', 'Ingest', 'Vulnerabilities', 'Reports', 'Threats',
      'NetworkFlow', 'Packets', 'Discovery', 'SIEM', 'WebSocket',
      'GeminiAI', 'SyslogReceiver', 'ThreatIntel', 'GeoIP', 'NVD_CVE',
    ],
    realFeatures: {
      geminiAI: geminiEnabled ? 'ACTIVE' : 'FALLBACK (add GEMINI_API_KEY)',
      syslogReceiver: syslogStats,
      threatIntel: threatIntelStats,
      osDiscovery: 'ACTIVE (arp, netstat, os.networkInterfaces)',
      nvdCveApi: 'ACTIVE (services.nvd.nist.gov)',
      geoIp: 'ACTIVE (ip-api.com)',
      pcapParser: 'ACTIVE (binary PCAP, pure JS)',
      realTcpScanner: 'ACTIVE (net.Socket)',
    },
    systemHealth,
  });
});

// ─── REST Routes — Core SOC ──────────────────────────────────────────────────
app.use('/api/auth', authRouter);
app.use('/api/assets', authenticateJwt, assetRouter);
app.use('/api/ingest', authenticateJwt, ingestRateLimiter, ingestRouter);
app.use('/api/vulnerabilities', authenticateJwt, vulnerabilityRouter);
app.use('/api/reports', authenticateJwt, reportRouter);
app.use('/api/threats', authenticateJwt, threatRouter);
app.use('/api/scan', threatRouter); // Compatibility mapping

// ─── REST Routes — Phase 2: Network Monitoring, PCAP, Discovery, SIEM ───────
app.use('/api/network-flows', authenticateJwt, networkFlowRouter);
app.use('/api/packets', authenticateJwt, packetRouter);
app.use('/api/discovery', authenticateJwt, discoveryRouter);
app.use('/api/siem', authenticateJwt, siemRouter);

// ─── REST Routes — Phase 4: Real AI, Threat Intel ───────────────────────────
app.use('/api/ai', authenticateJwt, aiRouter);

// Threat Intel IOC list (public read)
app.get('/api/threat-intel/iocs', authenticateJwt, (_req, res) => {
  res.json({ stats: getThreatIntelStats(), iocs: getActiveIocList().slice(0, 200) });
});

// Syslog receiver status
app.get('/api/syslog/status', authenticateJwt, (_req, res) => {
  res.json(getSyslogStats());
});

// ─── Error Handling ──────────────────────────────────────────────────────────
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[SOC Backend Error]:', err.stack || err);
  res.status(500).json({ error: 'Internal SOC Backend Error', message: err.message });
});

// ─── HTTP Server + WebSocket ──────────────────────────────────────────────────
const httpServer = http.createServer(app);
initWebSocketServer(httpServer);

httpServer.listen(PORT, async () => {
  console.log(`=======================================================`);
  console.log(`[Intelligent Enterprise Security Operations Platform v3.0] Running on http://localhost:${PORT}`);
  console.log(`[WebSocket] Live Telemetry Stream: ws://localhost:${PORT}/ws/telemetry`);
  console.log(`=======================================================`);

  await initDbConnection();

  // Start real services
  startSyslogReceiver();

  // Load threat intel feeds asynchronously (non-blocking)
  loadThreatIntelFeeds().catch(err => {
    console.warn('[ThreatIntel] Initial feed load failed:', err.message);
  });

  const geminiStatus = process.env.GEMINI_API_KEY
    ? '[AI] Gemini 1.5 Flash: ACTIVE'
    : '[AI] Gemini: FALLBACK MODE (set GEMINI_API_KEY in server/.env)';
  console.log(geminiStatus);
});
