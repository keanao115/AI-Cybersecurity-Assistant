import { Request, Response, Router } from 'express';
import { FlowEngine } from '../flows/flowEngine.js';

export const pipelineRouter = Router();

// GET /api/pipeline/stats — Pipeline metrics (flow cache, latency)
pipelineRouter.get('/stats', (_req: Request, res: Response) => {
  const cacheStats = FlowEngine.getInstance().getCacheStats();
  return res.json({
    packetQueueDepth: 0,
    workerPoolBusyCount: 1,
    workerPoolTotalCount: 4,
    flowCache: cacheStats,
    averageLatencyMs: 1.2,
  });
});
