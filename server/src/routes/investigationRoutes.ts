import { Request, Response, Router } from 'express';
import { EvidenceBundleService } from '../correlation/evidenceBundle.js';
import { TimelineEngine } from '../correlation/timelineEngine.js';

export const investigationRouter = Router();

// GET /api/investigation/evidence-bundles — Multi-source evidence bundles
investigationRouter.get('/evidence-bundles', (_req: Request, res: Response) => {
  const bundles = EvidenceBundleService.getEvidenceBundles();
  return res.json({ bundles, count: bundles.length });
});

// GET /api/investigation/timeline — Chronological incident timeline
investigationRouter.get('/timeline', (req: Request, res: Response) => {
  const targetIp = req.query.ip as string | undefined;
  const timeline = TimelineEngine.getChronologicalTimeline(targetIp);
  return res.json({ timeline, count: timeline.length });
});
