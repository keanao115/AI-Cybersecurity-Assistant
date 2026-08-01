import { NetworkFlowRecord } from '../services/networkFlowService.js';

export interface FlowCacheStats {
  activeFlowCount: number;
  expiredFlowCount: number;
  cacheHitCount: number;
  cacheMissCount: number;
  cacheHitRatePercentage: number;
  oldestFlowAgeMs: number;
}

export class FlowCache {
  private activeFlows: Map<string, NetworkFlowRecord> = new Map();
  private expiredFlows: NetworkFlowRecord[] = [];
  private hits: number = 0;
  private misses: number = 0;
  private totalExpired: number = 0;

  private idleTimeoutMs: number = 30000;  // 30s idle timeout
  private activeTimeoutMs: number = 120000; // 120s active timeout

  public get(flowKey: string): NetworkFlowRecord | undefined {
    const flow = this.activeFlows.get(flowKey);
    if (flow) {
      this.hits++;
    } else {
      this.misses++;
    }
    return flow;
  }

  public put(flowKey: string, flow: NetworkFlowRecord): void {
    this.activeFlows.set(flowKey, flow);
  }

  public flushExpiredFlows(): NetworkFlowRecord[] {
    const now = Date.now();
    const newlyExpired: NetworkFlowRecord[] = [];

    for (const [key, flow] of this.activeFlows.entries()) {
      const flowAge = now - new Date(flow.timestamp).getTime();
      if (flowAge > this.activeTimeoutMs) {
        newlyExpired.push(flow);
        this.activeFlows.delete(key);
        this.totalExpired++;
      }
    }

    this.expiredFlows.push(...newlyExpired);
    if (this.expiredFlows.length > 1000) {
      this.expiredFlows.splice(0, this.expiredFlows.length - 1000);
    }

    return newlyExpired;
  }

  public getStats(): FlowCacheStats {
    const totalRequests = this.hits + this.misses;
    const hitRate = totalRequests > 0 ? parseFloat(((this.hits / totalRequests) * 100).toFixed(1)) : 100.0;

    return {
      activeFlowCount: this.activeFlows.size,
      expiredFlowCount: this.totalExpired,
      cacheHitCount: this.hits,
      cacheMissCount: this.misses,
      cacheHitRatePercentage: hitRate,
      oldestFlowAgeMs: 0,
    };
  }

  public clear(): void {
    this.activeFlows.clear();
    this.expiredFlows = [];
  }
}
