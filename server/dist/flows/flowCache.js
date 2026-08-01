export class FlowCache {
    activeFlows = new Map();
    expiredFlows = [];
    hits = 0;
    misses = 0;
    totalExpired = 0;
    idleTimeoutMs = 30000; // 30s idle timeout
    activeTimeoutMs = 120000; // 120s active timeout
    get(flowKey) {
        const flow = this.activeFlows.get(flowKey);
        if (flow) {
            this.hits++;
        }
        else {
            this.misses++;
        }
        return flow;
    }
    put(flowKey, flow) {
        this.activeFlows.set(flowKey, flow);
    }
    flushExpiredFlows() {
        const now = Date.now();
        const newlyExpired = [];
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
    getStats() {
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
    clear() {
        this.activeFlows.clear();
        this.expiredFlows = [];
    }
}
