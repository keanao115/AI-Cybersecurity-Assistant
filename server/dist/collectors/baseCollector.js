import { TokenBucketRateLimiter } from '../security/tokenBucketRateLimiter.js';
import { sanitizeRawLog, maskSensitivePii } from '../security/sanitize.js';
export class BaseCollector {
    name;
    type;
    state = 'Stopped';
    config;
    queue;
    rateLimiter;
    startTimeMs = null;
    lastEventTimeMs = null;
    eventsProcessedTotal = 0;
    bytesProcessedTotal = 0;
    droppedPacketsTotal = 0;
    droppedReasonBreakdown = {
        rateLimited: 0,
        backpressureEvicted: 0,
        malformed: 0,
        paused: 0,
    };
    parserErrorTotal = 0;
    piiMaskedTotal = 0;
    totalLatencyMs = 0;
    healthMessage = 'Collector initialized';
    // Rolling 1-minute window for events/sec calculation
    secondBucketCounts = [];
    rateIntervalTimer = null;
    constructor(config, queue) {
        this.name = config.name;
        this.type = config.type;
        this.config = config;
        this.queue = queue;
        this.rateLimiter = new TokenBucketRateLimiter(config.rateLimitBurst || 1000, config.rateLimitEventsPerSec || 200);
    }
    // ─── Lifecycle State Machine Controls ─────────────────────────────────────
    async start() {
        if (this.state === 'Running' || this.state === 'Initializing')
            return;
        this.transitionState('Initializing', 'Starting collector listener sockets and parser engines...');
        try {
            this.startTimeMs = Date.now();
            await this.onStart();
            this.transitionState('Running', 'Collector listening and ready for incoming telemetry.');
            this.startRateTracking();
        }
        catch (err) {
            this.healthMessage = `Startup failed: ${err.message}`;
            this.transitionState('Failed', this.healthMessage);
            throw err;
        }
    }
    async pause() {
        if (this.state !== 'Running' && this.state !== 'Degraded')
            return;
        this.transitionState('Paused', 'Collector ingestion paused by administrator.');
        await this.onPause();
    }
    async resume() {
        if (this.state !== 'Paused')
            return;
        this.transitionState('Running', 'Collector ingestion resumed by administrator.');
        await this.onResume();
    }
    async stop() {
        if (this.state === 'Stopped' || this.state === 'Stopping')
            return;
        this.transitionState('Stopping', 'Gracefully stopping sockets and draining ingestion queues...');
        try {
            await this.onStop();
            this.stopRateTracking();
            this.transitionState('Stopped', 'Collector gracefully stopped.');
        }
        catch (err) {
            this.transitionState('Failed', `Stop failed: ${err.message}`);
        }
    }
    async restart() {
        this.transitionState('Restarting', 'Collector restarting...');
        await this.stop();
        await new Promise((res) => setTimeout(res, 500));
        await this.start();
    }
    // ─── Telemetry Event Pipeline Entry ───────────────────────────────────────
    async ingestRawPacket(rawTextOrBuffer, sourceIp, sourcePort, protocol, destPort) {
        const startTime = Date.now();
        // 1. Check Lifecycle State
        if (this.state === 'Paused') {
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.paused++;
            return false;
        }
        if (this.state !== 'Running' && this.state !== 'Degraded') {
            return false;
        }
        // 2. Token Bucket Rate Limiting
        if (!this.rateLimiter.tryConsume(sourceIp)) {
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.rateLimited++;
            return false;
        }
        // 3. Size Limits & Sanitization
        const rawStr = typeof rawTextOrBuffer === 'string'
            ? rawTextOrBuffer
            : rawTextOrBuffer.toString('utf8');
        if (rawStr.length > this.config.maxPacketSizeBytes) {
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.malformed++;
            return false;
        }
        this.bytesProcessedTotal += rawStr.length;
        // CRLF & Injection Sanitization
        const sanitizedRaw = sanitizeRawLog(rawStr);
        // PII Masking
        let finalRaw = sanitizedRaw;
        if (this.config.enablePiiMasking) {
            const { maskedText, hasPiiMasked } = maskSensitivePii(sanitizedRaw);
            finalRaw = maskedText;
            if (hasPiiMasked)
                this.piiMaskedTotal++;
        }
        // 4. Parse Event
        let unifiedEvent = null;
        try {
            unifiedEvent = await this.parseEvent(finalRaw, sourceIp, sourcePort, protocol, destPort);
        }
        catch (err) {
            this.parserErrorTotal++;
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.malformed++;
            this.evaluateDegradedState();
            return false;
        }
        if (!unifiedEvent) {
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.malformed++;
            return false;
        }
        // 5. Dispatch into Queue Layer with Backpressure
        const published = await this.queue.publish(`telemetry.${this.type}`, unifiedEvent);
        if (!published) {
            this.droppedPacketsTotal++;
            this.droppedReasonBreakdown.backpressureEvicted++;
            this.evaluateDegradedState();
            return false;
        }
        // 6. Metrics & Success
        this.eventsProcessedTotal++;
        this.lastEventTimeMs = Date.now();
        this.secondBucketCounts.push(1);
        this.totalLatencyMs += Math.max(0, Date.now() - startTime);
        this.evaluateDegradedState();
        return true;
    }
    // ─── Health & Metrics Probes ─────────────────────────────────────────────
    getHealth() {
        const isLive = this.state === 'Running' || this.state === 'Degraded';
        const uptime = this.startTimeMs
            ? Math.floor((Date.now() - this.startTimeMs) / 1000)
            : 0;
        return {
            name: this.name,
            type: this.type,
            state: this.state,
            liveness: isLive,
            readiness: isLive,
            uptimeSeconds: uptime,
            lastEventTimestamp: this.lastEventTimeMs
                ? new Date(this.lastEventTimeMs).toISOString()
                : null,
            listeningPorts: this.getListeningPorts(),
            activeConnections: this.getActiveConnections(),
            healthMessage: this.healthMessage,
        };
    }
    getMetrics() {
        const queueMetrics = this.queue.getMetrics();
        const totalEvents = Math.max(1, this.eventsProcessedTotal);
        const avgLatency = Math.round(this.totalLatencyMs / totalEvents);
        // Calculate rolling events per second
        const nowSec = Math.floor(Date.now() / 1000);
        const eps = this.secondBucketCounts.length;
        return {
            name: this.name,
            type: this.type,
            state: this.state,
            eventsProcessedTotal: this.eventsProcessedTotal,
            eventsPerSecond: eps,
            bytesProcessedTotal: this.bytesProcessedTotal,
            droppedPacketsTotal: this.droppedPacketsTotal,
            droppedReasonBreakdown: { ...this.droppedReasonBreakdown },
            parserErrorTotal: this.parserErrorTotal,
            piiMaskedTotal: this.piiMaskedTotal,
            averageLatencyMs: isNaN(avgLatency) ? 0 : avgLatency,
            queueDepth: queueMetrics.queueDepth,
            queueMaxCapacity: queueMetrics.maxCapacity,
            watermarkStatus: queueMetrics.watermarkStatus,
            activeSourceIpsCount: this.rateLimiter.getActiveIpCount(),
        };
    }
    getState() {
        return this.state;
    }
    // ─── Private Helpers ──────────────────────────────────────────────────────
    transitionState(newState, message) {
        const oldState = this.state;
        this.state = newState;
        this.healthMessage = message;
        console.log(`[Collector Lifecycle] ${this.name} (${this.type}): ${oldState} ➔ ${newState} (${message})`);
    }
    evaluateDegradedState() {
        const queueMetrics = this.queue.getMetrics();
        const isWatermarkHigh = queueMetrics.watermarkStatus === 'HIGH_WATERMARK' ||
            queueMetrics.watermarkStatus === 'CRITICAL_WATERMARK';
        const parserFailureRate = this.eventsProcessedTotal > 100
            ? this.parserErrorTotal / this.eventsProcessedTotal
            : 0;
        if (this.state === 'Running' && (isWatermarkHigh || parserFailureRate > 0.05)) {
            this.transitionState('Degraded', `Performance degraded (Queue: ${queueMetrics.watermarkStatus}, Parser Error Rate: ${(parserFailureRate * 100).toFixed(1)}%)`);
        }
        else if (this.state === 'Degraded' && !isWatermarkHigh && parserFailureRate <= 0.05) {
            this.transitionState('Running', 'Collector recovered from degraded state.');
        }
    }
    startRateTracking() {
        if (this.rateIntervalTimer)
            clearInterval(this.rateIntervalTimer);
        this.rateIntervalTimer = setInterval(() => {
            // Clear rolling event counts older than 1s
            this.secondBucketCounts = [];
        }, 1000);
    }
    stopRateTracking() {
        if (this.rateIntervalTimer) {
            clearInterval(this.rateIntervalTimer);
            this.rateIntervalTimer = null;
        }
    }
}
