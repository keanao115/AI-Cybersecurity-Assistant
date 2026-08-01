import {
  CollectorState,
  CollectorType,
  CollectorHealth,
  CollectorMetrics,
  CollectorConfig,
  UnifiedSecurityEvent,
} from './collectorTypes.js';
import { IMessageQueue } from '../queue/messageQueue.js';
import { TokenBucketRateLimiter } from '../security/tokenBucketRateLimiter.js';
import { sanitizeRawLog, maskSensitivePii } from '../security/sanitize.js';

export abstract class BaseCollector {
  public readonly name: string;
  public readonly type: CollectorType;
  protected state: CollectorState = 'Stopped';
  protected config: CollectorConfig;
  protected queue: IMessageQueue;
  protected rateLimiter: TokenBucketRateLimiter;

  protected startTimeMs: number | null = null;
  protected lastEventTimeMs: number | null = null;
  protected eventsProcessedTotal: number = 0;
  protected bytesProcessedTotal: number = 0;
  protected droppedPacketsTotal: number = 0;
  protected droppedReasonBreakdown = {
    rateLimited: 0,
    backpressureEvicted: 0,
    malformed: 0,
    paused: 0,
  };
  protected parserErrorTotal: number = 0;
  protected piiMaskedTotal: number = 0;
  protected totalLatencyMs: number = 0;
  protected healthMessage: string = 'Collector initialized';

  // Rolling 1-minute window for events/sec calculation
  private secondBucketCounts: number[] = [];
  private rateIntervalTimer: NodeJS.Timeout | null = null;

  constructor(config: CollectorConfig, queue: IMessageQueue) {
    this.name = config.name;
    this.type = config.type;
    this.config = config;
    this.queue = queue;
    this.rateLimiter = new TokenBucketRateLimiter(
      config.rateLimitBurst || 1000,
      config.rateLimitEventsPerSec || 200
    );
  }

  // ─── Lifecycle State Machine Controls ─────────────────────────────────────

  public async start(): Promise<void> {
    if (this.state === 'Running' || this.state === 'Initializing') return;

    this.transitionState('Initializing', 'Starting collector listener sockets and parser engines...');
    try {
      this.startTimeMs = Date.now();
      await this.onStart();
      this.transitionState('Running', 'Collector listening and ready for incoming telemetry.');
      this.startRateTracking();
    } catch (err: any) {
      this.healthMessage = `Startup failed: ${err.message}`;
      this.transitionState('Failed', this.healthMessage);
      throw err;
    }
  }

  public async pause(): Promise<void> {
    if (this.state !== 'Running' && this.state !== 'Degraded') return;
    this.transitionState('Paused', 'Collector ingestion paused by administrator.');
    await this.onPause();
  }

  public async resume(): Promise<void> {
    if (this.state !== 'Paused') return;
    this.transitionState('Running', 'Collector ingestion resumed by administrator.');
    await this.onResume();
  }

  public async stop(): Promise<void> {
    if (this.state === 'Stopped' || this.state === 'Stopping') return;

    this.transitionState('Stopping', 'Gracefully stopping sockets and draining ingestion queues...');
    try {
      await this.onStop();
      this.stopRateTracking();
      this.transitionState('Stopped', 'Collector gracefully stopped.');
    } catch (err: any) {
      this.transitionState('Failed', `Stop failed: ${err.message}`);
    }
  }

  public async restart(): Promise<void> {
    this.transitionState('Restarting', 'Collector restarting...');
    await this.stop();
    await new Promise((res) => setTimeout(res, 500));
    await this.start();
  }

  // ─── Telemetry Event Pipeline Entry ───────────────────────────────────────

  protected async ingestRawPacket(
    rawTextOrBuffer: string | Buffer,
    sourceIp: string,
    sourcePort: number,
    protocol: 'UDP' | 'TCP' | 'HTTP',
    destPort: number
  ): Promise<boolean> {
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
    const rawStr =
      typeof rawTextOrBuffer === 'string'
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
      if (hasPiiMasked) this.piiMaskedTotal++;
    }

    // 4. Parse Event
    let unifiedEvent: UnifiedSecurityEvent | null = null;
    try {
      unifiedEvent = await this.parseEvent(
        finalRaw,
        sourceIp,
        sourcePort,
        protocol,
        destPort
      );
    } catch (err: any) {
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
    const published = await this.queue.publish(
      `telemetry.${this.type}`,
      unifiedEvent
    );

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

  public getHealth(): CollectorHealth {
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

  public getMetrics(): CollectorMetrics {
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

  public getState(): CollectorState {
    return this.state;
  }

  // ─── Abstract Lifecycle Hooks to be implemented by child collectors ──────

  protected abstract onStart(): Promise<void>;
  protected abstract onPause(): Promise<void>;
  protected abstract onResume(): Promise<void>;
  protected abstract onStop(): Promise<void>;
  protected abstract parseEvent(
    rawText: string,
    sourceIp: string,
    sourcePort: number,
    protocol: 'UDP' | 'TCP' | 'HTTP',
    destPort: number
  ): Promise<UnifiedSecurityEvent | null>;
  protected abstract getListeningPorts(): number[];
  protected abstract getActiveConnections(): number;

  // ─── Private Helpers ──────────────────────────────────────────────────────

  protected transitionState(newState: CollectorState, message: string): void {
    const oldState = this.state;
    this.state = newState;
    this.healthMessage = message;
    console.log(`[Collector Lifecycle] ${this.name} (${this.type}): ${oldState} ➔ ${newState} (${message})`);
  }

  private evaluateDegradedState(): void {
    const queueMetrics = this.queue.getMetrics();
    const isWatermarkHigh =
      queueMetrics.watermarkStatus === 'HIGH_WATERMARK' ||
      queueMetrics.watermarkStatus === 'CRITICAL_WATERMARK';

    const parserFailureRate =
      this.eventsProcessedTotal > 100
        ? this.parserErrorTotal / this.eventsProcessedTotal
        : 0;

    if (this.state === 'Running' && (isWatermarkHigh || parserFailureRate > 0.05)) {
      this.transitionState(
        'Degraded',
        `Performance degraded (Queue: ${queueMetrics.watermarkStatus}, Parser Error Rate: ${(parserFailureRate * 100).toFixed(1)}%)`
      );
    } else if (this.state === 'Degraded' && !isWatermarkHigh && parserFailureRate <= 0.05) {
      this.transitionState('Running', 'Collector recovered from degraded state.');
    }
  }

  private startRateTracking(): void {
    if (this.rateIntervalTimer) clearInterval(this.rateIntervalTimer);
    this.rateIntervalTimer = setInterval(() => {
      // Clear rolling event counts older than 1s
      this.secondBucketCounts = [];
    }, 1000);
  }

  private stopRateTracking(): void {
    if (this.rateIntervalTimer) {
      clearInterval(this.rateIntervalTimer);
      this.rateIntervalTimer = null;
    }
  }
}
