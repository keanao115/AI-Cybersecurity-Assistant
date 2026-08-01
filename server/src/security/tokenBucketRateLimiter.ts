// IP-based Token Bucket Rate Limiter for Collector Ingestion Protection

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

export class TokenBucketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private maxTokens: number;
  private refillRatePerSec: number;
  private cleanupIntervalMs: number;

  constructor(maxTokens: number = 1000, refillRatePerSec: number = 100) {
    this.maxTokens = maxTokens;
    this.refillRatePerSec = refillRatePerSec;
    this.cleanupIntervalMs = 60 * 1000; // 1 minute cleanup for idle IPs

    setInterval(() => this.cleanupIdleBuckets(), this.cleanupIntervalMs).unref();
  }

  /**
   * Consumes 1 token for the specified IP address.
   * Returns true if request is allowed, false if rate limited.
   */
  public tryConsume(ip: string, tokensRequested: number = 1): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(ip);

    if (!bucket) {
      bucket = { tokens: this.maxTokens, lastRefill: now };
      this.buckets.set(ip, bucket);
    } else {
      // Refill tokens based on elapsed time
      const elapsedSec = (now - bucket.lastRefill) / 1000;
      const tokensToAdd = elapsedSec * this.refillRatePerSec;
      bucket.tokens = Math.min(this.maxTokens, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }

    if (bucket.tokens >= tokensRequested) {
      bucket.tokens -= tokensRequested;
      return true;
    }

    return false;
  }

  /**
   * Returns the count of unique IP addresses currently tracked.
   */
  public getActiveIpCount(): number {
    return this.buckets.size;
  }

  private cleanupIdleBuckets(): void {
    const now = Date.now();
    for (const [ip, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > 5 * 60 * 1000) { // 5 minutes idle
        this.buckets.delete(ip);
      }
    }
  }
}
