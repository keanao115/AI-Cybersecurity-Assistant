import { crypto } from '../utils/cryptoShim.js';
export class InMemoryMessageQueue {
    buffer = [];
    maxCapacity;
    subscribers = new Map();
    publishedCount = 0;
    consumedCount = 0;
    droppedCount = 0;
    isProcessing = false;
    constructor(maxCapacity = 10000) {
        this.maxCapacity = maxCapacity;
    }
    async publish(topic, payload) {
        const queueDepth = this.buffer.length;
        const fillRatio = queueDepth / this.maxCapacity;
        // Critical Watermark (95% full): Evict/drop non-critical events
        if (fillRatio >= 0.95) {
            // Check if event is Critical or High severity
            const severity = payload?.severity;
            if (severity !== 'Critical' && severity !== 'High') {
                this.droppedCount++;
                return false; // Backpressure eviction
            }
        }
        // Queue full (100% capacity)
        if (queueDepth >= this.maxCapacity) {
            this.droppedCount++;
            return false;
        }
        const message = {
            id: crypto?.randomUUID ? crypto.randomUUID() : `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            topic,
            payload,
            timestamp: Date.now(),
        };
        this.buffer.push(message);
        this.publishedCount++;
        // Trigger async processing loop if idle
        if (!this.isProcessing) {
            setImmediate(() => this.processQueue());
        }
        return true;
    }
    subscribe(topic, handler) {
        if (!this.subscribers.has(topic)) {
            this.subscribers.set(topic, new Set());
        }
        this.subscribers.get(topic).add(handler);
    }
    unsubscribe(topic) {
        this.subscribers.delete(topic);
    }
    getMetrics() {
        const depth = this.buffer.length;
        const fillRatio = depth / this.maxCapacity;
        let watermarkStatus = 'NORMAL';
        if (fillRatio >= 0.95)
            watermarkStatus = 'CRITICAL_WATERMARK';
        else if (fillRatio >= 0.80)
            watermarkStatus = 'HIGH_WATERMARK';
        else if (fillRatio >= 0.50)
            watermarkStatus = 'LOW_WATERMARK';
        return {
            publishedCount: this.publishedCount,
            consumedCount: this.consumedCount,
            droppedCount: this.droppedCount,
            queueDepth: depth,
            maxCapacity: this.maxCapacity,
            watermarkStatus,
        };
    }
    clear() {
        this.buffer = [];
    }
    async processQueue() {
        if (this.isProcessing || this.buffer.length === 0)
            return;
        this.isProcessing = true;
        while (this.buffer.length > 0) {
            const msg = this.buffer.shift();
            if (!msg)
                break;
            const handlers = this.subscribers.get(msg.topic);
            if (handlers && handlers.size > 0) {
                for (const handler of handlers) {
                    try {
                        await handler(msg);
                    }
                    catch (err) {
                        console.error(`[Queue Error] Handler error on topic "${msg.topic}":`, err);
                    }
                }
            }
            this.consumedCount++;
        }
        this.isProcessing = false;
    }
}
