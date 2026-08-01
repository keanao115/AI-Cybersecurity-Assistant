// Message Queue Abstraction Layer (Decouples Collectors from Storage)
// Allows plugging in Kafka, Redis Streams, or RabbitMQ without code changes in collectors.

export interface QueueMessage<T = any> {
  id: string;
  topic: string;
  payload: T;
  timestamp: number;
}

export type MessageHandler<T = any> = (message: QueueMessage<T>) => Promise<void>;

export interface QueueMetrics {
  publishedCount: number;
  consumedCount: number;
  droppedCount: number;
  queueDepth: number;
  maxCapacity: number;
  watermarkStatus: 'NORMAL' | 'LOW_WATERMARK' | 'HIGH_WATERMARK' | 'CRITICAL_WATERMARK';
}

export interface IMessageQueue {
  publish(topic: string, payload: any): Promise<boolean>;
  subscribe(topic: string, handler: MessageHandler): void;
  unsubscribe(topic: string): void;
  getMetrics(): QueueMetrics;
  clear(): void;
}
