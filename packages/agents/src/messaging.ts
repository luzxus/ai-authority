/**
 * Message Bus
 * 
 * Inter-agent communication system using publish/subscribe pattern.
 * Supports both direct messaging and broadcast.
 */

import { generateSecureId, MerkleTree } from '@ai-authority/core';
import type { AgentMessage } from './types.js';

/** Message handler function */
export type MessageHandler = (message: AgentMessage) => void | Promise<void>;

/** Message bus configuration */
export interface MessageBusConfig {
  maxQueueSize: number;
  processingIntervalMs: number;
  retainHistory: boolean;
  historyLimit: number;
}

const defaultConfig: MessageBusConfig = {
  maxQueueSize: 10000,
  processingIntervalMs: 10,
  retainHistory: true,
  historyLimit: 1000,
};

/**
 * In-memory message bus for agent communication.
 * In production, this would be replaced with a distributed message queue.
 */
export class MessageBus {
  private readonly config: MessageBusConfig;
  private readonly subscribers: Map<string, Set<MessageHandler>> = new Map();
  private readonly messageQueue: AgentMessage[] = [];
  private readonly history: MerkleTree;
  private readonly historyMessages: AgentMessage[] = [];
  private processing = false;
  private processingInterval?: ReturnType<typeof setInterval>;

  constructor(config: Partial<MessageBusConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.history = new MerkleTree();
  }

  /** Start message processing */
  start(): void {
    if (this.processing) return;
    this.processing = true;
    this.processingInterval = setInterval(
      () => this.processQueue(),
      this.config.processingIntervalMs
    );
  }

  /** Stop message processing */
  stop(): void {
    this.processing = false;
    if (this.processingInterval) {
      clearInterval(this.processingInterval);
    }
  }

  /** Subscribe to messages for a topic (agent ID or 'broadcast') */
  async subscribe(topic: string, handler: MessageHandler): Promise<string> {
    const handlers = this.subscribers.get(topic) ?? new Set();
    handlers.add(handler);
    this.subscribers.set(topic, handlers);
    return generateSecureId(); // Return subscription ID
  }

  /** Unsubscribe from a topic */
  async unsubscribe(topic: string, handler?: MessageHandler): Promise<void> {
    if (handler) {
      const handlers = this.subscribers.get(topic);
      if (handlers) {
        handlers.delete(handler);
      }
    } else {
      this.subscribers.delete(topic);
    }
  }

  /** Publish a message */
  async publish(topic: string, message: AgentMessage): Promise<void> {
    if (this.messageQueue.length >= this.config.maxQueueSize) {
      throw new Error('Message queue full');
    }

    // Add to queue
    this.messageQueue.push({ ...message, to: topic });

    // Add to history
    if (this.config.retainHistory) {
      this.historyMessages.push(message);
      if (this.historyMessages.length > this.config.historyLimit) {
        this.historyMessages.shift();
      }
      this.history.append(JSON.stringify({
        id: message.id,
        type: message.type,
        from: message.from,
        to: topic,
        timestamp: message.timestamp,
      }));
    }
  }

  /** Request-response pattern */
  async request<T, R>(
    topic: string,
    message: AgentMessage<T>,
    timeoutMs: number = 5000
  ): Promise<AgentMessage<R>> {
    return new Promise((resolve, reject) => {
      const correlationId = message.id;
      const timeout = setTimeout(() => {
        this.unsubscribe(`reply:${correlationId}`);
        reject(new Error('Request timeout'));
      }, timeoutMs);

      // Subscribe to reply
      this.subscribe(`reply:${correlationId}`, (reply: AgentMessage) => {
        clearTimeout(timeout);
        this.unsubscribe(`reply:${correlationId}`);
        resolve(reply as AgentMessage<R>);
      });

      // Publish request
      this.publish(topic, { ...message, replyTo: `reply:${correlationId}` });
    });
  }

  /** Get message history */
  getHistory(limit?: number): AgentMessage[] {
    const count = limit ?? this.historyMessages.length;
    return this.historyMessages.slice(-count);
  }

  /** Get history Merkle root */
  getHistoryRoot(): string {
    return this.history.getRoot();
  }

  /** Get queue size */
  getQueueSize(): number {
    return this.messageQueue.length;
  }

  /** Process message queue */
  private async processQueue(): Promise<void> {
    while (this.messageQueue.length > 0 && this.processing) {
      const message = this.messageQueue.shift();
      if (!message) continue;

      const topic = message.to;

      // Get direct subscribers
      const directHandlers = this.subscribers.get(topic) ?? new Set();

      // Deliver to all handlers
      const deliveryPromises: Promise<void>[] = [];

      for (const handler of directHandlers) {
        deliveryPromises.push(
          Promise.resolve(handler(message)).catch((error) => {
            console.error(`Error delivering message to handler:`, error);
          })
        );
      }

      // For broadcast, deliver to all subscribers except the sender
      if (topic === 'broadcast') {
        for (const [subscriberTopic, handlers] of this.subscribers) {
          if (subscriberTopic === 'broadcast' || subscriberTopic === message.from) continue;
          for (const handler of handlers) {
            deliveryPromises.push(
              Promise.resolve(handler(message)).catch((error) => {
                console.error(`Error delivering broadcast to handler:`, error);
              })
            );
          }
        }
      }

      await Promise.all(deliveryPromises);
    }
  }
}

/** Create a message bus instance */
export function createMessageBus(config?: Partial<MessageBusConfig>): MessageBus {
  const bus = new MessageBus(config);
  bus.start();
  return bus;
}
