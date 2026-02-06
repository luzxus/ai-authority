/**
 * MessageBus Tests
 */

import { MessageBus, createMessageBus, MessageHandler } from '../messaging';
import type { AgentMessage } from '../types';

describe('MessageBus', () => {
  let bus: MessageBus;

  beforeEach(() => {
    bus = new MessageBus({ processingIntervalMs: 1 });
    bus.start();
  });

  afterEach(() => {
    bus.stop();
  });

  describe('subscribe and publish', () => {
    it('should deliver messages to subscribers', async () => {
      const received: AgentMessage[] = [];
      const handler: MessageHandler = (msg) => {
        received.push(msg);
      };

      await bus.subscribe('test-topic', handler);

      const message: AgentMessage = {
        id: 'msg-1',
        type: 'signal',
        from: 'agent-1',
        to: 'test-topic',
        payload: { data: 'test' },
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('test-topic', message);

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(received.length).toBe(1);
      expect(received[0]!.id).toBe('msg-1');
      expect(received[0]!.payload).toEqual({ data: 'test' });
    });

    it('should support multiple subscribers on same topic', async () => {
      let count1 = 0;
      let count2 = 0;

      await bus.subscribe('multi-topic', () => { count1++; });
      await bus.subscribe('multi-topic', () => { count2++; });

      const message: AgentMessage = {
        id: 'msg-2',
        type: 'signal',
        from: 'agent-1',
        to: 'multi-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('multi-topic', message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(count1).toBe(1);
      expect(count2).toBe(1);
    });

    it('should return subscription ID', async () => {
      const subId = await bus.subscribe('topic', () => {});
      expect(typeof subId).toBe('string');
      expect(subId.length).toBeGreaterThan(0);
    });
  });

  describe('unsubscribe', () => {
    it('should remove specific handler', async () => {
      const received: string[] = [];
      const handler1: MessageHandler = () => { received.push('h1'); };
      const handler2: MessageHandler = () => { received.push('h2'); };

      await bus.subscribe('unsub-topic', handler1);
      await bus.subscribe('unsub-topic', handler2);

      await bus.unsubscribe('unsub-topic', handler1);

      const message: AgentMessage = {
        id: 'msg-3',
        type: 'signal',
        from: 'agent-1',
        to: 'unsub-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('unsub-topic', message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(received).toEqual(['h2']);
    });

    it('should remove all handlers for topic when no handler specified', async () => {
      let called = false;
      await bus.subscribe('remove-all', () => { called = true; });

      await bus.unsubscribe('remove-all');

      const message: AgentMessage = {
        id: 'msg-4',
        type: 'signal',
        from: 'agent-1',
        to: 'remove-all',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('remove-all', message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(called).toBe(false);
    });
  });

  describe('broadcast', () => {
    it('should deliver to broadcast subscribers', async () => {
      const received: AgentMessage[] = [];

      await bus.subscribe('broadcast', (msg) => {
        received.push(msg);
      });

      const message: AgentMessage = {
        id: 'msg-bc-1',
        type: 'signal',
        from: 'agent-1',
        to: 'broadcast',
        payload: { broadcast: true },
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('broadcast', message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(received.length).toBe(1);
      expect(received[0]!.payload).toEqual({ broadcast: true });
    });
  });

  describe('history', () => {
    it('should retain message history', async () => {
      for (let i = 0; i < 5; i++) {
        const message: AgentMessage = {
          id: `msg-hist-${i}`,
          type: 'signal',
          from: 'agent-1',
          to: 'history-topic',
          payload: { index: i },
          timestamp: Date.now(),
          signature: 'sig',
        };
        await bus.publish('history-topic', message);
      }

      const history = bus.getHistory();
      expect(history.length).toBe(5);
      expect(history[0]!.id).toBe('msg-hist-0');
      expect(history[4]!.id).toBe('msg-hist-4');
    });

    it('should respect history limit', async () => {
      const limitBus = new MessageBus({ historyLimit: 3, processingIntervalMs: 1 });
      limitBus.start();

      for (let i = 0; i < 5; i++) {
        const message: AgentMessage = {
          id: `msg-lim-${i}`,
          type: 'signal',
          from: 'agent-1',
          to: 'limit-topic',
          payload: {},
          timestamp: Date.now(),
          signature: 'sig',
        };
        await limitBus.publish('limit-topic', message);
      }

      const history = limitBus.getHistory();
      expect(history.length).toBe(3);
      expect(history[0]!.id).toBe('msg-lim-2'); // Oldest kept

      limitBus.stop();
    });

    it('should provide Merkle root for history', async () => {
      const message: AgentMessage = {
        id: 'msg-merkle',
        type: 'signal',
        from: 'agent-1',
        to: 'merkle-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };
      await bus.publish('merkle-topic', message);

      const root = bus.getHistoryRoot();
      expect(typeof root).toBe('string');
      expect(root.length).toBeGreaterThan(0);
    });
  });

  describe('queue management', () => {
    it('should track queue size', async () => {
      // Stop processing to see queue build up
      bus.stop();

      const message: AgentMessage = {
        id: 'msg-queue',
        type: 'signal',
        from: 'agent-1',
        to: 'queue-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await bus.publish('queue-topic', message);
      expect(bus.getQueueSize()).toBe(1);
    });

    it('should reject messages when queue is full', async () => {
      const smallBus = new MessageBus({ maxQueueSize: 2 });

      const message: AgentMessage = {
        id: 'msg-full',
        type: 'signal',
        from: 'agent-1',
        to: 'full-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await smallBus.publish('full-topic', message);
      await smallBus.publish('full-topic', message);

      await expect(smallBus.publish('full-topic', message)).rejects.toThrow('Message queue full');
    });
  });

  describe('request-response', () => {
    it('should timeout if no response', async () => {
      const message: AgentMessage = {
        id: 'msg-timeout',
        type: 'command',
        from: 'agent-1',
        to: 'no-responder',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await expect(
        bus.request('no-responder', message, 100)
      ).rejects.toThrow('Request timeout');
    });
  });

  describe('createMessageBus helper', () => {
    it('should create a started message bus', async () => {
      const helperBus = createMessageBus({ historyLimit: 5 });
      
      // Should be able to publish immediately
      const message: AgentMessage = {
        id: 'msg-helper',
        type: 'signal',
        from: 'agent-1',
        to: 'helper-topic',
        payload: {},
        timestamp: Date.now(),
        signature: 'sig',
      };

      await helperBus.publish('helper-topic', message);
      expect(helperBus.getHistory().length).toBe(1);

      helperBus.stop();
    });
  });
});
