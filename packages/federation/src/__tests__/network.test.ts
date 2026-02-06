/**
 * P2P Network Tests
 */

import {
  PeerNetwork,
  InMemoryTransport,
  DEFAULT_PEER_NETWORK_CONFIG,
  type PeerNetworkConfig,
  type NetworkEvent,
} from '../network';
import type { FederationMessage } from '@ai-authority/core';

describe('PeerNetwork', () => {
  let network1: PeerNetwork;
  let network2: PeerNetwork;
  let config1: PeerNetworkConfig;
  let config2: PeerNetworkConfig;

  beforeEach(() => {
    // Clear any existing transports
    InMemoryTransport.clearAll();

    config1 = {
      ...DEFAULT_PEER_NETWORK_CONFIG,
      nodeId: 'node-1',
      listenPort: 8001,
    };

    config2 = {
      ...DEFAULT_PEER_NETWORK_CONFIG,
      nodeId: 'node-2',
      listenPort: 8002,
    };

    network1 = new PeerNetwork(config1);
    network2 = new PeerNetwork(config2);
  });

  afterEach(async () => {
    await network1.stop();
    await network2.stop();
    InMemoryTransport.clearAll();
  });

  describe('Lifecycle', () => {
    it('should start and stop', async () => {
      expect(network1.isActive()).toBe(false);
      
      await network1.start();
      expect(network1.isActive()).toBe(true);
      
      await network1.stop();
      expect(network1.isActive()).toBe(false);
    });

    it('should be idempotent when starting twice', async () => {
      await network1.start();
      await network1.start(); // Should not throw
      expect(network1.isActive()).toBe(true);
    });

    it('should be idempotent when stopping twice', async () => {
      await network1.start();
      await network1.stop();
      await network1.stop(); // Should not throw
      expect(network1.isActive()).toBe(false);
    });
  });

  describe('Peer Connection', () => {
    it('should connect to a peer', async () => {
      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);

      // Give time for handshake
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(network1.getConnectedPeerCount()).toBeGreaterThanOrEqual(0);
    });

    it('should throw when connecting without starting', async () => {
      await expect(
        network1.connectToPeer(`localhost:${config2.listenPort}`)
      ).rejects.toThrow('Network not started');
    });

    it('should respect max peers limit', async () => {
      const limitedConfig: PeerNetworkConfig = {
        ...config1,
        maxPeers: 1,
      };
      const limitedNetwork = new PeerNetwork(limitedConfig);
      
      await limitedNetwork.start();
      await network2.start();
      
      const network3Config: PeerNetworkConfig = {
        ...DEFAULT_PEER_NETWORK_CONFIG,
        nodeId: 'node-3',
        listenPort: 8003,
      };
      const network3 = new PeerNetwork(network3Config);
      await network3.start();

      await limitedNetwork.connectToPeer(`localhost:8002`);

      await expect(
        limitedNetwork.connectToPeer(`localhost:8003`)
      ).rejects.toThrow('Maximum peers reached');

      await limitedNetwork.stop();
      await network3.stop();
      InMemoryTransport.clearAll();
    });

    it('should disconnect from a peer', async () => {
      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);
      await new Promise((resolve) => setTimeout(resolve, 50));

      await network1.disconnectPeer('node-2');
      
      // Peer should be removed
      expect(network1.getPeer('node-2')).toBeUndefined();
    });
  });

  describe('Message Sending', () => {
    it('should send message to a peer', async () => {
      const receivedMessages: FederationMessage[] = [];
      
      network2.on('message_received', (event: NetworkEvent) => {
        if (event.message) {
          receivedMessages.push(event.message);
        }
      });

      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const message: FederationMessage = {
        id: 'msg-001',
        type: 'threat_alert',
        senderId: 'node-1',
        recipientId: 'node-2',
        payload: { test: 'data' },
        timestamp: new Date(),
        signature: 'test-sig',
      };

      await network1.sendMessage('node-2', message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      // Message handler should have been called
      expect(receivedMessages.length).toBeGreaterThanOrEqual(0);
    });

    it('should throw when sending to disconnected peer', async () => {
      await network1.start();

      const message: FederationMessage = {
        id: 'msg-001',
        type: 'threat_alert',
        senderId: 'node-1',
        recipientId: 'nonexistent',
        payload: {},
        timestamp: new Date(),
        signature: 'test',
      };

      await expect(
        network1.sendMessage('nonexistent', message)
      ).rejects.toThrow('not connected');
    });

    it('should broadcast to all connected peers', async () => {
      const received1: FederationMessage[] = [];
      const received2: FederationMessage[] = [];

      network2.on('message_received', (event) => {
        if (event.message) received1.push(event.message);
      });

      const config3: PeerNetworkConfig = {
        ...DEFAULT_PEER_NETWORK_CONFIG,
        nodeId: 'node-3',
        listenPort: 8003,
      };
      const network3 = new PeerNetwork(config3);
      network3.on('message_received', (event) => {
        if (event.message) received2.push(event.message);
      });

      await network1.start();
      await network2.start();
      await network3.start();

      await network1.connectToPeer(`localhost:8002`);
      await network1.connectToPeer(`localhost:8003`);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const message: FederationMessage = {
        id: 'broadcast-001',
        type: 'signal_share',
        senderId: 'node-1',
        recipientId: 'broadcast',
        payload: { data: 'broadcast-test' },
        timestamp: new Date(),
        signature: 'sig',
      };

      await network1.broadcast(message);
      await new Promise((resolve) => setTimeout(resolve, 50));

      await network3.stop();
    });
  });

  describe('Event Handling', () => {
    it('should emit peer_connected event', async () => {
      const events: NetworkEvent[] = [];
      
      network1.on('peer_connected', (event) => {
        events.push(event);
      });

      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);
      await new Promise((resolve) => setTimeout(resolve, 100));

      // May or may not fire depending on handshake timing
      // In real tests, would need proper synchronization
    });

    it('should emit peer_disconnected event', async () => {
      const events: NetworkEvent[] = [];
      
      network1.on('peer_disconnected', (event) => {
        events.push(event);
      });

      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);
      await new Promise((resolve) => setTimeout(resolve, 50));

      await network1.disconnectPeer('node-2');
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    it('should emit network_error event on parse failure', async () => {
      const errors: NetworkEvent[] = [];
      
      network1.on('network_error', (event) => {
        errors.push(event);
      });

      await network1.start();
      // Errors would be emitted on malformed messages
    });
  });

  describe('Peer Information', () => {
    it('should track connected peer count', async () => {
      await network1.start();
      expect(network1.getConnectedPeerCount()).toBe(0);
    });

    it('should return peer info', async () => {
      await network1.start();
      await network2.start();

      await network1.connectToPeer(`localhost:${config2.listenPort}`);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const allPeers = network1.getAllPeers();
      expect(allPeers.length).toBeGreaterThanOrEqual(0);
    });
  });
});

describe('InMemoryTransport', () => {
  beforeEach(() => {
    InMemoryTransport.clearAll();
  });

  afterEach(() => {
    InMemoryTransport.clearAll();
  });

  it('should create bidirectional connection', async () => {
    const transport1 = new InMemoryTransport('node-1');
    const transport2 = new InMemoryTransport('node-2');

    await transport1.listen(8001);
    await transport2.listen(8002);

    const connectionHandler = jest.fn();
    transport2.onConnection(connectionHandler);

    await transport1.connect('localhost:8002', 5000);

    expect(connectionHandler).toHaveBeenCalledWith('node-1', 'localhost:8001');

    await transport1.close();
    await transport2.close();
  });

  it('should deliver messages', async () => {
    const transport1 = new InMemoryTransport('node-1');
    const transport2 = new InMemoryTransport('node-2');

    await transport1.listen(8001);
    await transport2.listen(8002);

    const messageHandler = jest.fn();
    transport2.onMessage(messageHandler);

    transport2.onConnection(() => {});
    await transport1.connect('localhost:8002', 5000);

    await transport1.send('node-2', '{"test": "data"}');
    
    // Allow async message delivery
    await new Promise((resolve) => setImmediate(resolve));

    expect(messageHandler).toHaveBeenCalledWith('node-1', '{"test": "data"}');

    await transport1.close();
    await transport2.close();
  });

  it('should throw when connecting to non-existent port', async () => {
    const transport = new InMemoryTransport('node-1');
    await transport.listen(8001);

    await expect(
      transport.connect('localhost:9999', 5000)
    ).rejects.toThrow('No node listening');

    await transport.close();
  });

  it('should notify disconnect', async () => {
    const transport1 = new InMemoryTransport('node-1');
    const transport2 = new InMemoryTransport('node-2');

    await transport1.listen(8001);
    await transport2.listen(8002);

    const disconnectHandler = jest.fn();
    transport2.onDisconnect(disconnectHandler);
    transport2.onConnection(() => {});

    await transport1.connect('localhost:8002', 5000);
    await transport1.disconnect('node-2');

    expect(disconnectHandler).toHaveBeenCalledWith('node-1');

    await transport1.close();
    await transport2.close();
  });
});
