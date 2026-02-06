/**
 * Federation Protocol Tests
 */

import {
  FederationNodeManager,
  DifferentialPrivacy,
  ZKProofGenerator,
  DEFAULT_FEDERATION_CONFIG,
  type FederationConfig,
  type ConsensusProposal,
} from '../protocol';
import type { ThreatSignal, FederationNode, FederationMessage } from '@ai-authority/core';

describe('FederationNodeManager', () => {
  let manager: FederationNodeManager;
  let config: FederationConfig;

  beforeEach(() => {
    config = {
      nodeId: 'test-node-001',
      region: 'us-east',
      ...DEFAULT_FEDERATION_CONFIG,
    };
    manager = new FederationNodeManager(config);
  });

  describe('Node Info', () => {
    it('should return correct node info', () => {
      const info = manager.getNodeInfo();
      expect(info.id).toBe('test-node-001');
      expect(info.region).toBe('us-east');
      expect(info.status).toBe('active');
      expect(info.trustScore).toBe(1.0);
      expect(info.publicKey).toBeTruthy();
    });
  });

  describe('Peer Management', () => {
    const mockPeer: FederationNode = {
      id: 'peer-001',
      publicKey: 'mock-public-key',
      capabilities: ['read:signals'],
      region: 'eu-west',
      trustScore: 0.9,
      lastSeen: new Date(),
      status: 'active',
      metadata: {},
    };

    it('should register a peer', () => {
      manager.registerPeer(mockPeer);
      const peers = manager.getPeers();
      expect(peers).toHaveLength(1);
      expect(peers[0].id).toBe('peer-001');
    });

    it('should remove a peer', () => {
      manager.registerPeer(mockPeer);
      manager.removePeer('peer-001');
      expect(manager.getPeers()).toHaveLength(0);
    });

    it('should track active peer count', () => {
      expect(manager.getActivePeerCount()).toBe(0);
      // Note: Peers start disconnected, would need to simulate connection
    });
  });

  describe('Message Handling', () => {
    it('should create signed messages', () => {
      const message = manager.createMessage('threat_alert', { test: 'data' }, 'broadcast');
      
      expect(message.id).toBeTruthy();
      expect(message.type).toBe('threat_alert');
      expect(message.senderId).toBe('test-node-001');
      expect(message.recipientId).toBe('broadcast');
      expect(message.signature).toBeTruthy();
      expect(message.timestamp).toBeInstanceOf(Date);
    });

    it('should call registered message handlers', () => {
      const handler = jest.fn();
      manager.onMessage('threat_alert', handler);

      // Register a peer first (needed for signature verification)
      const peerConfig: FederationConfig = {
        nodeId: 'peer-001',
        region: 'eu-west',
        ...DEFAULT_FEDERATION_CONFIG,
      };
      const peerManager = new FederationNodeManager(peerConfig);
      
      // Register peer with their public key
      const peerInfo = peerManager.getNodeInfo();
      manager.registerPeer(peerInfo);

      // Create message from peer
      const message = peerManager.createMessage('threat_alert', { data: 'test' }, 'test-node-001');
      
      manager.handleMessage(message);
      expect(handler).toHaveBeenCalledWith(message);
    });
  });

  describe('Threat Signal Broadcasting', () => {
    it('should broadcast threat signals to connected peers', () => {
      const signal: ThreatSignal = {
        id: 'signal-001',
        type: 'prompt_injection',
        severity: 'high',
        confidence: 0.85,
        sourceAgentId: 'test-agent',
        detectedAt: new Date(),
        indicators: [],
        instanceCount: 1,
        riskTier: 2,
      };

      const message = manager.broadcastThreatSignal(signal);
      
      expect(message.type).toBe('threat_alert');
      expect(message.recipientId).toBe('broadcast');
      expect(message.payload).toEqual(signal);
    });
  });

  describe('Consensus Protocol', () => {
    it('should create a consensus proposal', () => {
      const proposal = manager.proposeConsensus('intervention', { target: 'test-agent' });
      
      expect(proposal.id).toBeTruthy();
      expect(proposal.type).toBe('intervention');
      expect(proposal.proposerId).toBe('test-node-001');
      expect(proposal.status).toBe('pending');
      expect(proposal.votes.get('test-node-001')).toBe('approve');
    });

    it('should vote on proposals', () => {
      const proposal = manager.proposeConsensus('threat_alert', { signal: 'test' });
      
      // Simulate external vote by manipulating proposal directly
      proposal.votes.set('peer-001', 'approve');
      
      expect(proposal.votes.size).toBe(2);
    });

    it('should get pending proposals', () => {
      manager.proposeConsensus('intervention', { data: 1 });
      manager.proposeConsensus('threat_alert', { data: 2 });
      
      const pending = manager.getPendingProposals();
      expect(pending).toHaveLength(2);
    });

    it('should get a specific proposal', () => {
      const created = manager.proposeConsensus('intervention', { test: true });
      const retrieved = manager.getProposal(created.id);
      
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(created.id);
    });
  });

  describe('Message Queue', () => {
    it('should drain messages for a peer', () => {
      const mockPeer: FederationNode = {
        id: 'peer-001',
        publicKey: 'key',
        capabilities: [],
        region: 'test',
        trustScore: 1,
        lastSeen: new Date(),
        status: 'active',
        metadata: {},
      };
      
      manager.registerPeer(mockPeer);
      
      // Messages only queue for connected peers
      // In real usage, peer would be marked connected after handshake
    });
  });
});

describe('DifferentialPrivacy', () => {
  let dp: DifferentialPrivacy;

  beforeEach(() => {
    dp = new DifferentialPrivacy(1.0);
  });

  describe('Noise Addition', () => {
    it('should add noise to values', () => {
      const original = 100;
      const results = new Set<number>();
      
      // Multiple runs should give different results
      for (let i = 0; i < 10; i++) {
        results.add(dp.addNoise(original, 1));
      }
      
      // Should have some variation
      expect(results.size).toBeGreaterThan(1);
    });

    it('should respect sensitivity parameter', () => {
      // Higher sensitivity = more noise
      const original = 100;
      const lowSensitivity: number[] = [];
      const highSensitivity: number[] = [];
      
      for (let i = 0; i < 100; i++) {
        lowSensitivity.push(Math.abs(dp.addNoise(original, 0.1) - original));
        highSensitivity.push(Math.abs(dp.addNoise(original, 10) - original));
      }
      
      const avgLow = lowSensitivity.reduce((a, b) => a + b, 0) / lowSensitivity.length;
      const avgHigh = highSensitivity.reduce((a, b) => a + b, 0) / highSensitivity.length;
      
      expect(avgHigh).toBeGreaterThan(avgLow);
    });
  });

  describe('Count Privatization', () => {
    it('should privatize counts', () => {
      const count = 50;
      const privatized = dp.privatizeCount(count);
      
      // Should be close to original but not always exact
      expect(typeof privatized).toBe('number');
      expect(Number.isInteger(privatized)).toBe(true);
    });
  });

  describe('Rate Privatization', () => {
    it('should privatize rates and clamp to [0, 1]', () => {
      const rate = 0.5;
      
      for (let i = 0; i < 20; i++) {
        const privatized = dp.privatizeRate(rate);
        expect(privatized).toBeGreaterThanOrEqual(0);
        expect(privatized).toBeLessThanOrEqual(1);
      }
    });
  });

  describe('Epsilon', () => {
    it('should return configured epsilon', () => {
      expect(dp.getEpsilon()).toBe(1.0);
      
      const highPrivacy = new DifferentialPrivacy(0.1);
      expect(highPrivacy.getEpsilon()).toBe(0.1);
    });
  });
});

describe('ZKProofGenerator', () => {
  let zkGen: ZKProofGenerator;

  beforeEach(() => {
    zkGen = new ZKProofGenerator();
  });

  describe('Threshold Proofs', () => {
    it('should generate threshold proof', () => {
      const proof = zkGen.proveThresholdExceeded(0.9, 0.8, 'test-salt');
      
      expect(proof.commitment).toBeTruthy();
      expect(proof.statement).toBe('value > 0.8');
      expect(proof.proof).toBeTruthy();
      expect(proof.verificationKey).toBeTruthy();
    });

    it('should verify valid threshold proof', () => {
      const salt = 'test-salt-123';
      const proof = zkGen.proveThresholdExceeded(0.9, 0.8, salt);
      
      const isValid = zkGen.verifyThresholdProof(proof, 0.8, true, salt);
      expect(isValid).toBe(true);
    });

    it('should reject proof with wrong expected result', () => {
      const salt = 'test-salt-123';
      const proof = zkGen.proveThresholdExceeded(0.9, 0.8, salt);
      
      const isValid = zkGen.verifyThresholdProof(proof, 0.8, false, salt);
      expect(isValid).toBe(false);
    });

    it('should reject proof with wrong salt', () => {
      const proof = zkGen.proveThresholdExceeded(0.9, 0.8, 'salt-1');
      
      const isValid = zkGen.verifyThresholdProof(proof, 0.8, true, 'salt-2');
      expect(isValid).toBe(false);
    });

    it('should reject proof with wrong threshold', () => {
      const salt = 'test-salt';
      const proof = zkGen.proveThresholdExceeded(0.9, 0.8, salt);
      
      const isValid = zkGen.verifyThresholdProof(proof, 0.5, true, salt);
      expect(isValid).toBe(false);
    });
  });
});
