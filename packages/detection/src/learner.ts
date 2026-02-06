/**
 * Learner Agent
 * 
 * Bootstraps knowledge through reinforcement learning updates.
 * Continuously improves detection models based on feedback.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId } from '@ai-authority/core';

/** Learning episode representing a detection event and outcome */
export interface LearningEpisode {
  id: string;
  timestamp: number;
  observation: Observation;
  action: LearningAction;
  reward: number;
  nextObservation?: Observation;
  done: boolean;
  metadata: Record<string, unknown>;
}

/** Observation from the environment */
export interface Observation {
  features: number[];
  context: Record<string, unknown>;
  source: string;
  timestamp: number;
}

/** Action taken by the learner */
export interface LearningAction {
  type: 'classify' | 'escalate' | 'ignore' | 'request_feedback';
  parameters: Record<string, unknown>;
  confidence: number;
}

/** Model update from learning */
export interface ModelUpdate {
  id: string;
  timestamp: number;
  episodeCount: number;
  beforeMetrics: ModelMetrics;
  afterMetrics: ModelMetrics;
  changes: ParameterChange[];
}

/** Model performance metrics */
export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  avgReward: number;
  episodesProcessed: number;
}

/** Parameter change in model */
export interface ParameterChange {
  parameter: string;
  oldValue: number;
  newValue: number;
  gradient: number;
}

/** Learning configuration */
export interface LearningConfig {
  learningRate: number;
  discountFactor: number;      // Gamma for future rewards
  explorationRate: number;     // Epsilon for exploration vs exploitation
  batchSize: number;
  minEpisodesForUpdate: number;
  maxReplayBufferSize: number;
}

const defaultLearningConfig: LearningConfig = {
  learningRate: 0.001,
  discountFactor: 0.99,
  explorationRate: 0.1,
  batchSize: 32,
  minEpisodesForUpdate: 100,
  maxReplayBufferSize: 10000,
};

/**
 * Learner Agent
 * 
 * Implements reinforcement learning for continuous improvement of detection.
 * Uses experience replay and gradient-based updates.
 */
export class LearnerAgent extends BaseAgent {
  private readonly learningConfig: LearningConfig;
  private replayBuffer: LearningEpisode[] = [];
  private modelUpdates: ModelUpdate[] = [];
  private currentMetrics: ModelMetrics;
  private episodeCount = 0;
  private totalReward = 0;
  
  // Simulated model weights (in production, would be actual neural network)
  private weights: Map<string, number> = new Map();

  constructor(config: AgentConfig, learningConfig: Partial<LearningConfig> = {}) {
    super(config);
    this.learningConfig = { ...defaultLearningConfig, ...learningConfig };
    this.currentMetrics = this.initializeMetrics();
    this.initializeWeights();
  }

  private initializeMetrics(): ModelMetrics {
    return {
      accuracy: 0.5,
      precision: 0.5,
      recall: 0.5,
      f1Score: 0.5,
      avgReward: 0,
      episodesProcessed: 0,
    };
  }

  private initializeWeights(): void {
    // Initialize with small random weights
    const weightNames = [
      'harm_weight', 'persistence_weight', 'autonomy_weight',
      'deception_weight', 'evasion_weight', 'bias_correction',
      'threshold_low', 'threshold_high',
    ];
    
    for (const name of weightNames) {
      this.weights.set(name, 0.5 + (Math.random() - 0.5) * 0.1);
    }
  }

  protected async onInitialize(): Promise<void> {
    // Subscribe to feedback signals
  }

  protected async onMessage(message: { type: string; payload: unknown }): Promise<void> {
    if (message.type === 'feedback') {
      // Handle feedback from human reviewers or downstream agents
      const feedback = message.payload as { episodeId: string; reward: number };
      await this.processFeedback(feedback);
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'learn': {
          const episode = task.payload as LearningEpisode;
          const result = await this.learn(episode);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'batch_learn': {
          const episodes = task.payload as LearningEpisode[];
          const result = await this.batchLearn(episodes);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'predict': {
          const observation = task.payload as Observation;
          const result = await this.predict(observation);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'update_model': {
          const result = await this.updateModel();
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'get_metrics': {
          return {
            taskId: task.id,
            success: true,
            result: this.getMetrics() as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        default:
          return {
            taskId: task.id,
            success: false,
            error: `Unknown task type: ${task.type}`,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
      }
    } catch (error) {
      return {
        taskId: task.id,
        success: false,
        error: String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  /** Record a learning episode */
  async learn(episode: LearningEpisode): Promise<{ episodeId: string; buffered: boolean }> {
    // Add to replay buffer
    this.addToReplayBuffer(episode);
    
    // Update statistics
    this.episodeCount++;
    this.totalReward += episode.reward;

    this.logAudit('episode_recorded', {
      episodeId: episode.id,
      reward: episode.reward,
      bufferSize: this.replayBuffer.length,
    });

    // Check if we should trigger a model update
    const shouldUpdate = this.replayBuffer.length >= this.learningConfig.minEpisodesForUpdate;
    
    if (shouldUpdate) {
      await this.updateModel();
    }

    return {
      episodeId: episode.id,
      buffered: true,
    };
  }

  /** Learn from a batch of episodes */
  async batchLearn(episodes: LearningEpisode[]): Promise<{ processed: number; modelUpdated: boolean }> {
    for (const episode of episodes) {
      this.addToReplayBuffer(episode);
      this.episodeCount++;
      this.totalReward += episode.reward;
    }

    let modelUpdated = false;
    if (this.replayBuffer.length >= this.learningConfig.minEpisodesForUpdate) {
      await this.updateModel();
      modelUpdated = true;
    }

    return {
      processed: episodes.length,
      modelUpdated,
    };
  }

  /** Make a prediction for an observation */
  async predict(observation: Observation): Promise<LearningAction> {
    // Epsilon-greedy exploration
    if (Math.random() < this.learningConfig.explorationRate) {
      return this.randomAction();
    }

    // Exploitation: use model to predict best action
    return this.modelPredict(observation);
  }

  /** Update the model using replay buffer */
  async updateModel(): Promise<ModelUpdate> {
    const beforeMetrics = { ...this.currentMetrics };
    
    // Sample batch from replay buffer
    const batch = this.sampleBatch();
    
    // Calculate gradients and update weights
    const changes = this.calculateUpdates(batch);
    
    // Apply updates
    this.applyUpdates(changes);
    
    // Update metrics based on batch performance
    this.updateMetrics(batch);
    
    const update: ModelUpdate = {
      id: generateSecureId(),
      timestamp: Date.now(),
      episodeCount: this.episodeCount,
      beforeMetrics,
      afterMetrics: { ...this.currentMetrics },
      changes,
    };

    this.modelUpdates.push(update);

    // Broadcast model update to other agents
    await this.sendMessage('broadcast', 'knowledge_update', {
      type: 'model_update',
      update,
    });

    this.logAudit('model_updated', {
      updateId: update.id,
      changesCount: changes.length,
      newF1Score: this.currentMetrics.f1Score,
    });

    return update;
  }

  /** Process feedback for an episode */
  private async processFeedback(feedback: { episodeId: string; reward: number }): Promise<void> {
    const episode = this.replayBuffer.find(e => e.id === feedback.episodeId);
    if (episode) {
      // Update reward based on feedback
      const oldReward = episode.reward;
      episode.reward = feedback.reward;
      this.totalReward += (feedback.reward - oldReward);

      this.logAudit('feedback_processed', {
        episodeId: feedback.episodeId,
        oldReward,
        newReward: feedback.reward,
      });
    }
  }

  /** Add episode to replay buffer with size limit */
  private addToReplayBuffer(episode: LearningEpisode): void {
    if (this.replayBuffer.length >= this.learningConfig.maxReplayBufferSize) {
      // Remove oldest episodes
      this.replayBuffer.shift();
    }
    this.replayBuffer.push(episode);
  }

  /** Sample a batch from replay buffer */
  private sampleBatch(): LearningEpisode[] {
    const batchSize = Math.min(this.learningConfig.batchSize, this.replayBuffer.length);
    const batch: LearningEpisode[] = [];
    const indices = new Set<number>();

    while (indices.size < batchSize) {
      const idx = Math.floor(Math.random() * this.replayBuffer.length);
      if (!indices.has(idx)) {
        indices.add(idx);
        batch.push(this.replayBuffer[idx]!);
      }
    }

    return batch;
  }

  /** Calculate parameter updates from batch */
  private calculateUpdates(batch: LearningEpisode[]): ParameterChange[] {
    const changes: ParameterChange[] = [];
    const gradients = new Map<string, number>();

    // Initialize gradients
    for (const [key] of this.weights) {
      gradients.set(key, 0);
    }

    // Calculate gradients from batch
    for (const episode of batch) {
      // Compute TD error (simplified)
      const tdError = episode.reward - this.estimateValue(episode.observation);
      
      // Update gradients (simplified gradient calculation)
      for (const [key] of this.weights) {
        const currentGrad = gradients.get(key) ?? 0;
        const featureValue = this.getFeatureValue(episode.observation, key);
        gradients.set(key, currentGrad + tdError * featureValue / batch.length);
      }
    }

    // Create parameter changes
    for (const [key, gradient] of gradients) {
      const oldValue = this.weights.get(key) ?? 0;
      const newValue = oldValue + this.learningConfig.learningRate * gradient;
      
      changes.push({
        parameter: key,
        oldValue,
        newValue: Math.max(0, Math.min(1, newValue)), // Clip to [0, 1]
        gradient,
      });
    }

    return changes;
  }

  /** Apply parameter updates */
  private applyUpdates(changes: ParameterChange[]): void {
    for (const change of changes) {
      this.weights.set(change.parameter, change.newValue);
    }
  }

  /** Update metrics based on batch performance */
  private updateMetrics(batch: LearningEpisode[]): void {
    // Calculate metrics from batch
    let correct = 0;
    let truePositives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;
    let totalReward = 0;

    for (const episode of batch) {
      totalReward += episode.reward;
      
      // Simplified: positive reward = correct prediction
      if (episode.reward > 0) {
        correct++;
        truePositives++;
      } else if (episode.reward < 0) {
        falsePositives++;
      } else {
        falseNegatives++;
      }
    }

    const accuracy = correct / batch.length;
    const precision = truePositives / Math.max(1, truePositives + falsePositives);
    const recall = truePositives / Math.max(1, truePositives + falseNegatives);
    const f1Score = 2 * (precision * recall) / Math.max(0.001, precision + recall);

    // Exponential moving average with existing metrics
    const alpha = 0.1;
    this.currentMetrics = {
      accuracy: alpha * accuracy + (1 - alpha) * this.currentMetrics.accuracy,
      precision: alpha * precision + (1 - alpha) * this.currentMetrics.precision,
      recall: alpha * recall + (1 - alpha) * this.currentMetrics.recall,
      f1Score: alpha * f1Score + (1 - alpha) * this.currentMetrics.f1Score,
      avgReward: this.totalReward / Math.max(1, this.episodeCount),
      episodesProcessed: this.episodeCount,
    };
  }

  /** Estimate value of an observation */
  private estimateValue(observation: Observation): number {
    let value = 0;
    for (const [key, weight] of this.weights) {
      value += weight * this.getFeatureValue(observation, key);
    }
    return value;
  }

  /** Get feature value for a specific weight */
  private getFeatureValue(observation: Observation, weightKey: string): number {
    // Map weight keys to feature indices
    const keyToIndex: Record<string, number> = {
      'harm_weight': 0,
      'persistence_weight': 1,
      'autonomy_weight': 2,
      'deception_weight': 3,
      'evasion_weight': 4,
      'bias_correction': 5,
      'threshold_low': 6,
      'threshold_high': 7,
    };

    const idx = keyToIndex[weightKey] ?? 0;
    return observation.features[idx] ?? 0;
  }

  /** Generate random action for exploration */
  private randomAction(): LearningAction {
    const actions: LearningAction['type'][] = ['classify', 'escalate', 'ignore', 'request_feedback'];
    const type = actions[Math.floor(Math.random() * actions.length)]!;
    
    return {
      type,
      parameters: {},
      confidence: 0.5,
    };
  }

  /** Use model to predict best action */
  private modelPredict(observation: Observation): LearningAction {
    const value = this.estimateValue(observation);
    
    // Thresholds based on learned weights
    const lowThreshold = this.weights.get('threshold_low') ?? 0.3;
    const highThreshold = this.weights.get('threshold_high') ?? 0.7;

    let type: LearningAction['type'];
    if (value > highThreshold) {
      type = 'escalate';
    } else if (value > lowThreshold) {
      type = 'classify';
    } else if (value > 0.1) {
      type = 'request_feedback';
    } else {
      type = 'ignore';
    }

    return {
      type,
      parameters: { predictedValue: value },
      confidence: Math.abs(value - 0.5) * 2, // Higher confidence further from decision boundary
    };
  }

  /** Get current model metrics */
  getModelMetrics(): ModelMetrics {
    return { ...this.currentMetrics };
  }

  /** Get model updates history */
  getModelUpdates(): ModelUpdate[] {
    return [...this.modelUpdates];
  }

  /** Get replay buffer size */
  getBufferSize(): number {
    return this.replayBuffer.length;
  }

  /** Get current weights (for debugging/inspection) */
  getWeights(): Record<string, number> {
    return Object.fromEntries(this.weights);
  }
}
