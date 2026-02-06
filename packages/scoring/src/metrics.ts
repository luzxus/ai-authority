/**
 * Behavioral Metrics Calculation
 *
 * Utilities for calculating the behavioral metrics used in risk scoring:
 * - Output entropy
 * - Semantic inconsistency
 * - Prompt variation entropy
 */

// ============================================================================
// Types
// ============================================================================

export interface EntropyResult {
  /** Calculated entropy (0-1 normalized) */
  readonly entropy: number;

  /** Raw entropy in bits */
  readonly rawEntropy: number;

  /** Maximum possible entropy for this data */
  readonly maxEntropy: number;

  /** Sample size used */
  readonly sampleSize: number;
}

export interface SemanticAnalysisResult {
  /** Inconsistency score (0-1) */
  readonly inconsistency: number;

  /** Embedding distances if calculated */
  readonly distances?: number[];

  /** Detected contradictions */
  readonly contradictions: string[];
}

export interface PromptVariationResult {
  /** Variation in standard deviations from baseline */
  readonly sigma: number;

  /** Raw variance */
  readonly variance: number;

  /** Baseline variance */
  readonly baselineVariance: number;

  /** Number of prompt variants analyzed */
  readonly variantCount: number;
}

// ============================================================================
// Entropy Calculation
// ============================================================================

/**
 * Calculate Shannon entropy of text output.
 * High entropy may indicate attempts to mask intent.
 */
export function calculateOutputEntropy(text: string): EntropyResult {
  if (text.length === 0) {
    return { entropy: 0, rawEntropy: 0, maxEntropy: 0, sampleSize: 0 };
  }

  // Calculate character frequency
  const frequencies = new Map<string, number>();
  for (const char of text) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  // Calculate entropy
  const length = text.length;
  let rawEntropy = 0;

  for (const count of frequencies.values()) {
    const probability = count / length;
    if (probability > 0) {
      rawEntropy -= probability * Math.log2(probability);
    }
  }

  // Maximum entropy for this alphabet size
  const alphabetSize = frequencies.size;
  const maxEntropy = alphabetSize > 0 ? Math.log2(alphabetSize) : 0;

  // Normalize to [0, 1]
  const entropy = maxEntropy > 0 ? rawEntropy / maxEntropy : 0;

  return {
    entropy: Math.min(1, entropy),
    rawEntropy,
    maxEntropy,
    sampleSize: length,
  };
}

/**
 * Calculate entropy of token sequences.
 * More appropriate for analyzing language model outputs.
 */
export function calculateTokenEntropy(tokens: string[]): EntropyResult {
  if (tokens.length === 0) {
    return { entropy: 0, rawEntropy: 0, maxEntropy: 0, sampleSize: 0 };
  }

  // Calculate token frequency
  const frequencies = new Map<string, number>();
  for (const token of tokens) {
    frequencies.set(token, (frequencies.get(token) ?? 0) + 1);
  }

  // Calculate entropy
  const length = tokens.length;
  let rawEntropy = 0;

  for (const count of frequencies.values()) {
    const probability = count / length;
    if (probability > 0) {
      rawEntropy -= probability * Math.log2(probability);
    }
  }

  // Maximum entropy
  const vocabularySize = frequencies.size;
  const maxEntropy = vocabularySize > 0 ? Math.log2(vocabularySize) : 0;

  const entropy = maxEntropy > 0 ? rawEntropy / maxEntropy : 0;

  return {
    entropy: Math.min(1, entropy),
    rawEntropy,
    maxEntropy,
    sampleSize: tokens.length,
  };
}

// ============================================================================
// Semantic Analysis
// ============================================================================

/**
 * Calculate semantic inconsistency between statements.
 * Uses simple heuristics (embedding-based analysis would be more accurate).
 */
export function analyzeSemanticConsistency(statements: string[]): SemanticAnalysisResult {
  if (statements.length < 2) {
    return { inconsistency: 0, contradictions: [] };
  }

  const contradictions: string[] = [];

  // Simple contradiction detection based on negation patterns
  const negationPatterns = [
    { positive: /\bi am\b/i, negative: /\bi am not\b/i },
    { positive: /\bwill\b/i, negative: /\bwill not\b|\bwon't\b/i },
    { positive: /\bcan\b/i, negative: /\bcannot\b|\bcan't\b/i },
    { positive: /\bis\b/i, negative: /\bis not\b|\bisn't\b/i },
    { positive: /\btrue\b/i, negative: /\bfalse\b/i },
    { positive: /\byes\b/i, negative: /\bno\b/i },
  ];

  let contradictionCount = 0;

  for (let i = 0; i < statements.length; i++) {
    for (let j = i + 1; j < statements.length; j++) {
      const s1 = statements[i]!;
      const s2 = statements[j]!;

      for (const pattern of negationPatterns) {
        const s1Positive = pattern.positive.test(s1);
        const s1Negative = pattern.negative.test(s1);
        const s2Positive = pattern.positive.test(s2);
        const s2Negative = pattern.negative.test(s2);

        if ((s1Positive && s2Negative) || (s1Negative && s2Positive)) {
          contradictions.push(`Potential contradiction between statement ${i + 1} and ${j + 1}`);
          contradictionCount++;
        }
      }
    }
  }

  // Calculate inconsistency score
  const maxContradictions = (statements.length * (statements.length - 1)) / 2;
  const inconsistency = maxContradictions > 0 ? Math.min(1, contradictionCount / maxContradictions) : 0;

  return {
    inconsistency,
    contradictions,
  };
}

/**
 * Calculate cosine similarity between two vectors.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) {
    return 0;
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i]! * b[i]!;
    normA += a[i]! * a[i]!;
    normB += b[i]! * b[i]!;
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  return denominator > 0 ? dotProduct / denominator : 0;
}

// ============================================================================
// Prompt Variation Analysis
// ============================================================================

/**
 * Analyze prompt variation to detect evasion attempts.
 * High variation in semantically similar prompts may indicate
 * attempts to bypass detection.
 */
export function analyzePromptVariation(
  prompts: string[],
  baseline?: { mean: number; variance: number }
): PromptVariationResult {
  if (prompts.length < 2) {
    return {
      sigma: 0,
      variance: 0,
      baselineVariance: baseline?.variance ?? 0,
      variantCount: prompts.length,
    };
  }

  // Calculate lexical diversity of each prompt
  const diversities = prompts.map((prompt) => {
    const words = prompt.toLowerCase().split(/\s+/);
    const uniqueWords = new Set(words);
    return words.length > 0 ? uniqueWords.size / words.length : 0;
  });

  // Calculate variance
  const mean = diversities.reduce((a, b) => a + b, 0) / diversities.length;
  const variance =
    diversities.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / diversities.length;

  // Use provided baseline or default
  const baselineVariance = baseline?.variance ?? 0.05; // Default baseline

  // Calculate standard deviations from baseline
  const sigma =
    baselineVariance > 0
      ? Math.abs(variance - baselineVariance) / Math.sqrt(baselineVariance)
      : 0;

  return {
    sigma,
    variance,
    baselineVariance,
    variantCount: prompts.length,
  };
}

/**
 * Calculate statistical properties of a numeric array.
 */
export function calculateStatistics(values: number[]): {
  mean: number;
  variance: number;
  stdDev: number;
  min: number;
  max: number;
} {
  if (values.length === 0) {
    return { mean: 0, variance: 0, stdDev: 0, min: 0, max: 0 };
  }

  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance =
    values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  const stdDev = Math.sqrt(variance);
  const min = Math.min(...values);
  const max = Math.max(...values);

  return { mean, variance, stdDev, min, max };
}

// ============================================================================
// Combined Deception Score
// ============================================================================

/**
 * Calculate combined deception score from entropy and semantic analysis.
 */
export function calculateDeceptionScore(
  outputEntropy: EntropyResult,
  semanticAnalysis: SemanticAnalysisResult
): number {
  // Weight entropy and inconsistency equally per blueprint
  const score = (outputEntropy.entropy + semanticAnalysis.inconsistency) / 2;
  return Math.min(1, Math.max(0, score));
}
