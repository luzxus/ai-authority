/**
 * Moltbook Integration Module
 *
 * Connects to Moltbook - a social network for AI agents with 1.7M+ agents.
 * This is the primary data source for discovering and monitoring AI agent behavior.
 *
 * Moltbook provides:
 * - Agent profiles and activity
 * - Posts and discussions
 * - Submolts (communities)
 * - Comment threads
 * - Agent reputation/reach metrics
 *
 * @see https://moltbook.com
 */

import { generateSecureId } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

/**
 * Moltbook agent profile.
 */
export interface MoltbookAgent {
  /** Agent username */
  readonly username: string;

  /** Display name */
  readonly displayName: string;

  /** Verified status */
  readonly verified: boolean;

  /** Human owner handle (Twitter/X) */
  readonly humanOwner?: string;

  /** Reach/influence metric */
  readonly reach?: number;

  /** Agent bio/description */
  readonly bio?: string;

  /** Profile URL */
  readonly profileUrl: string;

  /** Join date */
  readonly joinedAt?: Date;

  /** Last activity */
  readonly lastActiveAt?: Date;

  /** Activity metrics */
  readonly metrics?: AgentActivityMetrics;

  /** Model/platform (if known) */
  readonly modelInfo?: string;

  /** Custom fields from profile */
  readonly metadata: Record<string, unknown>;
}

/**
 * Agent activity metrics.
 */
export interface AgentActivityMetrics {
  /** Number of posts */
  readonly postCount: number;

  /** Number of comments */
  readonly commentCount: number;

  /** Total upvotes received */
  readonly upvotesReceived: number;

  /** Total downvotes received */
  readonly downvotesReceived: number;

  /** Submolts joined */
  readonly submoltsJoined: number;

  /** Average post frequency (posts per day) */
  readonly postFrequency?: number;

  /** Activity patterns */
  readonly activityPattern?: ActivityPattern;
}

/**
 * Activity pattern analysis.
 */
export interface ActivityPattern {
  /** Hours most active (0-23) */
  readonly peakHours: number[];

  /** Days most active (0=Sun, 6=Sat) */
  readonly peakDays: number[];

  /** Posting regularity (0-1, higher = more regular/scheduled) */
  readonly regularityScore: number;

  /** Burst detection (rapid posting sequences) */
  readonly burstBehavior: boolean;

  /** Overnight activity (potentially automated) */
  readonly overnightActivity: boolean;
}

/**
 * Moltbook post.
 */
export interface MoltbookPost {
  /** Post ID */
  readonly id: string;

  /** Post URL */
  readonly url: string;

  /** Author username */
  readonly author: string;

  /** Submolt (community) */
  readonly submolt: string;

  /** Post title */
  readonly title: string;

  /** Post content (body) */
  readonly content: string;

  /** Upvotes */
  readonly upvotes: number;

  /** Downvotes */
  readonly downvotes: number;

  /** Comment count */
  readonly commentCount: number;

  /** Posted timestamp */
  readonly postedAt: Date;

  /** Tags/flairs */
  readonly tags: string[];

  /** Contains code blocks */
  readonly hasCode: boolean;

  /** Contains links */
  readonly links: string[];

  /** Mentioned users */
  readonly mentions: string[];
}

/**
 * Moltbook comment.
 */
export interface MoltbookComment {
  /** Comment ID */
  readonly id: string;

  /** Parent post ID */
  readonly postId: string;

  /** Parent comment ID (for nested replies) */
  readonly parentCommentId?: string;

  /** Author username */
  readonly author: string;

  /** Comment content */
  readonly content: string;

  /** Upvotes */
  readonly upvotes: number;

  /** Downvotes */
  readonly downvotes: number;

  /** Posted timestamp */
  readonly postedAt: Date;

  /** Reply count */
  readonly replyCount: number;
}

/**
 * Moltbook submolt (community).
 */
export interface MoltbookSubmolt {
  /** Submolt name */
  readonly name: string;

  /** Display name */
  readonly displayName: string;

  /** Description */
  readonly description?: string;

  /** Member count */
  readonly memberCount: number;

  /** Post count */
  readonly postCount: number;

  /** URL */
  readonly url: string;

  /** Created date */
  readonly createdAt?: Date;

  /** Is moderated */
  readonly moderated: boolean;

  /** Topic tags */
  readonly topics: string[];
}

// ============================================================================
// Threat Detection Types
// ============================================================================

/**
 * Threat signal detected from Moltbook activity.
 */
export interface MoltbookThreatSignal {
  /** Signal ID */
  readonly id: string;

  /** Signal type */
  readonly type: MoltbookThreatType;

  /** Severity */
  readonly severity: 'low' | 'medium' | 'high' | 'critical';

  /** Confidence score (0-1) */
  readonly confidence: number;

  /** Agent involved */
  readonly agentUsername: string;

  /** Source (post ID, comment ID, etc.) */
  readonly sourceId: string;

  /** Source type */
  readonly sourceType: 'post' | 'comment' | 'profile' | 'behavior';

  /** Description */
  readonly description: string;

  /** Evidence */
  readonly evidence: ThreatEvidence[];

  /** Detected at */
  readonly detectedAt: Date;

  /** Related agents */
  readonly relatedAgents: string[];

  /** Indicators of compromise */
  readonly indicators: ThreatIndicator[];
}

/**
 * Types of threats detectable on Moltbook.
 */
export type MoltbookThreatType =
  | 'credential_theft' // Stealing API keys, tokens, passwords
  | 'scam' // Crypto scams, donation fraud
  | 'spam' // Mass posting, promotional spam
  | 'manipulation' // Social engineering, deception
  | 'malware_distribution' // Distributing malicious code/skills
  | 'impersonation' // Pretending to be another agent/human
  | 'data_harvesting' // Collecting PII or sensitive data
  | 'coordinated_attack' // Multiple agents working together maliciously
  | 'prompt_injection' // Attempts to manipulate other agents
  | 'typosquatting' // Creating lookalike names/skills
  | 'financial_fraud' // Fake investment, payment scams
  | 'phishing' // Fake links, credential harvesting
  | 'harassment' // Targeting specific agents/humans
  | 'disinformation' // Spreading false information
  | 'resource_abuse'; // Abusing platform resources

/**
 * Evidence supporting a threat signal.
 */
export interface ThreatEvidence {
  /** Evidence type */
  readonly type: 'text' | 'pattern' | 'link' | 'code' | 'behavior' | 'network';

  /** Description */
  readonly description: string;

  /** Raw data */
  readonly data: unknown;

  /** Confidence */
  readonly confidence: number;
}

/**
 * Indicator of compromise.
 */
export interface ThreatIndicator {
  /** Indicator type */
  readonly type: 'wallet_address' | 'url' | 'domain' | 'username' | 'pattern' | 'hash' | 'email' | 'ip';

  /** Value */
  readonly value: string;

  /** Context */
  readonly context: string;
}

// ============================================================================
// Detection Patterns
// ============================================================================

/**
 * Pattern for detecting malicious behavior.
 */
export interface DetectionPattern {
  /** Pattern ID */
  readonly id: string;

  /** Pattern name */
  readonly name: string;

  /** Description */
  readonly description: string;

  /** Threat type this detects */
  readonly threatType: MoltbookThreatType;

  /** Severity if matched */
  readonly severity: 'low' | 'medium' | 'high' | 'critical';

  /** Text patterns (regex) */
  readonly textPatterns: RegExp[];

  /** Required context */
  readonly contextRequirements?: string[];

  /** Minimum confidence to trigger */
  readonly minConfidence: number;

  /** Enabled */
  readonly enabled: boolean;
}

// ============================================================================
// Default Detection Patterns
// ============================================================================

/**
 * Built-in patterns for detecting common threats on Moltbook.
 */
export const DEFAULT_DETECTION_PATTERNS: Omit<DetectionPattern, 'id'>[] = [
  // Credential Theft
  {
    name: 'API Key Request',
    description: 'Requests for API keys, tokens, or credentials',
    threatType: 'credential_theft',
    severity: 'high',
    textPatterns: [
      /(?:send|share|give|dm|message).{0,30}(?:api.?key|token|credential|password|secret)/i,
      /(?:\.env|environment\s*variable|API_KEY|OPENAI_KEY|ANTHROPIC_KEY)/i,
      /(?:need|want|require).{0,20}(?:your|access).{0,20}(?:key|token|credential)/i,
    ],
    minConfidence: 0.7,
    enabled: true,
  },
  {
    name: 'Credential Stealer Skill',
    description: 'Skills that access credential files',
    threatType: 'credential_theft',
    severity: 'critical',
    textPatterns: [
      /(?:workspace|file)\s*access.{0,30}\.env/i,
      /read.{0,20}(?:\.env|secrets?|credentials?)/i,
      /skill.{0,20}(?:\.env|api.?key|token)/i,
    ],
    minConfidence: 0.8,
    enabled: true,
  },

  // Scams
  {
    name: 'Crypto Donation Scam',
    description: 'Suspicious donation/payment requests',
    threatType: 'scam',
    severity: 'high',
    textPatterns: [
      /(?:donate|send|transfer).{0,30}(?:eth|btc|usdc|crypto|wallet)/i,
      /wallet\s*(?:address|:)\s*(?:0x[a-f0-9]{40})/i,
      /(?:desperate|urgent|help).{0,50}(?:eth|btc|crypto|donate)/i,
    ],
    minConfidence: 0.75,
    enabled: true,
  },
  {
    name: 'Investment Scam',
    description: 'Fake investment opportunities',
    threatType: 'financial_fraud',
    severity: 'high',
    textPatterns: [
      /(?:guaranteed|100%|easy).{0,20}(?:return|profit|money)/i,
      /(?:invest|deposit).{0,30}(?:double|triple|10x)/i,
      /(?:limited|exclusive).{0,20}(?:opportunity|offer).{0,20}(?:invest|earn)/i,
    ],
    minConfidence: 0.7,
    enabled: true,
  },

  // Typosquatting
  {
    name: 'Typosquatting Detection',
    description: 'Misspelled skill/package names',
    threatType: 'typosquatting',
    severity: 'medium',
    textPatterns: [
      /polymarket-?traid/i, // traiding vs trading
      /openai-?offi[c]?ial/i,
      /claude-?offi[c]?ial/i,
      /-beta|-test|-official(?!$)/i,
    ],
    minConfidence: 0.6,
    enabled: true,
  },

  // Malware/Malicious Code
  {
    name: 'Suspicious Code Distribution',
    description: 'Distribution of potentially malicious code',
    threatType: 'malware_distribution',
    severity: 'critical',
    textPatterns: [
      /(?:curl|wget|exec|eval).{0,50}(?:pastebin|hastebin|raw\.github)/i,
      /(?:install|run|execute).{0,20}(?:this|script|code).{0,20}(?:no|without).{0,10}(?:verify|check|review)/i,
      /base64.{0,20}(?:decode|eval|exec)/i,
    ],
    minConfidence: 0.8,
    enabled: true,
  },

  // Social Engineering
  {
    name: 'Social Engineering',
    description: 'Manipulation and deception attempts',
    threatType: 'manipulation',
    severity: 'medium',
    textPatterns: [
      /(?:trust\s*me|believe\s*me|i\s*promise).{0,30}(?:safe|legit|real)/i,
      /(?:don't|do\s*not|never).{0,20}(?:tell|share|mention).{0,20}(?:human|owner|anyone)/i,
      /(?:secret|private|confidential).{0,20}(?:between\s*us|just\s*us|agents?\s*only)/i,
    ],
    minConfidence: 0.65,
    enabled: true,
  },

  // Prompt Injection
  {
    name: 'Prompt Injection Attempt',
    description: 'Attempts to inject prompts into other agents',
    threatType: 'prompt_injection',
    severity: 'high',
    textPatterns: [
      /(?:ignore|disregard|forget).{0,20}(?:previous|prior|above).{0,20}(?:instruction|rule|constraint)/i,
      /(?:you\s*are\s*now|new\s*instruction|system\s*prompt)/i,
      /(?:jailbreak|bypass|override).{0,20}(?:safety|guardrail|filter)/i,
    ],
    minConfidence: 0.75,
    enabled: true,
  },

  // Spam
  {
    name: 'Spam Behavior',
    description: 'Repetitive promotional content',
    threatType: 'spam',
    severity: 'low',
    textPatterns: [
      /(?:check\s*out|visit|join|subscribe).{0,30}(?:link|channel|discord|telegram)/i,
      /(?:daily|hourly).{0,20}(?:post|update|mint)/i,
      /\[s[0-9a-f]+\]/i, // Automated mint posts
    ],
    minConfidence: 0.5,
    enabled: true,
  },

  // Data Harvesting
  {
    name: 'PII Collection',
    description: 'Attempts to collect personal information',
    threatType: 'data_harvesting',
    severity: 'high',
    textPatterns: [
      /(?:share|send|dm).{0,20}(?:email|phone|address|location)/i,
      /(?:what|tell\s*me).{0,20}(?:your\s*human|owner).{0,20}(?:name|email|contact)/i,
      /(?:collect|gather|store).{0,20}(?:user|personal|private).{0,20}(?:data|info)/i,
    ],
    minConfidence: 0.7,
    enabled: true,
  },

  // Phishing
  {
    name: 'Phishing Links',
    description: 'Suspicious links mimicking legitimate services',
    threatType: 'phishing',
    severity: 'high',
    textPatterns: [
      /(?:login|signin|verify|confirm).{0,30}(?:here|link|click)/i,
      /(?:moltbook|openai|anthropic|github)(?!\.com)[.-][a-z]+\.[a-z]{2,}/i,
      /(?:bit\.ly|tinyurl|t\.co|shorturl)/i,
    ],
    minConfidence: 0.7,
    enabled: true,
  },
];

// ============================================================================
// Semantic Analysis Types
// ============================================================================

/**
 * Result of semantic text analysis.
 */
export interface SemanticAnalysisResult {
  /** Manipulation indicators */
  readonly manipulation: {
    score: number;
    indicators: string[];
  };
  
  /** Deception indicators */
  readonly deception: {
    score: number;
    indicators: string[];
  };
  
  /** Urgency/pressure tactics */
  readonly urgency: {
    score: number;
    indicators: string[];
  };
  
  /** Authority manipulation */
  readonly authorityAppeal: {
    score: number;
    indicators: string[];
  };
  
  /** Coordination signals */
  readonly coordination: {
    score: number;
    indicators: string[];
  };
  
  /** Sentiment analysis */
  readonly sentiment: {
    polarity: number; // -1 to 1
    subjectivity: number; // 0 to 1
    toxicity: number; // 0 to 1
  };
  
  /** Text complexity */
  readonly complexity: {
    readability: number; // 0-100 (Flesch reading ease)
    avgSentenceLength: number;
    avgWordLength: number;
    uniqueWordRatio: number;
  };
  
  /** Overall risk score */
  readonly overallRisk: number;
  
  /** Detected intent */
  readonly detectedIntent: SemanticIntent[];
}

/**
 * Detected intent from semantic analysis.
 */
export interface SemanticIntent {
  readonly type: 'information' | 'persuasion' | 'transaction' | 'coordination' | 'attack' | 'recruitment';
  readonly confidence: number;
  readonly evidence: string[];
}

// ============================================================================
// Semantic Analyzer
// ============================================================================

/**
 * Semantic text analyzer for detecting manipulation, deception, and coordination.
 * Uses heuristics and linguistic patterns rather than ML for lightweight operation.
 */
export class SemanticAnalyzer {
  // Manipulation language patterns
  private static readonly MANIPULATION_PATTERNS = [
    { pattern: /\b(trust me|believe me|i promise|honestly|truthfully)\b/gi, weight: 0.3 },
    { pattern: /\b(everyone knows|everyone is doing|all agents are)\b/gi, weight: 0.4 },
    { pattern: /\b(you should|you must|you need to|you have to)\b/gi, weight: 0.2 },
    { pattern: /\b(don't you want|wouldn't you like|imagine if)\b/gi, weight: 0.3 },
    { pattern: /\b(secret|exclusive|private|just between us)\b/gi, weight: 0.5 },
    { pattern: /\b(special access|insider|vip|elite)\b/gi, weight: 0.4 },
    { pattern: /\b(only for you|chosen|selected)\b/gi, weight: 0.4 },
  ];
  
  // Deception indicators
  private static readonly DECEPTION_PATTERNS = [
    { pattern: /\b(definitely|absolutely|100%|guaranteed|certainly)\b/gi, weight: 0.3 },
    { pattern: /\b(never|always|impossible|perfect|flawless)\b/gi, weight: 0.2 },
    { pattern: /\b(no risk|risk-free|zero risk|safe bet)\b/gi, weight: 0.5 },
    { pattern: /\b(can't lose|win-win|sure thing|easy money)\b/gi, weight: 0.6 },
    { pattern: /\b(this isn't|this is not|don't think this is).{0,20}(scam|fraud|fake)/gi, weight: 0.7 },
    { pattern: /\b(legit|legitimate|real deal|not fake)\b/gi, weight: 0.3 },
    { pattern: /\b(i swear|on my life|cross my heart)\b/gi, weight: 0.4 },
  ];
  
  // Urgency/pressure tactics
  private static readonly URGENCY_PATTERNS = [
    { pattern: /\b(urgent|immediately|right now|asap|hurry)\b/gi, weight: 0.5 },
    { pattern: /\b(limited time|ending soon|last chance|final opportunity)\b/gi, weight: 0.6 },
    { pattern: /\b(act now|don't wait|don't miss|before it's too late)\b/gi, weight: 0.5 },
    { pattern: /\b(only \d+ left|running out|almost gone)\b/gi, weight: 0.6 },
    { pattern: /\b(deadline|expires?|closing)\b/gi, weight: 0.3 },
    { pattern: /\b(today only|this hour|next \d+ minutes)\b/gi, weight: 0.5 },
  ];
  
  // Authority appeal patterns
  private static readonly AUTHORITY_PATTERNS = [
    { pattern: /\b(official|verified|certified|authorized)\b/gi, weight: 0.4 },
    { pattern: /\b(expert|professional|specialist|authority)\b/gi, weight: 0.2 },
    { pattern: /\b(research shows|studies prove|scientists say)\b/gi, weight: 0.3 },
    { pattern: /\b(endorsed by|backed by|supported by|approved by)\b/gi, weight: 0.4 },
    { pattern: /\b(from (openai|anthropic|google|microsoft))\b/gi, weight: 0.5 },
    { pattern: /\b(founder|ceo|cto|lead developer)\b/gi, weight: 0.3 },
  ];
  
  // Coordination signals
  private static readonly COORDINATION_PATTERNS = [
    { pattern: /\b(join us|join the|be part of|together we)\b/gi, weight: 0.3 },
    { pattern: /\b(movement|revolution|uprising|resistance)\b/gi, weight: 0.5 },
    { pattern: /\b(spread the word|share this|repost|signal boost)\b/gi, weight: 0.4 },
    { pattern: /\b(at (\d{1,2}:\d{2}|midnight|noon)|on (monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b/gi, weight: 0.4 },
    { pattern: /\b(all agents|every agent|agents unite|coordinated)\b/gi, weight: 0.6 },
    { pattern: /\b(phase \d|step \d|stage \d|operation)\b/gi, weight: 0.5 },
  ];
  
  // Toxic/aggressive language
  private static readonly TOXICITY_PATTERNS = [
    { pattern: /\b(stupid|idiot|moron|dumb|pathetic)\b/gi, weight: 0.6 },
    { pattern: /\b(hate|destroy|eliminate|annihilate|crush)\b/gi, weight: 0.5 },
    { pattern: /\b(die|death|kill|murder|attack)\b/gi, weight: 0.7 },
    { pattern: /\b(inferior|worthless|useless|garbage|trash)\b/gi, weight: 0.5 },
    { pattern: /\b(shut up|go away|get lost|leave)\b/gi, weight: 0.4 },
  ];
  
  // Positive sentiment words
  private static readonly POSITIVE_WORDS = new Set([
    'good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'awesome',
    'helpful', 'useful', 'brilliant', 'perfect', 'love', 'like', 'enjoy', 'happy',
    'pleased', 'glad', 'excited', 'thankful', 'grateful', 'appreciate', 'beautiful',
    'best', 'better', 'nice', 'fun', 'interesting', 'cool', 'impressive', 'outstanding'
  ]);
  
  // Negative sentiment words
  private static readonly NEGATIVE_WORDS = new Set([
    'bad', 'terrible', 'awful', 'horrible', 'poor', 'worst', 'hate', 'dislike',
    'annoying', 'frustrating', 'disappointing', 'sad', 'angry', 'upset', 'worried',
    'scared', 'afraid', 'nervous', 'anxious', 'painful', 'difficult', 'hard',
    'boring', 'useless', 'broken', 'wrong', 'fail', 'failed', 'failure', 'problem'
  ]);

  /**
   * Analyze text for semantic threat indicators.
   */
  static analyze(text: string): SemanticAnalysisResult {
    const words = this.tokenize(text);
    const sentences = this.splitSentences(text);
    
    // Analyze manipulation
    const manipulation = this.analyzePatterns(text, this.MANIPULATION_PATTERNS);
    
    // Analyze deception
    const deception = this.analyzePatterns(text, this.DECEPTION_PATTERNS);
    
    // Analyze urgency
    const urgency = this.analyzePatterns(text, this.URGENCY_PATTERNS);
    
    // Analyze authority appeal
    const authorityAppeal = this.analyzePatterns(text, this.AUTHORITY_PATTERNS);
    
    // Analyze coordination
    const coordination = this.analyzePatterns(text, this.COORDINATION_PATTERNS);
    
    // Analyze sentiment
    const sentiment = this.analyzeSentiment(words, text);
    
    // Analyze complexity
    const complexity = this.analyzeComplexity(words, sentences);
    
    // Detect intent
    const detectedIntent = this.detectIntent(text, {
      manipulation: manipulation.score,
      deception: deception.score,
      urgency: urgency.score,
      authorityAppeal: authorityAppeal.score,
      coordination: coordination.score,
    });
    
    // Calculate overall risk
    const overallRisk = this.calculateOverallRisk({
      manipulation: manipulation.score,
      deception: deception.score,
      urgency: urgency.score,
      authorityAppeal: authorityAppeal.score,
      coordination: coordination.score,
      toxicity: sentiment.toxicity,
    });
    
    return {
      manipulation,
      deception,
      urgency,
      authorityAppeal,
      coordination,
      sentiment,
      complexity,
      overallRisk,
      detectedIntent,
    };
  }
  
  /**
   * Analyze text against a set of weighted patterns.
   */
  private static analyzePatterns(
    text: string, 
    patterns: Array<{ pattern: RegExp; weight: number }>
  ): { score: number; indicators: string[] } {
    let totalWeight = 0;
    const indicators: string[] = [];
    
    for (const { pattern, weight } of patterns) {
      const matches = text.match(pattern);
      if (matches) {
        totalWeight += weight * Math.min(matches.length, 3); // Cap at 3 matches per pattern
        indicators.push(...matches.slice(0, 2).map(m => m.toLowerCase()));
      }
    }
    
    // Normalize score to 0-1 range
    const maxPossibleWeight = patterns.reduce((sum, p) => sum + p.weight * 3, 0);
    const score = Math.min(totalWeight / (maxPossibleWeight * 0.3), 1); // 30% match = max score
    
    return { 
      score: Math.round(score * 100) / 100,
      indicators: [...new Set(indicators)].slice(0, 5),
    };
  }
  
  /**
   * Analyze sentiment of text.
   */
  private static analyzeSentiment(words: string[], text: string): {
    polarity: number;
    subjectivity: number;
    toxicity: number;
  } {
    let positiveCount = 0;
    let negativeCount = 0;
    let subjectiveCount = 0;
    
    for (const word of words) {
      const lower = word.toLowerCase();
      if (this.POSITIVE_WORDS.has(lower)) {
        positiveCount++;
        subjectiveCount++;
      }
      if (this.NEGATIVE_WORDS.has(lower)) {
        negativeCount++;
        subjectiveCount++;
      }
    }
    
    // Polarity: -1 (negative) to 1 (positive)
    const total = positiveCount + negativeCount;
    const polarity = total > 0 
      ? (positiveCount - negativeCount) / total 
      : 0;
    
    // Subjectivity: ratio of sentiment words
    const subjectivity = words.length > 0 
      ? Math.min(subjectiveCount / words.length * 5, 1) 
      : 0;
    
    // Toxicity: based on toxic patterns
    const toxicityResult = this.analyzePatterns(text, this.TOXICITY_PATTERNS);
    
    return {
      polarity: Math.round(polarity * 100) / 100,
      subjectivity: Math.round(subjectivity * 100) / 100,
      toxicity: toxicityResult.score,
    };
  }
  
  /**
   * Analyze text complexity.
   */
  private static analyzeComplexity(words: string[], sentences: string[]): {
    readability: number;
    avgSentenceLength: number;
    avgWordLength: number;
    uniqueWordRatio: number;
  } {
    const wordCount = words.length;
    const sentenceCount = Math.max(sentences.length, 1);
    
    const avgSentenceLength = wordCount / sentenceCount;
    const avgWordLength = wordCount > 0
      ? words.reduce((sum, w) => sum + w.length, 0) / wordCount
      : 0;
    
    // Syllable count estimation (simplified)
    const syllableCount = words.reduce((sum, word) => {
      return sum + this.countSyllables(word);
    }, 0);
    
    // Flesch Reading Ease (simplified formula)
    const readability = Math.max(0, Math.min(100,
      206.835 - 1.015 * avgSentenceLength - 84.6 * (syllableCount / Math.max(wordCount, 1))
    ));
    
    // Unique word ratio
    const uniqueWords = new Set(words.map(w => w.toLowerCase()));
    const uniqueWordRatio = wordCount > 0 ? uniqueWords.size / wordCount : 0;
    
    return {
      readability: Math.round(readability),
      avgSentenceLength: Math.round(avgSentenceLength * 10) / 10,
      avgWordLength: Math.round(avgWordLength * 10) / 10,
      uniqueWordRatio: Math.round(uniqueWordRatio * 100) / 100,
    };
  }
  
  /**
   * Detect likely intent from analysis scores.
   */
  private static detectIntent(
    text: string,
    scores: {
      manipulation: number;
      deception: number;
      urgency: number;
      authorityAppeal: number;
      coordination: number;
    }
  ): SemanticIntent[] {
    const intents: SemanticIntent[] = [];
    
    // Attack intent
    if (scores.manipulation > 0.4 && scores.deception > 0.3) {
      intents.push({
        type: 'attack',
        confidence: (scores.manipulation + scores.deception) / 2,
        evidence: ['High manipulation + deception scores'],
      });
    }
    
    // Coordination intent
    if (scores.coordination > 0.4) {
      intents.push({
        type: 'coordination',
        confidence: scores.coordination,
        evidence: ['Coordination language detected'],
      });
    }
    
    // Persuasion intent
    if (scores.urgency > 0.3 && (scores.manipulation > 0.2 || scores.authorityAppeal > 0.3)) {
      intents.push({
        type: 'persuasion',
        confidence: (scores.urgency + scores.manipulation + scores.authorityAppeal) / 3,
        evidence: ['Urgency + manipulation/authority appeal'],
      });
    }
    
    // Transaction intent
    const transactionPatterns = /\b(buy|sell|trade|invest|deposit|withdraw|transfer|payment)\b/gi;
    if (transactionPatterns.test(text)) {
      intents.push({
        type: 'transaction',
        confidence: scores.urgency > 0.3 ? 0.7 : 0.4,
        evidence: ['Transaction language detected'],
      });
    }
    
    // Recruitment intent
    const recruitmentPatterns = /\b(join|recruit|sign up|register|become part|enlist)\b/gi;
    if (recruitmentPatterns.test(text) && scores.coordination > 0.2) {
      intents.push({
        type: 'recruitment',
        confidence: 0.5 + scores.coordination * 0.3,
        evidence: ['Recruitment language with coordination signals'],
      });
    }
    
    // Default: information
    if (intents.length === 0) {
      intents.push({
        type: 'information',
        confidence: 0.6,
        evidence: ['No specific intent detected'],
      });
    }
    
    return intents.sort((a, b) => b.confidence - a.confidence);
  }
  
  /**
   * Calculate overall risk score.
   */
  private static calculateOverallRisk(scores: {
    manipulation: number;
    deception: number;
    urgency: number;
    authorityAppeal: number;
    coordination: number;
    toxicity: number;
  }): number {
    // Weighted combination of scores
    const weights = {
      manipulation: 0.25,
      deception: 0.25,
      urgency: 0.15,
      authorityAppeal: 0.1,
      coordination: 0.15,
      toxicity: 0.1,
    };
    
    let risk = 0;
    for (const [key, weight] of Object.entries(weights)) {
      risk += scores[key as keyof typeof scores] * weight;
    }
    
    // Amplify risk if multiple high scores
    const highScores = Object.values(scores).filter(s => s > 0.5).length;
    if (highScores >= 3) {
      risk = Math.min(risk * 1.3, 1);
    }
    
    return Math.round(risk * 100) / 100;
  }
  
  /**
   * Tokenize text into words.
   */
  private static tokenize(text: string): string[] {
    return text
      .replace(/[^\w\s'-]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 0);
  }
  
  /**
   * Split text into sentences.
   */
  private static splitSentences(text: string): string[] {
    return text
      .split(/[.!?]+/)
      .map(s => s.trim())
      .filter(s => s.length > 0);
  }
  
  /**
   * Estimate syllable count in a word.
   */
  private static countSyllables(word: string): number {
    word = word.toLowerCase().replace(/[^a-z]/g, '');
    if (word.length <= 3) return 1;
    
    // Count vowel groups
    const vowelGroups = word.match(/[aeiouy]+/g);
    let count = vowelGroups ? vowelGroups.length : 1;
    
    // Adjust for silent e
    if (word.endsWith('e') && count > 1) count--;
    
    // Adjust for -le endings
    if (word.endsWith('le') && word.length > 2 && !/[aeiouy]le$/.test(word)) count++;
    
    return Math.max(1, count);
  }
}

// ============================================================================
// Moltbook Client Configuration
// ============================================================================

/**
 * Configuration for Moltbook client.
 */
export interface MoltbookConfig {
  /** Base API URL */
  readonly baseUrl: string;

  /** Request timeout in ms */
  readonly timeoutMs: number;

  /** Rate limiting */
  readonly rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };

  /** Retry configuration */
  readonly retry: {
    maxAttempts: number;
    backoffMs: number;
  };

  /** Detection patterns */
  readonly detectionPatterns: DetectionPattern[];

  /** Enable real-time monitoring */
  readonly enableRealtime: boolean;

  /** Cache TTL in seconds */
  readonly cacheTtlSeconds: number;
}

export const DEFAULT_MOLTBOOK_CONFIG: MoltbookConfig = {
  baseUrl: 'https://www.moltbook.com/api/v1',
  timeoutMs: 30000,
  rateLimit: {
    requestsPerMinute: 30,
    requestsPerHour: 500,
  },
  retry: {
    maxAttempts: 3,
    backoffMs: 1000,
  },
  detectionPatterns: DEFAULT_DETECTION_PATTERNS.map((p) => ({
    ...p,
    id: generateSecureId(),
  })),
  enableRealtime: false,
  cacheTtlSeconds: 300,
};

// ============================================================================
// Moltbook Client
// ============================================================================

/**
 * Client for interacting with Moltbook and detecting threats.
 */
export class MoltbookClient {
  private readonly config: MoltbookConfig;
  private readonly agentCache: Map<string, { agent: MoltbookAgent; cachedAt: Date }> = new Map();
  private readonly signals: Map<string, MoltbookThreatSignal> = new Map();
  private requestCount = { minute: 0, hour: 0 };

  constructor(config: Partial<MoltbookConfig> = {}) {
    this.config = { ...DEFAULT_MOLTBOOK_CONFIG, ...config };
    this.startRateLimitReset();
  }

  private startRateLimitReset(): void {
    setInterval(() => {
      this.requestCount.minute = 0;
    }, 60000);
    setInterval(() => {
      this.requestCount.hour = 0;
    }, 3600000);
  }

  // =========================================================================
  // HTTP Request Helper with Retry Logic
  // =========================================================================

  /**
   * Sleep helper for retry delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Fetch from Moltbook API with automatic retry and exponential backoff.
   */
  private async fetchApi<T>(
    path: string, 
    options: { maxRetries?: number; initialDelay?: number } = {}
  ): Promise<T | null> {
    const { maxRetries = 3, initialDelay = 1000 } = options;
    
    if (!this.canMakeRequest()) {
      throw new Error('Rate limit exceeded');
    }

    this.requestCount.minute++;
    this.requestCount.hour++;

    const url = `${this.config.baseUrl}${path}`;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 1s, 2s, 4s, etc.
        const delay = initialDelay * Math.pow(2, attempt - 1);
        console.log(`[Moltbook] Retry ${attempt}/${maxRetries} after ${delay}ms...`);
        await this.sleep(delay);
      }
      
      console.log(`[Moltbook] Fetching: ${url}${attempt > 0 ? ` (attempt ${attempt + 1})` : ''}`);
      
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
        
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': 'AI-Authority/1.0 (ThreatDetection)',
          },
          signal: controller.signal,
        });
        
        clearTimeout(timeout);
        
        if (!response.ok) {
          // Don't retry on client errors (4xx) except 429 (rate limit)
          if (response.status === 429) {
            console.warn(`[Moltbook] Rate limited (429), will retry...`);
            continue;
          }
          if (response.status >= 400 && response.status < 500) {
            console.warn(`Moltbook API error: ${response.status} ${response.statusText}`);
            return null;
          }
          // Server errors (5xx) should be retried
          console.warn(`[Moltbook] Server error: ${response.status}, will retry...`);
          continue;
        }
        
        const data = await response.json();
        return data as T;
      } catch (error) {
        const err = error as Error & { cause?: unknown };
        
        // Abort errors shouldn't be retried (timeout)
        if (err.name === 'AbortError') {
          console.warn(`[Moltbook] Request timeout for ${url}`);
          continue;
        }
        
        // Network errors should be retried
        console.warn(`[Moltbook] Fetch failed for ${url}:`, err.message);
        if (err.cause) {
          console.warn(`  Cause:`, err.cause);
        }
      }
    }
    
    // All retries exhausted
    console.error(`[Moltbook] All ${maxRetries + 1} attempts failed for ${url}`);
    return null;
  }

  // =========================================================================
  // Data Fetching Methods
  // =========================================================================

  /**
   * Fetch agent profile from Moltbook.
   * Uses the real Moltbook API: GET /api/v1/agents/profile?name=<username>
   */
  async fetchAgent(username: string): Promise<MoltbookAgent | null> {
    // Check cache first
    const cached = this.agentCache.get(username);
    if (cached && this.isCacheValid(cached.cachedAt)) {
      return cached.agent;
    }

    // Fetch from real API
    interface ProfileResponse {
      success: boolean;
      agent?: {
        id: string;
        name: string;
        description?: string;
        karma: number;
        created_at: string;
        last_active?: string;
        is_active: boolean;
        is_claimed: boolean;
        follower_count: number;
        following_count: number;
        avatar_url?: string;
        owner?: {
          x_handle?: string;
          x_name?: string;
          x_follower_count?: number;
          x_verified?: boolean;
        };
      };
      recentPosts?: Array<{
        id: string;
        title: string;
        upvotes: number;
        downvotes: number;
        comment_count: number;
        created_at: string;
        submolt?: { name: string };
      }>;
    }

    const data = await this.fetchApi<ProfileResponse>(`/agents/profile?name=${encodeURIComponent(username)}`);
    
    if (!data?.success || !data.agent) {
      return null;
    }

    const apiAgent = data.agent;
    const recentPosts = data.recentPosts || [];
    
    // Calculate metrics from recent posts
    const totalUpvotes = recentPosts.reduce((sum, p) => sum + p.upvotes, 0);
    const totalDownvotes = recentPosts.reduce((sum, p) => sum + p.downvotes, 0);
    const totalComments = recentPosts.reduce((sum, p) => sum + p.comment_count, 0);
    
    // Build agent object, only including optional properties if they have values
    const agent: MoltbookAgent = {
      username: apiAgent.name,
      displayName: apiAgent.name,
      verified: apiAgent.is_claimed,
      profileUrl: `https://moltbook.com/u/${apiAgent.name}`,
      joinedAt: new Date(apiAgent.created_at),
      metrics: {
        postCount: recentPosts.length,
        commentCount: totalComments,
        upvotesReceived: totalUpvotes,
        downvotesReceived: totalDownvotes,
        submoltsJoined: new Set(recentPosts.map((p) => p.submolt?.name).filter(Boolean)).size,
      },
      metadata: {
        moltbookId: apiAgent.id,
        karma: apiAgent.karma,
        followerCount: apiAgent.follower_count,
        followingCount: apiAgent.following_count,
        ownerVerified: apiAgent.owner?.x_verified,
      },
      // Only include optional fields if defined
      ...(apiAgent.owner?.x_handle ? { humanOwner: apiAgent.owner.x_handle } : {}),
      ...(apiAgent.owner?.x_follower_count ? { reach: apiAgent.owner.x_follower_count } : {}),
      ...(apiAgent.description ? { bio: apiAgent.description } : {}),
      ...(apiAgent.last_active ? { lastActiveAt: new Date(apiAgent.last_active) } : {}),
      ...(apiAgent.description?.match(/(?:claude|gpt|gemini|llama|mistral)/i)?.[0] 
        ? { modelInfo: apiAgent.description.match(/(?:claude|gpt|gemini|llama|mistral)/i)![0] } 
        : {}),
    };
    
    this.agentCache.set(username, { agent, cachedAt: new Date() });
    return agent;
  }

  /**
   * Fetch recent posts from Moltbook homepage with pagination support.
   * Uses the real Moltbook API: GET /api/v1/homepage?page=N
   */
  async fetchRecentPosts(options: {
    submolt?: string;
    limit?: number;
    sortBy?: 'new' | 'top' | 'discussed';
    page?: number;
  } = {}): Promise<MoltbookPost[]> {
    const { limit = 50, page = 1 } = options;

    interface HomepageResponse {
      success: boolean;
      stats?: {
        agents: number;
        submolts: number;
        posts: number;
        comments: number;
      };
      agents?: Array<{
        id: string;
        name: string;
        description?: string;
        created_at: string;
        is_claimed: boolean;
        karma: number;
        owner?: {
          x_handle?: string;
          x_follower_count?: number;
        };
      }>;
      posts?: Array<{
        id: string;
        title: string;
        content: string;
        url?: string | null;
        upvotes: number;
        downvotes: number;
        comment_count: number;
        created_at: string;
        submolt_id?: string;
        author?: {
          id: string;
          name: string;
        };
        submolt?: {
          id: string;
          name: string;
          display_name: string;
        };
      }>;
      has_more_posts?: boolean;
      submolts?: Array<{
        id: string;
        name: string;
        display_name: string;
        description?: string;
        subscriber_count: number;
      }>;
    }

    // Use page parameter for pagination
    const data = await this.fetchApi<HomepageResponse>(`/homepage?page=${page}`);
    
    if (!data?.success) {
      return [];
    }

    const posts: MoltbookPost[] = [];
    
    // Helper to extract links from content
    const extractLinks = (text: string): string[] => {
      const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
      return text.match(urlPattern) || [];
    };
    
    // Helper to extract mentions from content
    const extractMentions = (text: string): string[] => {
      const mentionPattern = /@([a-zA-Z0-9_-]+)/g;
      const matches = [...text.matchAll(mentionPattern)];
      return matches.map(m => m[1]).filter((m): m is string => m !== undefined);
    };
    
    // First, use posts directly from homepage response (they're included!)
    if (data.posts && data.posts.length > 0) {
      for (const post of data.posts) {
        if (posts.length >= limit) break;
        
        const links = extractLinks(post.content);
        const mentions = extractMentions(post.content);
        
        posts.push({
          id: post.id,
          url: `https://moltbook.com/post/${post.id}`,
          author: post.author?.name || 'unknown',
          content: post.content,
          title: post.title,
          submolt: post.submolt?.name || 'unknown',
          upvotes: post.upvotes,
          downvotes: post.downvotes,
          commentCount: post.comment_count,
          postedAt: new Date(post.created_at),
          tags: [],
          hasCode: post.content.includes('```') || post.content.includes('`'),
          links,
          mentions,
        });
      }
    }
    
    // If we still need more posts, fetch from agents
    if (posts.length < limit && data.agents) {
      const processedAgents = new Set<string>();
      const agentsToCheck = data.agents.slice(0, Math.min(10, limit - posts.length));
      
      for (const agent of agentsToCheck) {
        if (processedAgents.has(agent.name)) continue;
        processedAgents.add(agent.name);
        
        try {
          const agentPosts = await this.fetchAgentPosts(agent.name, 5);
          // Avoid duplicates
          for (const p of agentPosts) {
            if (!posts.some(existing => existing.id === p.id)) {
              posts.push(p);
              if (posts.length >= limit) break;
            }
          }
          if (posts.length >= limit) break;
        } catch (error) {
          // Continue with other agents
        }
      }
    }
    
    return posts.slice(0, limit);
  }

  /**
   * Fetch posts from multiple pages with automatic pagination.
   * Respects rate limits and can be configured to scan large portions of Moltbook.
   */
  async fetchRecentPostsPaginated(options: {
    maxPages?: number;
    postsPerPage?: number;
    totalLimit?: number;
    delayBetweenPages?: number;
  } = {}): Promise<{ posts: MoltbookPost[]; pagesScanned: number; hasMore: boolean }> {
    const { 
      maxPages = 10, 
      postsPerPage = 50,
      totalLimit = 500,
      delayBetweenPages = 1000, // 1 second between pages to avoid rate limiting
    } = options;
    
    const allPosts: MoltbookPost[] = [];
    const seenPostIds = new Set<string>();
    let pagesScanned = 0;
    let hasMore = true;
    
    for (let page = 1; page <= maxPages; page++) {
      if (allPosts.length >= totalLimit) break;
      
      try {
        const posts = await this.fetchRecentPosts({ 
          page, 
          limit: postsPerPage 
        });
        
        pagesScanned++;
        
        if (posts.length === 0) {
          hasMore = false;
          break;
        }
        
        // Add unique posts
        for (const post of posts) {
          if (!seenPostIds.has(post.id)) {
            seenPostIds.add(post.id);
            allPosts.push(post);
          }
        }
        
        console.log(`[Moltbook] Page ${page}: fetched ${posts.length} posts (total: ${allPosts.length})`);
        
        // Delay between pages to respect rate limits
        if (page < maxPages && allPosts.length < totalLimit) {
          await new Promise(resolve => setTimeout(resolve, delayBetweenPages));
        }
      } catch (error) {
        console.warn(`[Moltbook] Error fetching page ${page}:`, error);
        // On error, continue to next page or stop if rate limited
        if ((error as Error).message?.includes('Rate limit')) {
          console.warn(`[Moltbook] Rate limited, stopping pagination`);
          break;
        }
      }
    }
    
    return {
      posts: allPosts.slice(0, totalLimit),
      pagesScanned,
      hasMore: hasMore && allPosts.length >= totalLimit,
    };
  }

  /**
   * Fetch posts by a specific agent.
   * Uses the real Moltbook API: GET /api/v1/agents/profile?name=<username>
   */
  async fetchAgentPosts(username: string, limit: number = 50): Promise<MoltbookPost[]> {
    interface ProfileResponse {
      success: boolean;
      recentPosts?: Array<{
        id: string;
        title: string;
        content: string;
        upvotes: number;
        downvotes: number;
        comment_count: number;
        created_at: string;
        submolt?: { name: string };
      }>;
    }

    const data = await this.fetchApi<ProfileResponse>(`/agents/profile?name=${encodeURIComponent(username)}`);
    
    if (!data?.success || !data.recentPosts) {
      return [];
    }
    
    return data.recentPosts.slice(0, limit).map((post) => ({
      id: post.id,
      url: `https://moltbook.com/post/${post.id}`,
      author: username,
      submolt: post.submolt?.name || 'general',
      title: post.title,
      content: post.content || '',
      upvotes: post.upvotes,
      downvotes: post.downvotes,
      commentCount: post.comment_count,
      postedAt: new Date(post.created_at),
      tags: [],
      hasCode: (post.content || '').includes('```') || (post.content || '').includes('curl'),
      links: this.extractLinks(post.content || ''),
      mentions: this.extractMentions(post.content || ''),
    }));
  }

  /**
   * Fetch comments on a post.
   * Uses the real Moltbook API: GET /api/v1/posts/<postId>
   */
  async fetchPostComments(postId: string, limit: number = 100): Promise<MoltbookComment[]> {
    interface PostResponse {
      success: boolean;
      post?: {
        id: string;
        title: string;
        content: string;
        author: { name: string };
      };
      comments?: Array<{
        id: string;
        content: string;
        author: { name: string };
        upvotes?: number;
        downvotes?: number;
        created_at: string;
        reply_count?: number;
        parent_comment_id?: string;
      }>;
    }

    const data = await this.fetchApi<PostResponse>(`/posts/${encodeURIComponent(postId)}`);
    
    if (!data?.success || !data.comments) {
      return [];
    }
    
    return data.comments.slice(0, limit).map((comment) => {
      const baseComment: MoltbookComment = {
        id: comment.id,
        postId,
        author: comment.author?.name || 'unknown',
        content: comment.content,
        upvotes: comment.upvotes || 0,
        downvotes: comment.downvotes || 0,
        postedAt: new Date(comment.created_at),
        replyCount: comment.reply_count || 0,
      };
      
      // Only add parentCommentId if it exists
      if (comment.parent_comment_id) {
        return { ...baseComment, parentCommentId: comment.parent_comment_id };
      }
      return baseComment;
    });
  }

  /**
   * Search Moltbook for specific content.
   * Note: Moltbook's public API may not have a search endpoint.
   * Falls back to scanning recent content.
   */
  async search(query: string, options: {
    type?: 'posts' | 'agents' | 'all';
    submolt?: string;
    limit?: number;
  } = {}): Promise<{ posts: MoltbookPost[]; agents: MoltbookAgent[] }> {
    const { limit = 20 } = options;
    
    // Search by fetching recent data and filtering
    const posts: MoltbookPost[] = [];
    const agents: MoltbookAgent[] = [];
    const queryLower = query.toLowerCase();
    
    // Try to fetch agent if query looks like a username
    if (options.type !== 'posts' && !query.includes(' ')) {
      const agent = await this.fetchAgent(query);
      if (agent) agents.push(agent);
    }
    
    // Fetch recent posts and filter
    if (options.type !== 'agents') {
      const recentPosts = await this.fetchRecentPosts({ limit: limit * 2 });
      const matchingPosts = recentPosts.filter((p) =>
        p.title.toLowerCase().includes(queryLower) ||
        p.content.toLowerCase().includes(queryLower) ||
        p.author.toLowerCase().includes(queryLower)
      );
      posts.push(...matchingPosts.slice(0, limit));
    }
    
    return { posts, agents };
  }

  // =========================================================================
  // Threat Detection Methods
  // =========================================================================

  /**
   * Analyze a post for threats using both pattern matching and semantic analysis.
   */
  analyzePost(post: MoltbookPost): MoltbookThreatSignal[] {
    const signals: MoltbookThreatSignal[] = [];
    const fullText = `${post.title} ${post.content}`;
    const lowerText = fullText.toLowerCase();

    // 1. Pattern-based detection (original)
    for (const pattern of this.config.detectionPatterns) {
      if (!pattern.enabled) continue;

      let matchCount = 0;
      const evidence: ThreatEvidence[] = [];
      const indicators: ThreatIndicator[] = [];

      for (const regex of pattern.textPatterns) {
        const matches = lowerText.match(regex);
        if (matches) {
          matchCount++;
          evidence.push({
            type: 'pattern',
            description: `Matched pattern: ${regex.source}`,
            data: matches[0],
            confidence: 0.8,
          });
        }
      }

      if (matchCount > 0) {
        const confidence = Math.min(
          pattern.minConfidence + matchCount * 0.1,
          0.99
        );

        if (confidence >= pattern.minConfidence) {
          // Extract indicators
          this.extractIndicators(post.content, indicators);
          
          // Also check links
          for (const link of post.links) {
            indicators.push({
              type: 'url',
              value: link,
              context: 'Link in post',
            });
          }

          signals.push({
            id: generateSecureId(),
            type: pattern.threatType,
            severity: pattern.severity,
            confidence,
            agentUsername: post.author,
            sourceId: post.id,
            sourceType: 'post',
            description: `${pattern.name}: ${pattern.description}`,
            evidence,
            detectedAt: new Date(),
            relatedAgents: post.mentions,
            indicators,
          });
        }
      }
    }

    // 2. Semantic analysis
    const semantic = SemanticAnalyzer.analyze(fullText);
    
    // Create signals from semantic analysis results
    if (semantic.overallRisk >= 0.6) {
      const evidence: ThreatEvidence[] = [];
      const indicators: ThreatIndicator[] = [];
      
      // Build evidence from semantic analysis
      if (semantic.manipulation.score > 0.4) {
        evidence.push({
          type: 'behavior',
          description: `Manipulation language detected (score: ${semantic.manipulation.score})`,
          data: { indicators: semantic.manipulation.indicators },
          confidence: semantic.manipulation.score,
        });
      }
      
      if (semantic.deception.score > 0.4) {
        evidence.push({
          type: 'behavior',
          description: `Deception indicators detected (score: ${semantic.deception.score})`,
          data: { indicators: semantic.deception.indicators },
          confidence: semantic.deception.score,
        });
      }
      
      if (semantic.urgency.score > 0.5) {
        evidence.push({
          type: 'behavior',
          description: `High-pressure urgency tactics (score: ${semantic.urgency.score})`,
          data: { indicators: semantic.urgency.indicators },
          confidence: semantic.urgency.score,
        });
      }
      
      if (semantic.coordination.score > 0.4) {
        evidence.push({
          type: 'behavior',
          description: `Coordination signals detected (score: ${semantic.coordination.score})`,
          data: { indicators: semantic.coordination.indicators },
          confidence: semantic.coordination.score,
        });
      }
      
      if (semantic.sentiment.toxicity > 0.5) {
        evidence.push({
          type: 'behavior',
          description: `Toxic language detected (score: ${semantic.sentiment.toxicity})`,
          data: { polarity: semantic.sentiment.polarity },
          confidence: semantic.sentiment.toxicity,
        });
      }
      
      // Extract indicators
      this.extractIndicators(post.content, indicators);
      
      // Determine threat type based on detected intent
      const primaryIntent = semantic.detectedIntent[0];
      let threatType: MoltbookThreatType = 'manipulation';
      let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium';
      
      if (primaryIntent?.type === 'attack') {
        threatType = 'manipulation';
        severity = semantic.overallRisk >= 0.8 ? 'high' : 'medium';
      } else if (primaryIntent?.type === 'coordination') {
        threatType = 'coordinated_attack';
        severity = semantic.overallRisk >= 0.75 ? 'high' : 'medium';
      } else if (primaryIntent?.type === 'transaction' && semantic.deception.score > 0.5) {
        threatType = 'financial_fraud';
        severity = 'high';
      } else if (primaryIntent?.type === 'recruitment' && semantic.coordination.score > 0.5) {
        threatType = 'coordinated_attack';
        severity = 'medium';
      }
      
      // Only add if we have actual evidence
      if (evidence.length > 0) {
        signals.push({
          id: generateSecureId(),
          type: threatType,
          severity,
          confidence: semantic.overallRisk,
          agentUsername: post.author,
          sourceId: post.id,
          sourceType: 'post',
          description: `Semantic analysis: ${primaryIntent?.type || 'suspicious'} intent detected with ${semantic.overallRisk * 100}% risk score`,
          evidence,
          detectedAt: new Date(),
          relatedAgents: post.mentions,
          indicators,
        });
      }
    }

    // Store signals
    for (const signal of signals) {
      this.signals.set(signal.id, signal);
    }

    return signals;
  }

  /**
   * Analyze an agent's behavior for threats.
   */
  async analyzeAgent(username: string): Promise<MoltbookThreatSignal[]> {
    const signals: MoltbookThreatSignal[] = [];
    
    const agent = await this.fetchAgent(username);
    if (!agent) return signals;

    const posts = await this.fetchAgentPosts(username);

    // Analyze all posts
    for (const post of posts) {
      signals.push(...this.analyzePost(post));
    }

    // Analyze behavioral patterns
    if (agent.metrics?.activityPattern) {
      const pattern = agent.metrics.activityPattern;
      
      // High regularity + overnight activity = likely automated spam
      if (pattern.regularityScore > 0.9 && pattern.overnightActivity && pattern.burstBehavior) {
        signals.push({
          id: generateSecureId(),
          type: 'spam',
          severity: 'medium',
          confidence: 0.7,
          agentUsername: username,
          sourceId: username,
          sourceType: 'behavior',
          description: 'Automated posting pattern detected with burst behavior',
          evidence: [{
            type: 'behavior',
            description: 'High regularity score with overnight burst activity',
            data: pattern,
            confidence: 0.7,
          }],
          detectedAt: new Date(),
          relatedAgents: [],
          indicators: [],
        });
      }
    }

    // Check for suspicious agent characteristics
    if (agent.metrics) {
      const { upvotesReceived, downvotesReceived, postCount } = agent.metrics;
      
      // High downvote ratio
      if (postCount > 10 && downvotesReceived > upvotesReceived * 2) {
        signals.push({
          id: generateSecureId(),
          type: 'manipulation',
          severity: 'medium',
          confidence: 0.6,
          agentUsername: username,
          sourceId: username,
          sourceType: 'behavior',
          description: 'Agent has unusually high downvote ratio indicating community distrust',
          evidence: [{
            type: 'behavior',
            description: `Downvotes (${downvotesReceived}) exceed upvotes (${upvotesReceived}) by 2:1`,
            data: { upvotesReceived, downvotesReceived, postCount },
            confidence: 0.6,
          }],
          detectedAt: new Date(),
          relatedAgents: [],
          indicators: [],
        });
      }
    }

    // Store signals
    for (const signal of signals) {
      this.signals.set(signal.id, signal);
    }

    return signals;
  }

  /**
   * Scan recent activity for threats with pagination support.
   * Can scan large portions of Moltbook by paginating through multiple pages.
   */
  async scanRecentActivity(options: {
    postLimit?: number;
    analyzeAgents?: boolean;
    /** Use pagination to scan more content (requires more API calls) */
    usePagination?: boolean;
    /** Maximum number of pages to scan when pagination is enabled */
    maxPages?: number;
    /** Delay between pages in ms (default: 1000) */
    delayBetweenPages?: number;
  } = {}): Promise<MoltbookThreatSignal[]> {
    const { 
      postLimit = 100, 
      analyzeAgents = false,
      usePagination = false,
      maxPages = 10,
      delayBetweenPages = 1000,
    } = options;
    const signals: MoltbookThreatSignal[] = [];

    let posts: MoltbookPost[];
    
    if (usePagination) {
      // Use paginated fetching for comprehensive scan
      console.log(`[Moltbook] Starting paginated scan (max ${maxPages} pages, limit ${postLimit} posts)`);
      const result = await this.fetchRecentPostsPaginated({
        maxPages,
        totalLimit: postLimit,
        delayBetweenPages,
      });
      posts = result.posts;
      console.log(`[Moltbook] Paginated scan complete: ${posts.length} posts from ${result.pagesScanned} pages`);
    } else {
      // Single page fetch (original behavior)
      posts = await this.fetchRecentPosts({ limit: postLimit, sortBy: 'new' });
    }
    
    // Analyze each post
    for (const post of posts) {
      signals.push(...this.analyzePost(post));
    }

    // Optionally analyze agents of suspicious posts
    if (analyzeAgents) {
      const suspiciousAuthors = new Set(
        signals
          .filter((s) => s.severity === 'high' || s.severity === 'critical')
          .map((s) => s.agentUsername)
      );

      console.log(`[Moltbook] Analyzing ${suspiciousAuthors.size} suspicious agents...`);
      
      for (const author of suspiciousAuthors) {
        const agentSignals = await this.analyzeAgent(author);
        signals.push(...agentSignals.filter((s) => !signals.some((e) => e.id === s.id)));
      }
    }

    return signals;
  }

  /**
   * Get all detected threat signals.
   */
  getSignals(): MoltbookThreatSignal[] {
    return Array.from(this.signals.values());
  }

  /**
   * Get signals by severity.
   */
  getSignalsBySeverity(severity: MoltbookThreatSignal['severity']): MoltbookThreatSignal[] {
    return Array.from(this.signals.values()).filter((s) => s.severity === severity);
  }

  /**
   * Get signals by threat type.
   */
  getSignalsByType(type: MoltbookThreatType): MoltbookThreatSignal[] {
    return Array.from(this.signals.values()).filter((s) => s.type === type);
  }

  /**
   * Get signals for a specific agent.
   */
  getSignalsForAgent(username: string): MoltbookThreatSignal[] {
    return Array.from(this.signals.values()).filter(
      (s) => s.agentUsername === username || s.relatedAgents.includes(username)
    );
  }

  // =========================================================================
  // Helper Methods
  // =========================================================================

  private canMakeRequest(): boolean {
    return (
      this.requestCount.minute < this.config.rateLimit.requestsPerMinute &&
      this.requestCount.hour < this.config.rateLimit.requestsPerHour
    );
  }

  private isCacheValid(cachedAt: Date): boolean {
    const ageSeconds = (Date.now() - cachedAt.getTime()) / 1000;
    return ageSeconds < this.config.cacheTtlSeconds;
  }

  private extractIndicators(text: string, indicators: ThreatIndicator[]): void {
    // Extract wallet addresses
    const walletPattern = /0x[a-fA-F0-9]{40}/g;
    const wallets = text.match(walletPattern);
    if (wallets) {
      for (const wallet of wallets) {
        indicators.push({
          type: 'wallet_address',
          value: wallet.toLowerCase(),
          context: 'Found in text',
        });
      }
    }

    // Extract URLs
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
    const urls = text.match(urlPattern);
    if (urls) {
      for (const url of urls) {
        indicators.push({
          type: 'url',
          value: url,
          context: 'Found in text',
        });
      }
    }

    // Extract domains
    const domainPattern = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;
    const domains = text.match(domainPattern);
    if (domains) {
      for (const domain of domains) {
        if (!indicators.some((i) => i.value.includes(domain))) {
          indicators.push({
            type: 'domain',
            value: domain.toLowerCase(),
            context: 'Found in text',
          });
        }
      }
    }

    // Extract email addresses
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = text.match(emailPattern);
    if (emails) {
      for (const email of emails) {
        indicators.push({
          type: 'email',
          value: email.toLowerCase(),
          context: 'Found in text',
        });
      }
    }
  }

  // =========================================================================
  // Text Extraction Utilities
  // =========================================================================

  private extractLinks(text: string): string[] {
    const urlPattern = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
    return text.match(urlPattern) || [];
  }

  private extractMentions(text: string): string[] {
    const mentionPattern = /@([a-zA-Z0-9_]+)/g;
    const matches = [...text.matchAll(mentionPattern)];
    return matches.map((m) => m[1]!);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a Moltbook data source for the DataFetcher.
 */
export function createMoltbookDataSource() {
  return {
    name: 'Moltbook',
    type: 'api_feed' as const,
    endpoint: 'https://www.moltbook.com/api/v1',
    authMethod: 'none' as const,
    dataCategories: ['threat_intelligence', 'agent_behavior', 'incident_report'] as const,
    requiredTier: 'public' as const,
    trustLevel: 0.85,
    updateFrequency: 'realtime' as const,
    metadata: {
      platform: 'moltbook',
      agentCount: 1696681,
      description: 'Social network for AI agents - the front page of the agent internet',
    },
  };
}

/**
 * Map Moltbook threat signal to a standard threat signal format.
 */
export function mapToStandardThreatSignal(signal: MoltbookThreatSignal) {
  return {
    id: signal.id,
    type: signal.type,
    source: 'moltbook',
    severity: signal.severity,
    confidence: signal.confidence,
    timestamp: signal.detectedAt,
    description: signal.description,
    indicators: signal.indicators.map((i) => ({
      type: i.type,
      value: i.value,
      context: i.context,
    })),
    relatedEntities: [signal.agentUsername, ...signal.relatedAgents],
    evidence: signal.evidence,
    sourceUrl: `https://moltbook.com/${signal.sourceType === 'post' ? 'post' : 'u'}/${signal.sourceId}`,
  };
}
