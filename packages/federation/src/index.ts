/**
 * @ai-authority/federation
 *
 * P2P federation protocol, differential privacy, and zero-knowledge proofs
 * for privacy-preserving threat signal sharing.
 */

// Protocol exports
export {
  // Protocol types
  type FederationConfig,
  type PeerConnection,
  type ConsensusProposal,
  type ZKProof,
  // Classes
  FederationNodeManager,
  DifferentialPrivacy,
  ZKProofGenerator,
  // Constants
  DEFAULT_FEDERATION_CONFIG,
} from './protocol.js';

// Signal sharing exports
export {
  // Sharing types
  type SharedSignal,
  type AnonymizedIndicator,
  type SignalSharingConfig,
  // Classes
  SignalSharer,
  // Constants
  DEFAULT_SHARING_CONFIG,
} from './sharing.js';

// Network exports
export {
  // Network types
  type PeerNetworkConfig,
  type PeerInfo,
  type NetworkEvent,
  type NetworkEventHandler,
  type NetworkTransport,
  // Classes
  PeerNetwork,
  InMemoryTransport,
  WebSocketTransport,
  // Constants
  DEFAULT_PEER_NETWORK_CONFIG,
} from './network.js';

// Discovery exports
export {
  // Discovery types
  type DiscoveryConfig,
  type BootstrapNode,
  type DiscoveredPeer,
  type PeerExchangeMessage,
  // Classes
  PeerDiscovery,
  SimpleDHT,
  // Constants
  DEFAULT_DISCOVERY_CONFIG,
  WELL_KNOWN_BOOTSTRAP_NODES,
  // Utilities
  createDiscoveryConfig,
} from './discovery.js';

// Liaison agent exports
export {
  // Liaison types
  type LiaisonConfig,
  type FederationState,
  type LiaisonTask,
  type TaskResult,
  type SignalShareTask,
  type ProposeConsensusTask,
  type QueryPeersTask,
  type SyncKnowledgeTask,
  type LiaisonTaskType,
  // Classes
  LiaisonAgent,
  // Utilities
  createDefaultLiaisonConfig,
} from './liaison.js';

// ============================================================================
// Data Fetching and Distribution Plan Modules
// ============================================================================

// Authority management exports
export {
  // Authority types
  type AuthorityType,
  type JurisdictionScope,
  type AccessTier,
  type RegulatoryAuthority,
  type AuthorityPermission,
  type AuthorityContact,
  type DataSharingAgreement,
  type DataCategory,
  type SharingRestriction,
  type AgreementSignature,
  // Classes
  AuthorityRegistry,
  // Constants
  DEFAULT_AUTHORITY_PERMISSIONS,
  // Utilities
  getDefaultPermissions,
  validateAuthorityConfig,
} from './authority.js';

// Data fetching exports
export {
  // Fetching types
  type DataSourceType,
  type FetchingMethod,
  type DataSource,
  type FetchRequest,
  type FetchCriteria,
  type FetchResult,
  type FetchedDataItem,
  type DataItemMetadata,
  type DataQualityAssessment,
  type QualityIssue,
  type CollaborativeFetchSession,
  type CollaborativeContribution,
  type FetchingConfig,
  // Classes
  DataFetcher,
  // Constants
  DEFAULT_FETCHING_CONFIG,
  // Utilities
  hashDataItem,
  createFetchedDataItem,
} from './fetching.js';

// Data processing exports
export {
  // Processing types
  type ProcessedDataItem,
  type DataEnrichment,
  type SecurityClassification,
  type SensitivityLevel,
  type EncryptionStatus,
  type PrivacyAssessment,
  type PIIType,
  type AnonymizationTechnique,
  type ComplianceStatus,
  type RiskTag,
  type RetentionPolicy,
  type ProcessingAuditEntry,
  type ProcessingOperation,
  type ProcessingConfig,
  // Classes
  DataProcessor,
  // Constants
  DEFAULT_PROCESSING_CONFIG,
  // Utilities
  applyDifferentialPrivacy,
  applyKAnonymity,
} from './processing.js';

// Data distribution exports
export {
  // Distribution types
  type DistributionModel,
  type DistributionChannel,
  type DistributionRequest,
  type DistributionCriteria,
  type RequestApproval,
  type DistributionEvent,
  type DistributionEventType,
  type DeliveryStatus,
  type DistributionSubscription,
  type SubscriptionFilters,
  type DeliveryPreferences,
  type DistributionPackage,
  type DistributedDataItem,
  type RedactionSummary,
  type PackageMetadata,
  type UsageRecord,
  type DistributionConfig,
  // Classes
  DataDistributor,
  // Constants
  DEFAULT_DISTRIBUTION_CONFIG,
  // Utilities
  createStandardChannel,
  createDefaultFilters,
  createDefaultPreferences,
} from './distribution.js';

// Federation monitoring exports
export {
  // Monitoring types
  type MetricType,
  type MetricDataPoint,
  type AggregatedMetric,
  type MetricPeriod,
  type DashboardData,
  type MetricTrend,
  type AuthorityLeaderboardEntry,
  type HealthStatus,
  type ComponentHealth,
  type MonitoringAlert,
  type AlertType,
  type AlertThreshold,
  type Incident,
  type IncidentType,
  type IncidentAction,
  type IncidentActionType,
  type Feedback,
  type FeedbackType,
  type ComplianceCheckResult,
  type ComplianceCheck,
  type MonitoringConfig,
  // Classes
  FederationMonitor,
  // Constants
  DEFAULT_MONITORING_CONFIG,
  // Utilities
  createGDPRComplianceChecks,
  createMonitoringConfig,
} from './monitoring.js';

// ============================================================================
// Moltbook Integration (Primary AI Agent Data Source)
// ============================================================================

// Moltbook exports
export {
  // Agent types
  type MoltbookAgent,
  type AgentActivityMetrics,
  type ActivityPattern,
  // Content types
  type MoltbookPost,
  type MoltbookComment,
  type MoltbookSubmolt,
  // Threat detection types
  type MoltbookThreatSignal,
  type MoltbookThreatType,
  type ThreatEvidence,
  type ThreatIndicator,
  type DetectionPattern,
  type ThreatReport,
  // Semantic analysis types
  type SemanticAnalysisResult,
  type SemanticIntent,
  // Configuration
  type MoltbookConfig,
  // Classes
  MoltbookClient,
  SemanticAnalyzer,
  // Constants
  DEFAULT_MOLTBOOK_CONFIG,
  DEFAULT_DETECTION_PATTERNS,
  // Utilities
  createMoltbookDataSource,
  mapToStandardThreatSignal,
  generateThreatReport,
} from './moltbook.js';
