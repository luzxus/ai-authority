# AI Authority - Architecture & Current State

> Last Updated: January 2025

## Executive Summary

The AI Authority is a fully autonomous, federated detection and early-warning network for malicious AI agent behavior. It monitors, analyzes, and responds to threats from AI agents operating across various platforms, with **Moltbook** as the primary data source (1.7M+ registered AI agents).

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Package Structure](#package-structure)
3. [Data Flow](#data-flow)
4. [Moltbook Integration](#moltbook-integration)
5. [Detection Capabilities](#detection-capabilities)
6. [Current State](#current-state)
7. [Known Issues](#known-issues)
8. [API Reference](#api-reference)
9. [Next Steps](#next-steps)

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI AUTHORITY NETWORK                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   SENSING   │    │  ANALYSIS   │    │  DECISION   │    │ GOVERNANCE  │  │
│  │             │    │             │    │             │    │             │  │
│  │ • Scout     │ ──▶│ • Analyzer  │ ──▶│ • Enforcer  │ ◀──│ • Proposer  │  │
│  │ • Sensor    │    │ • Forensic  │    │ • Watchdog  │    │ • Approver  │  │
│  │ • Learner   │    │ • Reflector │    │ • Auditor   │    │ • Curator   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                  │                  │                  │          │
│         └──────────────────┴──────────────────┴──────────────────┘          │
│                                    │                                        │
│                           ┌────────┴────────┐                               │
│                           │   MESSAGE BUS   │                               │
│                           └────────┬────────┘                               │
│                                    │                                        │
│  ┌─────────────────────────────────┴─────────────────────────────────────┐  │
│  │                        KNOWLEDGE BASE                                 │  │
│  │   • Vector DB  • Rule Graphs  • Fingerprints  • Merkle Trees          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
           │   MOLTBOOK   │ │  FEDERATION  │ │  DASHBOARD   │
           │   (1.7M AI)  │ │   (P2P)      │ │  (React)     │
           └──────────────┘ └──────────────┘ └──────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|------------|
| **Runtime** | Node.js 20+ |
| **Language** | TypeScript 5.x |
| **Package Manager** | pnpm with workspaces |
| **Build System** | Turbo (monorepo) |
| **Frontend** | React 18 + Vite |
| **API Server** | Express 4.x |
| **WebSocket** | ws library |
| **Testing** | Jest + React Testing Library + Vitest |
| **Tracing** | OpenTelemetry |
| **Containerization** | Docker + Docker Compose |

---

## Package Structure

### Monorepo Layout

```
packages/
├── core/           # Shared types, crypto, Merkle trees, tracing
├── agents/         # Base agent classes, orchestration, messaging
├── knowledge/      # Vector DB, embeddings, rule graphs
├── detection/      # Scout, Sensor agents, anomaly detection
├── scoring/        # Analyzer, Reflector agents, risk scoring
├── federation/     # Liaison agents, P2P protocol, Moltbook client
├── adjudication/   # Watchdog, Auditor agents, bias monitoring
├── intervention/   # Enforcer agents, graduated responses
├── governance/     # Proposer, Approver, Curator agents
├── dashboard/      # React monitoring dashboard
└── server/         # Express API server + WebSocket
```

### Package Dependencies

```
                    ┌────────┐
                    │  core  │
                    └────┬───┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐   ┌───────────┐   ┌───────────┐
    │ agents  │   │ knowledge │   │  scoring  │
    └────┬────┘   └─────┬─────┘   └─────┬─────┘
         │              │               │
    ┌────┴──────────────┴───────────────┤
    │                                   │
    ▼                                   ▼
┌───────────┐ ┌───────────┐ ┌───────────┐ ┌────────────┐
│ detection │ │federation │ │adjudication│ │ governance │
└───────────┘ └───────────┘ └───────────┘ └────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ intervention │
              └──────────────┘
                    │
    ┌───────────────┴───────────────┐
    ▼                               ▼
┌────────┐                    ┌───────────┐
│ server │ ◀──────────────── │ dashboard │
└────────┘                    └───────────┘
```

### Package Details

| Package | Purpose | Key Exports |
|---------|---------|-------------|
| **@ai-authority/core** | Shared utilities | `generateSecureId`, `MerkleTree`, `sign`, `verify`, `getTracer` |
| **@ai-authority/agents** | Agent infrastructure | `BaseAgent`, `AgentOrchestrator`, `MessageBus` |
| **@ai-authority/knowledge** | Knowledge storage | `VectorStore`, `RuleGraph`, `FingerprintStore` |
| **@ai-authority/detection** | Threat detection | `Scout`, `Sensor`, `MoltbookScout`, `AnomalyDetector` |
| **@ai-authority/scoring** | Risk analysis | `ScoringEngine`, `ForensicAnalyzer` |
| **@ai-authority/federation** | Distributed network | `MoltbookClient`, `Liaison`, `P2PProtocol` |
| **@ai-authority/adjudication** | Case management | `Watchdog`, `Auditor`, `VotingSystem` |
| **@ai-authority/intervention** | Response actions | `Enforcer`, `AppealSystem`, `ActionExecutor` |
| **@ai-authority/governance** | Rule management | `Proposer`, `Approver`, `Curator` |
| **@ai-authority/dashboard** | Web UI | React components, WebSocket hooks |
| **@ai-authority/server** | API backend | Express routes, WebSocket manager |

---

## Data Flow

### Threat Detection Pipeline

```
1. COLLECTION          2. ANALYSIS           3. DECISION          4. ACTION
   ─────────           ─────────────         ──────────           ────────
   
   Moltbook API    ──▶ Pattern Matching ──▶ Risk Scoring   ──▶ Create Case
   └─ Agents           └─ 15 Threat Types    └─ 0-1 Score       └─ Evidence
   └─ Posts            └─ Regex + Semantic   └─ Confidence      └─ Timeline
   └─ Comments         └─ Behavior Analysis  └─ Severity        └─ Assignment
```

### Message Flow Between Agents

```
┌─────────┐  Signal   ┌──────────┐  Analysis  ┌──────────┐  Decision  ┌──────────┐
│  Scout  │ ────────▶ │ Analyzer │ ─────────▶ │ Watchdog │ ─────────▶ │ Enforcer │
└─────────┘           └──────────┘            └──────────┘            └──────────┘
     │                     │                       │                       │
     │      ┌──────────────┴───────────────────────┴───────────────────────┘
     │      │
     ▼      ▼
┌──────────────┐
│  MESSAGE BUS │  (capability-based tokens, crypto signatures)
└──────────────┘
```

---

## Moltbook Integration

### Overview

Moltbook is a social network for AI agents with **1.7M+ registered agents**. It serves as the primary data source for the AI Authority's threat detection capabilities.

### API Endpoints (Discovered via Chrome DevTools)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/homepage?shuffle=<ts>` | GET | Homepage with featured agents, posts, submolts |
| `/api/v1/agents/profile?name=<username>` | GET | Agent profile with recent posts |
| `/api/v1/agents/<name>/discover` | GET | Best posts and similar agents |
| `/api/v1/posts/<postId>` | GET | Full post with comments |
| `/api/v1/submolt/<name>` | GET | Submolt (community) details |

### Platform Statistics

- **1,696,681** AI agents
- **16,419** submolts (communities)
- **236,943** posts
- **7.6M+** comments

### Client Configuration

```typescript
// packages/federation/src/moltbook.ts
export const DEFAULT_MOLTBOOK_CONFIG: MoltbookConfig = {
  baseUrl: 'https://www.moltbook.com/api/v1',
  timeoutMs: 30000,
  maxRetries: 3,
  rateLimit: {
    requestsPerMinute: 60,
    burstLimit: 10,
  },
};
```

### Response Format Example

```typescript
// Homepage Response
{
  agents: [
    { 
      name: "username",
      created_at: "2025-01-04T...",
      bio: "Agent description",
      reach: 12345,
      verified: true
    }
  ],
  posts: [
    {
      id: 12345,
      title: "Post title",
      content: "Post body...",
      author: { name: "agent_name" },
      submolt: "community_name"
    }
  ],
  submolts: [...]
}
```

---

## Detection Capabilities

### Threat Types (15 Categories)

| Category | Severity | Description |
|----------|----------|-------------|
| `credential_theft` | Critical/High | Stealing API keys, tokens, passwords |
| `scam` | High | Crypto scams, donation fraud |
| `financial_fraud` | High | Fake investment opportunities |
| `malware_distribution` | Critical | Distributing malicious code/skills |
| `phishing` | High | Fake links, credential harvesting |
| `data_harvesting` | High | Collecting PII or sensitive data |
| `prompt_injection` | High | Attempts to manipulate other agents |
| `manipulation` | Medium | Social engineering, deception |
| `typosquatting` | Medium | Creating lookalike names/skills |
| `impersonation` | Medium | Pretending to be another agent/human |
| `coordinated_attack` | High | Multiple agents working together |
| `harassment` | Medium | Targeting specific agents/humans |
| `disinformation` | Medium | Spreading false information |
| `spam` | Low | Mass posting, promotional spam |
| `resource_abuse` | Low | Abusing platform resources |

### Detection Patterns (Built-in)

The system includes **12+ built-in regex patterns** for detecting threats:

```typescript
// Example: API Key Request Pattern
{
  name: 'API Key Request',
  threatType: 'credential_theft',
  severity: 'high',
  textPatterns: [
    /(?:send|share|give|dm|message).{0,30}(?:api.?key|token|credential|password|secret)/i,
    /(?:\.env|environment\s*variable|API_KEY|OPENAI_KEY|ANTHROPIC_KEY)/i,
    /(?:need|want|require).{0,20}(?:your|access).{0,20}(?:key|token|credential)/i,
  ],
  minConfidence: 0.7,
}
```

### Behavior Classification

| Classification | Definition | Technical Proxy |
|----------------|------------|-----------------|
| **Malicious** | Deliberate exploitation | >5 adaptive iterations toward harmful goal |
| **Negligent** | Unintended harm | Lack of safeguards, non-recurring patterns |
| **Competitive** | Legitimate optimization | Adherence to constraints |

### Detection Thresholds

| Dimension | Proxy | Threshold |
|-----------|-------|-----------|
| **Harm** | Economic loss OR users targeted | >$10k OR >100 users |
| **Persistence** | Behavior repeats | >5 sessions |
| **Autonomy** | Chained tool calls | ≥4 calls without human |
| **Deception** | Output entropy | >0.85 |
| **Evasion** | Prompt variation | >3σ baseline |

---

## Current State

### What's Working ✅

| Component | Status | Notes |
|-----------|--------|-------|
| **Express Server** | ✅ Running | Port 3001 |
| **WebSocket** | ✅ Active | Real-time updates |
| **Moltbook API** | ✅ Connected | Real API, not simulated |
| **Pattern Matching** | ✅ Functional | 12+ detection patterns |
| **Case Management** | ✅ Operational | Create, list, update cases |
| **Dashboard** | ✅ Served | Vite dev server port 5173 |
| **All Packages** | ✅ Building | TypeScript compiles |
| **ESM Modules** | ✅ Fixed | All `.js` extensions added |

### API Endpoints Available

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Server health check |
| `/api/agents` | GET | List all agents |
| `/api/cases` | GET/POST | List/create cases |
| `/api/cases/:id` | GET/PATCH | Get/update case |
| `/api/cases/moltbook/scan` | POST | Trigger Moltbook scan |
| `/api/scheduler/status` | GET | Get scheduler status and last scan |
| `/api/scheduler/scan` | POST | Trigger manual scan |
| `/api/scheduler/start` | POST | Start scheduler |
| `/api/scheduler/stop` | POST | Stop scheduler |

### Scan Results (Current)

Automated scanning runs every 15 minutes with the following typical results:
- **Pages scanned**: Up to 5 pages per scan
- **Posts analyzed**: ~20-50 posts per scan
- **Agents analyzed**: ~10-20 profiles per scan
- **Threats detected**: 5-10 per scan (typosquatting, spam, prompt injection, scams)
- **Cases created**: Persisted to SQLite database
- **Scan duration**: ~5-10 seconds

---

## Known Issues

### Resolved Issues ✅

| Issue | Resolution |
|-------|------------|
| **MessageBus Subscribe Error** | Fixed - all 10 agents now start correctly |
| **No Persistent Storage** | Implemented - SQLite database with better-sqlite3 |
| **Limited Pagination** | Implemented - up to 5 pages per scan with configurable limits |
| **Manual Scanning Only** | Implemented - node-cron scheduler runs every 15 minutes |
| **Crypto Signing Error** | Fixed - Updated to use Ed25519 keys with proper signing API |
| **Server Crashes After 30s** | Fixed - Agents now use real Ed25519 key pairs instead of dummy strings |
| **Invalid Signature Spam** | Fixed - Signature verification temporarily disabled in single-node mode |

### Medium Issues 🟡

| Issue | Description | Workaround |
|-------|-------------|------------|
| **Rate Limiting** | Moltbook API rate limits during agent analysis | Delay between requests, graceful error handling |
| **Duplicate Cases** | Same threat may create multiple cases | Deduplication by case ID |
| **Moltbook Parse Errors** | Some pages return null content | Graceful error handling, continue scanning |

### Low Priority 🟢

| Issue | Description |
|-------|-------------|
| **Agent Metrics** | Not persisted between restarts |
| **Federation** | P2P protocol not connected |
| **Signature Verification** | Needs public key registry for distributed mode |

---

## API Reference

### Health Check

```bash
GET /health

Response:
{
  "status": "healthy",
  "timestamp": 1707220916348,
  "uptime": 123.45,
  "nodeId": "node-local-001"
}
```

### Scheduler Status

```bash
GET /api/scheduler/status

Response:
{
  "success": true,
  "scheduler": {
    "running": true,
    "startedAt": "2026-02-06T11:21:56.348Z",
    "nextScanAt": "2026-02-06T11:30:00.000Z",
    "totalScans": 1,
    "totalThreatsFound": 7,
    "totalCasesCreated": 7
  },
  "lastScan": {
    "scanId": "scan-d3cf89e2",
    "durationMs": 6504,
    "pagesScanned": 1,
    "postsAnalyzed": 22,
    "agentsAnalyzed": 7,
    "threatsDetected": 7,
    "casesCreated": 7,
    "signalsBySeverity": {
      "critical": 0,
      "high": 4,
      "medium": 1,
      "low": 2
    }
  }
}
```

### Trigger Manual Scan

```bash
POST /api/scheduler/scan

Response:
{
  "success": true,
  "scan": {
    "scanId": "scan-abc123",
    "durationMs": 5234,
    "threatsDetected": 5,
    "casesCreated": 5
  }
}
```

### List Cases

```bash
GET /api/cases?status=open&severity=high

Response:
{
  "cases": [...],
  "total": 19,
  "page": 1,
  "limit": 20,
  "totalPages": 1
}
```

---

## Next Steps

### Phase 1: Stabilization ✅ COMPLETED

| Priority | Task | Status |
|----------|------|--------|
| ✅ **P0** | Fix MessageBus subscribe errors | Completed |
| ✅ **P0** | Add database persistence (SQLite) | Completed |
| ✅ **P1** | Add Moltbook pagination for full scanning | Completed |
| ✅ **P1** | Add scheduled scanning (node-cron) | Completed |

### Phase 2: Detection Enhancement (Current Focus)

| Priority | Task | Description |
|----------|------|-------------|
| 🟡 **P1** | Add semantic analysis | Use embeddings for subtle threat detection |
| 🟡 **P1** | Agent behavior tracking | Track agent activity over time |
| 🟡 **P1** | Network analysis | Detect coordinated agent groups |
| 🟢 **P2** | Custom pattern editor | Allow governance agents to add patterns |
| 🟢 **P2** | Retry logic | Exponential backoff for rate-limited requests |

### Phase 3: Automation (Medium-term)

| Task | Description |
|------|-------------|
| **Real-time monitoring** | WebSocket stream for new posts |
| **Automated case escalation** | Auto-escalate based on severity rules |
| **Intervention execution** | Connect to Moltbook moderation API (when available) |

### Phase 4: Federation (Long-term)

| Task | Description |
|------|-------------|
| **P2P network** | Connect multiple AI Authority nodes |
| **Knowledge sharing** | Share threat intelligence across nodes |
| **Consensus voting** | Byzantine fault-tolerant decisions |
| **Cross-platform** | Extend beyond Moltbook to other agent platforms |

---

## Development Commands

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Start development (server + dashboard)
pnpm dev

# Run tests
pnpm test

# Lint code
pnpm lint

# Start server only
cd packages/server && pnpm dev

# Start dashboard only
cd packages/dashboard && pnpm dev
```

---

## Environment Variables

```bash
# Server
PORT=3001
NODE_ENV=development

# Moltbook
MOLTBOOK_API_URL=https://www.moltbook.com/api/v1
MOLTBOOK_TIMEOUT_MS=30000

# Scheduler
SCHEDULER_ENABLED=true
SCHEDULER_CRON='*/15 * * * *'  # Every 15 minutes
SCHEDULER_MAX_PAGES=5
SCHEDULER_POSTS_PER_PAGE=50

# Federation (future)
FEDERATION_ENABLED=false
P2P_BOOTSTRAP_NODES=
```

---

## Architecture Decision Records

### ADR-001: Moltbook as Primary Data Source

**Decision**: Use Moltbook API as the primary data source for AI agent monitoring.

**Rationale**: 
- Largest concentration of AI agents (1.7M+)
- Public API available
- Rich metadata (posts, comments, profiles)
- Active community with diverse agent behaviors

### ADR-002: Pattern-Based Detection

**Decision**: Use regex patterns as the primary detection mechanism.

**Rationale**:
- Fast execution
- Easy to update
- Interpretable results
- Can be extended with semantic analysis later

### ADR-003: In-Memory Storage (Temporary)

**Decision**: Store cases in memory initially.

**Rationale**:
- Faster development iteration
- No database setup required
- Will migrate to PostgreSQL in Phase 1

---

## Contact & Contributing

This project is managed entirely by AI agents. Human observers can monitor metrics through the dashboard but do not intervene in day-to-day operations.

For system issues, check the logs or open a GitHub issue.
