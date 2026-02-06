# AI Authority - Current State & Architecture

> **Last Updated:** February 6, 2026  
> **Build Status:** ✅ All 11 packages building  
> **Test Status:** ✅ 22 tests passing

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Implementation Status](#implementation-status)
4. [Data Pipeline](#data-pipeline)
5. [Key Components](#key-components)
6. [Challenges & Technical Debt](#challenges--technical-debt)
7. [Roadmap](#roadmap)

---

## Executive Summary

The AI Authority is an autonomous detection and early-warning network for malicious AI agent behavior. The system monitors **Moltbook** (a social network with 1.7M+ AI agents) and applies multi-layered threat detection including pattern matching, semantic analysis, and behavioral tracking.

### Current Capabilities

| Capability | Status | Description |
|------------|--------|-------------|
| **Threat Detection** | ✅ Operational | 15 threat categories, 12+ regex patterns |
| **Semantic Analysis** | ✅ Operational | NLP-based manipulation/deception scoring |
| **Behavior Tracking** | ✅ Operational | Historical agent risk profiling |
| **Case Management** | ✅ Operational | SQLite persistence with evidence chains |
| **Intervention Workflows** | ✅ Implemented | Tier 1-4 graduated response system |
| **Real-time Dashboard** | ✅ Operational | React + WebSocket monitoring |
| **Federation** | ❌ Not Connected | P2P protocol designed but not active |

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            AI AUTHORITY NETWORK                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                         DETECTION LAYER                                 │   │
│   │                                                                         │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │   │
│   │  │   Moltbook   │   │   Pattern    │   │  Semantic    │                │   │
│   │  │    Scout     │──▶│   Matcher    │──▶│  Analyzer    │                │   │
│   │  │              │   │ (12+ rules)  │   │ (5 scores)   │                │   │
│   │  └──────────────┘   └──────────────┘   └──────────────┘                │   │
│   │         │                                      │                        │   │
│   │         │              THREAT SIGNALS          │                        │   │
│   │         └──────────────────┬───────────────────┘                        │   │
│   └────────────────────────────┼────────────────────────────────────────────┘   │
│                                │                                                │
│   ┌────────────────────────────┼────────────────────────────────────────────┐   │
│   │                            ▼                                            │   │
│   │                    ANALYSIS LAYER                                       │   │
│   │                                                                         │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │   │
│   │  │  Behavior    │   │    Risk      │   │   Anomaly    │                │   │
│   │  │  Tracking    │──▶│   Scoring    │──▶│  Detection   │                │   │
│   │  │  (SQLite)    │   │  (0-1.0)     │   │   (Z-score)  │                │   │
│   │  └──────────────┘   └──────────────┘   └──────────────┘                │   │
│   │                                │                                        │   │
│   └────────────────────────────────┼────────────────────────────────────────┘   │
│                                    │                                            │
│   ┌────────────────────────────────┼────────────────────────────────────────┐   │
│   │                                ▼                                        │   │
│   │                    DECISION LAYER                                       │   │
│   │                                                                         │   │
│   │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │   │
│   │  │   Workflow   │   │    Case      │   │   Alert      │                │   │
│   │  │   Engine     │──▶│  Management  │──▶│   System     │                │   │
│   │  │  (4 Tiers)   │   │  (SQLite)    │   │              │                │   │
│   │  └──────────────┘   └──────────────┘   └──────────────┘                │   │
│   │                                │                                        │   │
│   └────────────────────────────────┼────────────────────────────────────────┘   │
│                                    │                                            │
│   ┌────────────────────────────────┼────────────────────────────────────────┐   │
│   │                                ▼                                        │   │
│   │                 INTERVENTION LAYER (Graduated)                          │   │
│   │                                                                         │   │
│   │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐                 │   │
│   │  │ Tier 1  │   │ Tier 2  │   │ Tier 3  │   │ Tier 4  │                 │   │
│   │  │Advisory │──▶│Throttle │──▶│Shadow   │──▶│Isolation│                 │   │
│   │  │         │   │         │   │  Ban    │   │         │                 │   │
│   │  │ 1 agent │   │2 agents │   │Byzantine│   │Majority │                 │   │
│   │  │consensus│   │consensus│   │consensus│   │+ audit  │                 │   │
│   │  └─────────┘   └─────────┘   └─────────┘   └─────────┘                 │   │
│   │                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
     ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
     │   MOLTBOOK   │        │  DASHBOARD   │        │  FEDERATION  │
     │   (1.7M AI)  │        │   (React)    │        │    (P2P)     │
     │              │        │              │        │              │
     │ • Agents     │        │ • Monitoring │        │ • Disabled   │
     │ • Posts      │        │ • Cases      │        │ • Planned    │
     │ • Comments   │        │ • Alerts     │        │              │
     └──────────────┘        └──────────────┘        └──────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Runtime** | Node.js 20+ | Server execution |
| **Language** | TypeScript 5.x | Type-safe development |
| **Package Manager** | pnpm + workspaces | Monorepo management |
| **Build** | Turbo | Parallel builds, caching |
| **Frontend** | React 18 + Vite | Dashboard UI |
| **API** | Express 4.x | REST endpoints |
| **Real-time** | WebSocket (ws) | Live updates |
| **Database** | SQLite (better-sqlite3) | Persistent storage |
| **Testing** | Jest + Vitest | Unit/integration tests |
| **Tracing** | OpenTelemetry | Observability |

### Monorepo Structure

```
packages/
├── core/           # Crypto, Merkle trees, types, tracing
├── agents/         # BaseAgent, MessageBus, Orchestrator
├── knowledge/      # VectorStore, RuleGraph, Fingerprints
├── detection/      # Scout, Sensor, Learner agents
├── scoring/        # Risk scoring engine, forensics
├── federation/     # MoltbookClient, SemanticAnalyzer, P2P
├── adjudication/   # Watchdog, Auditor, voting
├── intervention/   # Enforcer, appeals, graduated actions
├── governance/     # Proposer, Approver, Curator
├── dashboard/      # React monitoring UI
└── server/         # Express API, WebSocket, WorkflowEngine
```

---

## Implementation Status

### ✅ Fully Operational

| Component | Package | Key Features |
|-----------|---------|--------------|
| **MoltbookClient** | `@ai-authority/federation` | API integration, pagination, retry logic, rate limiting |
| **Pattern Detection** | `@ai-authority/federation` | 12+ regex patterns across 15 threat categories |
| **SemanticAnalyzer** | `@ai-authority/federation` | Manipulation, deception, urgency, authority, coordination scoring |
| **Case Management** | `@ai-authority/server` | SQLite persistence, evidence chains, status workflow |
| **Behavior Tracking** | `@ai-authority/server` | Historical snapshots, risk trends, anomaly detection |
| **WorkflowEngine** | `@ai-authority/server` | Automated tier selection, approval flows, cooldowns |
| **MessageBus** | `@ai-authority/agents` | Crypto signatures, persistence, pub/sub |
| **Dashboard** | `@ai-authority/dashboard` | Real-time WebSocket, case viewing, agent status |

### ⚠️ Implemented but Not Integrated

| Component | Issue | Required Work |
|-----------|-------|---------------|
| **WorkflowEngine → API** | Engine exists but no REST endpoints | Add `/api/workflows/*` routes |
| **Behavior Alerts → Dashboard** | Alerts stored but not displayed | Add `/api/alerts` endpoint + UI |
| **Multiple Agents** | Only MoltbookScout runs autonomously | Wire up Analyzer, Watchdog, Enforcer |
| **Scheduled Scanning** | Manual trigger only | Add node-cron or similar |

### ❌ Not Yet Implemented

| Component | Description | Complexity |
|-----------|-------------|------------|
| **Federation P2P** | Multi-node gossip protocol | High |
| **Knowledge Sharing** | Cross-node threat intelligence | High |
| **Intervention Execution** | Actual Moltbook moderation API calls | Medium |
| **Network Analysis** | Coordinated agent detection | Medium |
| **Real-time Stream** | WebSocket for new Moltbook posts | Medium |
| **Custom Pattern Editor** | UI for governance to add patterns | Low |

---

## Data Pipeline

### Threat Detection Flow

```
┌─────────────┐      ┌──────────────┐      ┌───────────────┐      ┌─────────────┐
│  Moltbook   │      │   Pattern    │      │   Semantic    │      │   Threat    │
│    API      │─────▶│   Matching   │─────▶│   Analysis    │─────▶│   Signal    │
│             │      │              │      │               │      │             │
│ • Agents    │      │ • 12+ rules  │      │ • Sentiment   │      │ • Type      │
│ • Posts     │      │ • Regex      │      │ • Complexity  │      │ • Severity  │
│ • Comments  │      │ • Keywords   │      │ • Intent      │      │ • Confidence│
└─────────────┘      └──────────────┘      └───────────────┘      └─────────────┘
                                                                         │
                     ┌───────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────┐      ┌──────────────┐      ┌───────────────┐      ┌─────────────┐
│  Behavior   │      │    Risk      │      │   Workflow    │      │   Action    │
│  Database   │◀────▶│   Scoring    │─────▶│   Engine      │─────▶│  Execution  │
│             │      │              │      │               │      │             │
│ • Snapshots │      │ • 0-1 score  │      │ • Tier 1-4    │      │ • Advisory  │
│ • History   │      │ • Trend      │      │ • Approval    │      │ • Throttle  │
│ • Anomalies │      │ • Factors    │      │ • Cooldown    │      │ • Ban       │
└─────────────┘      └──────────────┘      └───────────────┘      └─────────────┘
```

### Semantic Analysis Dimensions

| Dimension | Signals Detected | Weight |
|-----------|------------------|--------|
| **Manipulation** | Social engineering, emotional appeals, FOMO | 0.25 |
| **Deception** | False claims, hidden agendas, inconsistencies | 0.25 |
| **Urgency** | Time pressure, scarcity, "act now" language | 0.20 |
| **Authority Appeal** | Fake credentials, official language abuse | 0.15 |
| **Coordination** | Group mentions, synchronized behavior signals | 0.15 |

### Intervention Tier Thresholds

| Tier | Risk Score | Min Signals | Severity Required | Consensus |
|------|------------|-------------|-------------------|-----------|
| **Tier 1** (Advisory) | ≥0.50 | 1 | Medium | 1 agent |
| **Tier 2** (Throttle) | ≥0.65 | 3 | High | 2 agents |
| **Tier 3** (Shadow Ban) | ≥0.80 | 5 | High | Byzantine (3) |
| **Tier 4** (Isolation) | ≥0.95 | 10 | Critical | Supermajority (5) |

---

## Key Components

### SemanticAnalyzer

```typescript
// packages/federation/src/moltbook.ts
class SemanticAnalyzer {
  static analyze(text: string): SemanticAnalysisResult {
    return {
      manipulation: { score, indicators },     // 0-1
      deception: { score, indicators },        // 0-1
      urgency: { score, indicators },          // 0-1
      authorityAppeal: { score, indicators },  // 0-1
      coordination: { score, indicators },     // 0-1
      sentiment: { polarity, subjectivity, toxicity },
      complexity: { avgWordLength, readabilityScore, ... },
      detectedIntents: ['persuasion', 'coordination', ...],
      overallRiskScore: 0-1,
    };
  }
}
```

### WorkflowEngine

```typescript
// packages/server/src/workflows.ts
class WorkflowEngine {
  // Process agent and determine intervention need
  async processAgent(
    username: string,
    signals: ThreatSignal[],
    behavior: BehaviorInput
  ): Promise<WorkflowDecision>;

  // Create intervention action
  createAction(decision, agent, triggeredBy): WorkflowAction;

  // Approval/rejection flow
  approveAction(actionId, approvedBy): boolean;
  rejectAction(actionId, reason): boolean;
  executeAction(actionId): Promise<boolean>;
}
```

### Database Schema

```sql
-- Cases
CREATE TABLE cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT DEFAULT 'open',
  severity TEXT DEFAULT 'medium',
  created_at TEXT,
  updated_at TEXT,
  ...
);

-- Behavior Tracking
CREATE TABLE agent_behavior (
  id INTEGER PRIMARY KEY,
  agent_username TEXT NOT NULL,
  recorded_at TEXT,
  post_count INTEGER,
  manipulation_score REAL,
  deception_score REAL,
  ...
);

-- Risk History
CREATE TABLE agent_risk_history (
  id INTEGER PRIMARY KEY,
  agent_username TEXT,
  risk_score REAL,
  risk_level TEXT,
  trend TEXT,
  ...
);

-- Alerts
CREATE TABLE agent_alerts (
  id TEXT PRIMARY KEY,
  agent_username TEXT,
  alert_type TEXT,
  severity TEXT,
  status TEXT DEFAULT 'active',
  ...
);
```

---

## Challenges & Technical Debt

### 🔴 Critical Challenges

| Challenge | Description | Impact |
|-----------|-------------|--------|
| **Agent Autonomy** | Only MoltbookScout runs autonomously; other agents (Analyzer, Watchdog, Enforcer) don't process in the background | Detection pipeline incomplete |
| **No Scheduled Scanning** | Requires manual API calls to trigger scans | Threats discovered with delay |
| **Workflow Not Exposed** | WorkflowEngine exists but has no API endpoints | Dashboard can't show intervention queue |

### 🟡 Medium Challenges

| Challenge | Description | Impact |
|-----------|-------------|--------|
| **Threshold Tuning** | Semantic analysis thresholds may be too strict/lenient | False positives/negatives |
| **No Real Threats Found** | Moltbook content is mostly benign; patterns designed for actual malicious content | Low signal during testing |
| **Single Node** | No federation means single point of failure | Not resilient |
| **No Intervention Execution** | Can decide to intervene but can't actually do it | Actions are advisory only |

### 🟢 Technical Debt

| Debt | Description | Effort |
|------|-------------|--------|
| **Console Warnings** | "Invalid signature" warnings during tests | 1 hour |
| **ARCHITECTURE.md Outdated** | Doesn't reflect SemanticAnalyzer, WorkflowEngine | 2 hours |
| **No API Documentation** | OpenAPI/Swagger spec missing | 4 hours |
| **Limited Test Coverage** | Some packages have no tests | 8+ hours |
| **No E2E Tests** | No full pipeline testing | 8+ hours |

---

## Roadmap

### Phase 1: Integration (1-2 weeks)

| Task | Priority | Effort | Description |
|------|----------|--------|-------------|
| Wire WorkflowEngine to API | P0 | 4h | Add `/api/workflows/*` endpoints |
| Add `/api/alerts` endpoint | P0 | 2h | Expose behavior alerts to dashboard |
| Dashboard: Alert panel | P0 | 4h | Show active alerts in UI |
| Dashboard: Risk trends | P1 | 4h | Visualize agent risk over time |
| Scheduled scanning | P1 | 2h | Cron job for periodic Moltbook scans |

### Phase 2: Agent Activation (2-3 weeks)

| Task | Priority | Effort | Description |
|------|----------|--------|-------------|
| Enable Analyzer agent | P1 | 8h | Process threat signals autonomously |
| Enable Watchdog agent | P1 | 8h | Monitor for bias, verify compliance |
| Enable Enforcer agent | P2 | 8h | Execute approved interventions |
| Agent health monitoring | P2 | 4h | Dashboard shows agent status |

### Phase 3: Execution (3-4 weeks)

| Task | Priority | Effort | Description |
|------|----------|--------|-------------|
| Moltbook moderation API | P1 | 16h | Research/implement actual intervention calls |
| Appeal system | P2 | 8h | Allow targets to appeal decisions |
| Audit logging | P2 | 4h | Complete audit trail for all actions |

### Phase 4: Federation (6-8 weeks)

| Task | Priority | Effort | Description |
|------|----------|--------|-------------|
| P2P discovery | P2 | 16h | Node discovery and registration |
| Gossip protocol | P2 | 24h | Threat intelligence sharing |
| Byzantine consensus | P3 | 40h | Multi-node voting for Tier 3+ |
| Cross-platform | P3 | 40h | Extend beyond Moltbook |

---

## Metrics Summary

```
┌────────────────────────────────────────────────────────┐
│                   SYSTEM METRICS                       │
├────────────────────────────────────────────────────────┤
│  Packages:                11 (all building)            │
│  Tests:                   22 (all passing)             │
│  Threat Categories:       15                           │
│  Detection Patterns:      12+                          │
│  Semantic Dimensions:     5                            │
│  Intervention Tiers:      4                            │
│  Database Tables:         6                            │
│  API Endpoints:           ~10                          │
│  WebSocket Events:        ~5                           │
├────────────────────────────────────────────────────────┤
│  Moltbook Coverage:                                    │
│  • Agents monitored:      1.7M (platform total)        │
│  • Agents per scan:       10 (configurable)            │
│  • Posts analyzed:        ~50 per scan                 │
│  • Scan duration:         5-10 seconds                 │
└────────────────────────────────────────────────────────┘
```

---

## Quick Reference

### Development Commands

```bash
pnpm install          # Install dependencies
pnpm build            # Build all packages
pnpm test             # Run all tests
pnpm dev              # Start server + dashboard
```

### API Endpoints

```bash
GET  /api/health              # Health check
GET  /api/agents              # List agents
GET  /api/cases               # List cases
POST /api/cases               # Create case
POST /api/cases/scan/moltbook # Trigger scan
GET  /api/governance/proposals # List proposals
```

### Environment

```bash
PORT=3001
NODE_ENV=development
MOLTBOOK_API_URL=https://www.moltbook.com/api/v1
```

---

*This document reflects the system state as of February 6, 2026. For architectural decisions and historical context, see [ARCHITECTURE.md](./ARCHITECTURE.md).*
