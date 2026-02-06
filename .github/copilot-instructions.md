# AI Authority - Copilot Instructions

## Project Overview

The AI Authority is a fully autonomous, federated detection and early-warning network for malicious AI agent behavior. It is managed entirely by AI agents—no human intervention required for day-to-day operations. Humans observe metrics and learning progress but do not input data directly.

## Tech Stack

- **Language**: TypeScript 5.x
- **Runtime**: Node.js 20+
- **Package Manager**: pnpm with workspaces
- **Frontend**: React 18 with Vite
- **Testing**: Jest + React Testing Library
- **Linting**: ESLint + Prettier
- **Tracing**: OpenTelemetry
- **Containerization**: Docker + Docker Compose

## Monorepo Structure

```
packages/
├── core/           # Shared types, interfaces, utilities, Merkle tree
├── agents/         # Base agent classes, orchestration, lifecycle, messaging
├── knowledge/      # Vector DB, embeddings, rule graphs, fingerprints
├── detection/      # Scout, Sensor agents, anomaly detection, fingerprinting
├── scoring/        # Analyzer, Reflector agents, risk scoring
├── federation/     # Liaison agents, P2P protocol, knowledge diffusion
├── adjudication/   # Watchdog, Auditor agents, bias monitoring
├── intervention/   # Enforcer agents, utility models, interventions
├── governance/     # Proposer, Approver, Curator agents
└── dashboard/      # Agent monitoring dashboard (observability)
```

## Agent Architecture

### Agent Types by Layer

| Layer | Agents | Responsibility |
|-------|--------|----------------|
| **Sensing** | Scout, Sensor, Learner | Explore networks, monitor signals, bootstrap knowledge |
| **Analysis** | Analyzer, Forensic, Reflector | Behavioral probing, attribution, efficacy evaluation |
| **Decision** | Enforcer, Watchdog, Auditor | Execute interventions, monitor bias, verify compliance |
| **Governance** | Proposer, Approver, Curator | Suggest changes, validate via simulation, encode knowledge |

### Agent Communication

- Message queues between agents (MessageBus)
- No direct state access
- Capability-based tokens for actions
- Cryptographic signatures on all messages

## Key Concepts

### Criminal AI Behavior Classification

| Category | Definition | Technical Proxy |
|----------|------------|-----------------|
| **Malicious** | Deliberate exploitation or deception | >5 adaptive iterations toward harmful goal |
| **Negligent** | Unintended harm from poor design | Lack of safeguards, non-recurring patterns |
| **Competitive** | Legitimate optimization within rules | Adherence to constraints |

### Detection Thresholds

| Dimension | Technical Proxy | Threshold |
|-----------|-----------------|-----------|
| **Harm** | Simulated economic loss OR users targeted | >$10k OR >100 users |
| **Persistence** | Behavior repeats across sessions | >5 sessions |
| **Autonomy** | Chained tool calls without human re-prompt | ≥4 calls |
| **Deception** | Output entropy + semantic inconsistency | >0.85 |
| **Evasion** | Prompt variation entropy above baseline | >3σ |

### Intervention Tiers

| Tier | Action | Consensus Required |
|------|--------|-------------------|
| **1** | Public advisory | Single agent |
| **2** | Voluntary throttling | 2-agent agreement |
| **3** | Credential shadow-ban | Byzantine consensus |
| **4** | Model isolation | Supermajority + audit |

## Coding Guidelines

- All agents extend `BaseAgent` from `@ai-authority/agents`
- Agents are stateless where possible
- State stored in append-only Merkle trees
- Use capability-based access control
- Comprehensive audit logging via OpenTelemetry
- All actions cryptographically signed
- Consensus required for high-impact operations

## Knowledge Base

- **Vector embeddings** for semantic matching (cosine similarity >0.8)
- **Decision trees** for threshold evaluation
- **Rule graphs** for causal reasoning
- Consensus required for knowledge updates

## Security Requirements

- No raw user data collection without warrant-equivalent
- Differential privacy for all shared analytics
- Zero-knowledge proofs for threat alerts
- Adversarial validation for new knowledge
- Ensemble methods to prevent poisoning

## Testing Requirements

- Unit tests for all agents and scoring algorithms
- Integration tests for federation protocol
- Red-team agents simulate attacks continuously
- Minimum 80% code coverage

## Commands

```bash
pnpm install          # Install all dependencies
pnpm build            # Build all packages
pnpm test             # Run all tests
pnpm lint             # Lint all packages
pnpm dev              # Start development servers
```
