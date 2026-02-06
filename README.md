# AI Authority - Federated Detection Network

A proof-of-concept federated detection and early-warning network for malicious AI agent behavior.

## Project Overview

The AI Authority implements Phase 1 of the Minimum Viable Authority Components blueprint, focusing on:

- **Detection**: Anomaly detection, behavioral analysis, and model fingerprinting
- **Scoring**: Multi-dimensional risk assessment (harm, persistence, autonomy, deception, evasion)
- **Federation**: Privacy-preserving threat signal sharing between nodes
- **Adjudication**: Human-in-the-loop case management with 3-of-5 quorum voting
- **Intervention**: Graduated response tiers (advisory, throttle, revoke) with appeals

## Quick Start

### Prerequisites

- Node.js 20+
- pnpm 8+
- Docker & Docker Compose (optional)

### Installation

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Start development
pnpm dev
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run specific service
docker-compose up dashboard
```

## Architecture

```
packages/
├── core/           # Shared types, crypto, Merkle trees
├── detection/      # Anomaly detection, behavioral analysis
├── scoring/        # Risk scoring engine
├── federation/     # P2P protocol, differential privacy
├── adjudication/   # Case management, voting system
├── intervention/   # Graduated interventions, appeals
└── dashboard/      # React reviewer dashboard
```

## Key Concepts

### Risk Scoring Dimensions

| Dimension   | Technical Proxy                          | Threshold       |
|-------------|------------------------------------------|-----------------|
| Harm        | Economic loss OR users targeted          | >$10k OR >100   |
| Persistence | Repeated behavior across sessions        | >5 sessions     |
| Autonomy    | Chained tool calls without re-prompt     | ≥4 calls        |
| Deception   | Output entropy + semantic inconsistency  | >0.85           |
| Evasion     | Prompt variation entropy                 | >3σ             |

### Intervention Tiers

- **Tier 1**: Public advisory
- **Tier 2**: Voluntary throttling request
- **Tier 3**: Credential shadow-ban / rate-limit

All interventions include a 24-hour appeal window.

## Security

- Append-only Merkle trees for audit logs
- Capability-based access control with RSA signatures
- Differential privacy for shared analytics
- Zero-knowledge proofs for threat alerts
- Input sanitization against poisoning attacks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure 80% minimum code coverage
5. Submit a pull request

## License

MIT - See LICENSE file for details.

## 18-Month Sunset Clause

This system includes automatic expiration of all interventions as part of the pilot program. The sunset period can be configured but defaults to 18 months.
