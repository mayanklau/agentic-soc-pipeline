# 🛡️ Agentic SOC Pipeline

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A unified, AI-powered Security Operations Center (SOC) pipeline that consolidates multiple security data streams into a single source of truth, featuring specialized small language models (SLMs) for each security domain and a multi-tier memory architecture.

**Inspired by [Agoda's Financial Unified Data Pipeline (FINUDP)](https://medium.com/agoda-engineering)** architecture, adapted for security operations.

---

## 🎯 Overview

Modern SOCs face the same challenge Agoda encountered with financial data: **fragmented pipelines with inconsistent logic across teams**. This project provides:

- **Unified Security Data Lake**: Single source of truth for all security events
- **Specialized AI Agents**: Domain-specific SLMs fine-tuned for security tasks
- **Multi-Tier Memory System**: Episodic, semantic, procedural, and working memory
- **Quality Framework**: Data contracts, validation rules, and anomaly detection
- **Human-in-the-Loop**: Escalation workflows and analyst feedback integration

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AGENTIC SOC PIPELINE                             │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │   SIEM   │  │   EDR    │  │ Network  │  │  Threat  │            │
│  │   Logs   │  │  Alerts  │  │   Flow   │  │   Intel  │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       └─────────────┴─────────────┴─────────────┘                  │
│                          │                                          │
│                          ▼                                          │
│              ┌───────────────────────┐                              │
│              │   Unified Data Lake   │                              │
│              └───────────┬───────────┘                              │
│                          │                                          │
│       ┌──────────────────┼──────────────────┐                      │
│       ▼                  ▼                  ▼                      │
│  ┌─────────┐       ┌─────────┐        ┌─────────┐                  │
│  │Episodic │       │Semantic │        │Procedural│                 │
│  │ Memory  │       │ Memory  │        │  Memory  │                 │
│  └─────────┘       └─────────┘        └──────────┘                 │
│                          │                                          │
│                          ▼                                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   SPECIALIZED AGENTS                          │  │
│  │  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ │  │
│  │  │Triage │ │Malware│ │Network│ │Identity│ │Threat │ │Response│ │  │
│  │  │ Agent │ │ Agent │ │ Agent │ │ Agent │ │ Intel │ │ Agent │ │  │
│  │  └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ └───────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- 16GB+ RAM (for running local SLMs)
- GPU recommended (NVIDIA with CUDA 12+)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/agentic-soc-pipeline.git
cd agentic-soc-pipeline

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Start infrastructure services
docker-compose up -d

# Initialize the database and vector stores
python scripts/init_databases.py

# Run the pipeline
python -m src.main
```

### Using Docker (Recommended for Production)

```bash
# Build and run everything
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f agentic-soc
```

---

## 🏗️ Architecture

### Core Components

| Component | Description |
|-----------|-------------|
| **Data Ingestion** | Kafka-based streaming from SIEM, EDR, network, cloud sources |
| **Unified Data Lake** | Three-zone architecture (Raw → Enriched → Curated) |
| **Memory Systems** | Multi-tier memory for context and learning |
| **Agent Layer** | Specialized SLMs for each security domain |
| **Quality Framework** | Data contracts, validation, anomaly detection |
| **API Layer** | FastAPI-based REST and WebSocket APIs |

### Memory Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MEMORY SYSTEMS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  EPISODIC MEMORY          SEMANTIC MEMORY      PROCEDURAL MEM  │
│  ┌─────────────┐          ┌─────────────┐      ┌─────────────┐ │
│  │  ChromaDB/  │          │   Neo4j     │      │ PostgreSQL  │ │
│  │  Pinecone   │          │  Knowledge  │      │  + Git      │ │
│  │             │          │    Graph    │      │             │ │
│  │ • Incidents │          │ • Entities  │      │ • Runbooks  │ │
│  │ • Patterns  │          │ • Relations │      │ • Playbooks │ │
│  │ • Cases     │          │ • Context   │      │ • Procedures│ │
│  └─────────────┘          └─────────────┘      └─────────────┘ │
│                                                                 │
│  WORKING MEMORY           SHARED CONTEXT       LEARNING MEM    │
│  ┌─────────────┐          ┌─────────────┐      ┌─────────────┐ │
│  │   Redis     │          │   Kafka     │      │   MLflow    │ │
│  │             │          │   Topics    │      │             │ │
│  │ • Sessions  │          │ • Agent Msg │      │ • Feedback  │ │
│  │ • State     │          │ • Priority  │      │ • Metrics   │ │
│  │ • Scratch   │          │ • Handoffs  │      │ • Tuning    │ │
│  └─────────────┘          └─────────────┘      └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Specialized Agents

| Agent | Model | Purpose | Fine-tuning Focus |
|-------|-------|---------|-------------------|
| **Orchestrator** | Phi-3-medium (14B) | Route, coordinate, synthesize | Multi-step reasoning |
| **Triage** | Phi-3-mini (3.8B) | Alert scoring, deduplication | False positive detection |
| **Malware** | CodeLlama-7B | Static/dynamic analysis | Code patterns, YARA |
| **Network** | Mistral-7B | Traffic analysis, C2 detection | Protocol analysis |
| **Identity** | Phi-3-mini (3.8B) | Auth anomalies | Credential abuse |
| **Threat Intel** | Llama-3-8B | IOC enrichment, MITRE mapping | Attribution |
| **Response** | Phi-3-mini (3.8B) | Containment, remediation | Action generation |

---

## 📁 Project Structure

```
agentic-soc-pipeline/
├── src/
│   ├── agents/              # Specialized AI agents
│   │   ├── base.py          # Base agent class
│   │   ├── orchestrator.py  # Central coordinator
│   │   ├── triage.py        # Alert triage agent
│   │   ├── malware.py       # Malware analysis agent
│   │   ├── network.py       # Network analysis agent
│   │   ├── identity.py      # Identity/auth agent
│   │   ├── threat_intel.py  # Threat intelligence agent
│   │   └── response.py      # Incident response agent
│   ├── memory/              # Memory subsystems
│   │   ├── episodic.py      # Vector-based incident memory
│   │   ├── semantic.py      # Knowledge graph
│   │   ├── procedural.py    # Runbook/playbook storage
│   │   ├── working.py       # Session state
│   │   └── manager.py       # Unified memory interface
│   ├── pipeline/            # Data processing
│   │   ├── ingestion.py     # Kafka consumers
│   │   ├── enrichment.py    # Data enrichment
│   │   ├── normalization.py # Schema normalization
│   │   └── streaming.py     # Spark streaming jobs
│   ├── quality/             # Data quality framework
│   │   ├── contracts.py     # Data contract definitions
│   │   ├── validation.py    # Validation rules
│   │   ├── anomaly.py       # ML anomaly detection
│   │   └── alerts.py        # Quality alerting
│   ├── api/                 # REST API
│   │   ├── routes/          # API endpoints
│   │   ├── websocket.py     # Real-time updates
│   │   └── main.py          # FastAPI app
│   ├── utils/               # Utilities
│   └── main.py              # Entry point
├── config/                  # Configuration files
│   ├── agents.yaml          # Agent configurations
│   ├── memory.yaml          # Memory system config
│   ├── pipeline.yaml        # Pipeline settings
│   ├── quality.yaml         # Quality rules
│   └── data_contracts/      # Contract definitions
├── docker/                  # Docker configurations
├── scripts/                 # Utility scripts
├── tests/                   # Test suites
├── docs/                    # Documentation
└── examples/                # Usage examples
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# .env
# Infrastructure
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
REDIS_URL=redis://localhost:6379
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
CHROMA_HOST=localhost
CHROMA_PORT=8000
POSTGRES_URL=postgresql://user:pass@localhost:5432/soc

# Models
OLLAMA_HOST=http://localhost:11434
HF_TOKEN=your_huggingface_token
MODEL_CACHE_DIR=/models

# Integrations
SPLUNK_HOST=https://splunk.example.com
SPLUNK_TOKEN=your_token
CROWDSTRIKE_CLIENT_ID=your_id
CROWDSTRIKE_CLIENT_SECRET=your_secret

# Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_API_KEY=your_key
```

### Agent Configuration

```yaml
# config/agents.yaml
orchestrator:
  model: "phi3:14b-medium-128k-instruct-q4_K_M"
  temperature: 0.1
  max_tokens: 4096
  timeout_seconds: 60

triage:
  model: "phi3:mini"
  temperature: 0.0
  max_tokens: 1024
  batch_size: 50
  confidence_threshold: 0.85

malware:
  model: "codellama:7b"
  temperature: 0.1
  max_tokens: 2048
  sandbox_timeout: 300
```

---

## 📊 Data Contracts

Define expectations between data producers and consumers:

```yaml
# config/data_contracts/edr_events.yaml
contract:
  name: edr_endpoint_events
  version: "1.0.0"
  producer: crowdstrike_integration
  consumers:
    - triage_agent
    - malware_agent
  
  schema:
    required_fields:
      - event_id: uuid
      - timestamp: iso8601
      - hostname: string
      - process_hash: sha256
      - severity: enum[low, medium, high, critical]
    optional_fields:
      - parent_process: string
      - command_line: string
      - network_connections: array
    
  quality_rules:
    completeness:
      - field: event_id
        rule: not_null
      - field: timestamp
        rule: not_null
    validity:
      - field: severity
        rule: in_set
        values: [low, medium, high, critical]
    freshness:
      max_delay_seconds: 300
      
  sla:
    availability: 99.5%
    latency_p95_seconds: 30
    
  on_violation:
    actions:
      - type: alert
        channel: slack
        destination: "#soc-data-quality"
      - type: metric
        name: contract_violation
    escalation:
      after_minutes: 15
      destination: pagerduty
    halt_pipeline: false
```

---

## 🔌 Integrations

### Supported Data Sources

| Category | Sources |
|----------|---------|
| **SIEM** | Splunk, Elastic SIEM, Microsoft Sentinel, QRadar |
| **EDR** | CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black |
| **Network** | Zeek, Suricata, Palo Alto, Cisco |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit |
| **Identity** | Okta, Azure AD, CyberArk |
| **Threat Intel** | MISP, VirusTotal, AbuseIPDB, Shodan |

### Adding Custom Integrations

```python
from src.pipeline.ingestion import BaseIngestion

class CustomSIEMIngestion(BaseIngestion):
    """Custom integration for proprietary SIEM."""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.client = CustomSIEMClient(config["api_url"])
    
    async def fetch_events(self, since: datetime) -> AsyncIterator[SecurityEvent]:
        async for raw_event in self.client.stream_events(since):
            yield self.normalize(raw_event)
    
    def normalize(self, raw: dict) -> SecurityEvent:
        return SecurityEvent(
            event_id=raw["id"],
            timestamp=parse_timestamp(raw["time"]),
            source="custom_siem",
            severity=self.map_severity(raw["level"]),
            raw_data=raw
        )
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/

# Run agent tests
pytest tests/unit/agents/ -v
```

---

## 📈 Monitoring & Observability

The pipeline exposes metrics via Prometheus and provides pre-built Grafana dashboards:

- **Pipeline Health**: Event throughput, latency, error rates
- **Agent Performance**: Inference time, accuracy, confidence distributions
- **Memory Utilization**: Vector store size, cache hit rates
- **Quality Metrics**: Contract violations, data freshness, validation failures

```bash
# Access dashboards
open http://localhost:3000  # Grafana
open http://localhost:9090  # Prometheus
```

---

## 🛣️ Roadmap

- [x] Core pipeline architecture
- [x] Multi-tier memory system
- [x] Specialized agent framework
- [x] Data contract validation
- [ ] Fine-tuning pipeline for SLMs
- [ ] SOAR integration (Phantom, XSOAR)
- [ ] Automated playbook generation
- [ ] Federated learning across SOCs
- [ ] Natural language incident queries

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Setup development environment
pip install -e ".[dev]"
pre-commit install

# Run linters
black src/ tests/
ruff check src/ tests/
mypy src/
```

---

## 📄 License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- Architecture inspired by [Agoda's FINUDP](https://medium.com/agoda-engineering)
- Built with [LangGraph](https://github.com/langchain-ai/langgraph), [Ollama](https://ollama.ai), and [FastAPI](https://fastapi.tiangolo.com)
