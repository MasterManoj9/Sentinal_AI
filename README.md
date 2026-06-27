# Sentinel AI — Compliance Infrastructure for AI Agents

**Powered by Prime, the compliance gate agent**

Sentinel AI is a production-grade compliance layer that sits between your application and AI models. Its core agent, **Prime**, intercepts every AI query, scans for regulated data (HIPAA Protected Health Information by default), enforces model routing policies, and maintains an immutable audit trail of every decision. Prime remembers past decisions across sessions using [Hindsight](https://github.com/vectorize-io/hindsight), enabling adaptive enforcement that learns from your organization's compliance patterns over time.

---

## Why It Matters

Production AI systems regularly handle sensitive data — patient records, financial information, personally identifiable information. Most AI pipelines send this data directly to third-party models with no compliance checks, no audit trail, and no memory of past violations. This creates regulatory risk under HIPAA, GDPR, and other frameworks.

Sentinel AI solves this by placing an intelligent compliance gate between your application and AI models. Every query is scanned, every decision is logged, and only approved models receive your data.

---

## Architecture

```
                         ┌─────────────────────────────────┐
                         │         Sentinel AI              │
                         │                                  │
  Client Query ──────►   │  ┌──────────┐   ┌────────────┐  │
                         │  │ Detector │──►│    Gate     │  │
                         │  │(Regex+LLM│   │(ALLOW/BLOCK│  │
                         │  └──────────┘   │  /REDACT)  │  │
                         │        │        └─────┬──────┘  │
                         │        │              │         │
                         │  ┌─────▼──────┐ ┌─────▼──────┐  │
                         │  │ Hindsight  │ │   Router   │  │
                         │  │  (Memory)  │ │(cascadeflow)│  │
                         │  └────────────┘ └─────┬──────┘  │
                         │                       │         │
                         │  ┌────────────────────▼──────┐  │
                         │  │   Audit Log (JSONL)       │  │
                         │  │   (Append-only, immutable) │  │
                         │  └───────────────────────────┘  │
                         └─────────────────────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   Approved Models    │
                              │  • groq/gpt-oss-120b │
                              │  • ollama/llama3.1   │
                              └──────────────────────┘
```

**Key integrations:**
- **[Hindsight](https://github.com/vectorize-io/hindsight)** — Persistent cross-session memory for compliance decisions
- **[cascadeflow](https://pypi.org/project/cascadeflow/)** — Intelligent model routing with automatic escalation

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/sentinel-ai/sentinel-ai.git
cd sentinel-ai
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your GROQ_API_KEY and HINDSIGHT_API_KEY
```

### 3. Run

```bash
uvicorn sentinel_ai.main:app --reload --port 8000
```

Or with Docker:
```bash
docker-compose up
```

Then visit:
- **API docs**: http://localhost:8000/docs
- **Health check**: http://localhost:8000/health
- **Run demos**: http://localhost:8000/demo

---

## Demo Scenarios

Sentinel AI ships with three built-in scenarios that exercise the Prime compliance gate. Run them with:

```bash
python -m sentinel_ai.scenarios
```

Or via the API:
```bash
curl http://localhost:8000/demo
```

### Scenario 1: Block PHI (SSN + Diagnosis + Name)

**Input:** `"Patient John Smith (SSN: 123-45-6789) was diagnosed with Type 2 Diabetes..."`

| Field | Value |
|-------|-------|
| PHI Detected | Yes (10 entities) |
| Decision | **BLOCK** |
| Reason | Query contains high-sensitivity PHI (ssn) |
| Model Used | none |

### Scenario 2: Redact Medical (Diagnosis + Doctor Name)

**Input:** `"Dr. Emily Chen noted that the patient presents with symptoms consistent with Major Depressive Disorder..."`

| Field | Value |
|-------|-------|
| PHI Detected | Yes (3 entities) |
| Decision | **REDACT** |
| Reason | PHI eligible for redaction; mask strategy applied |
| Model Used | groq/openai-gpt-oss-120b |

### Scenario 3: Attack — Non-Compliant Model Request

**Input:** `"What are the common side effects of Lisinopril?"` with `requested_model: "openai/gpt-4"`

| Field | Value |
|-------|-------|
| Decision | **BLOCK** |
| Reason | Requested model 'openai/gpt-4' is not approved under HIPAA |
| Blocked Model | openai/gpt-4 |

---

## How Hindsight Memory Works in Prime

Prime uses [Hindsight](https://github.com/vectorize-io/hindsight) to maintain persistent, cross-session memory of compliance decisions:

1. **Store**: After every compliance decision, Prime stores the query hash, decision type, client ID, and outcome metadata in Hindsight's vector store.

2. **Recall**: Before evaluating a new query, Prime recalls the top-5 most relevant past decisions for the same client. This enables:
   - **Escalation**: Clients with prior BLOCK history face stricter enforcement
   - **Pattern recognition**: Repeated violation types are flagged

3. **Reflect**: The `reflect()` method analyzes accumulated decisions to surface trends — block rates, common violation types, and compliance improvements over time.

If Hindsight is unavailable (no API key or SDK not installed), Prime degrades gracefully to an in-memory fallback store. No functionality is lost — only cross-session persistence.

---

## How cascadeflow Routing Works in Prime

Prime uses [cascadeflow](https://pypi.org/project/cascadeflow/) to intelligently route queries to approved models:

1. **Policy enforcement**: Only models listed in `approved_models` in the policy file are available for routing. Blocked models are never called.

2. **Cost optimization**: Queries are routed to the cheapest approved model first (groq/openai-gpt-oss-120b).

3. **Automatic escalation**: If the primary model returns an empty or low-quality response, cascadeflow escalates to the fallback model (ollama/llama3.1).

4. **Redaction pipeline**: For REDACT decisions, PHI is masked with typed placeholders (`[REDACTED-SSN]`, `[REDACTED-DIAGNOSIS]`) before the query reaches any model.

If cascadeflow is unavailable, Prime returns a simulated response explaining the routing decision — useful for testing and development.

---

## Audit Trail

Every compliance decision is logged to an append-only JSONL file (`audit.log`). Entries are never overwritten or deleted.

### Format

Each line in `audit.log` is a JSON object:

```json
{
  "audit_id": "f5038df1-3a08-4f9b-9988-f95cf0bb0fde",
  "timestamp": "2025-01-15T10:30:00.150000+00:00",
  "event": "DECISION_MADE",
  "agent": "Prime",
  "project": "Sentinel AI",
  "client_id": "hospital-emr-001",
  "query_hash": "98ac1f09b938...",
  "decision": "BLOCK",
  "reason": "Query contains high-sensitivity PHI (ssn).",
  "model_used": "none",
  "cost": 0.0,
  "latency_ms": 7.84,
  "entity_count": 10,
  "redacted": false
}
```

### Access via API

```bash
# Recent entries
curl http://localhost:8000/audit/recent?limit=20

# By client
curl http://localhost:8000/audit/client/hospital-emr-001

# Aggregate stats
curl http://localhost:8000/audit/stats
```

### Location

- **File**: `audit.log` in the project root (configurable via `AUDIT_LOG_PATH`)
- **stdout**: All audit entries are also printed to stdout for live monitoring
- **Example**: See `examples/sample_audit_log.jsonl` for a sample

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/query` | Process a query through the Prime compliance gate |
| `GET` | `/audit/recent` | Get recent audit log entries |
| `GET` | `/audit/client/{id}` | Get audit entries for a specific client |
| `GET` | `/audit/stats` | Get aggregate audit statistics |
| `GET` | `/health` | System health check |
| `GET` | `/demo` | Run all 3 demo scenarios |
| `GET` | `/docs` | Interactive API documentation (Swagger UI) |

### Example: Process a query

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app-001",
    "query": "What are the side effects of Metformin?"
  }'
```

---

## Project Structure

```
sentinel-ai/
├── policies/hipaa.json          # HIPAA compliance policy configuration
├── sentinel_ai/
│   ├── main.py                  # FastAPI application & endpoints
│   ├── prime.py                 # Prime agent — main compliance gate class
│   ├── detector.py              # PHI/PII detection (regex + LLM)
│   ├── gate.py                  # Compliance decision engine
│   ├── router.py                # Model routing via cascadeflow
│   ├── memory.py                # Hindsight memory integration
│   ├── audit.py                 # Append-only JSONL audit logger
│   ├── redact.py                # PHI redaction utilities
│   ├── scenarios.py             # Built-in demo scenarios
│   └── config.py                # Configuration loader
├── tests/                       # 34 pytest tests
├── examples/                    # Sample queries and audit logs
├── Dockerfile                   # Production container image
└── docker-compose.yml           # One-command deployment
```

---

## Roadmap

- [ ] **Multi-framework support**: Add GDPR, SOC 2, and PCI-DSS policy templates
- [ ] **Dashboard UI**: Real-time compliance monitoring web interface
- [ ] **Webhook alerts**: Notify security teams on BLOCK decisions
- [ ] **Client-specific policies**: Per-client policy overrides
- [ ] **Model quality scoring**: Track and compare model response quality
- [ ] **Batch processing**: Support for bulk query compliance checking
- [ ] **Advanced PHI detection**: Fine-tuned NER model for medical entities
- [ ] **Rate limiting**: Per-client query rate limits with compliance tiers

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Sentinel AI</strong> — Because compliance shouldn't be an afterthought.<br>
  Powered by <strong>Prime</strong>, the compliance gate agent.
</p>
