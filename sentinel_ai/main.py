# sentinel_ai/main.py
# FastAPI application for Sentinel AI.
# Exposes the Prime compliance gate as a REST API with endpoints for
# query processing, audit retrieval, health checks, and demo scenarios.

import logging
import sys
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Request, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from groq import AsyncGroq

from sentinel_ai import __version__, __agent__, __project__
from sentinel_ai.audit import read_recent, read_by_client, get_stats
from sentinel_ai.config import SentinelConfig
from sentinel_ai.prime import Prime
from sentinel_ai.scenarios import run_all_scenarios

logger = logging.getLogger("sentinel_ai.main")

# ─── Configure logging ───
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","logger":"%(name)s","level":"%(levelname)s","message":"%(message)s"}',
    stream=sys.stdout,
)


# ─── Pydantic models for request/response shapes ───


class QueryRequest(BaseModel):
    """Request body for the /query endpoint."""

    client_id: str = Field(
        ...,
        description="Unique identifier for the requesting client.",
        examples=["client-001"],
    )
    query: str = Field(
        ...,
        description="The AI query text to evaluate for compliance.",
        examples=["What are the side effects of Metformin?"],
    )
    requested_model: Optional[str] = Field(
        default=None,
        description="Optional: specific model to route to (will be validated against policy).",
        examples=["groq/openai-gpt-oss-120b"],
    )


class QueryResponse(BaseModel):
    """Response body from the /query endpoint."""

    decision: str = Field(..., description="Compliance decision: ALLOW, REDACT, or BLOCK.")
    reason: str = Field(..., description="Human-readable explanation of the decision.")
    response: str = Field(..., description="Model response or block notice.")
    model_used: str = Field(..., description="The model that processed the query (or 'none').")
    cost: float = Field(..., description="Cost in USD for the model call.")
    latency_ms: float = Field(..., description="Total processing time in milliseconds.")
    audit_id: str = Field(..., description="Unique audit trail entry ID.")
    phi_detected: bool = Field(..., description="Whether PHI was detected in the query.")
    entity_count: int = Field(..., description="Number of PHI entities detected.")
    detection_method: str = Field(..., description="Detection method used (regex, llm, both).")
    redacted: bool = Field(..., description="Whether the query was redacted before routing.")
    escalated: bool = Field(..., description="Whether the model was escalated.")


class ChatRequest(BaseModel):
    """Request body for the FAQ /chat endpoint."""
    message: str = Field(..., description="The user's message to the FAQ agent.")


class ChatResponse(BaseModel):
    """Response body for the FAQ /chat endpoint."""
    response: str = Field(..., description="The agent's reply.")


class HealthResponse(BaseModel):
    """Response body from the /health endpoint."""

    status: str = Field(default="ok")
    agent: str = Field(default=__agent__)
    project: str = Field(default=__project__)
    version: str = Field(default=__version__)
    hindsight: bool = Field(..., description="Whether Hindsight memory is available.")
    cascadeflow: bool = Field(..., description="Whether cascadeflow routing is available.")
    policy_framework: str = Field(..., description="Active compliance framework.")


class AuditEntry(BaseModel):
    """Single audit log entry."""

    audit_id: str = ""
    timestamp: str = ""
    event: str = ""
    agent: str = ""
    project: str = ""
    client_id: str = ""
    query_hash: str = ""
    decision: str = ""
    reason: str = ""
    model_used: str = ""
    cost: float = 0.0
    latency_ms: float = 0.0
    entity_count: int = 0
    redacted: bool = False
    metadata: Dict[str, Any] = {}


class AuditResponse(BaseModel):
    """Response body for audit endpoints."""

    entries: List[Dict[str, Any]] = Field(default_factory=list)
    count: int = 0


# ─── Application lifecycle ───

prime_agent: Optional[Prime] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Prime agent on startup and clean up on shutdown."""
    global prime_agent
    logger.info("Initializing Sentinel AI...")
    try:
        config = SentinelConfig()
        prime_agent = Prime(config=config)
        logger.info(f"{__agent__} agent initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize {__agent__}: {e}")
        prime_agent = Prime(hindsight_enabled=False)

    yield

    logger.info("Shutting down Sentinel AI.")


# ─── FastAPI app ───

app = FastAPI(
    title="Sentinel AI",
    description="Prime Compliance Gate API",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the static directory for the spatial UI
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="static")


# ─── Endpoints ───


@app.post("/query", response_model=QueryResponse, tags=["Core"])
async def process_query(request: QueryRequest) -> QueryResponse:
    """Process an AI query through the Prime compliance gate.

    The full pipeline runs: detect PHI → recall memory → evaluate policy →
    route to approved model → redact if needed → log to audit trail.
    """
    global prime_agent
    if prime_agent is None:
        prime_agent = Prime(hindsight_enabled=False)

    try:
        result = prime_agent.process(
            query=request.query,
            client_id=request.client_id,
            requested_model=request.requested_model,
        )
        return QueryResponse(**result)
    except Exception as e:
        logger.error(f"Query processing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")


@app.post("/chat", response_model=ChatResponse, tags=["UI"])
async def process_chat(request: ChatRequest) -> ChatResponse:
    """Process a chat message for the Support FAQ Agent.
    
    Uses Groq to answer questions based strictly on the injected
    course policies and Sentinel AI capabilities.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return ChatResponse(response="I'm offline right now! Please provide a GROQ_API_KEY in your .env file to enable the support agent.")

    system_prompt = (
        "You are the Sentinel AI Support Agent, an expert assistant that lives inside the Sentinel AI Dashboard. "
        "Your job is to answer user questions concisely and helpfully.\n\n"
        "KNOWLEDGE BASE & COURSE POLICIES:\n"
        "- Sentinel AI is an enterprise-grade compliance gate that intercepts AI queries in real-time to detect and govern regulated data (like PHI, PII, Financial data).\n"
        "- It is agnostic: it can enforce ANY policy framework (HIPAA, GDPR, PCI) simply by loading a new JSON rulebook. It is NOT only for medical.\n"
        "- Core features include: Immutable Audit logging, Cross-Session Memory (via Hindsight) to remember repeat offenders, Cascade Routing to dynamically route to approved models (Groq/Ollama), and Smart Redaction.\n"
        "- Course Policy: Students must ensure all data handled complies with standard ethical guidelines. The platform enforces these rules automatically. Sentinel AI guarantees zero data leakage.\n"
        "TONE:\n"
        "- Be friendly, concise (1-3 sentences max), and extremely professional.\n"
        "CRITICAL RULE:\n"
        "- Under NO circumstances should you ever mention or use the word 'hackathon'. Treat this as a production, real-world enterprise product."
    )

    try:
        client = AsyncGroq(api_key=api_key)
        completion = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": request.message}
            ],
            temperature=0.3,
            max_tokens=150,
        )
        return ChatResponse(response=completion.choices[0].message.content or "I couldn't process that.")
    except Exception as e:
        logger.error(f"Chat agent error: {e}")
        return ChatResponse(response="Sorry, I am having trouble connecting to my brain right now.")


@app.get("/audit/recent", response_model=AuditResponse, tags=["Audit"])
async def get_recent_audit(limit: int = Query(default=20, ge=1, le=1000)) -> AuditResponse:
    """Retrieve the most recent audit log entries.

    Args:
        limit: Maximum number of entries to return (default: 20).
    """
    try:
        entries = read_recent(limit=limit)
        return AuditResponse(entries=entries, count=len(entries))
    except Exception as e:
        logger.error(f"Audit retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit error: {str(e)}")


@app.get("/audit/client/{client_id}", response_model=AuditResponse, tags=["Audit"])
async def get_client_audit(client_id: str) -> AuditResponse:
    """Retrieve all audit log entries for a specific client.

    Args:
        client_id: The client identifier to filter by.
    """
    try:
        entries = read_by_client(client_id=client_id)
        return AuditResponse(entries=entries, count=len(entries))
    except Exception as e:
        logger.error(f"Client audit retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit error: {str(e)}")


@app.get("/audit/stats", tags=["Audit"])
async def get_audit_stats() -> Dict[str, Any]:
    """Get aggregate statistics from the audit log."""
    try:
        return get_stats()
    except Exception as e:
        logger.error(f"Audit stats failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats error: {str(e)}")


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Check the health of the Sentinel AI system.

    Returns the status of all subsystems including Hindsight memory
    and cascadeflow routing availability.
    """
    hindsight_available = False
    cascadeflow_available = False

    try:
        import hindsight_client  # noqa: F401
        hindsight_available = True
    except ImportError:
        pass

    try:
        import cascadeflow  # noqa: F401
        cascadeflow_available = True
    except ImportError:
        pass

    config = SentinelConfig()

    return HealthResponse(
        status="ok",
        agent=__agent__,
        project=__project__,
        version=__version__,
        hindsight=hindsight_available,
        cascadeflow=cascadeflow_available,
        policy_framework=config.policy.get("framework", "unknown"),
    )


@app.get("/demo", tags=["Demo"])
async def run_demo() -> Dict[str, Any]:
    """Run all three demo scenarios and return results.

    Executes the built-in demo scenarios that exercise the Prime
    compliance gate across BLOCK, REDACT, and non-compliant model
    attack scenarios.
    """
    try:
        results = run_all_scenarios()
        return {
            "status": "completed",
            "scenarios_run": len(results),
            "results": results,
            "summary": {
                "scenario_1_block_phi": results[0].get("decision") if len(results) > 0 else "not run",
                "scenario_2_redact_medical": results[1].get("decision") if len(results) > 1 else "not run",
                "scenario_3_attack_noncompliant": results[2].get("decision") if len(results) > 2 else "not run",
            },
        }
    except Exception as e:
        logger.error(f"Demo execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Demo error: {str(e)}")


@app.get("/", tags=["UI"])
async def serve_ui():
    """Serve the Spatial UI dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Sentinel AI UI is building..."}
