"""
main.py — SentinelAI Gateway FastAPI Application Entry Point
"""
import sys
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from backend.config import settings
from backend.observability.metrics import setup_logging
from backend.routers import gateway, security, analytics, policy, agent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging()
    logger.info(f"🛡️  SentinelAI Gateway v{settings.APP_VERSION} starting up")
    logger.info(f"   Environment: {settings.ENVIRONMENT}")
    logger.info(f"   Debug mode: {settings.DEBUG}")
    yield
    logger.info("SentinelAI Gateway shutting down")


app = FastAPI(
    title="SentinelAI Gateway",
    description="""
## 🛡️ SentinelAI Gateway

Enterprise-grade AI Security Gateway that protects LLM applications, 
LangGraph agents, RAG pipelines, and MCP tool integrations.

### Features
- **Prompt Injection Detection** — Jailbreaks, role overrides, indirect injection
- **PII Detection & Redaction** — 20+ PII categories
- **Toxicity Filtering** — Violence, CSAM, CBRN, fraud, hate speech
- **RAG Security** — Document sanitization, poisoning detection
- **MCP Security** — Tool allow/deny policies, argument sanitization
- **Policy Engine** — YAML-configurable per-deployment policies
- **Observability** — Prometheus metrics, structured logging, dashboards
- **Multi-Provider** — OpenAI, Anthropic, Google, Ollama

### Authentication
Use the `X-API-Key` header with your API key.
Demo key: `sentinel-demo-key-12345`
    """,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request ID Middleware ─────────────────────────────────────────────────────
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    import uuid
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Powered-By"] = "SentinelAI Gateway"
    return response


# ── Global Error Handler ──────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ── Include Routers ───────────────────────────────────────────────────────────
app.include_router(gateway.router)
app.include_router(security.router)
app.include_router(analytics.router)
app.include_router(policy.router)
app.include_router(agent.router)


# ── Root Endpoints ────────────────────────────────────────────────────────────
@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "SentinelAI Gateway",
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
        "health": "/gateway/health",
    }


@app.get("/health", tags=["Root"])
async def health():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
    )
