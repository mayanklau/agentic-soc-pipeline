"""
FastAPI application for the Agentic SOC Pipeline.

Provides REST API and WebSocket endpoints for:
- Alert submission and querying
- Incident management
- Agent status and metrics
- Real-time event streaming
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.agents.orchestrator import OrchestratorAgent
from src.agents.base import AgentContext, AgentTask
from src.config import Settings, get_settings
from src.memory.manager import MemoryManager
from src.models import Alert, AlertStatus, Incident, Severity, SecurityEvent

logger = structlog.get_logger()


# Global instances
settings: Settings = None
memory_manager: MemoryManager = None
orchestrator: OrchestratorAgent = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global settings, memory_manager, orchestrator
    
    logger.info("Starting Agentic SOC Pipeline API")
    
    # Initialize settings
    settings = get_settings()
    
    # Initialize memory manager
    memory_manager = MemoryManager(settings)
    await memory_manager.initialize()
    
    # Initialize orchestrator agent
    orchestrator = OrchestratorAgent(settings, memory_manager)
    await orchestrator.initialize()
    
    logger.info("API startup complete")
    
    yield
    
    # Cleanup
    logger.info("Shutting down API")
    await orchestrator.shutdown()
    await memory_manager.close()


app = FastAPI(
    title="Agentic SOC Pipeline",
    description="AI-powered Security Operations Center with specialized agents",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Request/Response Models
# ============================================================================

class AlertSubmission(BaseModel):
    """Request model for submitting a new alert."""
    
    title: str
    description: str
    severity: Severity
    source_system: str
    detection_rule: str | None = None
    event_ids: list[UUID] = Field(default_factory=list)
    mitre_attack: list[dict[str, str]] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class AlertResponse(BaseModel):
    """Response model for alert operations."""
    
    alert_id: UUID
    status: AlertStatus
    triage_score: float | None = None
    assigned_agent: str | None = None
    message: str


class IncidentCreate(BaseModel):
    """Request model for creating an incident."""
    
    title: str
    description: str
    severity: Severity
    alert_ids: list[UUID] = Field(default_factory=list)


class AgentStatusResponse(BaseModel):
    """Response model for agent status."""
    
    agent_type: str
    status: str
    model: str
    tasks_completed: int = 0
    tasks_pending: int = 0
    average_execution_time_ms: float = 0.0
    last_active: datetime | None = None


class PipelineHealthResponse(BaseModel):
    """Response model for pipeline health check."""
    
    status: str
    uptime_seconds: float
    agents_active: int
    events_processed_24h: int = 0
    alerts_processed_24h: int = 0
    incidents_open: int = 0
    memory_systems: dict[str, str] = Field(default_factory=dict)


# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "agentic-soc-pipeline"}


@app.get("/health/detailed", response_model=PipelineHealthResponse, tags=["Health"])
async def detailed_health_check() -> PipelineHealthResponse:
    """Detailed health check with component status."""
    return PipelineHealthResponse(
        status="healthy",
        uptime_seconds=0.0,  # Would track actual uptime
        agents_active=7,  # Would query actual agent status
        events_processed_24h=0,
        alerts_processed_24h=0,
        incidents_open=0,
        memory_systems={
            "episodic": "connected",
            "semantic": "connected",
            "procedural": "connected",
            "working": "connected",
            "shared": "connected",
        },
    )


# ============================================================================
# Alert Endpoints
# ============================================================================

@app.post("/api/v1/alerts", response_model=AlertResponse, tags=["Alerts"])
async def submit_alert(alert: AlertSubmission) -> AlertResponse:
    """
    Submit a new security alert for processing.
    
    The alert will be routed through the orchestrator to appropriate
    specialized agents for analysis.
    """
    logger.info("Alert submitted", title=alert.title, severity=alert.severity)
    
    # Create alert object
    alert_obj = Alert(
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        source_system=alert.source_system,
        detection_rule=alert.detection_rule,
        events=alert.event_ids,
        mitre_attack=[],  # Would parse from input
    )
    
    # Create task for orchestrator
    task = AgentTask(
        agent_type="orchestrator",
        task_type="route_alert",
        priority={"critical": 1, "high": 2, "medium": 3, "low": 4}.get(alert.severity.value, 3),
        payload={
            "alert": alert_obj.model_dump(),
            "raw_data": alert.raw_data,
        },
    )
    
    # Execute routing
    context = AgentContext(
        task=task,
        related_events=[],
        related_alerts=[],
    )
    
    result = await orchestrator.execute(context)
    
    return AlertResponse(
        alert_id=alert_obj.alert_id,
        status=AlertStatus.TRIAGING,
        triage_score=result.confidence if result.success else None,
        assigned_agent="orchestrator",
        message="Alert submitted and routing initiated" if result.success else f"Routing failed: {result.error}",
    )


@app.get("/api/v1/alerts/{alert_id}", tags=["Alerts"])
async def get_alert(alert_id: UUID) -> dict[str, Any]:
    """Get alert details by ID."""
    # Would query from database
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Alert {alert_id} not found",
    )


@app.get("/api/v1/alerts", tags=["Alerts"])
async def list_alerts(
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List alerts with optional filtering."""
    # Would query from database
    return {
        "alerts": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


@app.patch("/api/v1/alerts/{alert_id}/status", tags=["Alerts"])
async def update_alert_status(
    alert_id: UUID,
    new_status: AlertStatus,
    reason: str | None = None,
) -> AlertResponse:
    """Update alert status."""
    logger.info("Alert status updated", alert_id=str(alert_id), new_status=new_status)
    
    return AlertResponse(
        alert_id=alert_id,
        status=new_status,
        message=f"Status updated to {new_status.value}",
    )


# ============================================================================
# Incident Endpoints
# ============================================================================

@app.post("/api/v1/incidents", tags=["Incidents"])
async def create_incident(incident: IncidentCreate) -> dict[str, Any]:
    """Create a new security incident."""
    incident_obj = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        incident_type="manual",
        alerts=incident.alert_ids,
    )
    
    logger.info("Incident created", incident_id=str(incident_obj.incident_id))
    
    return {
        "incident_id": str(incident_obj.incident_id),
        "status": incident_obj.status.value,
        "message": "Incident created successfully",
    }


@app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
async def get_incident(incident_id: UUID) -> dict[str, Any]:
    """Get incident details by ID."""
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident {incident_id} not found",
    )


@app.get("/api/v1/incidents", tags=["Incidents"])
async def list_incidents(
    status: str | None = None,
    severity: Severity | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List incidents with optional filtering."""
    return {
        "incidents": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


# ============================================================================
# Agent Endpoints
# ============================================================================

@app.get("/api/v1/agents", tags=["Agents"])
async def list_agents() -> list[AgentStatusResponse]:
    """List all available agents and their status."""
    agents = [
        AgentStatusResponse(
            agent_type="orchestrator",
            status="active",
            model=settings.ollama.orchestrator_model,
        ),
        AgentStatusResponse(
            agent_type="triage",
            status="active",
            model=settings.ollama.triage_model,
        ),
        AgentStatusResponse(
            agent_type="malware",
            status="active",
            model=settings.ollama.malware_model,
        ),
        AgentStatusResponse(
            agent_type="network",
            status="active",
            model=settings.ollama.network_model,
        ),
        AgentStatusResponse(
            agent_type="identity",
            status="active",
            model=settings.ollama.identity_model,
        ),
        AgentStatusResponse(
            agent_type="threat_intel",
            status="active",
            model=settings.ollama.threat_intel_model,
        ),
        AgentStatusResponse(
            agent_type="response",
            status="active",
            model=settings.ollama.response_model,
        ),
    ]
    
    return agents


@app.get("/api/v1/agents/{agent_type}", tags=["Agents"])
async def get_agent_status(agent_type: str) -> AgentStatusResponse:
    """Get detailed status for a specific agent."""
    valid_agents = ["orchestrator", "triage", "malware", "network", "identity", "threat_intel", "response"]
    
    if agent_type not in valid_agents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_type}' not found",
        )
    
    model_map = {
        "orchestrator": settings.ollama.orchestrator_model,
        "triage": settings.ollama.triage_model,
        "malware": settings.ollama.malware_model,
        "network": settings.ollama.network_model,
        "identity": settings.ollama.identity_model,
        "threat_intel": settings.ollama.threat_intel_model,
        "response": settings.ollama.response_model,
    }
    
    return AgentStatusResponse(
        agent_type=agent_type,
        status="active",
        model=model_map[agent_type],
    )


@app.post("/api/v1/agents/{agent_type}/tasks", tags=["Agents"])
async def submit_agent_task(
    agent_type: str,
    task_type: str,
    payload: dict[str, Any],
    priority: int = 3,
) -> dict[str, Any]:
    """Submit a task directly to a specific agent."""
    task = AgentTask(
        agent_type=agent_type,
        task_type=task_type,
        priority=priority,
        payload=payload,
    )
    
    # Queue task
    await memory_manager.working.enqueue_task(task)
    
    return {
        "task_id": str(task.task_id),
        "agent_type": agent_type,
        "task_type": task_type,
        "status": "queued",
    }


# ============================================================================
# Search & Query Endpoints
# ============================================================================

@app.post("/api/v1/search/similar-incidents", tags=["Search"])
async def search_similar_incidents(
    query: str,
    limit: int = 10,
) -> dict[str, Any]:
    """Search for similar past incidents using semantic search."""
    results = await memory_manager.episodic.search_similar(
        query=query,
        collection="incidents",
        limit=limit,
    )
    
    return {
        "query": query,
        "results": results,
        "count": len(results),
    }


@app.get("/api/v1/entities/{entity_type}/{entity_id}/context", tags=["Search"])
async def get_entity_context(
    entity_type: str,
    entity_id: str,
) -> dict[str, Any]:
    """Get context for an entity from the knowledge graph."""
    context = await memory_manager.semantic.get_entity_context([
        {"type": entity_type, "id": entity_id}
    ])
    
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "context": context,
    }


# ============================================================================
# WebSocket Endpoints
# ============================================================================

class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


ws_manager = ConnectionManager()


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.
    
    Clients can subscribe to receive:
    - New alerts
    - Agent activity
    - Incident updates
    - Pipeline metrics
    """
    await ws_manager.connect(websocket)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()
            
            # Handle subscription requests
            if data.get("type") == "subscribe":
                await websocket.send_json({
                    "type": "subscribed",
                    "channels": data.get("channels", []),
                })
            
            # Echo for testing
            elif data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ============================================================================
# Metrics Endpoint (Prometheus format)
# ============================================================================

@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics() -> str:
    """Prometheus metrics endpoint."""
    metrics = []
    
    # Add basic metrics
    metrics.append("# HELP soc_alerts_total Total number of alerts processed")
    metrics.append("# TYPE soc_alerts_total counter")
    metrics.append("soc_alerts_total 0")
    
    metrics.append("# HELP soc_incidents_open Number of open incidents")
    metrics.append("# TYPE soc_incidents_open gauge")
    metrics.append("soc_incidents_open 0")
    
    metrics.append("# HELP soc_agent_tasks_total Total tasks processed by agent")
    metrics.append("# TYPE soc_agent_tasks_total counter")
    for agent in ["orchestrator", "triage", "malware", "network", "identity", "threat_intel", "response"]:
        metrics.append(f'soc_agent_tasks_total{{agent="{agent}"}} 0')
    
    return "\n".join(metrics)


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Run the API server."""
    import uvicorn
    
    settings = get_settings()
    
    uvicorn.run(
        "src.api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        workers=settings.api.workers,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
