"""
Core data models for the Agentic SOC Pipeline.

These models define the canonical schema for security events, alerts,
incidents, and other core entities used throughout the pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Standardized severity levels across all data sources."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_numeric(cls, value: int) -> "Severity":
        """Convert numeric severity (1-10) to enum."""
        if value <= 3:
            return cls.LOW
        elif value <= 5:
            return cls.MEDIUM
        elif value <= 7:
            return cls.HIGH
        else:
            return cls.CRITICAL


class EventType(str, Enum):
    """Categories of security events."""
    
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    DNS = "dns"
    HTTP = "http"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class AlertStatus(str, Enum):
    """Status of an alert in the triage workflow."""
    
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class IncidentStatus(str, Enum):
    """Status of a security incident."""
    
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    

class MITREAttack(BaseModel):
    """MITRE ATT&CK framework mapping."""
    
    tactic_id: str = Field(..., description="e.g., TA0001")
    tactic_name: str = Field(..., description="e.g., Initial Access")
    technique_id: str = Field(..., description="e.g., T1566")
    technique_name: str = Field(..., description="e.g., Phishing")
    subtechnique_id: str | None = Field(None, description="e.g., T1566.001")
    subtechnique_name: str | None = Field(None, description="e.g., Spearphishing Attachment")
    

class ThreatActor(BaseModel):
    """Known threat actor or campaign attribution."""
    
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    motivation: str | None = None
    sophistication: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class IOC(BaseModel):
    """Indicator of Compromise."""
    
    id: UUID = Field(default_factory=uuid4)
    type: str = Field(..., description="ip, domain, hash, url, email, etc.")
    value: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)


class Asset(BaseModel):
    """Network asset (endpoint, server, etc.)."""
    
    id: UUID = Field(default_factory=uuid4)
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    os: str | None = None
    os_version: str | None = None
    asset_type: str = Field(default="endpoint", description="endpoint, server, network, cloud")
    criticality: Severity = Field(default=Severity.MEDIUM)
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    tags: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None


class User(BaseModel):
    """User entity for identity-related events."""
    
    id: UUID = Field(default_factory=uuid4)
    username: str
    email: str | None = None
    display_name: str | None = None
    department: str | None = None
    title: str | None = None
    manager: str | None = None
    privileged: bool = False
    service_account: bool = False
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)


class SecurityEvent(BaseModel):
    """
    Normalized security event - the canonical format for all ingested data.
    
    This is the "single source of truth" format that all data sources
    are normalized into before further processing.
    """
    
    # Identity
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID | None = Field(None, description="Links related events")
    
    # Temporal
    timestamp: datetime
    ingestion_time: datetime = Field(default_factory=datetime.utcnow)
    
    # Classification
    event_type: EventType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    
    # Source
    source_system: str = Field(..., description="e.g., crowdstrike, splunk, zeek")
    source_category: str = Field(..., description="e.g., edr, siem, network")
    
    # Entities
    asset: Asset | None = None
    user: User | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    
    # Process context
    process_name: str | None = None
    process_path: str | None = None
    process_hash: str | None = None
    process_command_line: str | None = None
    parent_process_name: str | None = None
    parent_process_hash: str | None = None
    
    # File context
    file_name: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    
    # Network context
    protocol: str | None = None
    domain: str | None = None
    url: str | None = None
    
    # Enrichment
    iocs: list[IOC] = Field(default_factory=list)
    mitre_attack: list[MITREAttack] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    
    # Metadata
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    enrichment_data: dict[str, Any] = Field(default_factory=dict)
    
    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


class Alert(BaseModel):
    """
    Security alert generated from one or more events.
    
    Alerts are the primary unit of work for SOC analysts and agents.
    """
    
    alert_id: UUID = Field(default_factory=uuid4)
    
    # Classification
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    
    # Source
    source_system: str
    detection_rule: str | None = None
    
    # Status
    status: AlertStatus = Field(default=AlertStatus.NEW)
    assigned_to: str | None = None
    
    # Related data
    events: list[UUID] = Field(default_factory=list, description="Related event IDs")
    incident_id: UUID | None = Field(None, description="Parent incident if escalated")
    
    # Enrichment
    mitre_attack: list[MITREAttack] = Field(default_factory=list)
    affected_assets: list[UUID] = Field(default_factory=list)
    affected_users: list[UUID] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    
    # Agent analysis
    triage_score: float | None = Field(None, ge=0.0, le=1.0)
    agent_analysis: dict[str, Any] = Field(default_factory=dict)
    recommended_actions: list[str] = Field(default_factory=list)
    
    # Temporal
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    first_event_time: datetime | None = None
    last_event_time: datetime | None = None
    
    # Metadata
    tags: list[str] = Field(default_factory=list)
    
    
class Incident(BaseModel):
    """
    Security incident - a confirmed threat requiring response.
    
    Incidents are created when alerts are escalated or correlated
    into a broader attack narrative.
    """
    
    incident_id: UUID = Field(default_factory=uuid4)
    
    # Classification
    title: str
    description: str
    severity: Severity
    incident_type: str = Field(..., description="e.g., ransomware, data_breach, apt")
    
    # Status
    status: IncidentStatus = Field(default=IncidentStatus.OPEN)
    priority: int = Field(ge=1, le=5, default=3)
    
    # Assignment
    lead_analyst: str | None = None
    team: list[str] = Field(default_factory=list)
    
    # Related data
    alerts: list[UUID] = Field(default_factory=list)
    events: list[UUID] = Field(default_factory=list)
    
    # Impact
    affected_assets: list[UUID] = Field(default_factory=list)
    affected_users: list[UUID] = Field(default_factory=list)
    business_impact: str | None = None
    data_classification: str | None = None
    
    # Attack context
    kill_chain_phase: str | None = None
    mitre_attack: list[MITREAttack] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    
    # Response
    containment_actions: list[str] = Field(default_factory=list)
    eradication_actions: list[str] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    lessons_learned: str | None = None
    
    # Timeline
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    detected_at: datetime | None = None
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    
    # Metadata
    tags: list[str] = Field(default_factory=list)
    external_references: list[str] = Field(default_factory=list)


class AgentTask(BaseModel):
    """Task assigned to a specialized agent."""
    
    task_id: UUID = Field(default_factory=uuid4)
    agent_type: str = Field(..., description="triage, malware, network, identity, threat_intel, response")
    
    # Task details
    task_type: str
    priority: int = Field(ge=1, le=5, default=3)
    payload: dict[str, Any]
    
    # Context
    alert_id: UUID | None = None
    incident_id: UUID | None = None
    parent_task_id: UUID | None = None
    
    # Status
    status: str = Field(default="pending")
    assigned_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    
    # Results
    result: dict[str, Any] | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    error: str | None = None
    
    # Metadata
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)
    timeout_seconds: int = Field(default=300)


class AgentMessage(BaseModel):
    """Message passed between agents via shared context."""
    
    message_id: UUID = Field(default_factory=uuid4)
    
    # Routing
    from_agent: str
    to_agent: str | None = Field(None, description="None for broadcast")
    
    # Content
    message_type: str = Field(..., description="task, result, query, notification")
    content: dict[str, Any]
    
    # Context
    correlation_id: UUID | None = None
    in_reply_to: UUID | None = None
    
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    priority: int = Field(ge=1, le=5, default=3)
    ttl_seconds: int = Field(default=3600)
