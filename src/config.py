"""
Configuration management for the Agentic SOC Pipeline.

Uses Pydantic Settings for type-safe configuration with environment
variable support and YAML file loading.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class KafkaSettings(BaseSettings):
    """Kafka configuration."""
    
    model_config = SettingsConfigDict(env_prefix="KAFKA_")
    
    bootstrap_servers: str = "localhost:9092"
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: str | None = None
    sasl_username: str | None = None
    sasl_password: SecretStr | None = None
    
    # Topics
    events_topic: str = "soc.events.raw"
    alerts_topic: str = "soc.alerts"
    agent_messages_topic: str = "soc.agents.messages"
    
    # Consumer settings
    consumer_group: str = "agentic-soc"
    auto_offset_reset: str = "latest"
    max_poll_records: int = 500


class RedisSettings(BaseSettings):
    """Redis configuration for working memory and caching."""
    
    model_config = SettingsConfigDict(env_prefix="REDIS_")
    
    url: str = "redis://localhost:6379"
    password: SecretStr | None = None
    db: int = 0
    
    # Connection pool
    max_connections: int = 50
    socket_timeout: float = 5.0
    
    # Keys
    session_prefix: str = "soc:session:"
    cache_prefix: str = "soc:cache:"
    lock_prefix: str = "soc:lock:"
    
    # TTLs
    session_ttl_seconds: int = 3600
    cache_ttl_seconds: int = 300


class Neo4jSettings(BaseSettings):
    """Neo4j configuration for semantic memory (knowledge graph)."""
    
    model_config = SettingsConfigDict(env_prefix="NEO4J_")
    
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: SecretStr = Field(default=SecretStr("password"))
    database: str = "neo4j"
    
    # Connection pool
    max_connection_pool_size: int = 50
    connection_acquisition_timeout: float = 60.0


class ChromaSettings(BaseSettings):
    """ChromaDB configuration for episodic memory (vector store)."""
    
    model_config = SettingsConfigDict(env_prefix="CHROMA_")
    
    host: str = "localhost"
    port: int = 8000
    
    # Collections
    incidents_collection: str = "soc_incidents"
    alerts_collection: str = "soc_alerts"
    playbooks_collection: str = "soc_playbooks"
    
    # Embedding
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dimension: int = 384


class PostgresSettings(BaseSettings):
    """PostgreSQL configuration for procedural memory and metadata."""
    
    model_config = SettingsConfigDict(env_prefix="POSTGRES_")
    
    url: str = "postgresql://postgres:postgres@localhost:5432/soc"
    pool_size: int = 20
    max_overflow: int = 10
    pool_pre_ping: bool = True


class OllamaSettings(BaseSettings):
    """Ollama configuration for local LLM inference."""
    
    model_config = SettingsConfigDict(env_prefix="OLLAMA_")
    
    host: str = "http://localhost:11434"
    timeout: float = 120.0
    
    # Default models per agent
    orchestrator_model: str = "phi3:14b-medium-128k-instruct-q4_K_M"
    triage_model: str = "phi3:mini"
    malware_model: str = "codellama:7b"
    network_model: str = "mistral:7b"
    identity_model: str = "phi3:mini"
    threat_intel_model: str = "llama3:8b"
    response_model: str = "phi3:mini"


class AgentSettings(BaseSettings):
    """Agent-specific configuration."""
    
    model_config = SettingsConfigDict(env_prefix="AGENT_")
    
    # Inference settings
    default_temperature: float = 0.1
    default_max_tokens: int = 2048
    default_timeout_seconds: int = 60
    
    # Triage settings
    triage_batch_size: int = 50
    triage_confidence_threshold: float = 0.85
    auto_close_false_positive_threshold: float = 0.95
    
    # Malware settings
    sandbox_timeout_seconds: int = 300
    max_file_size_mb: int = 100
    
    # Response settings
    auto_contain_threshold: float = 0.90
    require_approval_above_severity: str = "high"


class QualitySettings(BaseSettings):
    """Data quality framework configuration."""
    
    model_config = SettingsConfigDict(env_prefix="QUALITY_")
    
    # Validation
    halt_on_critical_failure: bool = True
    max_null_percentage: float = 0.05
    max_stale_seconds: int = 300
    
    # Anomaly detection
    anomaly_sensitivity: float = 0.8
    anomaly_window_hours: int = 24
    
    # Alerting
    slack_webhook_url: str | None = None
    pagerduty_api_key: SecretStr | None = None
    alert_cooldown_minutes: int = 15


class IntegrationSettings(BaseSettings):
    """External integration settings."""
    
    model_config = SettingsConfigDict(env_prefix="INTEGRATION_")
    
    # SIEM
    splunk_host: str | None = None
    splunk_token: SecretStr | None = None
    elastic_host: str | None = None
    elastic_api_key: SecretStr | None = None
    
    # EDR
    crowdstrike_client_id: str | None = None
    crowdstrike_client_secret: SecretStr | None = None
    sentinelone_api_key: SecretStr | None = None
    
    # Threat Intel
    virustotal_api_key: SecretStr | None = None
    misp_url: str | None = None
    misp_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None


class APISettings(BaseSettings):
    """API server configuration."""
    
    model_config = SettingsConfigDict(env_prefix="API_")
    
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    
    # Security
    api_key_header: str = "X-API-Key"
    cors_origins: list[str] = ["*"]
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60


class Settings(BaseSettings):
    """Root settings that aggregates all configuration."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    # Environment
    environment: str = Field(default="development", description="development, staging, production")
    debug: bool = False
    log_level: str = "INFO"
    
    # Component settings
    kafka: KafkaSettings = Field(default_factory=KafkaSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    chroma: ChromaSettings = Field(default_factory=ChromaSettings)
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    quality: QualitySettings = Field(default_factory=QualitySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    api: APISettings = Field(default_factory=APISettings)
    
    # Paths
    config_dir: Path = Field(default=Path("config"))
    data_dir: Path = Field(default=Path("data"))
    models_dir: Path = Field(default=Path("models"))
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v
    
    def load_yaml_config(self, name: str) -> dict[str, Any]:
        """Load additional YAML configuration file."""
        path = self.config_dir / f"{name}.yaml"
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)
        return {}


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience function for tests
def get_test_settings() -> Settings:
    """Get settings configured for testing."""
    return Settings(
        environment="development",
        debug=True,
        log_level="DEBUG",
        kafka=KafkaSettings(bootstrap_servers="localhost:9092"),
        redis=RedisSettings(url="redis://localhost:6379/1"),
        neo4j=Neo4jSettings(uri="bolt://localhost:7687"),
        chroma=ChromaSettings(host="localhost", port=8001),
        postgres=PostgresSettings(url="postgresql://postgres:postgres@localhost:5432/soc_test"),
    )
