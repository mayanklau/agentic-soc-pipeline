"""
Tests for the Agentic SOC Pipeline.
"""

import pytest
from datetime import datetime
from uuid import uuid4

from src.models import (
    SecurityEvent,
    Alert,
    Incident,
    Severity,
    EventType,
    AlertStatus,
    IncidentStatus,
)
from src.quality.contracts import (
    DataValidator,
    NotNullRule,
    InSetRule,
    RangeRule,
    FreshnessRule,
    ValidationSeverity,
)
from src.config import Settings, get_test_settings


class TestModels:
    """Test data models."""
    
    def test_security_event_creation(self):
        """Test creating a security event."""
        event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type=EventType.PROCESS,
            severity=Severity.HIGH,
            source_system="crowdstrike",
            source_category="edr",
            process_name="powershell.exe",
            process_command_line="powershell -enc SGVsbG8gV29ybGQ=",
        )
        
        assert event.event_id is not None
        assert event.severity == Severity.HIGH
        assert event.source_system == "crowdstrike"
    
    def test_alert_creation(self):
        """Test creating an alert."""
        alert = Alert(
            title="Suspicious PowerShell Activity",
            description="Encoded PowerShell command detected",
            severity=Severity.HIGH,
            confidence=0.85,
            source_system="crowdstrike",
        )
        
        assert alert.alert_id is not None
        assert alert.status == AlertStatus.NEW
        assert alert.confidence == 0.85
    
    def test_incident_creation(self):
        """Test creating an incident."""
        incident = Incident(
            title="Potential Ransomware Attack",
            description="Multiple indicators of ransomware activity",
            severity=Severity.CRITICAL,
            incident_type="ransomware",
        )
        
        assert incident.incident_id is not None
        assert incident.status == IncidentStatus.OPEN
        assert incident.severity == Severity.CRITICAL
    
    def test_severity_from_numeric(self):
        """Test converting numeric severity to enum."""
        assert Severity.from_numeric(1) == Severity.LOW
        assert Severity.from_numeric(4) == Severity.MEDIUM
        assert Severity.from_numeric(6) == Severity.HIGH
        assert Severity.from_numeric(9) == Severity.CRITICAL


class TestValidation:
    """Test data validation rules."""
    
    def test_not_null_rule_pass(self):
        """Test NotNullRule passes when field is present."""
        rule = NotNullRule("event_id")
        result = rule.validate({"event_id": "12345"})
        
        assert result.passed is True
    
    def test_not_null_rule_fail(self):
        """Test NotNullRule fails when field is missing."""
        rule = NotNullRule("event_id")
        result = rule.validate({"other_field": "value"})
        
        assert result.passed is False
    
    def test_in_set_rule_pass(self):
        """Test InSetRule passes when value is in set."""
        rule = InSetRule("severity", {"low", "medium", "high", "critical"})
        result = rule.validate({"severity": "high"})
        
        assert result.passed is True
    
    def test_in_set_rule_fail(self):
        """Test InSetRule fails when value is not in set."""
        rule = InSetRule("severity", {"low", "medium", "high", "critical"})
        result = rule.validate({"severity": "extreme"})
        
        assert result.passed is False
    
    def test_range_rule_pass(self):
        """Test RangeRule passes when value is in range."""
        rule = RangeRule("score", min_value=0.0, max_value=1.0)
        result = rule.validate({"score": 0.75})
        
        assert result.passed is True
    
    def test_range_rule_fail(self):
        """Test RangeRule fails when value is out of range."""
        rule = RangeRule("score", min_value=0.0, max_value=1.0)
        result = rule.validate({"score": 1.5})
        
        assert result.passed is False
    
    def test_freshness_rule_pass(self):
        """Test FreshnessRule passes when data is fresh."""
        rule = FreshnessRule("timestamp", max_age_seconds=300)
        result = rule.validate({"timestamp": datetime.utcnow().isoformat()})
        
        assert result.passed is True
    
    def test_validator_multiple_rules(self):
        """Test DataValidator with multiple rules."""
        settings = get_test_settings()
        validator = DataValidator(settings)
        
        validator.add_rule(NotNullRule("event_id"))
        validator.add_rule(InSetRule("severity", {"low", "medium", "high", "critical"}))
        
        # Valid data
        results = validator.validate({
            "event_id": "123",
            "severity": "high",
        })
        
        assert all(r.passed for r in results)
        
        # Invalid data
        results = validator.validate({
            "event_id": None,
            "severity": "extreme",
        })
        
        assert not all(r.passed for r in results)


class TestConfig:
    """Test configuration management."""
    
    def test_settings_defaults(self):
        """Test that settings have sensible defaults."""
        settings = Settings()
        
        assert settings.environment == "development"
        assert settings.kafka.bootstrap_servers == "localhost:9092"
        assert settings.redis.url == "redis://localhost:6379"
    
    def test_test_settings(self):
        """Test that test settings are properly configured."""
        settings = get_test_settings()
        
        assert settings.debug is True
        assert settings.log_level == "DEBUG"


@pytest.fixture
def sample_alert():
    """Fixture for a sample alert."""
    return Alert(
        title="Test Alert",
        description="Test description",
        severity=Severity.MEDIUM,
        confidence=0.7,
        source_system="test",
    )


@pytest.fixture
def sample_event():
    """Fixture for a sample security event."""
    return SecurityEvent(
        timestamp=datetime.utcnow(),
        event_type=EventType.PROCESS,
        severity=Severity.MEDIUM,
        source_system="test",
        source_category="test",
    )


class TestIntegration:
    """Integration tests (require infrastructure)."""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_memory_manager_initialization(self):
        """Test memory manager can initialize."""
        from src.memory.manager import MemoryManager
        
        settings = get_test_settings()
        manager = MemoryManager(settings)
        
        # Should initialize without errors (using fallbacks)
        await manager.initialize()
        await manager.close()
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_agent_initialization(self):
        """Test agent can initialize."""
        from src.agents.triage import TriageAgent
        
        settings = get_test_settings()
        agent = TriageAgent(settings)
        
        # Should initialize (may fail on LLM connection)
        try:
            await agent.initialize()
            await agent.shutdown()
        except Exception:
            pytest.skip("Agent initialization requires Ollama")
