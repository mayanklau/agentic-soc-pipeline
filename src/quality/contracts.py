"""
Data Quality Framework - Contracts, validation, and anomaly detection.

Implements Agoda-inspired quality controls:
- Data contracts between producers and consumers
- Automated validation rules
- ML-based anomaly detection
- Multi-tier alerting system
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
import yaml

from src.config import Settings

logger = structlog.get_logger()


class ValidationSeverity(str, Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationResult:
    """Result of a validation check."""
    
    def __init__(
        self,
        rule_name: str,
        passed: bool,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        self.rule_name = rule_name
        self.passed = passed
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.utcnow()
    
    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"ValidationResult({self.rule_name}: {status})"


@dataclass
class DataContract:
    """
    Data contract defining expectations between producer and consumers.
    
    Inspired by Agoda's FINUDP data contract approach.
    """
    
    name: str
    version: str
    producer: str
    consumers: list[str]
    
    # Schema definition
    required_fields: dict[str, str] = field(default_factory=dict)
    optional_fields: dict[str, str] = field(default_factory=dict)
    
    # Quality rules
    completeness_rules: list[dict[str, Any]] = field(default_factory=list)
    validity_rules: list[dict[str, Any]] = field(default_factory=list)
    freshness_rules: dict[str, Any] = field(default_factory=dict)
    
    # SLA
    availability_target: float = 0.995
    latency_p95_seconds: int = 30
    
    # Violation handling
    on_violation_alert_channel: str | None = None
    on_violation_escalate_after_minutes: int = 15
    halt_pipeline_on_violation: bool = False
    
    @classmethod
    def from_yaml(cls, path: Path) -> "DataContract":
        """Load contract from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        
        contract_data = data.get("contract", data)
        
        return cls(
            name=contract_data["name"],
            version=contract_data.get("version", "1.0.0"),
            producer=contract_data["producer"],
            consumers=contract_data.get("consumers", []),
            required_fields=contract_data.get("schema", {}).get("required_fields", {}),
            optional_fields=contract_data.get("schema", {}).get("optional_fields", {}),
            completeness_rules=contract_data.get("quality_rules", {}).get("completeness", []),
            validity_rules=contract_data.get("quality_rules", {}).get("validity", []),
            freshness_rules=contract_data.get("quality_rules", {}).get("freshness", {}),
            availability_target=contract_data.get("sla", {}).get("availability", 0.995),
            latency_p95_seconds=contract_data.get("sla", {}).get("latency_p95_seconds", 30),
            on_violation_alert_channel=contract_data.get("on_violation", {}).get("alert_channel"),
            on_violation_escalate_after_minutes=contract_data.get("on_violation", {}).get("escalate_after_minutes", 15),
            halt_pipeline_on_violation=contract_data.get("on_violation", {}).get("halt_pipeline", False),
        )


class ValidationRule(ABC):
    """Abstract base class for validation rules."""
    
    def __init__(
        self,
        name: str,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ):
        self.name = name
        self.severity = severity
    
    @abstractmethod
    def validate(self, data: Any) -> ValidationResult:
        """Execute the validation rule."""
        pass


class NotNullRule(ValidationRule):
    """Validate that a field is not null."""
    
    def __init__(self, field_name: str, severity: ValidationSeverity = ValidationSeverity.ERROR):
        super().__init__(f"not_null_{field_name}", severity)
        self.field_name = field_name
    
    def validate(self, data: dict[str, Any]) -> ValidationResult:
        value = data.get(self.field_name)
        passed = value is not None
        
        return ValidationResult(
            rule_name=self.name,
            passed=passed,
            severity=self.severity,
            message=f"Field '{self.field_name}' is {'present' if passed else 'null/missing'}",
            details={"field": self.field_name, "value": value},
        )


class InSetRule(ValidationRule):
    """Validate that a field value is in an allowed set."""
    
    def __init__(
        self,
        field_name: str,
        allowed_values: set[Any],
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ):
        super().__init__(f"in_set_{field_name}", severity)
        self.field_name = field_name
        self.allowed_values = allowed_values
    
    def validate(self, data: dict[str, Any]) -> ValidationResult:
        value = data.get(self.field_name)
        passed = value in self.allowed_values
        
        return ValidationResult(
            rule_name=self.name,
            passed=passed,
            severity=self.severity,
            message=f"Field '{self.field_name}' value {'valid' if passed else 'invalid'}",
            details={
                "field": self.field_name,
                "value": value,
                "allowed": list(self.allowed_values),
            },
        )


class RangeRule(ValidationRule):
    """Validate that a numeric field is within a range."""
    
    def __init__(
        self,
        field_name: str,
        min_value: float | None = None,
        max_value: float | None = None,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ):
        super().__init__(f"range_{field_name}", severity)
        self.field_name = field_name
        self.min_value = min_value
        self.max_value = max_value
    
    def validate(self, data: dict[str, Any]) -> ValidationResult:
        value = data.get(self.field_name)
        
        if value is None:
            return ValidationResult(
                rule_name=self.name,
                passed=False,
                severity=self.severity,
                message=f"Field '{self.field_name}' is null",
            )
        
        try:
            num_value = float(value)
        except (TypeError, ValueError):
            return ValidationResult(
                rule_name=self.name,
                passed=False,
                severity=self.severity,
                message=f"Field '{self.field_name}' is not numeric",
            )
        
        in_range = True
        if self.min_value is not None and num_value < self.min_value:
            in_range = False
        if self.max_value is not None and num_value > self.max_value:
            in_range = False
        
        return ValidationResult(
            rule_name=self.name,
            passed=in_range,
            severity=self.severity,
            message=f"Field '{self.field_name}' is {'within' if in_range else 'outside'} range",
            details={
                "field": self.field_name,
                "value": num_value,
                "min": self.min_value,
                "max": self.max_value,
            },
        )


class FreshnessRule(ValidationRule):
    """Validate that data is not stale."""
    
    def __init__(
        self,
        timestamp_field: str,
        max_age_seconds: int,
        severity: ValidationSeverity = ValidationSeverity.WARNING,
    ):
        super().__init__(f"freshness_{timestamp_field}", severity)
        self.timestamp_field = timestamp_field
        self.max_age_seconds = max_age_seconds
    
    def validate(self, data: dict[str, Any]) -> ValidationResult:
        timestamp_value = data.get(self.timestamp_field)
        
        if timestamp_value is None:
            return ValidationResult(
                rule_name=self.name,
                passed=False,
                severity=self.severity,
                message=f"Timestamp field '{self.timestamp_field}' is missing",
            )
        
        try:
            if isinstance(timestamp_value, str):
                timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
            elif isinstance(timestamp_value, datetime):
                timestamp = timestamp_value
            else:
                raise ValueError("Unknown timestamp format")
        except Exception:
            return ValidationResult(
                rule_name=self.name,
                passed=False,
                severity=self.severity,
                message=f"Cannot parse timestamp field '{self.timestamp_field}'",
            )
        
        age = (datetime.utcnow() - timestamp.replace(tzinfo=None)).total_seconds()
        is_fresh = age <= self.max_age_seconds
        
        return ValidationResult(
            rule_name=self.name,
            passed=is_fresh,
            severity=self.severity,
            message=f"Data is {int(age)}s old (max: {self.max_age_seconds}s)",
            details={
                "age_seconds": age,
                "max_age_seconds": self.max_age_seconds,
                "timestamp": str(timestamp),
            },
        )


class DataValidator:
    """
    Main validator that applies rules to data.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.rules: list[ValidationRule] = []
        self._contracts: dict[str, DataContract] = {}
    
    def add_rule(self, rule: ValidationRule) -> None:
        """Add a validation rule."""
        self.rules.append(rule)
    
    def load_contract(self, contract: DataContract) -> None:
        """Load rules from a data contract."""
        self._contracts[contract.name] = contract
        
        for rule_def in contract.completeness_rules:
            field = rule_def.get("field")
            rule_type = rule_def.get("rule")
            
            if rule_type == "not_null":
                self.add_rule(NotNullRule(field))
        
        for rule_def in contract.validity_rules:
            field = rule_def.get("field")
            rule_type = rule_def.get("rule")
            
            if rule_type == "in_set":
                values = set(rule_def.get("values", []))
                self.add_rule(InSetRule(field, values))
            elif rule_type == "range":
                self.add_rule(RangeRule(
                    field,
                    min_value=rule_def.get("min"),
                    max_value=rule_def.get("max"),
                ))
        
        if contract.freshness_rules:
            self.add_rule(FreshnessRule(
                timestamp_field=contract.freshness_rules.get("field", "timestamp"),
                max_age_seconds=contract.freshness_rules.get("max_delay_seconds", 300),
            ))
        
        logger.info("Loaded contract", contract=contract.name, rules_count=len(self.rules))
    
    def validate(self, data: dict[str, Any]) -> list[ValidationResult]:
        """Validate a single record against all rules."""
        results = []
        
        for rule in self.rules:
            try:
                result = rule.validate(data)
                results.append(result)
            except Exception as e:
                results.append(ValidationResult(
                    rule_name=rule.name,
                    passed=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Rule execution failed: {str(e)}",
                ))
        
        return results
    
    def validate_batch(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Validate a batch of records and return summary statistics."""
        total = len(records)
        passed = 0
        failed = 0
        failures_by_rule: dict[str, int] = {}
        
        for record in records:
            results = self.validate(record)
            record_passed = all(r.passed for r in results)
            
            if record_passed:
                passed += 1
            else:
                failed += 1
                for r in results:
                    if not r.passed:
                        failures_by_rule[r.rule_name] = failures_by_rule.get(r.rule_name, 0) + 1
        
        return {
            "total_records": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / total if total > 0 else 0,
            "failures_by_rule": failures_by_rule,
        }


class AnomalyDetector:
    """ML-based anomaly detection for security data quality."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._baseline: dict[str, dict[str, float]] = {}
        self._window_hours = settings.quality.anomaly_window_hours
        self._sensitivity = settings.quality.anomaly_sensitivity
    
    def update_baseline(self, metric_name: str, value: float) -> None:
        """Update the baseline for a metric using Welford's algorithm."""
        if metric_name not in self._baseline:
            self._baseline[metric_name] = {
                "mean": value, "std": 0.0, "count": 1, "min": value, "max": value,
            }
        else:
            b = self._baseline[metric_name]
            n = b["count"]
            old_mean = b["mean"]
            n += 1
            delta = value - old_mean
            new_mean = old_mean + delta / n
            delta2 = value - new_mean
            b["mean"] = new_mean
            b["std"] = ((b["std"] ** 2 * (n - 2) + delta * delta2) / (n - 1)) ** 0.5 if n > 1 else 0
            b["count"] = n
            b["min"] = min(b["min"], value)
            b["max"] = max(b["max"], value)
    
    def detect_anomaly(self, metric_name: str, value: float, z_threshold: float = 3.0) -> dict[str, Any]:
        """Detect if a value is anomalous based on z-score."""
        if metric_name not in self._baseline:
            return {"is_anomaly": False, "reason": "no_baseline", "metric": metric_name, "value": value}
        
        b = self._baseline[metric_name]
        if b["std"] == 0:
            is_anomaly = value != b["mean"]
            return {"is_anomaly": is_anomaly, "reason": "zero_variance", "metric": metric_name, "value": value}
        
        z_score = abs(value - b["mean"]) / b["std"]
        adjusted_threshold = z_threshold * (1 - self._sensitivity) + z_threshold * 0.5
        is_anomaly = z_score > adjusted_threshold
        
        return {
            "is_anomaly": is_anomaly,
            "reason": f"z_score_{z_score:.2f}" if is_anomaly else "within_baseline",
            "metric": metric_name, "value": value, "z_score": z_score,
            "threshold": adjusted_threshold, "baseline_mean": b["mean"], "baseline_std": b["std"],
        }


class QualityAlertManager:
    """Multi-tier alerting for data quality issues."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._alert_history: dict[str, datetime] = {}
        self._cooldown_minutes = settings.quality.alert_cooldown_minutes
    
    async def send_alert(
        self, severity: ValidationSeverity, title: str, message: str, details: dict[str, Any] | None = None,
    ) -> bool:
        """Send an alert based on severity level."""
        alert_key = f"{severity}:{title}"
        last_alert = self._alert_history.get(alert_key)
        
        if last_alert:
            if datetime.utcnow() - last_alert < timedelta(minutes=self._cooldown_minutes):
                return False
        
        self._alert_history[alert_key] = datetime.utcnow()
        
        if severity == ValidationSeverity.INFO:
            logger.info("Quality alert", title=title, message=message)
        elif severity in (ValidationSeverity.WARNING, ValidationSeverity.ERROR):
            await self._send_slack_alert(title, message, details, urgent=severity == ValidationSeverity.ERROR)
        elif severity == ValidationSeverity.CRITICAL:
            await self._send_slack_alert(title, message, details, urgent=True)
            await self._escalate_to_noc(title, message, details)
        
        return True
    
    async def _send_slack_alert(self, title: str, message: str, details: dict | None, urgent: bool = False) -> None:
        """Send alert to Slack."""
        webhook_url = self.settings.quality.slack_webhook_url
        if not webhook_url:
            logger.warning("Slack webhook not configured")
            return
        
        try:
            import httpx
            payload = {
                "attachments": [{
                    "color": "#ff0000" if urgent else "#ffaa00",
                    "title": f"{'🚨 ' if urgent else '⚠️ '}{title}",
                    "text": message,
                    "fields": [{"title": k, "value": str(v), "short": True} for k, v in (details or {}).items()][:10],
                }]
            }
            async with httpx.AsyncClient() as client:
                await client.post(webhook_url, json=payload)
        except Exception as e:
            logger.error("Failed to send Slack alert", error=str(e))
    
    async def _escalate_to_noc(self, title: str, message: str, details: dict | None) -> None:
        """Escalate to NOC via PagerDuty."""
        pagerduty_key = self.settings.quality.pagerduty_api_key
        if not pagerduty_key:
            logger.warning("PagerDuty not configured")
            return
        
        try:
            import httpx
            payload = {
                "routing_key": pagerduty_key.get_secret_value(),
                "event_action": "trigger",
                "payload": {
                    "summary": f"[SOC Data Quality] {title}",
                    "severity": "critical",
                    "source": "agentic-soc-pipeline",
                    "custom_details": {"message": message, **(details or {})},
                },
            }
            async with httpx.AsyncClient() as client:
                await client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
        except Exception as e:
            logger.error("Failed to escalate to NOC", error=str(e))


class QualityFramework:
    """Main entry point for the data quality framework."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.validator = DataValidator(settings)
        self.anomaly_detector = AnomalyDetector(settings)
        self.alert_manager = QualityAlertManager(settings)
    
    def load_contracts_from_directory(self, directory: Path) -> None:
        """Load all data contracts from a directory."""
        for yaml_file in directory.glob("*.yaml"):
            try:
                contract = DataContract.from_yaml(yaml_file)
                self.validator.load_contract(contract)
            except Exception as e:
                logger.error("Failed to load contract", file=str(yaml_file), error=str(e))
    
    async def validate_and_alert(self, contract_name: str, data: dict[str, Any]) -> tuple[bool, list[ValidationResult]]:
        """Validate data and send alerts for failures."""
        results = self.validator.validate(data)
        passed = all(r.passed for r in results)
        
        if not passed:
            failures = [r for r in results if not r.passed]
            max_severity = max(f.severity for f in failures)
            await self.alert_manager.send_alert(
                severity=max_severity,
                title=f"Data quality violation: {contract_name}",
                message=f"{len(failures)} validation rules failed",
                details={"contract": contract_name, "failed_rules": [f.rule_name for f in failures]},
            )
        
        return passed, results
