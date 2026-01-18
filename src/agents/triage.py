"""
Triage Agent - Initial alert assessment and prioritization.

The triage agent is the first line of defense, responsible for:
- Scoring alerts for severity and validity
- Detecting false positives
- Deduplicating related alerts
- Initial enrichment and context gathering
- Priority assignment for downstream processing
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import structlog

from src.agents.base import AgentContext, AgentResult, BatchAgent
from src.models import Alert, AlertStatus, Severity

logger = structlog.get_logger()


class TriageAgent(BatchAgent):
    """
    Triage agent for initial alert assessment.
    
    Uses a fast, lightweight model (Phi-3-mini) optimized for
    classification and scoring tasks at high volume.
    """
    
    agent_type = "triage"
    agent_description = "Alert Triage Specialist"
    default_model = "phi3:mini"
    default_temperature = 0.0  # Deterministic for consistent scoring
    default_max_tokens = 1024
    
    # Classification thresholds
    FALSE_POSITIVE_THRESHOLD = 0.85
    AUTO_ESCALATE_THRESHOLD = 0.90
    DEDUP_SIMILARITY_THRESHOLD = 0.92
    
    async def _execute(self, context: AgentContext) -> AgentResult:
        """Execute triage assessment on an alert."""
        task = context.task
        task_type = task.task_type
        
        if task_type == "assess_alert":
            return await self._assess_alert(context)
        elif task_type == "detect_false_positive":
            return await self._detect_false_positive(context)
        elif task_type == "deduplicate":
            return await self._deduplicate_alerts(context)
        elif task_type == "batch_triage":
            return await self._batch_triage(context)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=f"Unknown task type: {task_type}",
            )
    
    async def _assess_alert(self, context: AgentContext) -> AgentResult:
        """
        Perform comprehensive triage assessment of an alert.
        
        This includes severity validation, false positive detection,
        and initial enrichment recommendations.
        """
        alert_data = context.task.payload.get("alert", {})
        
        system_prompt = self._build_triage_system_prompt()
        
        prompt = f"""Assess this security alert for triage.

ALERT DETAILS:
Title: {alert_data.get('title', 'Unknown')}
Description: {alert_data.get('description', 'No description')}
Declared Severity: {alert_data.get('severity', 'unknown')}
Source System: {alert_data.get('source_system', 'unknown')}
Detection Rule: {alert_data.get('detection_rule', 'unknown')}

EVENT DATA:
{self._format_event_summary(context.related_events)}

HISTORICAL CONTEXT:
Similar past alerts: {len(context.memory_context.get('similar_incidents', []))}
Past false positive rate for this rule: {self._get_fp_rate(alert_data.get('detection_rule'))}

ENTITY CONTEXT:
{json.dumps(context.memory_context.get('entity_context', {}), indent=2)[:1000]}

Provide your triage assessment in JSON:
{{
    "triage_score": 0.0-1.0,
    "validated_severity": "low|medium|high|critical",
    "false_positive_probability": 0.0-1.0,
    "false_positive_reason": "reason if FP likely",
    "confidence": 0.0-1.0,
    "key_indicators": ["indicator1", "indicator2"],
    "enrichment_needed": ["type of enrichment needed"],
    "recommended_priority": 1-5,
    "reasoning": "brief explanation"
}}"""

        try:
            response = await self.llm_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            assessment = json.loads(response)
            
            # Determine follow-up actions
            follow_up_tasks = []
            recommended_actions = []
            
            fp_prob = assessment.get("false_positive_probability", 0)
            triage_score = assessment.get("triage_score", 0.5)
            
            if fp_prob >= self.FALSE_POSITIVE_THRESHOLD:
                recommended_actions.append("Mark as likely false positive")
                recommended_actions.append("Update detection rule tuning")
            elif triage_score >= self.AUTO_ESCALATE_THRESHOLD:
                recommended_actions.append("Auto-escalate to incident")
                follow_up_tasks.append({
                    "agent_type": "orchestrator",
                    "task_type": "escalation_decision",
                    "priority": 1,
                    "payload": {
                        "alert": alert_data,
                        "triage_assessment": assessment,
                    },
                })
            
            # Request enrichment if needed
            for enrichment in assessment.get("enrichment_needed", []):
                if "threat" in enrichment.lower() or "ioc" in enrichment.lower():
                    follow_up_tasks.append({
                        "agent_type": "threat_intel",
                        "task_type": "enrich_iocs",
                        "priority": assessment.get("recommended_priority", 3),
                        "payload": {"alert": alert_data},
                    })
                elif "malware" in enrichment.lower() or "hash" in enrichment.lower():
                    follow_up_tasks.append({
                        "agent_type": "malware",
                        "task_type": "analyze_artifact",
                        "priority": assessment.get("recommended_priority", 3),
                        "payload": {"alert": alert_data},
                    })
            
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=assessment.get("confidence", 0.7),
                result={
                    "assessment": assessment,
                    "original_severity": alert_data.get("severity"),
                    "validated_severity": assessment.get("validated_severity"),
                    "status_recommendation": (
                        AlertStatus.FALSE_POSITIVE.value
                        if fp_prob >= self.FALSE_POSITIVE_THRESHOLD
                        else AlertStatus.INVESTIGATING.value
                    ),
                },
                reasoning=assessment.get("reasoning"),
                recommended_actions=recommended_actions,
                follow_up_tasks=follow_up_tasks,
            )
            
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse triage response", error=str(e))
            return await self._rule_based_triage(context)
    
    async def _detect_false_positive(self, context: AgentContext) -> AgentResult:
        """
        Specialized false positive detection.
        
        Uses historical data and patterns to identify likely false positives.
        """
        alert_data = context.task.payload.get("alert", {})
        
        # Get historical FP data for this rule
        detection_rule = alert_data.get("detection_rule", "")
        historical_fps = context.memory_context.get("similar_incidents", [])
        
        fp_indicators = []
        fp_score = 0.0
        
        # Check historical false positive rate
        fp_count = sum(1 for i in historical_fps if i.get("was_false_positive", False))
        if historical_fps:
            historical_fp_rate = fp_count / len(historical_fps)
            if historical_fp_rate > 0.7:
                fp_indicators.append(f"High historical FP rate: {historical_fp_rate:.0%}")
                fp_score += 0.3
        
        # Check for known benign patterns
        benign_patterns = self._check_benign_patterns(alert_data, context.related_events)
        if benign_patterns:
            fp_indicators.extend(benign_patterns)
            fp_score += 0.2 * len(benign_patterns)
        
        # Check entity reputation
        entity_context = context.memory_context.get("entity_context", {})
        if entity_context.get("asset_criticality") == "low" and entity_context.get("user_risk_score", 0) < 10:
            fp_indicators.append("Low-risk entity context")
            fp_score += 0.1
        
        # Normalize score
        fp_score = min(fp_score, 1.0)
        
        return AgentResult(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            success=True,
            confidence=0.8,
            result={
                "false_positive_score": fp_score,
                "is_likely_false_positive": fp_score >= self.FALSE_POSITIVE_THRESHOLD,
                "indicators": fp_indicators,
            },
            reasoning=f"FP score: {fp_score:.2f} based on {len(fp_indicators)} indicators",
            recommended_actions=(
                ["Suppress alert", "Add to allowlist"]
                if fp_score >= self.FALSE_POSITIVE_THRESHOLD
                else ["Continue investigation"]
            ),
        )
    
    async def _deduplicate_alerts(self, context: AgentContext) -> AgentResult:
        """
        Identify and group duplicate or related alerts.
        
        Uses semantic similarity and entity matching to find alerts
        that should be correlated together.
        """
        alert_data = context.task.payload.get("alert", {})
        candidate_alerts = context.task.payload.get("candidate_alerts", [])
        
        if not candidate_alerts:
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=1.0,
                result={"duplicates": [], "related": []},
                reasoning="No candidate alerts to compare",
            )
        
        duplicates = []
        related = []
        
        # Extract key features for comparison
        alert_features = self._extract_alert_features(alert_data)
        
        for candidate in candidate_alerts:
            candidate_features = self._extract_alert_features(candidate)
            similarity = self._calculate_similarity(alert_features, candidate_features)
            
            if similarity >= self.DEDUP_SIMILARITY_THRESHOLD:
                duplicates.append({
                    "alert_id": candidate.get("alert_id"),
                    "similarity": similarity,
                    "matching_features": self._get_matching_features(alert_features, candidate_features),
                })
            elif similarity >= 0.7:
                related.append({
                    "alert_id": candidate.get("alert_id"),
                    "similarity": similarity,
                    "relationship": "potentially_related",
                })
        
        return AgentResult(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            success=True,
            confidence=0.85,
            result={
                "duplicates": duplicates,
                "related": related,
                "total_compared": len(candidate_alerts),
            },
            reasoning=f"Found {len(duplicates)} duplicates and {len(related)} related alerts",
            recommended_actions=(
                [f"Merge {len(duplicates)} duplicate alerts"] if duplicates else []
            ) + (
                [f"Correlate {len(related)} related alerts"] if related else []
            ),
        )
    
    async def _batch_triage(self, context: AgentContext) -> AgentResult:
        """
        Process multiple alerts in a single batch for efficiency.
        
        Uses a structured prompt to assess multiple alerts at once.
        """
        alerts = context.task.payload.get("alerts", [])
        
        if not alerts:
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                result={"assessments": []},
                reasoning="No alerts to process",
            )
        
        # Limit batch size
        batch = alerts[:self.batch_size]
        
        system_prompt = """You are a high-speed alert triage system.
Quickly assess multiple alerts and provide scores.
Be consistent in your scoring criteria."""

        alerts_text = "\n".join([
            f"Alert {i+1}: {a.get('title', 'Unknown')} | "
            f"Severity: {a.get('severity', 'unknown')} | "
            f"Source: {a.get('source_system', 'unknown')}"
            for i, a in enumerate(batch)
        ])
        
        prompt = f"""Quickly assess these {len(batch)} alerts.

{alerts_text}

For each alert, provide in JSON array format:
[
    {{
        "alert_index": 1,
        "triage_score": 0.0-1.0,
        "false_positive_probability": 0.0-1.0,
        "priority": 1-5,
        "quick_assessment": "one line summary"
    }},
    ...
]"""

        try:
            response = await self.llm_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            assessments = json.loads(response)
            
            # Ensure it's a list
            if not isinstance(assessments, list):
                assessments = [assessments]
            
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=0.75,
                result={
                    "assessments": assessments,
                    "batch_size": len(batch),
                    "total_alerts": len(alerts),
                },
                reasoning=f"Batch processed {len(batch)} alerts",
            )
            
        except Exception as e:
            self.logger.error("Batch triage failed", error=str(e))
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
            )
    
    async def _rule_based_triage(self, context: AgentContext) -> AgentResult:
        """Fallback rule-based triage when LLM fails."""
        alert_data = context.task.payload.get("alert", {})
        
        severity = alert_data.get("severity", "medium")
        source = alert_data.get("source_system", "")
        
        # Simple scoring rules
        severity_scores = {"critical": 0.95, "high": 0.8, "medium": 0.5, "low": 0.2}
        triage_score = severity_scores.get(severity, 0.5)
        
        # Adjust based on source reputation
        trusted_sources = {"crowdstrike", "sentinel", "splunk"}
        if source.lower() in trusted_sources:
            triage_score = min(triage_score + 0.1, 1.0)
        
        priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)
        
        return AgentResult(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            success=True,
            confidence=0.6,
            result={
                "assessment": {
                    "triage_score": triage_score,
                    "validated_severity": severity,
                    "false_positive_probability": 0.3,
                    "recommended_priority": priority,
                },
                "method": "rule_based_fallback",
            },
            reasoning="Used rule-based scoring due to LLM failure",
        )
    
    def _build_triage_system_prompt(self) -> str:
        """Build the system prompt for triage assessment."""
        return """You are an expert SOC analyst specializing in alert triage.

Your job is to quickly and accurately assess security alerts to determine:
1. True severity (may differ from declared severity)
2. Likelihood of being a false positive
3. Priority for further investigation
4. What additional context or enrichment is needed

Scoring guidelines:
- triage_score: Overall threat score (0=benign, 1=critical threat)
- false_positive_probability: Based on patterns, context, historical data
- confidence: Your confidence in this assessment

Key indicators to look for:
- Known malicious hashes, IPs, domains
- Unusual process behavior or command lines
- Privilege escalation attempts
- Lateral movement indicators
- Data exfiltration patterns
- Time-based anomalies (off-hours activity)

Be precise and evidence-based. Cite specific indicators."""
    
    def _format_event_summary(self, events: list) -> str:
        """Format events for LLM context."""
        if not events:
            return "No associated events"
        
        lines = []
        for event in events[:5]:
            lines.append(
                f"- Type: {event.event_type.value}, "
                f"Source: {event.source_ip or 'N/A'} -> {event.destination_ip or 'N/A'}, "
                f"Process: {event.process_name or 'N/A'}, "
                f"User: {event.user.username if event.user else 'N/A'}"
            )
        
        return "\n".join(lines)
    
    def _get_fp_rate(self, detection_rule: str | None) -> str:
        """Get historical false positive rate for a detection rule."""
        # In production, this would query the metrics database
        return "Unknown (no historical data)"
    
    def _check_benign_patterns(self, alert_data: dict, events: list) -> list[str]:
        """Check for known benign patterns that indicate false positives."""
        benign_indicators = []
        
        # Check for known benign processes
        benign_processes = {
            "windows defender", "mbam", "carbon black", "crowdstrike",
            "splunk", "tanium", "qualys", "nessus"
        }
        
        for event in events:
            if hasattr(event, 'process_name') and event.process_name:
                if any(bp in event.process_name.lower() for bp in benign_processes):
                    benign_indicators.append(f"Security tool process: {event.process_name}")
        
        return benign_indicators
    
    def _extract_alert_features(self, alert: dict) -> dict[str, Any]:
        """Extract comparable features from an alert."""
        return {
            "title_tokens": set(alert.get("title", "").lower().split()),
            "source_system": alert.get("source_system", ""),
            "severity": alert.get("severity", ""),
            "detection_rule": alert.get("detection_rule", ""),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "hostname": alert.get("hostname"),
            "user": alert.get("user"),
            "process_hash": alert.get("process_hash"),
        }
    
    def _calculate_similarity(self, features1: dict, features2: dict) -> float:
        """Calculate similarity between two alerts."""
        score = 0.0
        weights = {
            "process_hash": 0.3,
            "detection_rule": 0.2,
            "source_ip": 0.15,
            "destination_ip": 0.15,
            "hostname": 0.1,
            "title_tokens": 0.1,
        }
        
        for feature, weight in weights.items():
            v1 = features1.get(feature)
            v2 = features2.get(feature)
            
            if v1 and v2:
                if feature == "title_tokens":
                    if v1 and v2:
                        intersection = len(v1 & v2)
                        union = len(v1 | v2)
                        if union > 0:
                            score += weight * (intersection / union)
                elif v1 == v2:
                    score += weight
        
        return score
    
    def _get_matching_features(self, features1: dict, features2: dict) -> list[str]:
        """Get list of matching features between two alerts."""
        matching = []
        for key in ["process_hash", "detection_rule", "source_ip", "destination_ip", "hostname"]:
            if features1.get(key) and features1.get(key) == features2.get(key):
                matching.append(key)
        return matching
