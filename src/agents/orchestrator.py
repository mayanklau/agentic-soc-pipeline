"""
Orchestrator Agent - Central coordinator for the Agentic SOC Pipeline.

The orchestrator is responsible for:
- Receiving incoming alerts and events
- Routing tasks to appropriate specialized agents
- Coordinating multi-agent investigations
- Synthesizing findings from multiple agents
- Managing priority and escalation
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import structlog

from src.agents.base import AgentContext, AgentResult, BaseAgent
from src.models import Alert, AlertStatus, Incident, IncidentStatus, Severity

logger = structlog.get_logger()


class OrchestratorDecision(BaseAgent):
    """Decision schema for orchestrator routing."""
    
    route_to: list[str]  # Agent types to route to
    priority: int
    reasoning: str
    parallel: bool  # Execute in parallel or sequential
    create_incident: bool
    escalate_to_human: bool


class OrchestratorAgent(BaseAgent):
    """
    Central orchestrator that coordinates all specialized agents.
    
    Uses a larger model (Phi-3-medium) for complex reasoning about
    how to handle alerts and coordinate investigations.
    """
    
    agent_type = "orchestrator"
    agent_description = "Central Orchestrator"
    default_model = "phi3:14b-medium-128k-instruct-q4_K_M"
    default_temperature = 0.1
    default_max_tokens = 4096
    
    # Routing rules based on alert characteristics
    ROUTING_RULES = {
        "malware": ["triage", "malware", "threat_intel"],
        "network": ["triage", "network", "threat_intel"],
        "authentication": ["triage", "identity"],
        "authorization": ["triage", "identity"],
        "process": ["triage", "malware"],
        "lateral_movement": ["triage", "network", "identity", "threat_intel"],
        "data_exfiltration": ["triage", "network", "threat_intel", "response"],
        "ransomware": ["triage", "malware", "response", "threat_intel"],
    }
    
    async def _execute(self, context: AgentContext) -> AgentResult:
        """Orchestrate the handling of an alert or event."""
        task = context.task
        task_type = task.task_type
        
        if task_type == "route_alert":
            return await self._route_alert(context)
        elif task_type == "coordinate_investigation":
            return await self._coordinate_investigation(context)
        elif task_type == "synthesize_findings":
            return await self._synthesize_findings(context)
        elif task_type == "escalation_decision":
            return await self._escalation_decision(context)
        else:
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=f"Unknown task type: {task_type}",
            )
    
    async def _route_alert(self, context: AgentContext) -> AgentResult:
        """
        Analyze an alert and determine which agents should handle it.
        
        This is the primary entry point for new alerts entering the system.
        """
        alert_data = context.task.payload.get("alert", {})
        
        # Build context for LLM decision
        system_prompt = self._build_routing_system_prompt()
        
        prompt = f"""Analyze this security alert and decide how to route it for investigation.

ALERT:
Title: {alert_data.get('title', 'Unknown')}
Description: {alert_data.get('description', 'No description')}
Severity: {alert_data.get('severity', 'unknown')}
Source: {alert_data.get('source_system', 'unknown')}

MITRE ATT&CK Mapping:
{json.dumps(alert_data.get('mitre_attack', []), indent=2)}

Related Events Summary:
{self._summarize_events(context.related_events)}

Similar Past Incidents:
{json.dumps(context.memory_context.get('similar_incidents', [])[:3], indent=2)}

Based on this information, provide your routing decision in JSON format:
{{
    "route_to": ["list", "of", "agent_types"],
    "priority": 1-5,
    "reasoning": "explanation of routing decision",
    "parallel": true/false,
    "create_incident": true/false,
    "escalate_to_human": true/false,
    "suggested_title": "concise incident title if creating incident"
}}

Available agents: triage, malware, network, identity, threat_intel, response"""

        try:
            response = await self.llm_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            decision = json.loads(response)
            
            # Validate and apply routing
            route_to = decision.get("route_to", ["triage"])
            priority = decision.get("priority", 3)
            parallel = decision.get("parallel", True)
            
            # Create follow-up tasks
            follow_up_tasks = []
            for agent_type in route_to:
                follow_up_tasks.append({
                    "agent_type": agent_type,
                    "task_type": self._get_task_type_for_agent(agent_type),
                    "priority": priority,
                    "payload": {
                        "alert": alert_data,
                        "routing_context": decision.get("reasoning"),
                    },
                })
            
            # Handle incident creation
            if decision.get("create_incident"):
                follow_up_tasks.append({
                    "agent_type": "orchestrator",
                    "task_type": "create_incident",
                    "priority": priority,
                    "payload": {
                        "alert": alert_data,
                        "suggested_title": decision.get("suggested_title"),
                    },
                })
            
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=0.85,
                result={
                    "decision": decision,
                    "routed_to": route_to,
                    "parallel_execution": parallel,
                },
                reasoning=decision.get("reasoning"),
                recommended_actions=[
                    f"Route to {', '.join(route_to)}",
                    "Create incident" if decision.get("create_incident") else "Monitor alert",
                ],
                follow_up_tasks=follow_up_tasks,
            )
            
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse LLM response", error=str(e))
            
            # Fallback to rule-based routing
            return await self._rule_based_routing(context)
    
    async def _rule_based_routing(self, context: AgentContext) -> AgentResult:
        """Fallback rule-based routing when LLM fails."""
        alert_data = context.task.payload.get("alert", {})
        
        # Determine category from MITRE or event type
        mitre_tactics = [m.get("tactic_name", "").lower() for m in alert_data.get("mitre_attack", [])]
        
        route_to = ["triage"]  # Always start with triage
        
        # Add specialized agents based on indicators
        for tactic in mitre_tactics:
            if "execution" in tactic or "persistence" in tactic:
                route_to.append("malware")
            if "lateral" in tactic or "discovery" in tactic:
                route_to.append("network")
            if "credential" in tactic or "privilege" in tactic:
                route_to.append("identity")
        
        route_to.append("threat_intel")  # Always enrich with threat intel
        route_to = list(set(route_to))  # Deduplicate
        
        severity = alert_data.get("severity", "medium")
        priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)
        
        follow_up_tasks = [
            {
                "agent_type": agent,
                "task_type": self._get_task_type_for_agent(agent),
                "priority": priority,
                "payload": {"alert": alert_data},
            }
            for agent in route_to
        ]
        
        return AgentResult(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            success=True,
            confidence=0.7,
            result={
                "decision": {"route_to": route_to, "priority": priority},
                "routed_to": route_to,
                "method": "rule_based_fallback",
            },
            reasoning="Used rule-based routing due to LLM parsing failure",
            follow_up_tasks=follow_up_tasks,
        )
    
    async def _coordinate_investigation(self, context: AgentContext) -> AgentResult:
        """
        Coordinate an ongoing investigation across multiple agents.
        
        Called when multiple agents are working on related tasks and
        their findings need to be correlated.
        """
        incident_id = context.task.payload.get("incident_id")
        agent_results = context.task.payload.get("agent_results", [])
        
        system_prompt = """You are coordinating a security investigation.
Analyze the findings from multiple specialized agents and determine next steps.
Consider what additional analysis might be needed and whether to escalate."""

        prompt = f"""Coordinate the investigation for incident {incident_id}.

Agent Findings:
{json.dumps(agent_results, indent=2)}

Current Incident State:
{json.dumps(context.task.payload.get('incident_state', {}), indent=2)}

Determine:
1. Are the findings consistent or conflicting?
2. What additional analysis is needed?
3. Should this be escalated?
4. What is the current threat assessment?

Respond in JSON:
{{
    "findings_consistent": true/false,
    "threat_assessment": "summary",
    "confidence_level": 0.0-1.0,
    "additional_analysis_needed": ["agent_type: task_type", ...],
    "escalate": true/false,
    "escalation_reason": "reason if escalating",
    "next_steps": ["step1", "step2"]
}}"""

        try:
            response = await self.llm_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            coordination = json.loads(response)
            
            # Generate follow-up tasks
            follow_up_tasks = []
            for analysis in coordination.get("additional_analysis_needed", []):
                if ":" in analysis:
                    agent_type, task_type = analysis.split(":", 1)
                    follow_up_tasks.append({
                        "agent_type": agent_type.strip(),
                        "task_type": task_type.strip(),
                        "priority": 2 if coordination.get("escalate") else 3,
                        "payload": {"incident_id": incident_id},
                    })
            
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=coordination.get("confidence_level", 0.7),
                result=coordination,
                reasoning=coordination.get("threat_assessment"),
                recommended_actions=coordination.get("next_steps", []),
                follow_up_tasks=follow_up_tasks,
            )
            
        except Exception as e:
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
            )
    
    async def _synthesize_findings(self, context: AgentContext) -> AgentResult:
        """
        Synthesize findings from all agents into a coherent narrative.
        
        Used to generate incident reports and executive summaries.
        """
        incident_data = context.task.payload.get("incident", {})
        all_findings = context.task.payload.get("findings", [])
        
        system_prompt = """You are synthesizing security investigation findings into a clear report.
Create a coherent narrative that explains the attack, its impact, and response actions.
Be concise but thorough. Focus on facts and evidence."""

        prompt = f"""Synthesize the following investigation findings into a comprehensive report.

Incident: {incident_data.get('title', 'Unknown Incident')}
Severity: {incident_data.get('severity', 'Unknown')}

Findings from Agents:
{json.dumps(all_findings, indent=2)}

Timeline of Events:
{json.dumps(context.task.payload.get('timeline', []), indent=2)}

Create a synthesis report in JSON:
{{
    "executive_summary": "2-3 sentence summary for leadership",
    "attack_narrative": "detailed description of what happened",
    "impact_assessment": "what was affected and how",
    "threat_actor_assessment": "who/what is behind this",
    "mitre_attack_mapping": ["T1234: Technique Name", ...],
    "indicators_of_compromise": ["ioc1", "ioc2"],
    "recommendations": ["rec1", "rec2"],
    "lessons_learned": ["lesson1", "lesson2"],
    "confidence": 0.0-1.0
}}"""

        try:
            response = await self.llm_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
                max_tokens=4096,
            )
            
            synthesis = json.loads(response)
            
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=True,
                confidence=synthesis.get("confidence", 0.8),
                result=synthesis,
                reasoning=synthesis.get("executive_summary"),
                recommended_actions=synthesis.get("recommendations", []),
            )
            
        except Exception as e:
            return AgentResult(
                task_id=context.task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
            )
    
    async def _escalation_decision(self, context: AgentContext) -> AgentResult:
        """
        Decide whether an alert/incident should be escalated to humans.
        
        Considers severity, confidence, potential impact, and analyst workload.
        """
        alert_data = context.task.payload.get("alert", {})
        agent_findings = context.task.payload.get("findings", {})
        
        severity = alert_data.get("severity", "medium")
        confidence = agent_findings.get("confidence", 0.5)
        
        # Rule-based escalation thresholds
        should_escalate = False
        escalation_reasons = []
        
        if severity in ["critical", "high"]:
            should_escalate = True
            escalation_reasons.append(f"High severity: {severity}")
        
        if confidence < self.settings.agent.auto_contain_threshold:
            should_escalate = True
            escalation_reasons.append(f"Low agent confidence: {confidence:.2f}")
        
        # Check for specific high-risk indicators
        mitre_techniques = [m.get("technique_id", "") for m in alert_data.get("mitre_attack", [])]
        high_risk_techniques = {"T1486", "T1490", "T1561"}  # Ransomware-related
        if any(t in high_risk_techniques for t in mitre_techniques):
            should_escalate = True
            escalation_reasons.append("High-risk MITRE techniques detected")
        
        return AgentResult(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            success=True,
            confidence=0.9,
            result={
                "escalate": should_escalate,
                "reasons": escalation_reasons,
                "severity": severity,
                "agent_confidence": confidence,
            },
            reasoning="; ".join(escalation_reasons) if escalation_reasons else "No escalation needed",
            recommended_actions=(
                ["Escalate to SOC analyst", "Page on-call if after hours"]
                if should_escalate
                else ["Continue automated analysis"]
            ),
        )
    
    def _build_routing_system_prompt(self) -> str:
        """Build system prompt for routing decisions."""
        return """You are the central orchestrator for an AI-powered Security Operations Center.

Your job is to analyze incoming security alerts and determine the best routing strategy.

Available specialized agents:
- triage: Initial alert assessment, false positive detection, severity validation
- malware: Static/dynamic malware analysis, YARA rules, sandbox detonation
- network: Traffic analysis, C2 detection, lateral movement identification
- identity: Authentication anomalies, privilege escalation, credential abuse
- threat_intel: IOC enrichment, MITRE mapping, threat actor attribution
- response: Automated containment, isolation, remediation

Routing principles:
1. Always start with triage for initial assessment
2. Route based on alert type and indicators present
3. Use parallel execution when agents don't depend on each other
4. Escalate to humans for high-severity or low-confidence situations
5. Consider similar past incidents when making decisions

Be decisive and explain your reasoning."""
    
    def _summarize_events(self, events: list) -> str:
        """Summarize related events for LLM context."""
        if not events:
            return "No related events"
        
        summary_lines = []
        for event in events[:10]:  # Limit to 10 events
            summary_lines.append(
                f"- {event.event_type.value}: {event.source_system} "
                f"({event.severity.value}) at {event.timestamp}"
            )
        
        return "\n".join(summary_lines)
    
    def _get_task_type_for_agent(self, agent_type: str) -> str:
        """Get the default task type for an agent."""
        task_types = {
            "triage": "assess_alert",
            "malware": "analyze_artifact",
            "network": "analyze_traffic",
            "identity": "analyze_authentication",
            "threat_intel": "enrich_iocs",
            "response": "recommend_actions",
        }
        return task_types.get(agent_type, "analyze")
