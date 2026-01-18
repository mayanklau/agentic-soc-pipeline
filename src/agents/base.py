"""
Base agent class for all specialized SOC agents.

Provides common functionality for LLM inference, memory access,
task management, and inter-agent communication.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

import structlog
from ollama import AsyncClient as OllamaClient
from pydantic import BaseModel

from src.config import Settings, get_settings
from src.memory.manager import MemoryManager
from src.models import AgentMessage, AgentTask, Alert, Incident, SecurityEvent

logger = structlog.get_logger()

# Type variable for agent-specific input/output
InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


class AgentContext(BaseModel):
    """Context passed to agent during task execution."""
    
    task: AgentTask
    related_events: list[SecurityEvent] = []
    related_alerts: list[Alert] = []
    related_incidents: list[Incident] = []
    memory_context: dict[str, Any] = {}
    messages_from_agents: list[AgentMessage] = []


class AgentResult(BaseModel):
    """Standardized result from agent execution."""
    
    task_id: UUID
    agent_type: str
    success: bool
    confidence: float = 0.0
    result: dict[str, Any] = {}
    reasoning: str | None = None
    recommended_actions: list[str] = []
    follow_up_tasks: list[dict[str, Any]] = []
    error: str | None = None
    execution_time_ms: int = 0


class BaseAgent(ABC, Generic[InputT, OutputT]):
    """
    Abstract base class for all SOC agents.
    
    Each specialized agent inherits from this class and implements
    the domain-specific processing logic.
    """
    
    # Class attributes to be overridden by subclasses
    agent_type: str = "base"
    agent_description: str = "Base agent"
    default_model: str = "phi3:mini"
    default_temperature: float = 0.1
    default_max_tokens: int = 2048
    
    def __init__(
        self,
        settings: Settings | None = None,
        memory_manager: MemoryManager | None = None,
    ):
        self.settings = settings or get_settings()
        self.memory = memory_manager
        self._ollama_client: OllamaClient | None = None
        self._initialized = False
        
        self.logger = logger.bind(agent=self.agent_type)
        
    async def initialize(self) -> None:
        """Initialize agent resources."""
        if self._initialized:
            return
            
        self.logger.info("Initializing agent")
        
        # Initialize Ollama client
        self._ollama_client = OllamaClient(host=self.settings.ollama.host)
        
        # Initialize memory manager if not provided
        if self.memory is None:
            self.memory = MemoryManager(self.settings)
            await self.memory.initialize()
        
        # Agent-specific initialization
        await self._initialize()
        
        self._initialized = True
        self.logger.info("Agent initialized")
    
    async def _initialize(self) -> None:
        """Override for agent-specific initialization."""
        pass
    
    async def shutdown(self) -> None:
        """Cleanup agent resources."""
        self.logger.info("Shutting down agent")
        await self._shutdown()
        self._initialized = False
    
    async def _shutdown(self) -> None:
        """Override for agent-specific cleanup."""
        pass
    
    @property
    def model(self) -> str:
        """Get the model to use for this agent."""
        model_map = {
            "orchestrator": self.settings.ollama.orchestrator_model,
            "triage": self.settings.ollama.triage_model,
            "malware": self.settings.ollama.malware_model,
            "network": self.settings.ollama.network_model,
            "identity": self.settings.ollama.identity_model,
            "threat_intel": self.settings.ollama.threat_intel_model,
            "response": self.settings.ollama.response_model,
        }
        return model_map.get(self.agent_type, self.default_model)
    
    async def execute(self, context: AgentContext) -> AgentResult:
        """
        Execute the agent's task.
        
        This is the main entry point for task execution.
        """
        if not self._initialized:
            await self.initialize()
        
        start_time = datetime.utcnow()
        task = context.task
        
        self.logger.info(
            "Executing task",
            task_id=str(task.task_id),
            task_type=task.task_type,
        )
        
        try:
            # Pre-process: load relevant memory
            memory_context = await self._load_memory_context(context)
            context.memory_context = memory_context
            
            # Execute agent-specific logic
            result = await self._execute(context)
            
            # Post-process: store results in memory
            await self._store_results(context, result)
            
            execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            result.execution_time_ms = execution_time
            
            self.logger.info(
                "Task completed",
                task_id=str(task.task_id),
                success=result.success,
                confidence=result.confidence,
                execution_time_ms=execution_time,
            )
            
            return result
            
        except Exception as e:
            self.logger.error(
                "Task failed",
                task_id=str(task.task_id),
                error=str(e),
                exc_info=True,
            )
            
            execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
                execution_time_ms=execution_time,
            )
    
    @abstractmethod
    async def _execute(self, context: AgentContext) -> AgentResult:
        """
        Agent-specific execution logic.
        
        Override this method in subclasses to implement the agent's
        core functionality.
        """
        pass
    
    async def _load_memory_context(self, context: AgentContext) -> dict[str, Any]:
        """Load relevant context from memory systems."""
        if self.memory is None:
            return {}
        
        memory_context = {}
        
        # Load similar past incidents from episodic memory
        if context.related_alerts:
            alert = context.related_alerts[0]
            similar_incidents = await self.memory.episodic.search_similar(
                query=f"{alert.title} {alert.description}",
                limit=5,
            )
            memory_context["similar_incidents"] = similar_incidents
        
        # Load entity context from semantic memory
        if context.related_events:
            entities = self._extract_entities(context.related_events)
            entity_context = await self.memory.semantic.get_entity_context(entities)
            memory_context["entity_context"] = entity_context
        
        # Load relevant procedures from procedural memory
        if context.task.task_type:
            procedures = await self.memory.procedural.get_procedures(
                task_type=context.task.task_type,
                agent_type=self.agent_type,
            )
            memory_context["procedures"] = procedures
        
        return memory_context
    
    async def _store_results(self, context: AgentContext, result: AgentResult) -> None:
        """Store execution results in memory."""
        if self.memory is None:
            return
        
        # Store in working memory for other agents
        await self.memory.working.store_result(
            task_id=context.task.task_id,
            agent_type=self.agent_type,
            result=result.model_dump(),
        )
    
    def _extract_entities(self, events: list[SecurityEvent]) -> list[dict[str, str]]:
        """Extract entities from events for semantic memory lookup."""
        entities = []
        
        for event in events:
            if event.asset:
                entities.append({"type": "asset", "id": str(event.asset.id)})
            if event.user:
                entities.append({"type": "user", "id": str(event.user.id)})
            if event.source_ip:
                entities.append({"type": "ip", "value": event.source_ip})
            if event.destination_ip:
                entities.append({"type": "ip", "value": event.destination_ip})
            if event.domain:
                entities.append({"type": "domain", "value": event.domain})
            if event.process_hash:
                entities.append({"type": "hash", "value": event.process_hash})
        
        return entities
    
    async def llm_completion(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        """
        Get completion from the LLM.
        
        Uses Ollama for local inference with the agent's configured model.
        """
        if self._ollama_client is None:
            raise RuntimeError("Agent not initialized")
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = await self._ollama_client.chat(
            model=self.model,
            messages=messages,
            options={
                "temperature": temperature or self.default_temperature,
                "num_predict": max_tokens or self.default_max_tokens,
            },
            format="json" if json_mode else None,
        )
        
        return response["message"]["content"]
    
    async def send_message(
        self,
        to_agent: str | None,
        message_type: str,
        content: dict[str, Any],
        correlation_id: UUID | None = None,
        priority: int = 3,
    ) -> AgentMessage:
        """Send a message to another agent or broadcast."""
        if self.memory is None:
            raise RuntimeError("Memory manager not available")
        
        message = AgentMessage(
            from_agent=self.agent_type,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            correlation_id=correlation_id,
            priority=priority,
        )
        
        await self.memory.shared.publish_message(message)
        
        return message
    
    async def request_task(
        self,
        target_agent: str,
        task_type: str,
        payload: dict[str, Any],
        priority: int = 3,
        parent_task_id: UUID | None = None,
    ) -> AgentTask:
        """Request another agent to perform a task."""
        task = AgentTask(
            agent_type=target_agent,
            task_type=task_type,
            priority=priority,
            payload=payload,
            parent_task_id=parent_task_id,
        )
        
        if self.memory:
            await self.memory.working.enqueue_task(task)
        
        return task
    
    def build_system_prompt(self) -> str:
        """Build the system prompt for this agent."""
        return f"""You are a specialized {self.agent_description} in an AI-powered Security Operations Center.

Your role is to analyze security data and provide accurate, actionable insights.

Guidelines:
- Be precise and evidence-based in your analysis
- Cite specific data points that support your conclusions
- Express confidence levels appropriately
- Recommend specific next steps when applicable
- Consider the broader attack context (kill chain, MITRE ATT&CK)
- Prioritize based on business impact and threat severity

Always respond in valid JSON format when requested."""


class BatchAgent(BaseAgent[InputT, OutputT]):
    """
    Base class for agents that process items in batches.
    
    Useful for high-volume processing like alert triage.
    """
    
    batch_size: int = 50
    max_concurrent_batches: int = 4
    
    async def execute_batch(
        self,
        contexts: list[AgentContext],
    ) -> list[AgentResult]:
        """Execute multiple tasks in parallel batches."""
        if not self._initialized:
            await self.initialize()
        
        results = []
        
        # Process in batches
        for i in range(0, len(contexts), self.batch_size):
            batch = contexts[i : i + self.batch_size]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(
                *[self.execute(ctx) for ctx in batch],
                return_exceptions=True,
            )
            
            # Handle exceptions
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    results.append(
                        AgentResult(
                            task_id=batch[j].task.task_id,
                            agent_type=self.agent_type,
                            success=False,
                            error=str(result),
                        )
                    )
                else:
                    results.append(result)
        
        return results
