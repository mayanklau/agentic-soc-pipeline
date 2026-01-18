"""
Agentic SOC Pipeline - Main Entry Point

AI-powered Security Operations Center with specialized agents
and multi-tier memory architecture.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import NoReturn

import structlog

from src.config import get_settings
from src.memory.manager import MemoryManager
from src.agents.orchestrator import OrchestratorAgent
from src.agents.triage import TriageAgent
from src.agents.malware import MalwareAgent

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer() if sys.stderr.isatty() else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class AgenticSOCPipeline:
    """
    Main pipeline coordinator.
    
    Manages the lifecycle of all components:
    - Memory systems
    - Specialized agents
    - Event processing
    - Health monitoring
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.memory: MemoryManager | None = None
        self.agents: dict = {}
        self._shutdown_event = asyncio.Event()
        self._running = False
    
    async def initialize(self) -> None:
        """Initialize all pipeline components."""
        logger.info(
            "Initializing Agentic SOC Pipeline",
            environment=self.settings.environment,
        )
        
        # Initialize memory systems
        self.memory = MemoryManager(self.settings)
        await self.memory.initialize()
        
        # Initialize agents
        self.agents["orchestrator"] = OrchestratorAgent(self.settings, self.memory)
        self.agents["triage"] = TriageAgent(self.settings, self.memory)
        self.agents["malware"] = MalwareAgent(self.settings, self.memory)
        
        for name, agent in self.agents.items():
            await agent.initialize()
            logger.info("Agent initialized", agent=name)
        
        logger.info("Pipeline initialization complete")
    
    async def run(self) -> None:
        """Run the main event processing loop."""
        self._running = True
        
        logger.info("Starting event processing loop")
        
        try:
            while self._running:
                # Process tasks from queues
                await self._process_pending_tasks()
                
                # Small sleep to prevent busy-waiting
                await asyncio.sleep(0.1)
                
                # Check for shutdown
                if self._shutdown_event.is_set():
                    break
                    
        except asyncio.CancelledError:
            logger.info("Event loop cancelled")
        except Exception as e:
            logger.error("Error in event loop", error=str(e), exc_info=True)
            raise
    
    async def _process_pending_tasks(self) -> None:
        """Process pending tasks from the working memory queue."""
        if not self.memory:
            return
        
        for agent_type, agent in self.agents.items():
            # Try to get a task for this agent
            task_data = await self.memory.working.dequeue_task(agent_type, timeout=1)
            
            if task_data:
                logger.info(
                    "Processing task",
                    agent=agent_type,
                    task_type=task_data.get("task_type"),
                )
                
                # Build context and execute
                from src.agents.base import AgentContext, AgentTask
                
                task = AgentTask(**task_data)
                context = AgentContext(task=task)
                
                result = await agent.execute(context)
                
                logger.info(
                    "Task completed",
                    agent=agent_type,
                    success=result.success,
                    confidence=result.confidence,
                )
    
    async def shutdown(self) -> None:
        """Gracefully shutdown the pipeline."""
        logger.info("Shutting down pipeline")
        
        self._running = False
        self._shutdown_event.set()
        
        # Shutdown agents
        for name, agent in self.agents.items():
            await agent.shutdown()
            logger.info("Agent shutdown", agent=name)
        
        # Close memory connections
        if self.memory:
            await self.memory.close()
        
        logger.info("Pipeline shutdown complete")


async def main() -> NoReturn:
    """Main entry point."""
    pipeline = AgenticSOCPipeline()
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig,
            lambda: asyncio.create_task(pipeline.shutdown()),
        )
    
    try:
        await pipeline.initialize()
        await pipeline.run()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        await pipeline.shutdown()
    
    sys.exit(0)


def main_sync() -> None:
    """Synchronous entry point for console script."""
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
