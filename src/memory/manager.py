"""
Memory Manager - Unified interface for all memory subsystems.

Coordinates access to:
- Episodic Memory (Vector DB): Past incidents, attack patterns
- Semantic Memory (Knowledge Graph): Entity relationships, context
- Procedural Memory (PostgreSQL): Runbooks, playbooks, procedures
- Working Memory (Redis): Active session state, agent scratch space
- Shared Context (Kafka): Cross-agent communication
- Learning Memory (MLflow): Feedback loops, model performance
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import structlog

from src.config import Settings

logger = structlog.get_logger()


class EpisodicMemory:
    """
    Vector-based memory for past incidents and attack patterns.
    
    Uses ChromaDB or Pinecone for similarity search across
    historical security events and incidents.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._client = None
        self._collections = {}
    
    async def initialize(self) -> None:
        """Initialize vector store connection."""
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            
            self._client = chromadb.HttpClient(
                host=self.settings.chroma.host,
                port=self.settings.chroma.port,
            )
            
            # Initialize collections
            self._collections["incidents"] = self._client.get_or_create_collection(
                name=self.settings.chroma.incidents_collection,
                metadata={"description": "Past security incidents"}
            )
            self._collections["alerts"] = self._client.get_or_create_collection(
                name=self.settings.chroma.alerts_collection,
                metadata={"description": "Historical alerts"}
            )
            self._collections["playbooks"] = self._client.get_or_create_collection(
                name=self.settings.chroma.playbooks_collection,
                metadata={"description": "Response playbooks"}
            )
            
            logger.info("Episodic memory initialized", collections=list(self._collections.keys()))
            
        except Exception as e:
            logger.warning("Failed to initialize ChromaDB, using in-memory fallback", error=str(e))
            self._client = None
            self._in_memory_store = {"incidents": [], "alerts": [], "playbooks": []}
    
    async def search_similar(
        self,
        query: str,
        collection: str = "incidents",
        limit: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Search for similar items in episodic memory."""
        if self._client and collection in self._collections:
            try:
                results = self._collections[collection].query(
                    query_texts=[query],
                    n_results=limit,
                    where=filters,
                )
                
                items = []
                if results and results.get("documents"):
                    for i, doc in enumerate(results["documents"][0]):
                        items.append({
                            "id": results["ids"][0][i] if results.get("ids") else None,
                            "content": doc,
                            "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                            "distance": results["distances"][0][i] if results.get("distances") else None,
                        })
                return items
                
            except Exception as e:
                logger.error("Episodic search failed", error=str(e))
                return []
        
        # Fallback: return empty for in-memory
        return []
    
    async def store_incident(
        self,
        incident_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> None:
        """Store an incident in episodic memory."""
        if self._client and "incidents" in self._collections:
            try:
                self._collections["incidents"].add(
                    ids=[incident_id],
                    documents=[content],
                    metadatas=[metadata],
                )
            except Exception as e:
                logger.error("Failed to store incident", error=str(e))
    
    async def store_alert(
        self,
        alert_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> None:
        """Store an alert in episodic memory."""
        if self._client and "alerts" in self._collections:
            try:
                self._collections["alerts"].add(
                    ids=[alert_id],
                    documents=[content],
                    metadatas=[metadata],
                )
            except Exception as e:
                logger.error("Failed to store alert", error=str(e))


class SemanticMemory:
    """
    Knowledge graph for entity relationships and context.
    
    Uses Neo4j to store and query relationships between:
    - Assets (endpoints, servers, network devices)
    - Users (employees, service accounts)
    - Threat actors and campaigns
    - Vulnerabilities and IOCs
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._driver = None
    
    async def initialize(self) -> None:
        """Initialize Neo4j connection."""
        try:
            from neo4j import AsyncGraphDatabase
            
            self._driver = AsyncGraphDatabase.driver(
                self.settings.neo4j.uri,
                auth=(
                    self.settings.neo4j.user,
                    self.settings.neo4j.password.get_secret_value(),
                ),
            )
            
            # Verify connection
            async with self._driver.session() as session:
                await session.run("RETURN 1")
            
            logger.info("Semantic memory initialized")
            
        except Exception as e:
            logger.warning("Failed to initialize Neo4j, using in-memory fallback", error=str(e))
            self._driver = None
            self._in_memory_graph = {"nodes": {}, "edges": []}
    
    async def close(self) -> None:
        """Close Neo4j connection."""
        if self._driver:
            await self._driver.close()
    
    async def get_entity_context(
        self,
        entities: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Get context for a list of entities from the knowledge graph."""
        if not self._driver:
            return {}
        
        context = {}
        
        async with self._driver.session() as session:
            for entity in entities:
                entity_type = entity.get("type")
                entity_id = entity.get("id") or entity.get("value")
                
                if entity_type == "asset":
                    result = await session.run(
                        """
                        MATCH (a:Asset {id: $id})
                        OPTIONAL MATCH (a)-[:BELONGS_TO]->(d:Department)
                        OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                        OPTIONAL MATCH (a)<-[:ACCESSED]-(u:User)
                        RETURN a, d.name as department, 
                               collect(distinct v.cve_id) as vulnerabilities,
                               collect(distinct u.username) as recent_users
                        LIMIT 1
                        """,
                        id=entity_id,
                    )
                    record = await result.single()
                    if record:
                        context[f"asset_{entity_id}"] = {
                            "criticality": record["a"].get("criticality"),
                            "department": record["department"],
                            "vulnerabilities": record["vulnerabilities"],
                            "recent_users": record["recent_users"],
                        }
                
                elif entity_type == "user":
                    result = await session.run(
                        """
                        MATCH (u:User {id: $id})
                        OPTIONAL MATCH (u)-[:MEMBER_OF]->(g:Group)
                        OPTIONAL MATCH (u)-[:ACCESSED]->(a:Asset)
                        RETURN u, collect(distinct g.name) as groups,
                               count(distinct a) as asset_count
                        LIMIT 1
                        """,
                        id=entity_id,
                    )
                    record = await result.single()
                    if record:
                        context[f"user_{entity_id}"] = {
                            "risk_score": record["u"].get("risk_score", 0),
                            "privileged": record["u"].get("privileged", False),
                            "groups": record["groups"],
                            "asset_count": record["asset_count"],
                        }
                
                elif entity_type == "ip":
                    result = await session.run(
                        """
                        MATCH (i:IP {address: $address})
                        OPTIONAL MATCH (i)-[:ASSOCIATED_WITH]->(t:ThreatActor)
                        OPTIONAL MATCH (i)-[:RESOLVES_TO]->(d:Domain)
                        RETURN i, collect(distinct t.name) as threat_actors,
                               collect(distinct d.name) as domains
                        LIMIT 1
                        """,
                        address=entity_id,
                    )
                    record = await result.single()
                    if record:
                        context[f"ip_{entity_id}"] = {
                            "reputation": record["i"].get("reputation"),
                            "threat_actors": record["threat_actors"],
                            "domains": record["domains"],
                        }
        
        return context
    
    async def add_entity(
        self,
        entity_type: str,
        entity_id: str,
        properties: dict[str, Any],
    ) -> None:
        """Add or update an entity in the knowledge graph."""
        if not self._driver:
            return
        
        async with self._driver.session() as session:
            await session.run(
                f"""
                MERGE (e:{entity_type} {{id: $id}})
                SET e += $properties
                """,
                id=entity_id,
                properties=properties,
            )
    
    async def add_relationship(
        self,
        from_type: str,
        from_id: str,
        to_type: str,
        to_id: str,
        relationship: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Add a relationship between entities."""
        if not self._driver:
            return
        
        async with self._driver.session() as session:
            await session.run(
                f"""
                MATCH (a:{from_type} {{id: $from_id}})
                MATCH (b:{to_type} {{id: $to_id}})
                MERGE (a)-[r:{relationship}]->(b)
                SET r += $properties
                """,
                from_id=from_id,
                to_id=to_id,
                properties=properties or {},
            )


class ProceduralMemory:
    """
    Storage for runbooks, playbooks, and response procedures.
    
    Uses PostgreSQL with version control for procedure management.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._engine = None
    
    async def initialize(self) -> None:
        """Initialize database connection."""
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            
            # Convert sync URL to async
            db_url = self.settings.postgres.url.replace(
                "postgresql://", "postgresql+asyncpg://"
            )
            
            self._engine = create_async_engine(
                db_url,
                pool_size=self.settings.postgres.pool_size,
                max_overflow=self.settings.postgres.max_overflow,
                pool_pre_ping=self.settings.postgres.pool_pre_ping,
            )
            
            logger.info("Procedural memory initialized")
            
        except Exception as e:
            logger.warning("Failed to initialize PostgreSQL", error=str(e))
            self._engine = None
            self._in_memory_procedures = {}
    
    async def get_procedures(
        self,
        task_type: str,
        agent_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get relevant procedures for a task type."""
        # In production, this would query the database
        # For now, return predefined procedures
        
        procedures = {
            "assess_alert": [
                {
                    "name": "Standard Alert Triage",
                    "steps": [
                        "Validate alert source and severity",
                        "Check for false positive indicators",
                        "Enrich with threat intelligence",
                        "Determine if escalation needed",
                    ],
                }
            ],
            "analyze_artifact": [
                {
                    "name": "Malware Analysis Procedure",
                    "steps": [
                        "Calculate file hashes",
                        "Check against known malware databases",
                        "Perform static analysis",
                        "Execute in sandbox if needed",
                        "Extract IOCs",
                    ],
                }
            ],
            "recommend_actions": [
                {
                    "name": "Incident Response Procedure",
                    "steps": [
                        "Assess scope and impact",
                        "Determine containment actions",
                        "Identify affected assets",
                        "Recommend eradication steps",
                        "Plan recovery actions",
                    ],
                }
            ],
        }
        
        return procedures.get(task_type, [])
    
    async def store_procedure(
        self,
        name: str,
        task_types: list[str],
        agent_types: list[str],
        steps: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a new procedure or update existing."""
        # Would implement database storage
        procedure_id = f"proc_{name.lower().replace(' ', '_')}"
        return procedure_id


class WorkingMemory:
    """
    Short-term memory for active sessions and agent scratch space.
    
    Uses Redis for fast read/write access to current state.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._redis = None
    
    async def initialize(self) -> None:
        """Initialize Redis connection."""
        try:
            import redis.asyncio as redis
            
            self._redis = redis.from_url(
                self.settings.redis.url,
                encoding="utf-8",
                decode_responses=True,
            )
            
            # Verify connection
            await self._redis.ping()
            
            logger.info("Working memory initialized")
            
        except Exception as e:
            logger.warning("Failed to initialize Redis", error=str(e))
            self._redis = None
            self._in_memory_cache = {}
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
    
    async def store_result(
        self,
        task_id: UUID,
        agent_type: str,
        result: dict[str, Any],
        ttl: int | None = None,
    ) -> None:
        """Store agent task result."""
        import json
        
        key = f"{self.settings.redis.session_prefix}result:{task_id}:{agent_type}"
        ttl = ttl or self.settings.redis.session_ttl_seconds
        
        if self._redis:
            await self._redis.setex(key, ttl, json.dumps(result))
        else:
            self._in_memory_cache[key] = result
    
    async def get_result(
        self,
        task_id: UUID,
        agent_type: str,
    ) -> dict[str, Any] | None:
        """Retrieve agent task result."""
        import json
        
        key = f"{self.settings.redis.session_prefix}result:{task_id}:{agent_type}"
        
        if self._redis:
            data = await self._redis.get(key)
            return json.loads(data) if data else None
        else:
            return self._in_memory_cache.get(key)
    
    async def enqueue_task(self, task: Any) -> None:
        """Add a task to the processing queue."""
        import json
        
        queue_key = f"soc:queue:{task.agent_type}"
        
        if self._redis:
            await self._redis.lpush(queue_key, json.dumps(task.model_dump(), default=str))
    
    async def dequeue_task(self, agent_type: str, timeout: int = 5) -> dict | None:
        """Get next task from queue."""
        import json
        
        queue_key = f"soc:queue:{agent_type}"
        
        if self._redis:
            result = await self._redis.brpop(queue_key, timeout=timeout)
            if result:
                return json.loads(result[1])
        
        return None
    
    async def set_session_data(
        self,
        session_id: str,
        key: str,
        value: Any,
    ) -> None:
        """Store session-specific data."""
        import json
        
        redis_key = f"{self.settings.redis.session_prefix}{session_id}:{key}"
        
        if self._redis:
            await self._redis.setex(
                redis_key,
                self.settings.redis.session_ttl_seconds,
                json.dumps(value, default=str),
            )
    
    async def get_session_data(
        self,
        session_id: str,
        key: str,
    ) -> Any | None:
        """Retrieve session-specific data."""
        import json
        
        redis_key = f"{self.settings.redis.session_prefix}{session_id}:{key}"
        
        if self._redis:
            data = await self._redis.get(redis_key)
            return json.loads(data) if data else None
        
        return None


class SharedContext:
    """
    Cross-agent communication via Kafka topics.
    
    Enables agents to share findings and coordinate
    through a pub/sub messaging pattern.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._producer = None
        self._consumer = None
    
    async def initialize(self) -> None:
        """Initialize Kafka connection."""
        try:
            from aiokafka import AIOKafkaProducer
            
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.settings.kafka.bootstrap_servers,
            )
            await self._producer.start()
            
            logger.info("Shared context initialized")
            
        except Exception as e:
            logger.warning("Failed to initialize Kafka", error=str(e))
            self._producer = None
    
    async def close(self) -> None:
        """Close Kafka connections."""
        if self._producer:
            await self._producer.stop()
    
    async def publish_message(self, message: Any) -> None:
        """Publish a message to the agent communication topic."""
        import json
        
        if self._producer:
            await self._producer.send_and_wait(
                self.settings.kafka.agent_messages_topic,
                json.dumps(message.model_dump(), default=str).encode(),
            )


class MemoryManager:
    """
    Unified interface for all memory subsystems.
    
    Provides a single point of access for agents to interact
    with different types of memory.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        
        self.episodic = EpisodicMemory(settings)
        self.semantic = SemanticMemory(settings)
        self.procedural = ProceduralMemory(settings)
        self.working = WorkingMemory(settings)
        self.shared = SharedContext(settings)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize all memory subsystems."""
        if self._initialized:
            return
        
        logger.info("Initializing memory manager")
        
        await self.episodic.initialize()
        await self.semantic.initialize()
        await self.procedural.initialize()
        await self.working.initialize()
        await self.shared.initialize()
        
        self._initialized = True
        logger.info("Memory manager initialized")
    
    async def close(self) -> None:
        """Close all memory connections."""
        await self.semantic.close()
        await self.working.close()
        await self.shared.close()
        
        self._initialized = False
        logger.info("Memory manager closed")
