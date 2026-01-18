"""
Data Ingestion Pipeline - Consume events from various security sources.

Handles ingestion from:
- Kafka topics (SIEM, EDR, network sensors)
- REST APIs (threat intel feeds)
- File-based sources (log files)
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, AsyncIterator
from uuid import uuid4

import structlog

from src.config import Settings
from src.models import SecurityEvent, EventType, Severity

logger = structlog.get_logger()


class BaseIngestion(ABC):
    """Abstract base class for data ingestion sources."""
    
    def __init__(self, settings: Settings, source_name: str):
        self.settings = settings
        self.source_name = source_name
        self.logger = logger.bind(source=source_name)
        self._running = False
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the data source."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the data source."""
        pass
    
    @abstractmethod
    async def consume(self) -> AsyncIterator[SecurityEvent]:
        """Consume and yield normalized security events."""
        pass
    
    @abstractmethod
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize raw event to canonical SecurityEvent format."""
        pass
    
    async def start(self) -> None:
        """Start the ingestion process."""
        self._running = True
        await self.connect()
        self.logger.info("Ingestion started")
    
    async def stop(self) -> None:
        """Stop the ingestion process."""
        self._running = False
        await self.disconnect()
        self.logger.info("Ingestion stopped")


class KafkaIngestion(BaseIngestion):
    """
    Kafka-based ingestion for high-volume event streams.
    
    Consumes from topics like:
    - soc.events.siem
    - soc.events.edr
    - soc.events.network
    """
    
    def __init__(self, settings: Settings, topic: str, source_name: str):
        super().__init__(settings, source_name)
        self.topic = topic
        self._consumer = None
    
    async def connect(self) -> None:
        """Connect to Kafka cluster."""
        try:
            from aiokafka import AIOKafkaConsumer
            
            self._consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.settings.kafka.bootstrap_servers,
                group_id=f"{self.settings.kafka.consumer_group}-{self.source_name}",
                auto_offset_reset=self.settings.kafka.auto_offset_reset,
                enable_auto_commit=True,
                value_deserializer=lambda m: __import__('json').loads(m.decode('utf-8')),
            )
            
            await self._consumer.start()
            self.logger.info("Connected to Kafka", topic=self.topic)
            
        except Exception as e:
            self.logger.error("Failed to connect to Kafka", error=str(e))
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Kafka."""
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
    
    async def consume(self) -> AsyncIterator[SecurityEvent]:
        """Consume events from Kafka topic."""
        if not self._consumer:
            raise RuntimeError("Consumer not connected")
        
        async for message in self._consumer:
            if not self._running:
                break
            
            try:
                raw_event = message.value
                event = self.normalize(raw_event)
                yield event
                
            except Exception as e:
                self.logger.error(
                    "Failed to process message",
                    error=str(e),
                    offset=message.offset,
                )
    
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize Kafka message to SecurityEvent."""
        # Generic normalization - subclasses can override
        return SecurityEvent(
            event_id=uuid4(),
            timestamp=datetime.fromisoformat(
                raw_event.get("timestamp", datetime.utcnow().isoformat())
            ),
            event_type=EventType(raw_event.get("event_type", "custom")),
            severity=Severity(raw_event.get("severity", "medium")),
            source_system=self.source_name,
            source_category=raw_event.get("category", "unknown"),
            raw_data=raw_event,
        )


class CrowdStrikeIngestion(KafkaIngestion):
    """CrowdStrike EDR event ingestion."""
    
    # CrowdStrike event type mappings
    EVENT_TYPE_MAP = {
        "ProcessRollup2": EventType.PROCESS,
        "SyntheticProcessRollup2": EventType.PROCESS,
        "ProcessBlocked": EventType.PROCESS,
        "NetworkConnectIP4": EventType.NETWORK,
        "NetworkConnectIP6": EventType.NETWORK,
        "DnsRequest": EventType.DNS,
        "FileWritten": EventType.FILE,
        "NewExecutableWritten": EventType.FILE,
        "PeFileWritten": EventType.FILE,
        "AsepValueUpdate": EventType.REGISTRY,
        "UserLogon": EventType.AUTHENTICATION,
        "UserLogoff": EventType.AUTHENTICATION,
    }
    
    SEVERITY_MAP = {
        "informational": Severity.LOW,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    
    def __init__(self, settings: Settings):
        super().__init__(
            settings,
            topic="soc.events.edr.crowdstrike",
            source_name="crowdstrike",
        )
    
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize CrowdStrike event to SecurityEvent."""
        event_type_str = raw_event.get("event_simpleName", "")
        event_type = self.EVENT_TYPE_MAP.get(event_type_str, EventType.CUSTOM)
        
        severity_str = raw_event.get("Severity", "medium").lower()
        severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
        
        # Parse timestamp
        timestamp_str = raw_event.get("timestamp") or raw_event.get("ProcessStartTime")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
        
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_system="crowdstrike",
            source_category="edr",
            # Process context
            process_name=raw_event.get("FileName") or raw_event.get("ImageFileName"),
            process_path=raw_event.get("FilePath"),
            process_hash=raw_event.get("SHA256HashData"),
            process_command_line=raw_event.get("CommandLine"),
            parent_process_name=raw_event.get("ParentBaseFileName"),
            parent_process_hash=raw_event.get("ParentProcessSHA256"),
            # Network context
            source_ip=raw_event.get("LocalAddressIP4"),
            destination_ip=raw_event.get("RemoteAddressIP4"),
            source_port=raw_event.get("LocalPort"),
            destination_port=raw_event.get("RemotePort"),
            # DNS context
            domain=raw_event.get("DomainName"),
            # File context
            file_name=raw_event.get("TargetFileName"),
            file_path=raw_event.get("TargetFilePath"),
            file_hash=raw_event.get("TargetFileSHA256"),
            # Raw data
            raw_data=raw_event,
        )


class SplunkIngestion(KafkaIngestion):
    """Splunk SIEM event ingestion."""
    
    SOURCETYPE_MAP = {
        "WinEventLog:Security": EventType.AUTHENTICATION,
        "WinEventLog:System": EventType.PROCESS,
        "linux:audit": EventType.AUTHENTICATION,
        "pan:traffic": EventType.NETWORK,
        "cisco:asa": EventType.NETWORK,
        "aws:cloudtrail": EventType.AUTHORIZATION,
    }
    
    def __init__(self, settings: Settings):
        super().__init__(
            settings,
            topic="soc.events.siem.splunk",
            source_name="splunk",
        )
    
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize Splunk event to SecurityEvent."""
        sourcetype = raw_event.get("sourcetype", "")
        event_type = self.SOURCETYPE_MAP.get(sourcetype, EventType.CUSTOM)
        
        # Parse severity from Splunk's urgency or priority fields
        urgency = raw_event.get("urgency", "medium").lower()
        severity_map = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
        severity = severity_map.get(urgency, Severity.MEDIUM)
        
        # Parse timestamp
        timestamp_str = raw_event.get("_time") or raw_event.get("timestamp")
        if timestamp_str:
            try:
                if isinstance(timestamp_str, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp_str)
                else:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
        
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_system="splunk",
            source_category="siem",
            source_ip=raw_event.get("src_ip") or raw_event.get("src"),
            destination_ip=raw_event.get("dest_ip") or raw_event.get("dest"),
            source_port=raw_event.get("src_port"),
            destination_port=raw_event.get("dest_port"),
            protocol=raw_event.get("protocol") or raw_event.get("transport"),
            raw_data=raw_event,
        )


class ZeekIngestion(KafkaIngestion):
    """Zeek network security monitor ingestion."""
    
    LOG_TYPE_MAP = {
        "conn": EventType.NETWORK,
        "dns": EventType.DNS,
        "http": EventType.HTTP,
        "ssl": EventType.NETWORK,
        "files": EventType.FILE,
        "notice": EventType.CUSTOM,
    }
    
    def __init__(self, settings: Settings):
        super().__init__(
            settings,
            topic="soc.events.network.zeek",
            source_name="zeek",
        )
    
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize Zeek log to SecurityEvent."""
        log_type = raw_event.get("_path", "conn")
        event_type = self.LOG_TYPE_MAP.get(log_type, EventType.NETWORK)
        
        # Zeek timestamps are usually epoch floats
        ts = raw_event.get("ts")
        if ts:
            try:
                timestamp = datetime.fromtimestamp(float(ts))
            except (ValueError, TypeError):
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
        
        # Determine severity based on notice type or connection flags
        severity = Severity.LOW
        if raw_event.get("notice"):
            severity = Severity.MEDIUM
        if raw_event.get("conn_state") in ["S0", "REJ", "RSTO", "RSTOS0"]:
            severity = Severity.MEDIUM
        
        return SecurityEvent(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_system="zeek",
            source_category="network",
            source_ip=raw_event.get("id.orig_h"),
            destination_ip=raw_event.get("id.resp_h"),
            source_port=raw_event.get("id.orig_p"),
            destination_port=raw_event.get("id.resp_p"),
            protocol=raw_event.get("proto"),
            domain=raw_event.get("query"),  # For DNS logs
            url=raw_event.get("uri"),  # For HTTP logs
            raw_data=raw_event,
        )


class ThreatIntelIngestion(BaseIngestion):
    """
    Threat intelligence feed ingestion.
    
    Pulls IOCs from MISP, VirusTotal, AbuseIPDB, etc.
    """
    
    def __init__(self, settings: Settings):
        super().__init__(settings, "threat_intel")
        self._poll_interval = 300  # 5 minutes
    
    async def connect(self) -> None:
        """Initialize threat intel API clients."""
        self.logger.info("Threat intel ingestion initialized")
    
    async def disconnect(self) -> None:
        """Cleanup threat intel connections."""
        pass
    
    async def consume(self) -> AsyncIterator[SecurityEvent]:
        """Poll threat intel feeds periodically."""
        while self._running:
            try:
                # Pull from MISP if configured
                if self.settings.integrations.misp_url:
                    async for event in self._pull_misp():
                        yield event
                
                # Pull from VirusTotal if configured
                if self.settings.integrations.virustotal_api_key:
                    async for event in self._pull_virustotal():
                        yield event
                
                # Wait before next poll
                await asyncio.sleep(self._poll_interval)
                
            except Exception as e:
                self.logger.error("Threat intel poll failed", error=str(e))
                await asyncio.sleep(60)  # Back off on error
    
    async def _pull_misp(self) -> AsyncIterator[SecurityEvent]:
        """Pull IOCs from MISP instance."""
        # Implementation would use pymisp or direct API
        # For now, yield nothing
        return
        yield  # Make this a generator
    
    async def _pull_virustotal(self) -> AsyncIterator[SecurityEvent]:
        """Pull data from VirusTotal."""
        # Implementation would use vt-py or direct API
        return
        yield
    
    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Normalize threat intel data to SecurityEvent."""
        return SecurityEvent(
            timestamp=datetime.utcnow(),
            event_type=EventType.CUSTOM,
            severity=Severity.MEDIUM,
            source_system="threat_intel",
            source_category="threat_intel",
            raw_data=raw_event,
        )


class IngestionManager:
    """
    Manages multiple ingestion sources and routes events to the pipeline.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.sources: dict[str, BaseIngestion] = {}
        self._running = False
        self._tasks: list[asyncio.Task] = []
    
    def register_source(self, name: str, source: BaseIngestion) -> None:
        """Register an ingestion source."""
        self.sources[name] = source
        logger.info("Registered ingestion source", name=name)
    
    def register_default_sources(self) -> None:
        """Register default ingestion sources based on configuration."""
        # Always register Kafka sources if Kafka is configured
        if self.settings.kafka.bootstrap_servers:
            self.register_source("crowdstrike", CrowdStrikeIngestion(self.settings))
            self.register_source("splunk", SplunkIngestion(self.settings))
            self.register_source("zeek", ZeekIngestion(self.settings))
        
        # Register threat intel if any feeds are configured
        if (self.settings.integrations.misp_url or 
            self.settings.integrations.virustotal_api_key):
            self.register_source("threat_intel", ThreatIntelIngestion(self.settings))
    
    async def start(self) -> None:
        """Start all ingestion sources."""
        self._running = True
        
        for name, source in self.sources.items():
            try:
                await source.start()
                task = asyncio.create_task(self._process_source(name, source))
                self._tasks.append(task)
            except Exception as e:
                logger.error("Failed to start source", source=name, error=str(e))
        
        logger.info("Ingestion manager started", sources=list(self.sources.keys()))
    
    async def stop(self) -> None:
        """Stop all ingestion sources."""
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        # Stop all sources
        for name, source in self.sources.items():
            try:
                await source.stop()
            except Exception as e:
                logger.error("Failed to stop source", source=name, error=str(e))
        
        logger.info("Ingestion manager stopped")
    
    async def _process_source(self, name: str, source: BaseIngestion) -> None:
        """Process events from a single source."""
        try:
            async for event in source.consume():
                if not self._running:
                    break
                
                # Route event to processing pipeline
                await self._route_event(event)
                
        except asyncio.CancelledError:
            logger.info("Source processing cancelled", source=name)
        except Exception as e:
            logger.error("Source processing error", source=name, error=str(e))
    
    async def _route_event(self, event: SecurityEvent) -> None:
        """Route event to the processing pipeline."""
        # In full implementation, this would:
        # 1. Publish to Kafka for persistence
        # 2. Apply quality validation
        # 3. Trigger alert generation if needed
        # 4. Update metrics
        
        logger.debug(
            "Event received",
            event_id=str(event.event_id),
            event_type=event.event_type.value,
            source=event.source_system,
        )
