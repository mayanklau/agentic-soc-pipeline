"""
Streaming Pipeline - Real-time event processing with Apache Spark.

Implements the three-zone data lake architecture:
- Raw Zone: Immutable event storage
- Enriched Zone: Normalized and enriched data
- Curated Zone: Analysis-ready aggregations
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import structlog

from src.config import Settings
from src.models import SecurityEvent, Alert, Severity, EventType

logger = structlog.get_logger()


class StreamingPipeline:
    """
    Apache Spark Structured Streaming pipeline for security events.
    
    Processes events in micro-batches with:
    - Schema validation
    - Enrichment
    - Anomaly detection
    - Alert generation
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._spark = None
        self._streams: dict[str, Any] = {}
    
    def initialize(self) -> None:
        """Initialize Spark session."""
        try:
            from pyspark.sql import SparkSession
            
            self._spark = (
                SparkSession.builder
                .appName("AgenticSOCPipeline")
                .config("spark.sql.streaming.checkpointLocation", "/tmp/spark-checkpoints")
                .config("spark.sql.shuffle.partitions", "8")
                .config("spark.streaming.backpressure.enabled", "true")
                .config("spark.sql.streaming.metricsEnabled", "true")
                .getOrCreate()
            )
            
            # Set log level
            self._spark.sparkContext.setLogLevel("WARN")
            
            logger.info("Spark session initialized")
            
        except ImportError:
            logger.warning("PySpark not available, using lightweight processing")
            self._spark = None
        except Exception as e:
            logger.error("Failed to initialize Spark", error=str(e))
            self._spark = None
    
    def create_kafka_stream(self, topic: str, name: str) -> Any:
        """Create a streaming DataFrame from Kafka topic."""
        if not self._spark:
            raise RuntimeError("Spark not initialized")
        
        stream = (
            self._spark.readStream
            .format("kafka")
            .option("kafka.bootstrap.servers", self.settings.kafka.bootstrap_servers)
            .option("subscribe", topic)
            .option("startingOffsets", "latest")
            .option("maxOffsetsPerTrigger", self.settings.kafka.max_poll_records)
            .load()
        )
        
        self._streams[name] = stream
        logger.info("Created Kafka stream", name=name, topic=topic)
        
        return stream
    
    def process_events_stream(self, stream: Any) -> Any:
        """
        Process raw events through the enrichment pipeline.
        
        Pipeline stages:
        1. Parse JSON
        2. Validate schema
        3. Normalize fields
        4. Enrich with context
        5. Calculate risk scores
        """
        if not self._spark:
            return None
        
        from pyspark.sql import functions as F
        from pyspark.sql.types import (
            StructType, StructField, StringType, TimestampType, 
            IntegerType, DoubleType, MapType
        )
        
        # Define schema for security events
        event_schema = StructType([
            StructField("event_id", StringType(), True),
            StructField("timestamp", StringType(), True),
            StructField("event_type", StringType(), True),
            StructField("severity", StringType(), True),
            StructField("source_system", StringType(), True),
            StructField("source_ip", StringType(), True),
            StructField("destination_ip", StringType(), True),
            StructField("hostname", StringType(), True),
            StructField("user", StringType(), True),
            StructField("process_name", StringType(), True),
            StructField("process_hash", StringType(), True),
            StructField("command_line", StringType(), True),
            StructField("raw_data", StringType(), True),
        ])
        
        # Parse JSON from Kafka value
        parsed = (
            stream
            .select(
                F.from_json(
                    F.col("value").cast("string"),
                    event_schema
                ).alias("event"),
                F.col("timestamp").alias("kafka_timestamp"),
            )
            .select("event.*", "kafka_timestamp")
        )
        
        # Normalize and enrich
        enriched = (
            parsed
            # Parse timestamp
            .withColumn(
                "event_timestamp",
                F.to_timestamp(F.col("timestamp"))
            )
            # Add processing metadata
            .withColumn("processing_time", F.current_timestamp())
            .withColumn(
                "latency_ms",
                (F.col("processing_time").cast("long") - 
                 F.col("event_timestamp").cast("long")) * 1000
            )
            # Normalize severity
            .withColumn(
                "severity_normalized",
                F.when(F.col("severity").isin(["critical", "CRITICAL"]), 4)
                .when(F.col("severity").isin(["high", "HIGH"]), 3)
                .when(F.col("severity").isin(["medium", "MEDIUM"]), 2)
                .otherwise(1)
            )
            # Add risk score placeholder (would be calculated by ML model)
            .withColumn("risk_score", F.lit(0.5))
        )
        
        return enriched
    
    def create_alert_stream(self, enriched_stream: Any) -> Any:
        """
        Generate alerts from enriched events based on detection rules.
        """
        if not self._spark:
            return None
        
        from pyspark.sql import functions as F
        
        # Apply detection rules
        alerts = (
            enriched_stream
            # Rule: High severity events
            .filter(F.col("severity_normalized") >= 3)
            # Rule: Suspicious process names
            .withColumn(
                "suspicious_process",
                F.col("process_name").rlike(
                    "(?i)(powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin)"
                )
            )
            # Generate alert if conditions met
            .filter(
                (F.col("severity_normalized") >= 3) |
                F.col("suspicious_process")
            )
            # Create alert structure
            .select(
                F.expr("uuid()").alias("alert_id"),
                F.col("event_id"),
                F.concat(
                    F.lit("Suspicious activity: "),
                    F.coalesce(F.col("process_name"), F.lit("Unknown process"))
                ).alias("title"),
                F.col("severity"),
                F.col("source_system"),
                F.col("hostname"),
                F.col("user"),
                F.col("risk_score"),
                F.col("event_timestamp"),
                F.current_timestamp().alias("alert_timestamp"),
            )
        )
        
        return alerts
    
    def create_aggregation_stream(self, enriched_stream: Any) -> Any:
        """
        Create time-windowed aggregations for analytics and anomaly detection.
        """
        if not self._spark:
            return None
        
        from pyspark.sql import functions as F
        
        # 5-minute windowed aggregations
        aggregations = (
            enriched_stream
            .withWatermark("event_timestamp", "10 minutes")
            .groupBy(
                F.window("event_timestamp", "5 minutes"),
                F.col("source_system"),
                F.col("severity"),
            )
            .agg(
                F.count("*").alias("event_count"),
                F.countDistinct("hostname").alias("unique_hosts"),
                F.countDistinct("user").alias("unique_users"),
                F.avg("risk_score").alias("avg_risk_score"),
                F.max("severity_normalized").alias("max_severity"),
            )
        )
        
        return aggregations
    
    def write_to_data_lake(
        self,
        stream: Any,
        zone: str,
        table_name: str,
        checkpoint_path: str,
    ) -> Any:
        """
        Write streaming data to the data lake.
        
        Supports Delta Lake format for ACID transactions.
        """
        if not self._spark:
            return None
        
        query = (
            stream.writeStream
            .format("delta")
            .outputMode("append")
            .option("checkpointLocation", checkpoint_path)
            .option("path", f"/data/{zone}/{table_name}")
            .trigger(processingTime="30 seconds")
            .start()
        )
        
        logger.info(
            "Started data lake writer",
            zone=zone,
            table=table_name,
        )
        
        return query
    
    def write_alerts_to_kafka(self, alert_stream: Any, topic: str) -> Any:
        """Write generated alerts back to Kafka for agent processing."""
        if not self._spark:
            return None
        
        from pyspark.sql import functions as F
        
        query = (
            alert_stream
            .select(
                F.col("alert_id").alias("key"),
                F.to_json(F.struct("*")).alias("value"),
            )
            .writeStream
            .format("kafka")
            .option("kafka.bootstrap.servers", self.settings.kafka.bootstrap_servers)
            .option("topic", topic)
            .option("checkpointLocation", f"/tmp/spark-checkpoints/alerts-{topic}")
            .trigger(processingTime="10 seconds")
            .start()
        )
        
        logger.info("Started alert writer", topic=topic)
        
        return query


class LightweightPipeline:
    """
    Lightweight event processing pipeline for environments without Spark.
    
    Uses asyncio for concurrent processing with in-memory buffering.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._buffer: list[SecurityEvent] = []
        self._buffer_size = 1000
        self._flush_interval = 30  # seconds
        self._running = False
    
    async def process_event(self, event: SecurityEvent) -> Alert | None:
        """
        Process a single event through the lightweight pipeline.
        
        Returns an Alert if detection rules trigger.
        """
        # Add to buffer for batch processing
        self._buffer.append(event)
        
        # Apply detection rules
        alert = self._apply_detection_rules(event)
        
        # Flush buffer if full
        if len(self._buffer) >= self._buffer_size:
            await self._flush_buffer()
        
        return alert
    
    def _apply_detection_rules(self, event: SecurityEvent) -> Alert | None:
        """Apply detection rules to generate alerts."""
        
        # Rule 1: High/Critical severity events
        if event.severity in [Severity.HIGH, Severity.CRITICAL]:
            return Alert(
                title=f"High severity {event.event_type.value} event",
                description=f"Detected from {event.source_system}",
                severity=event.severity,
                confidence=0.8,
                source_system=event.source_system,
                events=[event.event_id],
            )
        
        # Rule 2: Suspicious PowerShell
        if event.process_name and "powershell" in event.process_name.lower():
            if event.process_command_line:
                suspicious_indicators = [
                    "-enc", "-encoded", "bypass", "hidden",
                    "downloadstring", "invoke-expression", "iex",
                    "frombase64", "webclient",
                ]
                cmd_lower = event.process_command_line.lower()
                if any(ind in cmd_lower for ind in suspicious_indicators):
                    return Alert(
                        title="Suspicious PowerShell Activity",
                        description=f"Command: {event.process_command_line[:200]}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        source_system=event.source_system,
                        events=[event.event_id],
                    )
        
        # Rule 3: Known malicious process names
        malicious_processes = {
            "mimikatz", "rubeus", "sharphound", "bloodhound",
            "cobalt", "beacon", "psexec", "wmic",
        }
        if event.process_name:
            proc_lower = event.process_name.lower()
            for mal_proc in malicious_processes:
                if mal_proc in proc_lower:
                    return Alert(
                        title=f"Known Malicious Tool Detected: {event.process_name}",
                        description=f"Process hash: {event.process_hash or 'Unknown'}",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        source_system=event.source_system,
                        events=[event.event_id],
                    )
        
        # Rule 4: Unusual outbound connections
        suspicious_ports = {4444, 5555, 6666, 8080, 8443, 9001, 31337}
        if event.destination_port and event.destination_port in suspicious_ports:
            return Alert(
                title=f"Suspicious Outbound Connection on Port {event.destination_port}",
                description=f"Destination: {event.destination_ip}:{event.destination_port}",
                severity=Severity.MEDIUM,
                confidence=0.7,
                source_system=event.source_system,
                events=[event.event_id],
            )
        
        return None
    
    async def _flush_buffer(self) -> None:
        """Flush event buffer to storage."""
        if not self._buffer:
            return
        
        events_to_flush = self._buffer.copy()
        self._buffer.clear()
        
        # In production, this would write to:
        # - Data lake (S3, Delta Lake, etc.)
        # - Time-series database (InfluxDB, TimescaleDB)
        # - Search index (Elasticsearch)
        
        logger.info("Flushed event buffer", count=len(events_to_flush))
    
    async def get_aggregations(
        self,
        window_minutes: int = 5,
    ) -> dict[str, Any]:
        """
        Calculate aggregations over recent events.
        
        Used for anomaly detection and dashboards.
        """
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        recent_events = [
            e for e in self._buffer
            if e.timestamp >= cutoff
        ]
        
        if not recent_events:
            return {
                "window_minutes": window_minutes,
                "event_count": 0,
                "by_severity": {},
                "by_source": {},
                "by_type": {},
            }
        
        # Aggregate by severity
        by_severity: dict[str, int] = {}
        for event in recent_events:
            sev = event.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Aggregate by source
        by_source: dict[str, int] = {}
        for event in recent_events:
            src = event.source_system
            by_source[src] = by_source.get(src, 0) + 1
        
        # Aggregate by type
        by_type: dict[str, int] = {}
        for event in recent_events:
            etype = event.event_type.value
            by_type[etype] = by_type.get(etype, 0) + 1
        
        return {
            "window_minutes": window_minutes,
            "event_count": len(recent_events),
            "by_severity": by_severity,
            "by_source": by_source,
            "by_type": by_type,
            "unique_hosts": len(set(e.asset.hostname if e.asset else None for e in recent_events) - {None}),
        }
