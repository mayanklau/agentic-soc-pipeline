"""
Enrichment Pipeline - Add context and intelligence to security events.

Enrichment sources:
- Asset inventory (CMDB)
- User directory (AD, Okta)
- Threat intelligence (MISP, VirusTotal)
- Geolocation (MaxMind)
- Reputation services
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import structlog

from src.config import Settings
from src.models import SecurityEvent, IOC, Asset, User, MITREAttack, ThreatActor

logger = structlog.get_logger()


@dataclass
class EnrichmentResult:
    """Result from an enrichment source."""
    source: str
    success: bool
    data: dict[str, Any]
    cached: bool = False
    latency_ms: float = 0.0
    error: str | None = None


class EnrichmentSource(ABC):
    """Abstract base class for enrichment sources."""
    
    def __init__(self, settings: Settings, name: str):
        self.settings = settings
        self.name = name
        self.logger = logger.bind(enrichment_source=name)
        self._cache: dict[str, tuple[datetime, Any]] = {}
        self._cache_ttl = timedelta(minutes=15)
    
    @abstractmethod
    async def enrich(self, event: SecurityEvent) -> EnrichmentResult:
        """Enrich an event with additional context."""
        pass
    
    def _get_cached(self, key: str) -> Any | None:
        """Get value from cache if not expired."""
        if key in self._cache:
            timestamp, value = self._cache[key]
            if datetime.utcnow() - timestamp < self._cache_ttl:
                return value
            else:
                del self._cache[key]
        return None
    
    def _set_cached(self, key: str, value: Any) -> None:
        """Store value in cache."""
        self._cache[key] = (datetime.utcnow(), value)
        
        # Evict old entries if cache is too large
        if len(self._cache) > 10000:
            cutoff = datetime.utcnow() - self._cache_ttl
            self._cache = {
                k: v for k, v in self._cache.items()
                if v[0] > cutoff
            }


class AssetEnrichment(EnrichmentSource):
    """
    Enrich events with asset context from CMDB/inventory.
    
    Adds:
    - Asset criticality
    - Owner information
    - Department
    - Location
    - Installed software
    """
    
    def __init__(self, settings: Settings):
        super().__init__(settings, "asset_inventory")
        # In production, this would connect to ServiceNow, Qualys, etc.
        self._mock_assets: dict[str, dict] = {}
    
    async def enrich(self, event: SecurityEvent) -> EnrichmentResult:
        """Enrich event with asset information."""
        start = datetime.utcnow()
        
        # Determine lookup key
        lookup_key = None
        if event.asset and event.asset.hostname:
            lookup_key = event.asset.hostname.lower()
        elif event.source_ip:
            lookup_key = event.source_ip
        
        if not lookup_key:
            return EnrichmentResult(
                source=self.name,
                success=False,
                data={},
                error="No hostname or IP to lookup",
            )
        
        # Check cache
        cached = self._get_cached(lookup_key)
        if cached:
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            return EnrichmentResult(
                source=self.name,
                success=True,
                data=cached,
                cached=True,
                latency_ms=latency,
            )
        
        # Lookup asset (mock implementation)
        asset_data = await self._lookup_asset(lookup_key)
        
        if asset_data:
            self._set_cached(lookup_key, asset_data)
        
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        
        return EnrichmentResult(
            source=self.name,
            success=asset_data is not None,
            data=asset_data or {},
            latency_ms=latency,
        )
    
    async def _lookup_asset(self, key: str) -> dict[str, Any] | None:
        """Lookup asset from inventory system."""
        # Mock implementation - would query actual CMDB
        # Simulate some latency
        await asyncio.sleep(0.01)
        
        # Return mock data for demonstration
        if key.startswith("10.") or key.startswith("192.168."):
            return {
                "hostname": key,
                "criticality": "medium",
                "asset_type": "workstation",
                "os": "Windows 11",
                "owner": "IT Department",
                "department": "Engineering",
                "location": "HQ-Floor2",
                "last_scan": datetime.utcnow().isoformat(),
            }
        
        return None


class UserEnrichment(EnrichmentSource):
    """
    Enrich events with user context from directory services.
    
    Adds:
    - User role and department
    - Manager chain
    - Risk score
    - Privileged status
    - Recent activity patterns
    """
    
    def __init__(self, settings: Settings):
        super().__init__(settings, "user_directory")
    
    async def enrich(self, event: SecurityEvent) -> EnrichmentResult:
        """Enrich event with user information."""
        start = datetime.utcnow()
        
        if not event.user:
            return EnrichmentResult(
                source=self.name,
                success=False,
                data={},
                error="No user context in event",
            )
        
        username = event.user.username
        
        # Check cache
        cached = self._get_cached(username)
        if cached:
            latency = (datetime.utcnow() - start).total_seconds() * 1000
            return EnrichmentResult(
                source=self.name,
                success=True,
                data=cached,
                cached=True,
                latency_ms=latency,
            )
        
        # Lookup user
        user_data = await self._lookup_user(username)
        
        if user_data:
            self._set_cached(username, user_data)
        
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        
        return EnrichmentResult(
            source=self.name,
            success=user_data is not None,
            data=user_data or {},
            latency_ms=latency,
        )
    
    async def _lookup_user(self, username: str) -> dict[str, Any] | None:
        """Lookup user from directory service."""
        # Mock implementation - would query AD, Okta, etc.
        await asyncio.sleep(0.01)
        
        # Check for service accounts
        if username.startswith("svc_") or username.startswith("service"):
            return {
                "username": username,
                "type": "service_account",
                "privileged": True,
                "department": "IT",
                "risk_score": 30,
                "mfa_enabled": False,
            }
        
        # Regular user
        return {
            "username": username,
            "type": "employee",
            "privileged": False,
            "department": "Unknown",
            "manager": "Unknown",
            "risk_score": 10,
            "mfa_enabled": True,
            "last_login": datetime.utcnow().isoformat(),
        }


class ThreatIntelEnrichment(EnrichmentSource):
    """
    Enrich events with threat intelligence.
    
    Checks:
    - IP reputation
    - Domain reputation
    - File hash lookups
    - Known malware signatures
    """
    
    def __init__(self, settings: Settings):
        super().__init__(settings, "threat_intel")
        self._cache_ttl = timedelta(hours=1)  # Longer TTL for threat intel
    
    async def enrich(self, event: SecurityEvent) -> EnrichmentResult:
        """Enrich event with threat intelligence."""
        start = datetime.utcnow()
        
        enrichment_data = {
            "iocs_found": [],
            "threat_actors": [],
            "mitre_techniques": [],
            "reputation_scores": {},
        }
        
        tasks = []
        
        # Check IPs
        if event.source_ip:
            tasks.append(self._check_ip(event.source_ip))
        if event.destination_ip:
            tasks.append(self._check_ip(event.destination_ip))
        
        # Check domain
        if event.domain:
            tasks.append(self._check_domain(event.domain))
        
        # Check file hash
        if event.process_hash:
            tasks.append(self._check_hash(event.process_hash))
        if event.file_hash:
            tasks.append(self._check_hash(event.file_hash))
        
        # Execute all lookups in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict):
                    if result.get("ioc"):
                        enrichment_data["iocs_found"].append(result["ioc"])
                    if result.get("threat_actor"):
                        enrichment_data["threat_actors"].append(result["threat_actor"])
                    if result.get("mitre"):
                        enrichment_data["mitre_techniques"].extend(result["mitre"])
                    if result.get("reputation"):
                        enrichment_data["reputation_scores"].update(result["reputation"])
        
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        
        return EnrichmentResult(
            source=self.name,
            success=True,
            data=enrichment_data,
            latency_ms=latency,
        )
    
    async def _check_ip(self, ip: str) -> dict[str, Any]:
        """Check IP against threat intelligence."""
        # Check cache
        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached
        
        # Mock implementation - would query VirusTotal, AbuseIPDB, etc.
        await asyncio.sleep(0.02)
        
        result = {}
        
        # Simulate known bad IPs
        known_bad_ranges = ["185.220.", "45.155.", "91.219."]
        if any(ip.startswith(r) for r in known_bad_ranges):
            result = {
                "ioc": {
                    "type": "ip",
                    "value": ip,
                    "confidence": 0.85,
                    "source": "threat_intel",
                    "tags": ["malicious", "tor_exit", "c2"],
                },
                "reputation": {ip: -80},
                "threat_actor": "Unknown APT",
            }
        else:
            result = {"reputation": {ip: 0}}
        
        self._set_cached(f"ip:{ip}", result)
        return result
    
    async def _check_domain(self, domain: str) -> dict[str, Any]:
        """Check domain against threat intelligence."""
        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached
        
        await asyncio.sleep(0.02)
        
        result = {}
        
        # Simulate known bad domains
        bad_tlds = [".xyz", ".top", ".tk", ".ml"]
        bad_keywords = ["malware", "phish", "hack", "crack"]
        
        domain_lower = domain.lower()
        if (any(domain_lower.endswith(tld) for tld in bad_tlds) or
            any(kw in domain_lower for kw in bad_keywords)):
            result = {
                "ioc": {
                    "type": "domain",
                    "value": domain,
                    "confidence": 0.75,
                    "source": "threat_intel",
                    "tags": ["suspicious", "recently_registered"],
                },
                "reputation": {domain: -60},
            }
        else:
            result = {"reputation": {domain: 0}}
        
        self._set_cached(f"domain:{domain}", result)
        return result
    
    async def _check_hash(self, file_hash: str) -> dict[str, Any]:
        """Check file hash against threat intelligence."""
        cached = self._get_cached(f"hash:{file_hash}")
        if cached:
            return cached
        
        await asyncio.sleep(0.03)
        
        result = {}
        
        # In production, would query VirusTotal, Hybrid Analysis, etc.
        # For demo, simulate some known bad hashes
        known_malware_prefixes = ["a1b2c3", "deadbeef", "cafebabe"]
        
        if any(file_hash.lower().startswith(p) for p in known_malware_prefixes):
            result = {
                "ioc": {
                    "type": "hash",
                    "value": file_hash,
                    "confidence": 0.95,
                    "source": "virustotal",
                    "tags": ["malware", "trojan"],
                },
                "mitre": [
                    {"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"},
                ],
            }
        else:
            result = {}
        
        self._set_cached(f"hash:{file_hash}", result)
        return result


class GeoIPEnrichment(EnrichmentSource):
    """Enrich IP addresses with geolocation data."""
    
    def __init__(self, settings: Settings):
        super().__init__(settings, "geoip")
    
    async def enrich(self, event: SecurityEvent) -> EnrichmentResult:
        """Enrich IPs with geolocation."""
        start = datetime.utcnow()
        
        geo_data = {}
        
        for ip_field, ip_value in [
            ("source_ip", event.source_ip),
            ("destination_ip", event.destination_ip),
        ]:
            if ip_value and not ip_value.startswith(("10.", "192.168.", "172.")):
                geo = await self._lookup_geo(ip_value)
                if geo:
                    geo_data[ip_field] = geo
        
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        
        return EnrichmentResult(
            source=self.name,
            success=True,
            data=geo_data,
            latency_ms=latency,
        )
    
    async def _lookup_geo(self, ip: str) -> dict[str, Any] | None:
        """Lookup geolocation for IP."""
        cached = self._get_cached(f"geo:{ip}")
        if cached:
            return cached
        
        # Mock implementation - would use MaxMind GeoIP
        await asyncio.sleep(0.005)
        
        # Simulate geolocation
        result = {
            "country": "US",
            "country_name": "United States",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": "AS15169",
            "org": "Google LLC",
        }
        
        self._set_cached(f"geo:{ip}", result)
        return result


class EnrichmentPipeline:
    """
    Coordinates multiple enrichment sources for events.
    
    Runs enrichment in parallel and merges results.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.sources: list[EnrichmentSource] = []
        self._initialize_sources()
    
    def _initialize_sources(self) -> None:
        """Initialize all enrichment sources."""
        self.sources = [
            AssetEnrichment(self.settings),
            UserEnrichment(self.settings),
            ThreatIntelEnrichment(self.settings),
            GeoIPEnrichment(self.settings),
        ]
        
        logger.info(
            "Enrichment pipeline initialized",
            sources=[s.name for s in self.sources],
        )
    
    async def enrich_event(self, event: SecurityEvent) -> SecurityEvent:
        """
        Enrich an event with all available sources.
        
        Runs enrichment in parallel and merges results into the event.
        """
        start = datetime.utcnow()
        
        # Run all enrichments in parallel
        tasks = [source.enrich(event) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        enrichment_data: dict[str, Any] = {}
        
        for result in results:
            if isinstance(result, EnrichmentResult) and result.success:
                enrichment_data[result.source] = result.data
                
                # Log slow enrichments
                if result.latency_ms > 100:
                    logger.warning(
                        "Slow enrichment",
                        source=result.source,
                        latency_ms=result.latency_ms,
                        cached=result.cached,
                    )
            elif isinstance(result, Exception):
                logger.error("Enrichment failed", error=str(result))
        
        # Merge enrichment data into event
        enriched_event = self._merge_enrichment(event, enrichment_data)
        
        total_latency = (datetime.utcnow() - start).total_seconds() * 1000
        logger.debug(
            "Event enriched",
            event_id=str(event.event_id),
            total_latency_ms=total_latency,
            sources_succeeded=len(enrichment_data),
        )
        
        return enriched_event
    
    def _merge_enrichment(
        self,
        event: SecurityEvent,
        enrichment_data: dict[str, Any],
    ) -> SecurityEvent:
        """Merge enrichment data into the event."""
        # Store full enrichment data
        event.enrichment_data = enrichment_data
        
        # Extract and apply specific enrichments
        
        # Asset enrichment
        asset_data = enrichment_data.get("asset_inventory", {})
        if asset_data and event.asset:
            event.asset.criticality = asset_data.get("criticality", event.asset.criticality)
            event.asset.owner = asset_data.get("owner")
            event.asset.department = asset_data.get("department")
            event.asset.location = asset_data.get("location")
        
        # User enrichment
        user_data = enrichment_data.get("user_directory", {})
        if user_data and event.user:
            event.user.department = user_data.get("department")
            event.user.privileged = user_data.get("privileged", False)
            event.user.risk_score = user_data.get("risk_score", 0)
        
        # Threat intel enrichment
        threat_data = enrichment_data.get("threat_intel", {})
        if threat_data:
            # Add IOCs
            for ioc_data in threat_data.get("iocs_found", []):
                event.iocs.append(IOC(
                    type=ioc_data["type"],
                    value=ioc_data["value"],
                    confidence=ioc_data.get("confidence", 0.5),
                    source=ioc_data.get("source", "threat_intel"),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    tags=ioc_data.get("tags", []),
                ))
            
            # Add MITRE mappings
            for mitre_data in threat_data.get("mitre_techniques", []):
                event.mitre_attack.append(MITREAttack(
                    tactic_id="",
                    tactic_name=mitre_data.get("tactic", ""),
                    technique_id=mitre_data.get("technique", ""),
                    technique_name=mitre_data.get("name", ""),
                ))
            
            # Add threat actors
            for actor in threat_data.get("threat_actors", []):
                if isinstance(actor, str):
                    event.threat_actors.append(ThreatActor(
                        id=actor.lower().replace(" ", "_"),
                        name=actor,
                        confidence=0.5,
                    ))
        
        return event
    
    async def enrich_batch(
        self,
        events: list[SecurityEvent],
        max_concurrent: int = 50,
    ) -> list[SecurityEvent]:
        """
        Enrich a batch of events with concurrency control.
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def enrich_with_limit(event: SecurityEvent) -> SecurityEvent:
            async with semaphore:
                return await self.enrich_event(event)
        
        tasks = [enrich_with_limit(event) for event in events]
        enriched = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        results = []
        for i, result in enumerate(enriched):
            if isinstance(result, SecurityEvent):
                results.append(result)
            else:
                logger.error(
                    "Batch enrichment failed for event",
                    event_index=i,
                    error=str(result),
                )
                results.append(events[i])  # Return original event
        
        return results
