"""
Fleet Registry — agent, service, and health tracking for the fleet.

Provides centralized registries for tracking all agents in the fleet, their
capabilities, health status, and supports registry synchronization and
anti-entropy conflict resolution.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from fleet_protocol.messages import FleetMessage, MessageBuilder, MessageType, MessagePriority
from fleet_protocol.protocol import ProtocolConstants, HeartbeatState

CONSTANTS = ProtocolConstants()


# ---------------------------------------------------------------------------
# Agent Record
# ---------------------------------------------------------------------------

class AgentRole(str, enum.Enum):
    """Roles an agent can have in the fleet."""
    WORKER = "worker"
    KEEPER = "keeper"
    COORDINATOR = "coordinator"
    GATEWAY = "gateway"
    MONITOR = "monitor"


@dataclass
class AgentRecord:
    """
    Registry record for a single fleet agent.

    Attributes:
        agent_id: Unique identifier for the agent.
        name: Human-readable name.
        role: Role within the fleet.
        address: Network address or endpoint.
        version: Protocol version the agent supports.
        capabilities: List of capabilities this agent provides.
        registered_at: Timestamp when the agent was first registered.
        last_seen: Timestamp of the most recent activity.
        metadata: Arbitrary key-value metadata.
        generation: Monotonically increasing version for anti-entropy.
    """
    agent_id: str
    name: str = ""
    role: str = AgentRole.WORKER.value
    address: str = ""
    version: str = "2.0"
    capabilities: List[str] = field(default_factory=list)
    registered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    generation: int = 0

    def fingerprint(self) -> str:
        """Generate a content hash for anti-entropy comparison."""
        content = f"{self.agent_id}:{self.role}:{self.version}:{','.join(sorted(self.capabilities))}:{self.generation}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "address": self.address,
            "version": self.version,
            "capabilities": self.capabilities,
            "registered_at": self.registered_at,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
            "generation": self.generation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Service Record
# ---------------------------------------------------------------------------

@dataclass
class ServiceRecord:
    """
    Registry record mapping a capability/service to agents that provide it.

    Attributes:
        service_name: Name of the service/capability.
        provider_ids: Agent IDs that provide this service.
        description: Human-readable description.
        metadata: Service-specific metadata.
    """
    service_name: str
    provider_ids: List[str] = field(default_factory=list)
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "provider_ids": self.provider_ids,
            "description": self.description,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServiceRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Health Record
# ---------------------------------------------------------------------------

class HealthStatus(str, enum.Enum):
    """Health status of an agent."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    OFFLINE = "offline"


@dataclass
class HealthRecord:
    """
    Registry record tracking the health of a fleet agent.

    Attributes:
        agent_id: The agent being tracked.
        status: Current health status.
        last_check: When the health was last checked.
        consecutive_failures: Number of consecutive health check failures.
        latency_ms: Most recent round-trip latency in milliseconds.
        details: Additional health check details.
    """
    agent_id: str
    status: str = HealthStatus.UNKNOWN.value
    last_check: float = field(default_factory=time.time)
    consecutive_failures: int = 0
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "last_check": self.last_check,
            "consecutive_failures": self.consecutive_failures,
            "latency_ms": self.latency_ms,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HealthRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Fleet Registry
# ---------------------------------------------------------------------------

class FleetRegistry:
    """
    Combined fleet registry for agents, services, and health.

    Provides CRUD operations, queries, synchronization support, and
    anti-entropy conflict detection and resolution.
    """

    def __init__(self) -> None:
        self._agents: Dict[str, AgentRecord] = {}
        self._services: Dict[str, ServiceRecord] = {}
        self._health: Dict[str, HealthRecord] = {}
        self._generation: int = 0
        self._lock_token: Optional[str] = None

    # -- Agent Registry ------------------------------------------------------

    def register_agent(self, record: AgentRecord) -> None:
        """Register or update an agent."""
        existing = self._agents.get(record.agent_id)
        if existing:
            record.generation = existing.generation + 1
            # Preserve registered_at from first registration
            record.registered_at = existing.registered_at
        else:
            record.generation = 1

        self._agents[record.agent_id] = record
        self._update_service_index(record)
        self._generation += 1

        # Initialize health record if not present
        if record.agent_id not in self._health:
            self._health[record.agent_id] = HealthRecord(
                agent_id=record.agent_id,
                status=HealthStatus.HEALTHY.value,
            )

    def unregister_agent(self, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        if agent_id not in self._agents:
            return False

        record = self._agents.pop(agent_id)
        self._remove_from_service_index(record)
        self._health.pop(agent_id, None)
        self._generation += 1
        return True

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        """Get an agent record by ID."""
        return self._agents.get(agent_id)

    def get_all_agents(self) -> List[AgentRecord]:
        """Return all registered agents."""
        return list(self._agents.values())

    def find_agents_by_capability(self, capability: str) -> List[AgentRecord]:
        """Find all agents that provide a specific capability."""
        return [
            a for a in self._agents.values()
            if capability in a.capabilities
        ]

    def find_agents_by_role(self, role: str) -> List[AgentRecord]:
        """Find all agents with a specific role."""
        return [a for a in self._agents.values() if a.role == role]

    def find_agents_by_name(self, name: str) -> List[AgentRecord]:
        """Find agents by name (case-insensitive substring match)."""
        name_lower = name.lower()
        return [a for a in self._agents.values() if name_lower in a.name.lower()]

    def update_last_seen(self, agent_id: str) -> None:
        """Update the last_seen timestamp for an agent."""
        record = self._agents.get(agent_id)
        if record:
            record.last_seen = time.time()
            self._generation += 1

    def agent_count(self) -> int:
        """Return the number of registered agents."""
        return len(self._agents)

    # -- Service Registry ----------------------------------------------------

    def _update_service_index(self, record: AgentRecord) -> None:
        """Update the service index when an agent is registered/updated."""
        for cap in record.capabilities:
            if cap not in self._services:
                self._services[cap] = ServiceRecord(service_name=cap)
            srv = self._services[cap]
            if record.agent_id not in srv.provider_ids:
                srv.provider_ids.append(record.agent_id)

    def _remove_from_service_index(self, record: AgentRecord) -> None:
        """Remove an agent from the service index."""
        for cap in record.capabilities:
            srv = self._services.get(cap)
            if srv and record.agent_id in srv.provider_ids:
                srv.provider_ids.remove(record.agent_id)
                if not srv.provider_ids:
                    del self._services[cap]

    def get_service(self, service_name: str) -> Optional[ServiceRecord]:
        """Get a service record by name."""
        return self._services.get(service_name)

    def get_all_services(self) -> List[ServiceRecord]:
        """Return all registered services."""
        return list(self._services.values())

    def get_service_providers(self, service_name: str) -> List[str]:
        """Get agent IDs that provide a specific service."""
        srv = self._services.get(service_name)
        return srv.provider_ids if srv else []

    # -- Health Registry -----------------------------------------------------

    def update_health(self, record: HealthRecord) -> None:
        """Update or create a health record."""
        record.last_check = time.time()
        self._health[record.agent_id] = record
        self._generation += 1

    def get_health(self, agent_id: str) -> Optional[HealthRecord]:
        """Get health record for an agent."""
        return self._health.get(agent_id)

    def get_all_health(self) -> List[HealthRecord]:
        """Return all health records."""
        return list(self._health.values())

    def get_healthy_agents(self) -> List[str]:
        """Return IDs of all healthy agents."""
        return [
            aid for aid, h in self._health.items()
            if h.status == HealthStatus.HEALTHY.value
        ]

    def get_unhealthy_agents(self) -> List[str]:
        """Return IDs of all unhealthy agents."""
        return [
            aid for aid, h in self._health.items()
            if h.status in (HealthStatus.UNHEALTHY.value, HealthStatus.OFFLINE.value)
        ]

    # -- Registry Synchronization -------------------------------------------

    def get_snapshot(self) -> Dict[str, Any]:
        """
        Get a full snapshot of the registry for synchronization.

        Returns:
            Dictionary containing agents, services, health, and generation.
        """
        return {
            "generation": self._generation,
            "agents": {aid: a.to_dict() for aid, a in self._agents.items()},
            "services": {name: s.to_dict() for name, s in self._services.items()},
            "health": {aid: h.to_dict() for aid, h in self._health.items()},
        }

    def apply_snapshot(self, snapshot: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Apply a remote snapshot, performing conflict resolution.

        Returns:
            Tuple of (success, list of conflicts resolved).
        """
        conflicts: List[str] = []
        remote_gen = snapshot.get("generation", 0)

        # Only apply if remote is newer
        if remote_gen <= self._generation:
            return (True, conflicts)

        # Merge agents
        for aid, agent_data in snapshot.get("agents", {}).items():
            existing = self._agents.get(aid)
            incoming = AgentRecord.from_dict(agent_data)

            if existing and existing.generation >= incoming.generation:
                continue  # Keep local (newer or same)

            if existing and existing.generation < incoming.generation:
                if existing.fingerprint() != incoming.fingerprint():
                    conflicts.append(
                        f"agent:{aid} gen {existing.generation} -> {incoming.generation}"
                    )
            self._agents[aid] = incoming

        # Merge services (rebuild index from agents)
        self._services.clear()
        for agent in self._agents.values():
            self._update_service_index(agent)

        # Merge health
        for aid, health_data in snapshot.get("health", {}).items():
            existing = self._health.get(aid)
            incoming = HealthRecord.from_dict(health_data)
            if existing is None or incoming.last_check > existing.last_check:
                self._health[aid] = incoming

        self._generation = remote_gen
        return (True, conflicts)

    def build_sync_request(self) -> FleetMessage:
        """Build a registry sync request message."""
        return (
            MessageBuilder()
            .sender("registry")
            .recipient("fleet:broadcast")
            .type(MessageType.QUERY)
            .payload({
                "action": "REGISTRY_SYNC_REQUEST",
                "local_generation": self._generation,
            })
            .priority(MessagePriority.NORMAL)
            .build()
        )

    def build_sync_response(self, recipient: str) -> FleetMessage:
        """Build a registry sync response with full snapshot."""
        return (
            MessageBuilder()
            .sender("registry")
            .recipient(recipient)
            .type(MessageType.RESPONSE)
            .payload({
                "action": "REGISTRY_SYNC_RESPONSE",
                "snapshot": self.get_snapshot(),
            })
            .priority(MessagePriority.NORMAL)
            .build()
        )

    # -- Anti-Entropy --------------------------------------------------------

    def detect_conflicts(self, other_snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect conflicts between local registry and a remote snapshot.

        Returns:
            List of conflict descriptors.
        """
        conflicts: List[Dict[str, Any]] = []

        for aid, remote_data in other_snapshot.get("agents", {}).items():
            local = self._agents.get(aid)
            remote = AgentRecord.from_dict(remote_data)

            if local is None:
                continue  # New agent, not a conflict

            if local.fingerprint() != remote.fingerprint():
                if local.generation == remote.generation:
                    conflicts.append({
                        "type": "generation_collision",
                        "agent_id": aid,
                        "local_generation": local.generation,
                        "remote_generation": remote.generation,
                        "local_fingerprint": local.fingerprint(),
                        "remote_fingerprint": remote.fingerprint(),
                        "resolution": "keep_local",
                    })
                elif remote.generation > local.generation:
                    conflicts.append({
                        "type": "outdated_local",
                        "agent_id": aid,
                        "local_generation": local.generation,
                        "remote_generation": remote.generation,
                        "resolution": "accept_remote",
                    })

        # Detect agents in local but not remote (possible partition)
        local_ids = set(self._agents.keys())
        remote_ids = set(other_snapshot.get("agents", {}).keys())
        only_local = local_ids - remote_ids
        for aid in only_local:
            conflicts.append({
                "type": "missing_remote",
                "agent_id": aid,
                "resolution": "keep_local",
            })

        return conflicts

    def resolve_conflicts(
        self,
        conflicts: List[Dict[str, Any]],
        strategy: str = "latest_wins",
    ) -> List[str]:
        """
        Resolve detected conflicts using the specified strategy.

        Strategies:
            - "latest_wins": Higher generation always wins.
            - "keep_local": Always keep local records.
            - "accept_remote": Always accept remote records.

        Returns:
            List of resolution descriptions.
        """
        resolutions: List[str] = []

        for conflict in conflicts:
            conflict_type = conflict["type"]
            agent_id = conflict["agent_id"]

            if strategy == "keep_local":
                resolutions.append(f"{agent_id}: kept local (strategy)")
                continue

            if strategy == "accept_remote":
                # Would need remote data; mark for acceptance
                resolutions.append(f"{agent_id}: accepted remote (strategy)")
                continue

            # latest_wins (default)
            if conflict_type == "generation_collision":
                resolutions.append(f"{agent_id}: kept local (generation tie, local wins)")
            elif conflict_type == "outdated_local":
                resolutions.append(f"{agent_id}: will accept remote on next sync")
            elif conflict_type == "missing_remote":
                resolutions.append(f"{agent_id}: kept local (not in remote)")
            else:
                resolutions.append(f"{agent_id}: unknown conflict type, kept local")

        return resolutions

    # -- Queries -------------------------------------------------------------

    def query(self, query_type: str, **kwargs: Any) -> List[Any]:
        """
        Generic query interface for the registry.

        Args:
            query_type: One of "all", "capability", "role", "name", "health".
            **kwargs: Query parameters.

        Returns:
            List of matching records.
        """
        if query_type == "all":
            return self.get_all_agents()
        elif query_type == "capability":
            return self.find_agents_by_capability(kwargs["capability"])
        elif query_type == "role":
            return self.find_agents_by_role(kwargs.get("role", ""))
        elif query_type == "name":
            return self.find_agents_by_name(kwargs.get("name", ""))
        elif query_type == "health":
            status = kwargs.get("status", "")
            if status == "healthy":
                return [self.get_health(aid) for aid in self.get_healthy_agents() if self.get_health(aid)]
            elif status == "unhealthy":
                return [self.get_health(aid) for aid in self.get_unhealthy_agents() if self.get_health(aid)]
            return self.get_all_health()
        elif query_type == "service":
            srv = self.get_service(kwargs.get("service", ""))
            return [srv] if srv else []
        return []

    # -- Utility -------------------------------------------------------------

    @property
    def generation(self) -> int:
        """Current registry generation number."""
        return self._generation

    def __repr__(self) -> str:
        return (
            f"FleetRegistry(agents={self.agent_count()}, "
            f"services={len(self._services)}, "
            f"generation={self._generation})"
        )
