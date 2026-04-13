"""
Fleet Wire Protocol — versioning, handshake, heartbeat, discovery, capability negotiation.

This module defines the low-level coordination protocol that governs how agents
connect, authenticate, exchange capabilities, and maintain presence within the fleet.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from fleet_protocol.messages import (
    FleetMessage,
    MessageBuilder,
    MessageType,
    MessagePriority,
    MessageValidator,
)


# ---------------------------------------------------------------------------
# Protocol Constants
# ---------------------------------------------------------------------------

class ProtocolVersion(enum.Enum):
    """Supported protocol versions."""
    V1 = "1.0"
    V2 = "2.0"

    @classmethod
    def latest(cls) -> ProtocolVersion:
        """Return the latest supported version."""
        return cls.V2


@dataclass
class ProtocolConstants:
    """Default constants for the fleet wire protocol."""
    HANDSHAKE_TIMEOUT: float = 10.0  # seconds
    HEARTBEAT_INTERVAL: float = 5.0  # seconds
    HEARTBEAT_TIMEOUT: float = 15.0  # seconds before considered dead
    HEARTBEAT_DEGRADED_TIMEOUT: float = 10.0  # degraded threshold
    DISCOVERY_INTERVAL: float = 30.0  # seconds between discovery broadcasts
    DISCOVERY_TTL: int = 5  # max hops for discovery
    MAX_HANDSHAKE_RETRIES: int = 3
    CAPABILITY_NEGOTIATION_TIMEOUT: float = 5.0
    SYNC_INTERVAL: float = 60.0  # registry sync interval

    # Wire magic bytes
    MAGIC_V1: bytes = b"FLT1"
    MAGIC_V2: bytes = b"FLT2"


CONSTANTS = ProtocolConstants()


# ---------------------------------------------------------------------------
# Error Codes
# ---------------------------------------------------------------------------

class ErrorCode(enum.IntEnum):
    """Standard protocol error codes."""
    # Handshake errors (1xx)
    HANDSHAKE_TIMEOUT = 101
    HANDSHAKE_REJECTED = 102
    HANDSHAKE_VERSION_MISMATCH = 103
    HANDSHAKE_AUTH_FAILED = 104

    # Heartbeat errors (2xx)
    HEARTBEAT_MISSED = 201
    HEARTBEAT_DEGRADED = 202
    HEARTBEAT_DEAD = 203

    # Discovery errors (3xx)
    DISCOVERY_FAILED = 301
    DISCOVERY_NO_AGENTS = 302
    DISCOVERY_CAPABILITY_NOT_FOUND = 303

    # Capability errors (4xx)
    CAPABILITY_NEGOTIATION_FAILED = 401
    CAPABILITY_NOT_SUPPORTED = 402
    CAPABILITY_REQUIRED = 403

    # Registry errors (5xx)
    REGISTRY_SYNC_FAILED = 501
    REGISTRY_CONFLICT = 502
    REGISTRY_AGENT_NOT_FOUND = 503

    # Security errors (6xx)
    SECURITY_SIGNATURE_INVALID = 601
    SECURITY_TOKEN_EXPIRED = 602
    SECURITY_UNAUTHORIZED = 603

    # General errors (9xx)
    UNKNOWN_ERROR = 901
    INTERNAL_ERROR = 902


ERROR_MESSAGES: Dict[int, str] = {
    ErrorCode.HANDSHAKE_TIMEOUT: "Handshake timed out",
    ErrorCode.HANDSHAKE_REJECTED: "Handshake rejected by remote",
    ErrorCode.HANDSHAKE_VERSION_MISMATCH: "Protocol version mismatch",
    ErrorCode.HANDSHAKE_AUTH_FAILED: "Authentication failed during handshake",
    ErrorCode.HEARTBEAT_MISSED: "Heartbeat missed",
    ErrorCode.HEARTBEAT_DEGRADED: "Agent health degraded",
    ErrorCode.HEARTBEAT_DEAD: "Agent considered dead",
    ErrorCode.DISCOVERY_FAILED: "Discovery broadcast failed",
    ErrorCode.DISCOVERY_NO_AGENTS: "No agents discovered",
    ErrorCode.DISCOVERY_CAPABILITY_NOT_FOUND: "Capability not found in fleet",
    ErrorCode.CAPABILITY_NEGOTIATION_FAILED: "Capability negotiation failed",
    ErrorCode.CAPABILITY_NOT_SUPPORTED: "Requested capability not supported",
    ErrorCode.CAPABILITY_REQUIRED: "Required capability not available",
    ErrorCode.REGISTRY_SYNC_FAILED: "Registry synchronization failed",
    ErrorCode.REGISTRY_CONFLICT: "Registry conflict detected",
    ErrorCode.REGISTRY_AGENT_NOT_FOUND: "Agent not found in registry",
    ErrorCode.SECURITY_SIGNATURE_INVALID: "Message signature is invalid",
    ErrorCode.SECURITY_TOKEN_EXPIRED: "Authentication token expired",
    ErrorCode.SECURITY_UNAUTHORIZED: "Operation not authorized",
    ErrorCode.UNKNOWN_ERROR: "Unknown error",
    ErrorCode.INTERNAL_ERROR: "Internal error",
}


def error_message(code: int) -> str:
    """Get the human-readable message for an error code."""
    return ERROR_MESSAGES.get(code, "Unknown error code")


def build_error_message(
    sender: str,
    recipient: str,
    code: ErrorCode,
    details: Optional[Dict[str, Any]] = None,
    in_reply_to: Optional[str] = None,
) -> FleetMessage:
    """Build a standard error response message."""
    payload: Dict[str, Any] = {
        "error_code": code.value,
        "error_message": error_message(code.value),
    }
    if details:
        payload["details"] = details

    return (
        MessageBuilder()
        .sender(sender)
        .recipient(recipient)
        .type(MessageType.ERROR)
        .payload(payload)
        .priority(MessagePriority.HIGH)
        .in_reply_to(in_reply_to)
        .build()
    )


# ---------------------------------------------------------------------------
# Handshake Protocol
# ---------------------------------------------------------------------------

class HandshakeState(enum.Enum):
    """States in the handshake lifecycle."""
    INIT = "INIT"
    HELLO_SENT = "HELLO_SENT"
    HELLO_RECEIVED = "HELLO_RECEIVED"
    CAPABILITIES_EXCHANGED = "CAPABILITIES_EXCHANGED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


@dataclass
class HandshakeConfig:
    """Configuration for handshake behaviour."""
    version: ProtocolVersion = ProtocolVersion.latest()
    timeout: float = CONSTANTS.HANDSHAKE_TIMEOUT
    max_retries: int = CONSTANTS.MAX_HANDSHAKE_RETRIES
    capabilities: List[str] = field(default_factory=list)


@dataclass
class HandshakeResult:
    """Result of a handshake attempt."""
    success: bool
    state: HandshakeState
    peer_agent_id: str
    negotiated_version: ProtocolVersion
    shared_capabilities: List[str] = field(default_factory=list)
    error_code: Optional[int] = None
    error_message: Optional[str] = None


class HandshakeProtocol:
    """
    Implements the fleet handshake protocol.

    Sequence:
        1. Initiator sends HELLO with version + capabilities
        2. Responder replies with HELLO_ACK (or REJECT)
        3. Both exchange capability details
        4. Handshake marked COMPLETED
    """

    def __init__(self, agent_id: str, config: Optional[HandshakeConfig] = None) -> None:
        self.agent_id = agent_id
        self.config = config or HandshakeConfig()
        self.state = HandshakeState.INIT
        self._session_id: Optional[str] = None
        self._peer_capabilities: Set[str] = set()
        self._retry_count = 0

    @property
    def session_id(self) -> str:
        """Return the session ID, creating one if needed."""
        if self._session_id is None:
            self._session_id = str(uuid.uuid4())
        return self._session_id

    def build_hello(self, recipient: str) -> FleetMessage:
        """Build a HELLO message to initiate handshake."""
        self.state = HandshakeState.HELLO_SENT
        self._retry_count += 1

        return (
            MessageBuilder()
            .sender(self.agent_id)
            .recipient(recipient)
            .type(MessageType.REQUEST)
            .payload({
                "action": "HELLO",
                "session_id": self.session_id,
                "version": self.config.version.value,
                "capabilities": self.config.capabilities,
            })
            .priority(MessagePriority.HIGH)
            .requires_ack(True)
            .build()
        )

    def build_hello_ack(self, recipient: str) -> FleetMessage:
        """Build a HELLO_ACK message to accept a handshake."""
        self.state = HandshakeState.HELLO_RECEIVED

        return (
            MessageBuilder()
            .sender(self.agent_id)
            .recipient(recipient)
            .type(MessageType.RESPONSE)
            .payload({
                "action": "HELLO_ACK",
                "session_id": self.session_id,
                "version": self.config.version.value,
                "capabilities": self.config.capabilities,
            })
            .priority(MessagePriority.HIGH)
            .requires_ack(True)
            .build()
        )

    def build_reject(self, recipient: str, code: ErrorCode, reason: str) -> FleetMessage:
        """Build a REJECT message to decline a handshake."""
        self.state = HandshakeState.FAILED

        return (
            MessageBuilder()
            .sender(self.agent_id)
            .recipient(recipient)
            .type(MessageType.ERROR)
            .payload({
                "action": "HELLO_REJECT",
                "session_id": self.session_id,
                "error_code": code.value,
                "reason": reason,
            })
            .priority(MessagePriority.HIGH)
            .build()
        )

    def process_hello(self, message: FleetMessage) -> HandshakeResult:
        """
        Process an incoming HELLO message.

        Returns:
            HandshakeResult with success/failure status.
        """
        payload = message.body.payload
        peer_version = payload.get("version", "1.0")
        peer_caps = set(payload.get("capabilities", []))

        self._peer_capabilities = peer_caps
        self._session_id = payload.get("session_id", str(uuid.uuid4()))

        # Version negotiation: use the lower of the two
        try:
            peer_enum = ProtocolVersion(peer_version)
            negotiated = min(self.config.version, peer_enum, key=lambda v: v.value)
        except ValueError:
            negotiated = ProtocolVersion.V1

        shared = set(self.config.capabilities) & peer_caps

        self.state = HandshakeState.CAPABILITIES_EXCHANGED

        return HandshakeResult(
            success=True,
            state=self.state,
            peer_agent_id=message.header.sender,
            negotiated_version=negotiated,
            shared_capabilities=list(shared),
        )

    def complete(self) -> HandshakeResult:
        """Mark the handshake as completed."""
        self.state = HandshakeState.COMPLETED
        return HandshakeResult(
            success=True,
            state=self.state,
            peer_agent_id="",
            negotiated_version=self.config.version,
            shared_capabilities=list(self._peer_capabilities),
        )

    def fail(self, code: ErrorCode, reason: str) -> HandshakeResult:
        """Mark the handshake as failed."""
        self.state = HandshakeState.FAILED
        return HandshakeResult(
            success=False,
            state=self.state,
            peer_agent_id="",
            negotiated_version=ProtocolVersion.V1,
            error_code=code.value,
            error_message=reason,
        )

    def is_exhausted(self) -> bool:
        """Check if retry attempts have been exhausted."""
        return self._retry_count >= self.config.max_retries


# ---------------------------------------------------------------------------
# Heartbeat Protocol
# ---------------------------------------------------------------------------

class HeartbeatState(enum.Enum):
    """Health state based on heartbeat analysis."""
    ALIVE = "ALIVE"
    DEGRADED = "DEGRADED"
    SUSPECT = "SUSPECT"
    DEAD = "DEAD"


@dataclass
class HeartbeatRecord:
    """Tracks heartbeat state for a single agent."""
    agent_id: str
    state: HeartbeatState = HeartbeatState.ALIVE
    last_heartbeat: Optional[float] = None
    missed_count: int = 0
    consecutive_misses: int = 0

    def update(self, timestamp: Optional[float] = None) -> None:
        """Record a received heartbeat."""
        self.last_heartbeat = timestamp or time.time()
        self.missed_count = 0
        self.consecutive_misses = 0
        self.state = HeartbeatState.ALIVE

    def check_health(self, now: Optional[float] = None) -> HeartbeatState:
        """Evaluate health based on time since last heartbeat."""
        now = now or time.time()
        if self.last_heartbeat is None:
            self.state = HeartbeatState.DEAD
            return self.state

        elapsed = now - self.last_heartbeat

        if elapsed < CONSTANTS.HEARTBEAT_DEGRADED_TIMEOUT:
            self.state = HeartbeatState.ALIVE
        elif elapsed < CONSTANTS.HEARTBEAT_TIMEOUT:
            self.state = HeartbeatState.DEGRADED
        elif elapsed < CONSTANTS.HEARTBEAT_TIMEOUT * 2:
            self.state = HeartbeatState.SUSPECT
        else:
            self.state = HeartbeatState.DEAD

        return self.state

    def record_miss(self) -> None:
        """Record a missed heartbeat."""
        self.missed_count += 1
        self.consecutive_misses += 1


class HeartbeatProtocol:
    """
    Manages heartbeat monitoring for fleet agents.

    Agents send periodic heartbeats. The monitor tracks state transitions
    from ALIVE → DEGRADED → SUSPECT → DEAD.
    """

    def __init__(self, interval: float = CONSTANTS.HEARTBEAT_INTERVAL) -> None:
        self.interval = interval
        self._records: Dict[str, HeartbeatRecord] = {}

    def register(self, agent_id: str) -> None:
        """Register an agent for heartbeat monitoring."""
        if agent_id not in self._records:
            self._records[agent_id] = HeartbeatRecord(agent_id=agent_id)

    def unregister(self, agent_id: str) -> None:
        """Stop monitoring an agent."""
        self._records.pop(agent_id, None)

    def record_heartbeat(self, agent_id: str, timestamp: Optional[float] = None) -> None:
        """Record a heartbeat from an agent."""
        self.register(agent_id)
        self._records[agent_id].update(timestamp)

    def get_state(self, agent_id: str) -> HeartbeatState:
        """Get the current heartbeat state for an agent."""
        record = self._records.get(agent_id)
        if record is None:
            return HeartbeatState.DEAD
        return record.check_health()

    def get_all_states(self) -> Dict[str, HeartbeatState]:
        """Get heartbeat states for all tracked agents."""
        return {aid: rec.check_health() for aid, rec in self._records.items()}

    def get_alive_agents(self) -> List[str]:
        """Return list of agents currently alive."""
        return [
            aid for aid, state in self.get_all_states().items()
            if state == HeartbeatState.ALIVE
        ]

    def build_heartbeat(self, sender_id: str) -> FleetMessage:
        """Build a heartbeat status message."""
        return (
            MessageBuilder()
            .sender(sender_id)
            .recipient("fleet:broadcast")
            .type(MessageType.STATUS)
            .payload({
                "action": "HEARTBEAT",
                "timestamp": time.time(),
            })
            .priority(MessagePriority.LOW)
            .ttl(10)
            .build()
        )


# ---------------------------------------------------------------------------
# Discovery Protocol
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryBeacon:
    """A discovery broadcast beacon."""
    agent_id: str
    capabilities: List[str]
    version: str
    timestamp: float = field(default_factory=time.time)
    hop_count: int = 0
    max_hops: int = CONSTANTS.DISCOVERY_TTL


class DiscoveryProtocol:
    """
    Fleet discovery broadcast protocol.

    Agents periodically broadcast discovery beacons. Other agents
    receive these beacons and learn about available services.
    """

    def __init__(self, agent_id: str, capabilities: Optional[List[str]] = None) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities or []
        self._discovered: Dict[str, DiscoveryBeacon] = {}

    def build_beacon(self) -> FleetMessage:
        """Build a discovery beacon message."""
        return (
            MessageBuilder()
            .sender(self.agent_id)
            .recipient("fleet:discovery")
            .type(MessageType.EVENT)
            .payload({
                "action": "DISCOVERY",
                "agent_id": self.agent_id,
                "capabilities": self.capabilities,
                "version": ProtocolVersion.latest().value,
                "timestamp": time.time(),
                "hop_count": 0,
            })
            .priority(MessagePriority.LOW)
            .ttl(CONSTANTS.DISCOVERY_TTL * 2)
            .build()
        )

    def process_beacon(self, message: FleetMessage) -> Optional[DiscoveryBeacon]:
        """
        Process an incoming discovery beacon.

        Returns:
            DiscoveryBeacon if the beacon is new and valid, None otherwise.
        """
        payload = message.body.payload
        if payload.get("action") != "DISCOVERY":
            return None

        agent_id = payload.get("agent_id", "")
        if agent_id == self.agent_id:
            return None  # Ignore own beacons

        hop_count = payload.get("hop_count", 0)
        if hop_count >= CONSTANTS.DISCOVERY_TTL:
            return None  # TTL exceeded

        beacon = DiscoveryBeacon(
            agent_id=agent_id,
            capabilities=payload.get("capabilities", []),
            version=payload.get("version", "1.0"),
            timestamp=payload.get("timestamp", time.time()),
            hop_count=hop_count,
        )

        # Update if newer or same agent
        existing = self._discovered.get(agent_id)
        if existing is None or beacon.timestamp > existing.timestamp:
            self._discovered[agent_id] = beacon
            return beacon

        return None

    def forward_beacon(self, message: FleetMessage) -> Optional[FleetMessage]:
        """
        Forward a discovery beacon (increment hop count).

        Returns a new beacon message or None if max hops reached.
        """
        payload = message.body.payload
        hop_count = payload.get("hop_count", 0) + 1

        if hop_count >= CONSTANTS.DISCOVERY_TTL:
            return None

        forward_payload = dict(payload)
        forward_payload["hop_count"] = hop_count

        return (
            MessageBuilder()
            .sender(self.agent_id)
            .recipient("fleet:discovery")
            .type(MessageType.EVENT)
            .payload(forward_payload)
            .priority(MessagePriority.LOW)
            .ttl(CONSTANTS.DISCOVERY_TTL * 2)
            .build()
        )

    def get_discovered_agents(self) -> List[DiscoveryBeacon]:
        """Return all discovered agent beacons."""
        return list(self._discovered.values())

    def find_by_capability(self, capability: str) -> List[DiscoveryBeacon]:
        """Find all agents that provide a specific capability."""
        return [
            b for b in self._discovered.values()
            if capability in b.capabilities
        ]


# ---------------------------------------------------------------------------
# Capability Negotiation
# ---------------------------------------------------------------------------

@dataclass
class CapabilitySet:
    """Represents a set of capabilities offered by an agent."""
    agent_id: str
    capabilities: Set[str] = field(default_factory=set)
    version: str = ProtocolVersion.latest().value

    def supports(self, capability: str) -> bool:
        """Check if a specific capability is supported."""
        return capability in self.capabilities

    def intersect(self, other: CapabilitySet) -> Set[str]:
        """Return shared capabilities with another agent."""
        return self.capabilities & other.capabilities


class CapabilityNegotiator:
    """
    Negotiates shared capabilities between agents.

    During handshake, both agents exchange capability sets. This class
    determines what capabilities are mutually available.
    """

    def __init__(self, local_capabilities: Optional[List[str]] = None) -> None:
        self._local = CapabilitySet(agent_id="local", capabilities=set(local_capabilities or []))
        self._remote: Dict[str, CapabilitySet] = {}

    def add_remote_capabilities(self, agent_id: str, capabilities: List[str]) -> None:
        """Register capabilities from a remote agent."""
        self._remote[agent_id] = CapabilitySet(
            agent_id=agent_id, capabilities=set(capabilities)
        )

    def negotiate(self, agent_id: str) -> Set[str]:
        """Return shared capabilities with a specific agent."""
        remote = self._remote.get(agent_id)
        if remote is None:
            return set()
        return self._local.intersect(remote)

    def negotiate_all(self) -> Dict[str, Set[str]]:
        """Return shared capabilities with all known agents."""
        return {aid: self._local.intersect(cs) for aid, cs in self._remote.items()}

    def build_capability_exchange(self, recipient: str) -> FleetMessage:
        """Build a capability exchange message."""
        return (
            MessageBuilder()
            .sender(self._local.agent_id)
            .recipient(recipient)
            .type(MessageType.QUERY)
            .payload({
                "action": "CAPABILITY_EXCHANGE",
                "capabilities": list(self._local.capabilities),
                "version": self._local.version,
            })
            .requires_ack(True)
            .build()
        )

    def process_capability_exchange(self, message: FleetMessage) -> Set[str]:
        """
        Process a capability exchange message from another agent.

        Returns:
            Set of shared capabilities.
        """
        payload = message.body.payload
        if payload.get("action") != "CAPABILITY_EXCHANGE":
            return set()

        peer_caps = payload.get("capabilities", [])
        self.add_remote_capabilities(message.header.sender, peer_caps)
        return self.negotiate(message.header.sender)


# ---------------------------------------------------------------------------
# Fleet Protocol (orchestrator)
# ---------------------------------------------------------------------------

@dataclass
class RecoveryAction:
    """A recovery action to take after an error."""
    error_code: ErrorCode
    action: str  # "retry", "reset", "escalate", "ignore"
    delay: float = 0.0  # seconds to wait before retry
    max_attempts: int = 3


RECOVERY_PROCEDURES: Dict[ErrorCode, RecoveryAction] = {
    ErrorCode.HANDSHAKE_TIMEOUT: RecoveryAction(
        ErrorCode.HANDSHAKE_TIMEOUT, "retry", delay=2.0, max_attempts=3
    ),
    ErrorCode.HANDSHAKE_VERSION_MISMATCH: RecoveryAction(
        ErrorCode.HANDSHAKE_VERSION_MISMATCH, "reset", delay=1.0, max_attempts=1
    ),
    ErrorCode.HEARTBEAT_MISSED: RecoveryAction(
        ErrorCode.HEARTBEAT_MISSED, "ignore", delay=0.0, max_attempts=0
    ),
    ErrorCode.HEARTBEAT_DEGRADED: RecoveryAction(
        ErrorCode.HEARTBEAT_DEGRADED, "ignore", delay=0.0, max_attempts=0
    ),
    ErrorCode.HEARTBEAT_DEAD: RecoveryAction(
        ErrorCode.HEARTBEAT_DEAD, "escalate", delay=5.0, max_attempts=1
    ),
    ErrorCode.CAPABILITY_NEGOTIATION_FAILED: RecoveryAction(
        ErrorCode.CAPABILITY_NEGOTIATION_FAILED, "retry", delay=1.0, max_attempts=2
    ),
    ErrorCode.REGISTRY_SYNC_FAILED: RecoveryAction(
        ErrorCode.REGISTRY_SYNC_FAILED, "retry", delay=5.0, max_attempts=5
    ),
    ErrorCode.SECURITY_SIGNATURE_INVALID: RecoveryAction(
        ErrorCode.SECURITY_SIGNATURE_INVALID, "escalate", delay=0.0, max_attempts=0
    ),
}


def get_recovery_action(code: ErrorCode) -> RecoveryAction:
    """Get the recommended recovery action for an error code."""
    return RECOVERY_PROCEDURES.get(
        code,
        RecoveryAction(code, "ignore", delay=0.0, max_attempts=0),
    )


class FleetProtocol:
    """
    Main orchestrator for the fleet wire protocol.

    Combines handshake, heartbeat, discovery, and capability negotiation
    into a unified interface.
    """

    def __init__(
        self,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
        version: ProtocolVersion = ProtocolVersion.latest(),
    ) -> None:
        self.agent_id = agent_id
        self.version = version
        self.capabilities = capabilities or []

        self.handshake = HandshakeProtocol(
            agent_id,
            HandshakeConfig(version=version, capabilities=capabilities),
        )
        self.heartbeat = HeartbeatProtocol()
        self.discovery = DiscoveryProtocol(agent_id, capabilities)
        self.capability_negotiator = CapabilityNegotiator(capabilities)

    def init_connection(self, recipient: str) -> FleetMessage:
        """Build an initial HELLO message to start a connection."""
        return self.handshake.build_hello(recipient)

    def accept_connection(self, message: FleetMessage) -> Tuple[HandshakeResult, Optional[FleetMessage]]:
        """
        Process an incoming connection request.

        Returns:
            Tuple of (handshake result, optional reply message).
        """
        result = self.handshake.process_hello(message)
        reply = self.handshake.build_hello_ack(message.header.sender)
        self.heartbeat.register(message.header.sender)
        return (result, reply)

    def handle_heartbeat(self, message: FleetMessage) -> None:
        """Process an incoming heartbeat."""
        self.heartbeat.record_heartbeat(message.header.sender)

    def handle_discovery(self, message: FleetMessage) -> Optional[FleetMessage]:
        """Process and optionally forward a discovery beacon."""
        beacon = self.discovery.process_beacon(message)
        if beacon is None:
            return None
        return self.discovery.forward_beacon(message)

    def get_fleet_status(self) -> Dict[str, Any]:
        """Get a comprehensive status of the fleet protocol state."""
        return {
            "agent_id": self.agent_id,
            "version": self.version.value,
            "handshake_state": self.handshake.state.value,
            "heartbeat_states": {
                aid: state.value for aid, state in self.heartbeat.get_all_states().items()
            },
            "discovered_agents": len(self.discovery.get_discovered_agents()),
            "capability_negotiations": {
                aid: list(caps) for aid, caps in self.capability_negotiator.negotiate_all().items()
            },
        }
