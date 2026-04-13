"""
Fleet Protocol — shared library for inter-agent communication within the SuperInstance.

This package provides the common language, wire format, and coordination protocol
that ALL standalone agents use to communicate within the Fleet.

Modules:
    messages   — FleetMessage format, serialization, validation, builder
    protocol   — Wire protocol versioning, handshake, heartbeat, discovery
    registry   — Agent/Service/Health registries, sync, anti-entropy
    bottle     — Message-in-a-Bottle async coordination protocol
    security   — Identity, signing, session, HMAC, secret redaction
    cli        — Command-line interface for fleet operations
"""

__version__ = "0.1.0"
__protocol_version__ = "2.0"

from fleet_protocol.messages import (
    FleetMessage,
    MessageType,
    MessageBuilder,
    MessageValidator,
)
from fleet_protocol.protocol import FleetProtocol, ProtocolVersion, HandshakeState
from fleet_protocol.registry import (
    FleetRegistry,
    AgentRecord,
    ServiceRecord,
    HealthStatus,
    HealthRecord,
)
from fleet_protocol.bottle import Bottle, BottleRouter, BottleInbox, BottlePostmark
from fleet_protocol.security import (
    AgentIdentity,
    MessageAuthenticator,
    SessionManager,
    SecretRedactor,
)

__all__ = [
    "__version__",
    "__protocol_version__",
    # messages
    "FleetMessage",
    "MessageType",
    "MessageBuilder",
    "MessageValidator",
    # protocol
    "FleetProtocol",
    "ProtocolVersion",
    "HandshakeState",
    # registry
    "FleetRegistry",
    "AgentRecord",
    "ServiceRecord",
    "HealthStatus",
    "HealthRecord",
    # bottle
    "Bottle",
    "BottleRouter",
    "BottleInbox",
    "BottlePostmark",
    # security
    "AgentIdentity",
    "MessageAuthenticator",
    "SessionManager",
    "SecretRedactor",
]
