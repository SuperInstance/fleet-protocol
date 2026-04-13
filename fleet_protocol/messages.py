"""
Fleet Message Format — standard message format for all fleet communication.

Defines the FleetMessage dataclass, message types, serialization/deserialization,
message validation, sanitization, and a builder pattern for easy construction.

Wire format supports JSON (default) and a compact binary format using struct+msgpack-like
encoding built entirely on stdlib.
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Message Types
# ---------------------------------------------------------------------------

class MessageType(str, Enum):
    """Standard message types for fleet communication."""
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    EVENT = "EVENT"
    COMMAND = "COMMAND"
    QUERY = "QUERY"
    STATUS = "STATUS"
    ERROR = "ERROR"


class MessageEncoding(str, Enum):
    """Supported serialization encodings."""
    JSON = "json"
    BINARY = "binary"


class MessagePriority(int, Enum):
    """Message priority levels."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class MessageHeader:
    """Header metadata for a fleet message."""
    sender: str
    recipient: str
    message_type: str
    timestamp: float
    message_id: str
    in_reply_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert header to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MessageHeader:
        """Create header from dictionary."""
        return cls(**data)


@dataclass
class MessageBody:
    """Body payload of a fleet message."""
    payload: Dict[str, Any] = field(default_factory=dict)
    encoding: str = MessageEncoding.JSON.value

    def to_dict(self) -> Dict[str, Any]:
        """Convert body to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MessageBody:
        """Create body from dictionary."""
        return cls(**data)


@dataclass
class MessageMetadata:
    """Metadata for message routing and delivery."""
    priority: int = MessagePriority.NORMAL.value
    ttl: int = 300  # seconds
    requires_ack: bool = False
    capabilities_needed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MessageMetadata:
        """Create metadata from dictionary."""
        return cls(**data)


@dataclass
class MessageSecurity:
    """Security information for a fleet message."""
    signature: Optional[str] = None
    encrypted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert security to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MessageSecurity:
        """Create security from dictionary."""
        return cls(**data)


@dataclass
class FleetMessage:
    """
    Standard message format for all fleet communication.

    This is the core data structure that every agent uses to communicate
    within the Fleet. Messages consist of a header, body, metadata, and
    security section.

    Attributes:
        header: Routing and identification metadata.
        body: The actual payload data and its encoding.
        metadata: Delivery hints and requirements.
        security: Signing and encryption information.
    """
    header: MessageHeader
    body: MessageBody = field(default_factory=MessageBody)
    metadata: MessageMetadata = field(default_factory=MessageMetadata)
    security: MessageSecurity = field(default_factory=MessageSecurity)

    # -- Serialization -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the message to a plain dictionary."""
        return {
            "header": self.header.to_dict(),
            "body": self.body.to_dict(),
            "metadata": self.metadata.to_dict(),
            "security": self.security.to_dict(),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize the message to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_binary(self) -> bytes:
        """
        Serialize to a compact binary format.

        Layout:
            [4 bytes] total frame length
            [2 bytes] protocol version (0x0002)
            [1 byte]  message type (enum ordinal)
            [16 bytes] message_id (UUID bytes)
            [16 bytes] sender_id_hash (first 16 of sha256)
            [16 bytes] recipient_id_hash (first 16 of sha256)
            [8 bytes]  timestamp (double)
            [4 bytes]  payload length
            [N bytes]  payload (JSON-encoded)
        """
        payload_bytes = json.dumps(self.body.payload, default=str).encode("utf-8")
        sender_hash = hashlib.sha256(self.header.sender.encode()).digest()[:16]
        recipient_hash = hashlib.sha256(self.header.recipient.encode()).digest()[:16]

        msg_id_bytes = uuid.UUID(self.header.message_id).bytes

        try:
            type_ordinal = MessageType(self.header.message_type).value
            type_byte = {
                "REQUEST": 0, "RESPONSE": 1, "EVENT": 2,
                "COMMAND": 3, "QUERY": 4, "STATUS": 5, "ERROR": 6,
            }.get(type_ordinal, 0)
        except ValueError:
            type_byte = 0

        header_len = 2 + 1 + 16 + 16 + 16 + 8
        frame_len = header_len + 4 + len(payload_bytes)

        parts = [
            struct.pack("!I", frame_len),
            struct.pack("!H", 2),  # protocol version
            struct.pack("!B", type_byte),
            msg_id_bytes,
            sender_hash,
            recipient_hash,
            struct.pack("!d", self.header.timestamp),
            struct.pack("!I", len(payload_bytes)),
            payload_bytes,
        ]
        return b"".join(parts)

    # -- Deserialization -----------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FleetMessage:
        """Deserialize from a plain dictionary."""
        return cls(
            header=MessageHeader.from_dict(data["header"]),
            body=MessageBody.from_dict(data.get("body", {})),
            metadata=MessageMetadata.from_dict(data.get("metadata", {})),
            security=MessageSecurity.from_dict(data.get("security", {})),
        )

    @classmethod
    def from_json(cls, raw: str) -> FleetMessage:
        """Deserialize from a JSON string."""
        return cls.from_dict(json.loads(raw))

    @classmethod
    def from_binary(cls, data: bytes) -> FleetMessage:
        """Deserialize from the compact binary format."""
        offset = 0

        frame_len = struct.unpack_from("!I", data, offset)[0]
        offset += 4

        _proto_ver = struct.unpack_from("!H", data, offset)[0]
        offset += 2

        type_byte = struct.unpack_from("!B", data, offset)[0]
        offset += 1

        msg_id_bytes = data[offset:offset + 16]
        offset += 16
        message_id = str(uuid.UUID(bytes=msg_id_bytes))

        sender_hash = data[offset:offset + 16]
        offset += 16

        recipient_hash = data[offset:offset + 16]
        offset += 16

        timestamp = struct.unpack_from("!d", data, offset)[0]
        offset += 8

        payload_len = struct.unpack_from("!I", data, offset)[0]
        offset += 4

        payload_bytes = data[offset:offset + payload_len]
        offset += payload_len

        type_map = {
            0: MessageType.REQUEST, 1: MessageType.RESPONSE,
            2: MessageType.EVENT, 3: MessageType.COMMAND,
            4: MessageType.QUERY, 5: MessageType.STATUS,
            6: MessageType.ERROR,
        }
        message_type = type_map.get(type_byte, MessageType.REQUEST)

        # Sender/recipient hashes are irreversible; reconstruct placeholders
        sender = f"agent:{sender_hash.hex()[:12]}"
        recipient = f"agent:{recipient_hash.hex()[:12]}"

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"raw": payload_bytes.hex()}

        return cls(
            header=MessageHeader(
                sender=sender,
                recipient=recipient,
                message_type=message_type.value,
                timestamp=timestamp,
                message_id=message_id,
            ),
            body=MessageBody(payload=payload, encoding=MessageEncoding.BINARY.value),
        )

    # -- Utility -------------------------------------------------------------

    def copy(self) -> FleetMessage:
        """Return a deep copy of this message."""
        return copy.deepcopy(self)

    def is_expired(self) -> bool:
        """Check if the message has exceeded its TTL."""
        elapsed = time.time() - self.header.timestamp
        return elapsed > self.metadata.ttl

    def __repr__(self) -> str:
        return (
            f"FleetMessage(id={self.header.message_id[:8]}, "
            f"type={self.header.message_type}, "
            f"from={self.header.sender}, "
            f"to={self.header.recipient})"
        )


# ---------------------------------------------------------------------------
# Message Validator
# ---------------------------------------------------------------------------

class MessageValidator:
    """Validates and sanitizes fleet messages."""

    REQUIRED_HEADER_FIELDS = {"sender", "recipient", "message_type", "timestamp", "message_id"}
    MAX_PAYLOAD_SIZE = 1_048_576  # 1 MB
    MAX_MESSAGE_ID_LENGTH = 64
    MAX_AGENT_NAME_LENGTH = 128
    ALLOWED_MESSAGE_TYPES = {mt.value for mt in MessageType}

    @classmethod
    def validate(cls, message: FleetMessage) -> Tuple[bool, List[str]]:
        """
        Validate a FleetMessage.

        Returns:
            Tuple of (is_valid, list_of_errors).
        """
        errors: List[str] = []

        # Header validation
        header = message.header
        if not header.sender or len(header.sender) > cls.MAX_AGENT_NAME_LENGTH:
            errors.append(f"Invalid sender: '{header.sender}'")
        if not header.recipient or len(header.recipient) > cls.MAX_AGENT_NAME_LENGTH:
            errors.append(f"Invalid recipient: '{header.recipient}'")
        if header.message_type not in cls.ALLOWED_MESSAGE_TYPES:
            errors.append(f"Unknown message type: '{header.message_type}'")
        if header.timestamp <= 0:
            errors.append(f"Invalid timestamp: {header.timestamp}")
        if not header.message_id or len(header.message_id) > cls.MAX_MESSAGE_ID_LENGTH:
            errors.append(f"Invalid message_id: '{header.message_id}'")

        # Payload size check
        payload_str = json.dumps(message.body.payload, default=str)
        if len(payload_str.encode("utf-8")) > cls.MAX_PAYLOAD_SIZE:
            errors.append("Payload exceeds maximum size (1 MB)")

        # TTL sanity
        if message.metadata.ttl < 0:
            errors.append("TTL cannot be negative")

        return (len(errors) == 0, errors)

    @classmethod
    def sanitize(cls, message: FleetMessage) -> FleetMessage:
        """
        Return a sanitized copy of the message.
        Strips potentially dangerous content from payload.
        """
        sanitized = message.copy()
        payload = sanitized.body.payload

        # Remove any keys starting with __ (potential dunder exploit)
        dangerous_keys = [k for k in payload if isinstance(k, str) and k.startswith("__")]
        for key in dangerous_keys:
            del payload[key]

        # Ensure encoding is valid
        if sanitized.body.encoding not in {e.value for e in MessageEncoding}:
            sanitized.body.encoding = MessageEncoding.JSON.value

        # Clamp priority
        try:
            prio = int(sanitized.metadata.priority)
            if not (0 <= prio <= 3):
                sanitized.metadata.priority = MessagePriority.NORMAL.value
        except (ValueError, TypeError):
            sanitized.metadata.priority = MessagePriority.NORMAL.value

        return sanitized


# ---------------------------------------------------------------------------
# Message Builder
# ---------------------------------------------------------------------------

class MessageBuilder:
    """
    Builder pattern for constructing FleetMessage instances.

    Usage:
        msg = (MessageBuilder()
               .sender("agent-alpha")
               .recipient("agent-beta")
               .type(MessageType.REQUEST)
               .payload({"action": "scan"})
               .priority(MessagePriority.HIGH)
               .requires_ack(True)
               .build())
    """

    def __init__(self) -> None:
        self._header: Dict[str, Any] = {}
        self._body: Dict[str, Any] = {"payload": {}, "encoding": MessageEncoding.JSON.value}
        self._metadata: Dict[str, Any] = {}
        self._security: Dict[str, Any] = {}

    def sender(self, agent_id: str) -> MessageBuilder:
        self._header["sender"] = agent_id
        return self

    def recipient(self, agent_id: str) -> MessageBuilder:
        self._header["recipient"] = agent_id
        return self

    def type(self, message_type: MessageType) -> MessageBuilder:
        self._header["message_type"] = message_type.value
        return self

    def in_reply_to(self, message_id: str) -> MessageBuilder:
        self._header["in_reply_to"] = message_id
        return self

    def payload(self, data: Dict[str, Any]) -> MessageBuilder:
        self._body["payload"] = data
        return self

    def encoding(self, enc: MessageEncoding) -> MessageBuilder:
        self._body["encoding"] = enc.value
        return self

    def priority(self, p: MessagePriority) -> MessageBuilder:
        self._metadata["priority"] = p.value
        return self

    def ttl(self, seconds: int) -> MessageBuilder:
        self._metadata["ttl"] = seconds
        return self

    def requires_ack(self, flag: bool = True) -> MessageBuilder:
        self._metadata["requires_ack"] = flag
        return self

    def capabilities_needed(self, caps: List[str]) -> MessageBuilder:
        self._metadata["capabilities_needed"] = caps
        return self

    def signature(self, sig: str) -> MessageBuilder:
        self._security["signature"] = sig
        return self

    def encrypted(self, flag: bool = True) -> MessageBuilder:
        self._security["encrypted"] = flag
        return self

    def build(self) -> FleetMessage:
        """Construct and return the FleetMessage."""
        # Fill defaults
        self._header.setdefault("message_id", str(uuid.uuid4()))
        self._header.setdefault("timestamp", time.time())

        if "message_type" not in self._header:
            raise ValueError("Message type is required. Call .type() before .build().")
        if "sender" not in self._header:
            raise ValueError("Sender is required. Call .sender() before .build().")
        if "recipient" not in self._header:
            raise ValueError("Recipient is required. Call .recipient() before .build().")

        return FleetMessage(
            header=MessageHeader(**self._header),
            body=MessageBody(**self._body),
            metadata=MessageMetadata(**self._metadata),
            security=MessageSecurity(**self._security),
        )
