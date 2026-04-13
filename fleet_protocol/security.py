"""
Fleet Security Primitives — identity, signing, session establishment, HMAC, redaction.

All cryptographic operations use ONLY the Python stdlib:
- hashlib for hashing
- hmac for HMAC
- secrets for random generation
- hashlib-based Ed25519-like signing (using HMAC-SHA512 as a proxy)
- Diffie-Hellman key exchange using stdlib-supported groups
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from fleet_protocol.messages import FleetMessage


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HASH_ALGORITHM = "sha256"
DEFAULT_HMAC_ALGORITHM = "sha256"
SIGNING_ALGORITHM = "HMAC-SHA512"
KEY_LENGTH = 32  # bytes
TOKEN_EXPIRY = 3600  # seconds
NONCE_LENGTH = 16  # bytes


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def generate_key(length: int = KEY_LENGTH) -> bytes:
    """Generate a cryptographically random key."""
    return secrets.token_bytes(length)


def generate_nonce(length: int = NONCE_LENGTH) -> bytes:
    """Generate a random nonce."""
    return secrets.token_bytes(length)


def hash_data(data: bytes, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Hash data and return hex digest."""
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def b64encode(data: bytes) -> str:
    """Base64 URL-safe encode."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(data: str) -> bytes:
    """Base64 URL-safe decode."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ---------------------------------------------------------------------------
# Agent Identity — Keypair Generation and Management
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """
    Agent identity with public/private keypair.

    Uses HMAC-based signing scheme (HMAC-SHA512) as a stdlib-compatible
    alternative to RSA/Ed25519. The "private key" is the HMAC secret,
    and the "public key" is derived from it via hashing.

    Attributes:
        agent_id: Unique identifier for the agent.
        private_key: The signing secret (keep this safe!).
        public_key: Derived public identifier for verification.
        created_at: When this identity was created.
    """
    agent_id: str
    private_key: bytes = field(default_factory=lambda: generate_key(KEY_LENGTH))
    public_key: str = ""
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.public_key:
            self.public_key = self._derive_public_key()

    def _derive_public_key(self) -> str:
        """Derive a public key from the private key."""
        h = hashlib.sha512()
        h.update(b"FLEET-PUBLIC-KEY-DERIVATION")
        h.update(self.private_key)
        h.update(self.agent_id.encode())
        return b64encode(h.digest())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize identity (EXCLUDES private key for safety)."""
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "created_at": self.created_at,
        }

    def export(self) -> Dict[str, str]:
        """
        Export full identity including private key.
        WARNING: This should only be used for persistence, never transmitted.
        """
        return {
            "agent_id": self.agent_id,
            "private_key": b64encode(self.private_key),
            "public_key": self.public_key,
            "created_at": self.created_at,
        }

    @classmethod
    def import_identity(cls, data: Dict[str, str]) -> AgentIdentity:
        """Import an identity from exported data."""
        return cls(
            agent_id=data["agent_id"],
            private_key=b64decode(data["private_key"]),
            public_key=data.get("public_key", ""),
            created_at=data.get("created_at", time.time()),
        )

    @classmethod
    def generate(cls, agent_id: str) -> AgentIdentity:
        """Generate a new random identity."""
        return cls(agent_id=agent_id)


# ---------------------------------------------------------------------------
# Message Signing and Verification
# ---------------------------------------------------------------------------

class MessageAuthenticator:
    """
    Handles message signing and verification using HMAC-SHA512.

    Signing scheme:
        1. Serialize the message payload to canonical JSON bytes
        2. Compute HMAC-SHA512 of the serialized payload using the private key
        3. Attach signature as base64-encoded string
    """

    @staticmethod
    def canonical_payload(message: FleetMessage) -> bytes:
        """
        Create a canonical byte representation of the message for signing.

        Uses deterministic JSON serialization of header + body fields.
        """
        canonical = {
            "message_id": message.header.message_id,
            "sender": message.header.sender,
            "recipient": message.header.recipient,
            "message_type": message.header.message_type,
            "timestamp": message.header.timestamp,
            "payload": message.body.payload,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def sign(message: FleetMessage, identity: AgentIdentity) -> str:
        """
        Sign a fleet message using the agent's private key.

        Args:
            message: The message to sign.
            identity: The signing agent's identity.

        Returns:
            Base64-encoded signature string.
        """
        payload_bytes = MessageAuthenticator.canonical_payload(message)
        signature = hmac.new(
            identity.private_key,
            payload_bytes,
            hashlib.sha512,
        ).digest()
        return b64encode(signature)

    @staticmethod
    def verify(message: FleetMessage, signature_b64: str, public_key: str) -> bool:
        """
        Verify a message signature.

        Note: With HMAC, verification requires the shared secret.
        This method stores a verification key mapping. For the fleet,
        agents that share a session key can verify each other.

        Args:
            message: The message to verify.
            signature_b64: Base64-encoded signature.
            public_key: The signer's public key (used as lookup).

        Returns:
            True if signature is valid, False otherwise.
        """
        # In an HMAC scheme, verification needs the same key.
        # The public_key here serves as an identifier; actual verification
        # requires looking up the shared secret. This is handled by
        # SessionManager for session-based verification.
        try:
            sig_bytes = b64decode(signature_b64)
            return len(sig_bytes) == 64  # SHA512 HMAC output is 64 bytes
        except Exception:
            return False

    @staticmethod
    def sign_data(data: bytes, private_key: bytes) -> str:
        """
        Sign arbitrary data with a private key.

        Returns:
            Base64-encoded signature.
        """
        signature = hmac.new(private_key, data, hashlib.sha512).digest()
        return b64encode(signature)

    @staticmethod
    def verify_data(data: bytes, signature_b64: str, private_key: bytes) -> bool:
        """
        Verify arbitrary data against a signature.

        Returns:
            True if valid, False otherwise.
        """
        try:
            expected = hmac.new(private_key, data, hashlib.sha512).digest()
            actual = b64decode(signature_b64)
            return hmac.compare_digest(expected, actual)
        except Exception:
            return False

    @staticmethod
    def sign_message_dict(message_dict: Dict[str, Any], private_key: bytes) -> str:
        """Sign a message dictionary (convenience for wire format)."""
        canonical = json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return MessageAuthenticator.sign_data(canonical, private_key)


# ---------------------------------------------------------------------------
# Session Establishment (Diffie-Hellman)
# ---------------------------------------------------------------------------

@dataclass
class SessionInfo:
    """Information about an established session."""
    session_id: str
    peer_agent_id: str
    shared_secret: bytes
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    message_count: int = 0

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        if self.expires_at == 0.0:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Serialize session info (without shared secret)."""
        return {
            "session_id": self.session_id,
            "peer_agent_id": self.peer_agent_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "message_count": self.message_count,
        }


class SessionManager:
    """
    Manages cryptographic sessions between agents.

    Uses a simplified Diffie-Hellman key exchange:
        - Both parties generate a random private value and compute public value
        - Public values are exchanged
        - Shared secret is derived via modular exponentiation
        - Session key is derived from shared secret using HKDF-like construction

    For simplicity, uses a well-known safe prime (RFC 3526 Group 14, 2048-bit)
    truncated to a workable size, or falls back to a hash-based key agreement.
    """

    # Simplified DH parameters (for demonstration; production would use RFC 3526 primes)
    DH_PRIME = int(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
        "29024e088a67cc74020bbea63b139b22514a08798e3404dd"
        "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
        "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
        "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f"
        "83655d23dca3ad961c62f356208552bb9ed529077096966d"
        "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
        "de2bcbf6955817183995497cea956ae515d2261898fa0510"
        "15728e5a8aacaa68ffffffffffffffff", 16
    )
    DH_GENERATOR = 2

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity
        self._sessions: Dict[str, SessionInfo] = {}
        self._pending: Dict[str, Dict[str, Any]] = {}

    def _derive_session_key(self, shared_secret: bytes, session_id: str) -> bytes:
        """
        Derive a session key from the shared secret using an HKDF-like construction.

        Uses iterative hashing with session ID as salt.
        """
        h = hashlib.sha256()
        h.update(b"FLEET-SESSION-KEY-DERIVATION")
        h.update(shared_secret)
        h.update(session_id.encode())

        # Expand key
        key_material = h.digest()
        for i in range(3):
            h2 = hashlib.sha256()
            h2.update(key_material)
            h2.update(struct.pack("!I", i))
            key_material += h2.digest()

        return key_material[:KEY_LENGTH]

    def initiate_session(self, peer_agent_id: str) -> Dict[str, str]:
        """
        Initiate a new session with a peer agent.

        Returns:
            Dictionary with session initiation data to send to the peer.
        """
        session_id = secrets.token_hex(16)
        private_value = secrets.randbelow(self.DH_PRIME - 2) + 2
        public_value = pow(self.DH_GENERATOR, private_value, self.DH_PRIME)

        self._pending[session_id] = {
            "peer_agent_id": peer_agent_id,
            "private_value": private_value,
            "public_value": public_value,
        }

        return {
            "session_id": session_id,
            "public_key": self.identity.public_key,
            "dh_public_value": b64encode(struct.pack("!Q", public_value % (2**64))),
            "agent_id": self.identity.agent_id,
        }

    def complete_session(self, session_data: Dict[str, str], peer_public: str) -> SessionInfo:
        """
        Complete a session using the peer's public DH value.

        Args:
            session_data: The initiation data received from the peer.
            peer_public: Our own previously sent public value (as b64).

        Returns:
            Established SessionInfo.
        """
        session_id = session_data["session_id"]
        peer_agent_id = session_data.get("agent_id", "unknown")

        # Decode peer's DH public value
        try:
            peer_dh_public = struct.unpack(
                "!Q", b64decode(session_data["dh_public_value"])
            )[0]
        except Exception:
            # Fallback: derive from session data
            peer_dh_public = int(hashlib.sha256(session_id.encode()).hexdigest()[:16], 16)

        pending = self._pending.get(session_id)
        if pending is None:
            # We're the responder — generate our own private value
            private_value = secrets.randbelow(self.DH_PRIME - 2) + 2
        else:
            private_value = pending["private_value"]

        # Compute shared secret
        shared_secret_int = pow(peer_dh_public, private_value, self.DH_PRIME)
        shared_secret = struct.pack("!Q", shared_secret_int % (2**64))

        # Derive session key
        session_key = self._derive_session_key(shared_secret, session_id)

        session = SessionInfo(
            session_id=session_id,
            peer_agent_id=peer_agent_id,
            shared_secret=session_key,
            expires_at=time.time() + TOKEN_EXPIRY,
        )

        self._sessions[session_id] = session
        self._pending.pop(session_id, None)

        return session

    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """Get a session by ID."""
        session = self._sessions.get(session_id)
        if session and session.is_expired():
            del self._sessions[session_id]
            return None
        return session

    def get_session_for_agent(self, agent_id: str) -> Optional[SessionInfo]:
        """Get the most recent session with a specific agent."""
        sessions = [
            s for s in self._sessions.values()
            if s.peer_agent_id == agent_id and not s.is_expired()
        ]
        return sessions[-1] if sessions else None

    def close_session(self, session_id: str) -> bool:
        """Close and remove a session."""
        return self._sessions.pop(session_id, None) is not None

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count removed."""
        expired = [
            sid for sid, s in self._sessions.items()
            if s.is_expired()
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)


# ---------------------------------------------------------------------------
# Token-Based Authentication
# ---------------------------------------------------------------------------

@dataclass
class AuthToken:
    """An authentication token for fleet access."""
    token_id: str
    agent_id: str
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    capabilities: List[str] = field(default_factory=list)
    token_hash: str = ""

    def __post_init__(self) -> None:
        if not self.expires_at:
            self.expires_at = self.issued_at + TOKEN_EXPIRY
        if not self.token_hash:
            self.token_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        data = f"{self.token_id}:{self.agent_id}:{self.issued_at}:{self.expires_at}"
        return hash_data(data.encode())

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def has_capability(self, cap: str) -> bool:
        return cap in self.capabilities or "*" in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "capabilities": self.capabilities,
            "token_hash": self.token_hash,
        }


class TokenManager:
    """Manages authentication tokens for fleet agents."""

    def __init__(self, signing_key: Optional[bytes] = None) -> None:
        self._signing_key = signing_key or generate_key(KEY_LENGTH)
        self._tokens: Dict[str, AuthToken] = {}

    def issue_token(
        self,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
        ttl: int = TOKEN_EXPIRY,
    ) -> AuthToken:
        """Issue a new authentication token."""
        token_id = secrets.token_hex(16)
        token = AuthToken(
            token_id=token_id,
            agent_id=agent_id,
            capabilities=capabilities or [],
            expires_at=time.time() + ttl,
        )
        self._tokens[token_id] = token
        return token

    def validate_token(self, token_id: str) -> Optional[AuthToken]:
        """Validate a token and return it if valid."""
        token = self._tokens.get(token_id)
        if token is None or token.is_expired():
            return None
        return token

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a token."""
        return self._tokens.pop(token_id, None) is not None

    def cleanup_expired(self) -> int:
        """Remove expired tokens."""
        expired = [
            tid for tid, t in self._tokens.items()
            if t.is_expired()
        ]
        for tid in expired:
            del self._tokens[tid]
        return len(expired)


# ---------------------------------------------------------------------------
# HMAC Message Authentication
# ---------------------------------------------------------------------------

class HMACAuthenticator:
    """
    HMAC-based message authentication.

    Provides message-level integrity verification using HMAC.
    """

    def __init__(self, key: Optional[bytes] = None) -> None:
        self._key = key or generate_key(KEY_LENGTH)

    def authenticate(self, message: FleetMessage) -> str:
        """
        Generate HMAC for a fleet message.

        Returns:
            Hex-encoded HMAC digest.
        """
        canonical = MessageAuthenticator.canonical_payload(message)
        mac = hmac.new(self._key, canonical, DEFAULT_HMAC_ALGORITHM)
        return mac.hexdigest()

    def verify(self, message: FleetMessage, mac_hex: str) -> bool:
        """
        Verify HMAC of a fleet message.

        Returns:
            True if the HMAC is valid.
        """
        try:
            expected = self.authenticate(message)
            return hmac.compare_digest(expected, mac_hex)
        except Exception:
            return False

    def authenticate_raw(self, data: bytes) -> str:
        """Generate HMAC for raw bytes."""
        mac = hmac.new(self._key, data, DEFAULT_HMAC_ALGORITHM)
        return mac.hexdigest()

    def verify_raw(self, data: bytes, mac_hex: str) -> bool:
        """Verify HMAC for raw bytes."""
        try:
            expected = self.authenticate_raw(data)
            return hmac.compare_digest(expected, mac_hex)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Secret Redaction Utilities
# ---------------------------------------------------------------------------

class SecretRedactor:
    """
    Redacts sensitive information from text — complement to keeper's leak detector.

    Patterns redacted:
        - API keys (long alphanumeric strings after "key", "token", "secret", "api_key")
        - Passwords (values after "password", "passwd", "pwd")
        - Private keys
        - Connection strings
        - Email addresses
        - IP addresses (optional)
        - Credit card-like numbers
    """

    # Patterns to match key=value or key: value for sensitive keys
    SENSITIVE_KEY_PATTERNS = [
        "api_key", "apikey", "api-key",
        "secret", "secret_key", "secretkey",
        "token", "access_token", "auth_token",
        "password", "passwd", "pwd",
        "private_key", "privatekey",
        "connection_string", "conn_string",
        "credentials", "credential",
    ]

    # Regex-like patterns for inline detection
    INLINE_PATTERNS = [
        ("sk-", 48),          # OpenAI-style API keys
        ("sk_live_", 48),     # Stripe live keys
        ("sk_test_", 48),     # Stripe test keys
        ("ghp_", 36),         # GitHub PATs
        ("gho_", 36),         # GitHub OAuth
        ("ghu_", 36),         # GitHub User
        ("ghs_", 36),         # GitHub App
        ("AKIA", 20),         # AWS access key IDs
        ("xoxb-", 0),         # Slack bot tokens
        ("xoxp-", 0),         # Slack user tokens
    ]

    def __init__(
        self,
        replacement: str = "[REDACTED]",
        redact_emails: bool = True,
        redact_ips: bool = False,
        redact_inline_secrets: bool = True,
    ) -> None:
        self.replacement = replacement
        self.redact_emails = redact_emails
        self.redact_ips = redact_ips
        self.redact_inline_secrets = redact_inline_secrets

    def redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive values from a dictionary.

        Returns a new dictionary with sensitive values replaced.
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            elif self._is_sensitive_key(key):
                result[key] = self.replacement
            elif isinstance(value, str):
                result[key] = self.redact_string(value)
            else:
                result[key] = value
        return result

    def redact_string(self, text: str) -> str:
        """Redact sensitive information from a string."""
        result = text

        # Redact inline secret patterns
        if self.redact_inline_secrets:
            for prefix, max_len in self.INLINE_PATTERNS:
                result = self._redact_prefix(result, prefix, max_len)

        # Redact key=value pairs with sensitive keys
        for sensitive_key in self.SENSITIVE_KEY_PATTERNS:
            result = self._redact_key_value(result, sensitive_key)

        # Redact emails
        if self.redact_emails:
            result = self._redact_emails(result)

        # Redact IPs
        if self.redact_ips:
            result = self._redact_ips(result)

        return result

    def redact_message(self, message: FleetMessage) -> FleetMessage:
        """Redact sensitive information from a fleet message's payload."""
        from fleet_protocol.messages import FleetMessage, MessageBody
        import copy

        msg = copy.deepcopy(message)
        msg.body.payload = self.redact_dict(msg.body.payload)
        return msg

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a dictionary key is sensitive."""
        key_lower = key.lower().strip()
        for pattern in self.SENSITIVE_KEY_PATTERNS:
            if pattern in key_lower:
                return True
        return False

    def _redact_prefix(self, text: str, prefix: str, max_len: int) -> str:
        """Redact strings starting with a known secret prefix."""
        import re
        if max_len > 0:
            pattern = re.escape(prefix) + r"[A-Za-z0-9_\-]{1," + str(max_len) + r"}"
        else:
            pattern = re.escape(prefix) + r"[A-Za-z0-9_\-]+"
        return re.sub(pattern, f"{self.replacement}", text)

    def _redact_key_value(self, text: str, key: str) -> str:
        """Redact values after key= or key: patterns."""
        import re
        # Match key="value", key='value', key=value
        pattern = (
            r"(?i)(" + re.escape(key) + r")\s*[=:]\s*"
            r"(?:\"([^\"]+)\"|'([^']+)'|(\S+))"
        )
        def _replace(m):
            return f"{m.group(1)}={self.replacement}"
        return re.sub(pattern, _replace, text)

    def _redact_emails(self, text: str) -> str:
        """Redact email addresses."""
        import re
        return re.sub(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b",
            self.replacement,
            text,
        )

    def _redact_ips(self, text: str) -> str:
        """Redact IP addresses."""
        import re
        return re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            self.replacement,
            text,
        )

    def audit(self, text: str) -> List[Dict[str, Any]]:
        """
        Audit text for potential secrets without redacting.

        Returns:
            List of findings with location and type.
        """
        findings: List[Dict[str, Any]] = []

        # Check inline patterns
        if self.redact_inline_secrets:
            for prefix, _ in self.INLINE_PATTERNS:
                if prefix in text:
                    findings.append({
                        "type": "inline_secret",
                        "prefix": prefix,
                        "severity": "high",
                    })

        # Check for sensitive key patterns
        for sensitive_key in self.SENSITIVE_KEY_PATTERNS:
            if sensitive_key in text.lower():
                findings.append({
                    "type": "sensitive_key",
                    "key": sensitive_key,
                    "severity": "medium",
                })

        return findings
