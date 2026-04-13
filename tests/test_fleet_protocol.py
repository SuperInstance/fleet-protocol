"""
Comprehensive test suite for the Fleet Protocol library.

Tests cover:
    - Message serialization/deserialization (JSON + binary)
    - Protocol handshake sequence
    - Registry operations (CRUD, queries, sync, anti-entropy)
    - Bottle routing (delivery conditions, TTL, hops)
    - Security primitives (keygen, sign, verify, HMAC, redaction)
    - CLI parsing
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid

import pytest

# Add the parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fleet_protocol.messages import (
    FleetMessage,
    MessageType,
    MessageEncoding,
    MessagePriority,
    MessageHeader,
    MessageBody,
    MessageMetadata,
    MessageSecurity,
    MessageBuilder,
    MessageValidator,
)
from fleet_protocol.protocol import (
    FleetProtocol,
    ProtocolVersion,
    ProtocolConstants,
    HandshakeProtocol,
    HandshakeConfig,
    HandshakeState,
    HeartbeatProtocol,
    HeartbeatState,
    HeartbeatRecord,
    DiscoveryProtocol,
    DiscoveryBeacon,
    CapabilityNegotiator,
    ErrorCode,
    error_message,
    build_error_message,
    get_recovery_action,
    RecoveryAction,
)
from fleet_protocol.registry import (
    FleetRegistry,
    AgentRecord,
    AgentRole,
    ServiceRecord,
    HealthRecord,
    HealthStatus,
)
from fleet_protocol.bottle import (
    Bottle,
    BottleStatus,
    BottleRouter,
    BottleInbox,
    BottlePostmark,
    DeliveryCondition,
    DeliveryConditionType,
)
from fleet_protocol.security import (
    AgentIdentity,
    MessageAuthenticator,
    SessionManager,
    SessionInfo,
    TokenManager,
    AuthToken,
    HMACAuthenticator,
    SecretRedactor,
    hash_data,
    generate_key,
    b64encode,
    b64decode,
    KEY_LENGTH,
    SIGNING_ALGORITHM,
)


# ===========================================================================
# Messages Tests
# ===========================================================================

class TestMessageType:
    def test_message_type_values(self):
        assert MessageType.REQUEST.value == "REQUEST"
        assert MessageType.RESPONSE.value == "RESPONSE"
        assert MessageType.EVENT.value == "EVENT"
        assert MessageType.COMMAND.value == "COMMAND"
        assert MessageType.QUERY.value == "QUERY"
        assert MessageType.STATUS.value == "STATUS"
        assert MessageType.ERROR.value == "ERROR"


class TestMessageBuilder:
    def test_build_basic_message(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"action": "test"})
            .build()
        )
        assert msg.header.sender == "agent-1"
        assert msg.header.recipient == "agent-2"
        assert msg.header.message_type == "REQUEST"
        assert msg.body.payload == {"action": "test"}
        assert msg.header.message_id is not None

    def test_build_with_all_options(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.COMMAND)
            .payload({"cmd": "restart"})
            .priority(MessagePriority.HIGH)
            .ttl(60)
            .requires_ack(True)
            .capabilities_needed(["admin"])
            .signature("sig-123")
            .encrypted(True)
            .build()
        )
        assert msg.metadata.priority == MessagePriority.HIGH.value
        assert msg.metadata.ttl == 60
        assert msg.metadata.requires_ack is True
        assert msg.metadata.capabilities_needed == ["admin"]
        assert msg.security.signature == "sig-123"
        assert msg.security.encrypted is True

    def test_build_fails_without_type(self):
        with pytest.raises(ValueError, match="Message type"):
            MessageBuilder().sender("a").recipient("b").build()

    def test_build_fails_without_sender(self):
        with pytest.raises(ValueError, match="Sender"):
            MessageBuilder().type(MessageType.REQUEST).recipient("b").build()

    def test_build_reply(self):
        msg = (
            MessageBuilder()
            .sender("agent-2")
            .recipient("agent-1")
            .type(MessageType.RESPONSE)
            .in_reply_to("msg-123")
            .payload({"result": "ok"})
            .build()
        )
        assert msg.header.in_reply_to == "msg-123"


class TestMessageSerialization:
    def test_to_dict_roundtrip(self):
        original = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.EVENT)
            .payload({"data": [1, 2, 3]})
            .build()
        )
        data = original.to_dict()
        assert data["header"]["sender"] == "agent-1"
        assert data["body"]["payload"] == {"data": [1, 2, 3]}

    def test_json_serialization(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"key": "value"})
            .build()
        )
        json_str = msg.to_json()
        parsed = json.loads(json_str)
        assert parsed["header"]["sender"] == "agent-1"
        assert parsed["body"]["payload"]["key"] == "value"

    def test_json_deserialization(self):
        msg = (
            MessageBuilder()
            .sender("agent-a")
            .recipient("agent-b")
            .type(MessageType.QUERY)
            .payload({"query": "test"})
            .build()
        )
        json_str = msg.to_json()
        restored = FleetMessage.from_json(json_str)
        assert restored.header.sender == "agent-a"
        assert restored.header.recipient == "agent-b"
        assert restored.header.message_type == "QUERY"

    def test_binary_serialization_roundtrip(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.COMMAND)
            .payload({"command": "deploy", "version": "3.0"})
            .build()
        )
        binary = msg.to_binary()
        assert isinstance(binary, bytes)
        assert len(binary) > 0

        restored = FleetMessage.from_binary(binary)
        assert restored.header.message_type == "COMMAND"
        assert restored.body.payload.get("command") == "deploy"
        assert restored.body.encoding == MessageEncoding.BINARY.value

    def test_binary_all_message_types(self):
        for mt in MessageType:
            msg = (
                MessageBuilder()
                .sender("a")
                .recipient("b")
                .type(mt)
                .payload({"type_test": mt.value})
                .build()
            )
            binary = msg.to_binary()
            restored = FleetMessage.from_binary(binary)
            assert restored.header.message_type == mt.value

    def test_message_copy(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"data": "original"})
            .build()
        )
        copied = msg.copy()
        copied.body.payload["data"] = "modified"
        assert msg.body.payload["data"] == "original"


class TestMessageValidation:
    def test_valid_message(self):
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"key": "value"})
            .build()
        )
        is_valid, errors = MessageValidator.validate(msg)
        assert is_valid is True
        assert errors == []

    def test_invalid_sender_empty(self):
        msg = (
            MessageBuilder()
            .sender("")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .build()
        )
        is_valid, errors = MessageValidator.validate(msg)
        assert is_valid is False
        assert any("sender" in e for e in errors)

    def test_invalid_message_type(self):
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .build()
        )
        msg.header.message_type = "INVALID_TYPE"
        is_valid, errors = MessageValidator.validate(msg)
        assert is_valid is False

    def test_negative_ttl(self):
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .ttl(-1)
            .build()
        )
        is_valid, errors = MessageValidator.validate(msg)
        assert is_valid is False
        assert any("TTL" in e for e in errors)

    def test_sanitization_removes_dunder_keys(self):
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .payload({"__dangerous": "yes", "safe": "ok"})
            .build()
        )
        sanitized = MessageValidator.sanitize(msg)
        assert "__dangerous" not in sanitized.body.payload
        assert "safe" in sanitized.body.payload


class TestMessageExpiry:
    def test_not_expired(self):
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .ttl(300)
            .build()
        )
        assert msg.is_expired() is False

    def test_expired(self):
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .ttl(0)
            .build()
        )
        # Force old timestamp
        msg.header.timestamp = time.time() - 1
        assert msg.is_expired() is True


# ===========================================================================
# Protocol Tests
# ===========================================================================

class TestProtocolVersion:
    def test_latest_is_v2(self):
        assert ProtocolVersion.latest() == ProtocolVersion.V2

    def test_version_values(self):
        assert ProtocolVersion.V1.value == "1.0"
        assert ProtocolVersion.V2.value == "2.0"


class TestErrorCode:
    def test_error_messages_exist(self):
        for code in ErrorCode:
            msg = error_message(code.value)
            assert isinstance(msg, str)
            assert len(msg) > 0

    def test_build_error_message(self):
        msg = build_error_message("sender", "recipient", ErrorCode.HANDSHAKE_TIMEOUT)
        assert msg.header.message_type == MessageType.ERROR.value
        assert msg.body.payload["error_code"] == ErrorCode.HANDSHAKE_TIMEOUT.value

    def test_recovery_actions_exist(self):
        for code in [ErrorCode.HANDSHAKE_TIMEOUT, ErrorCode.HEARTBEAT_DEAD,
                     ErrorCode.SECURITY_SIGNATURE_INVALID]:
            action = get_recovery_action(code)
            assert isinstance(action, RecoveryAction)
            assert action.action in ("retry", "reset", "escalate", "ignore")


class TestHandshake:
    def test_build_hello(self):
        hs = HandshakeProtocol("agent-1", HandshakeConfig(capabilities=["compute"]))
        hello = hs.build_hello("agent-2")
        assert hello.header.sender == "agent-1"
        assert hello.header.recipient == "agent-2"
        assert hello.body.payload["action"] == "HELLO"
        assert "compute" in hello.body.payload["capabilities"]

    def test_build_hello_ack(self):
        hs = HandshakeProtocol("agent-1")
        ack = hs.build_hello_ack("agent-2")
        assert ack.body.payload["action"] == "HELLO_ACK"

    def test_build_reject(self):
        hs = HandshakeProtocol("agent-1")
        reject = hs.build_reject("agent-2", ErrorCode.HANDSHAKE_VERSION_MISMATCH, "old version")
        assert reject.body.payload["action"] == "HELLO_REJECT"
        assert reject.header.message_type == MessageType.ERROR.value

    def test_process_hello(self):
        hs = HandshakeProtocol(
            "agent-1",
            HandshakeConfig(capabilities=["compute", "analyze"]),
        )
        hello = (
            MessageBuilder()
            .sender("agent-2")
            .recipient("agent-1")
            .type(MessageType.REQUEST)
            .payload({
                "action": "HELLO",
                "session_id": "sess-123",
                "version": "2.0",
                "capabilities": ["compute", "schedule"],
            })
            .build()
        )
        result = hs.process_hello(hello)
        assert result.success is True
        assert result.peer_agent_id == "agent-2"
        assert "compute" in result.shared_capabilities
        assert "schedule" not in result.shared_capabilities

    def test_retry_exhaustion(self):
        hs = HandshakeProtocol("agent-1", HandshakeConfig(max_retries=2))
        assert hs.is_exhausted() is False
        hs.build_hello("agent-2")
        assert hs.is_exhausted() is False
        hs.build_hello("agent-2")
        assert hs.is_exhausted() is True


class TestHeartbeat:
    def test_record_heartbeat(self):
        hb = HeartbeatProtocol()
        hb.record_heartbeat("agent-1")
        assert hb.get_state("agent-1") == HeartbeatState.ALIVE

    def test_dead_after_timeout(self):
        hb = HeartbeatProtocol()
        hb.record_heartbeat("agent-1", timestamp=time.time() - 100)
        state = hb.get_state("agent-1")
        assert state == HeartbeatState.DEAD

    def test_degraded_state(self):
        hb = HeartbeatProtocol()
        hb.record_heartbeat("agent-1", timestamp=time.time() - 12)
        state = hb.get_state("agent-1")
        assert state == HeartbeatState.DEGRADED

    def test_get_alive_agents(self):
        hb = HeartbeatProtocol()
        hb.record_heartbeat("agent-1")
        hb.record_heartbeat("agent-2", timestamp=time.time() - 100)
        alive = hb.get_alive_agents()
        assert "agent-1" in alive
        assert "agent-2" not in alive

    def test_build_heartbeat_message(self):
        hb = HeartbeatProtocol()
        msg = hb.build_heartbeat("agent-1")
        assert msg.body.payload["action"] == "HEARTBEAT"

    def test_unknown_agent_is_dead(self):
        hb = HeartbeatProtocol()
        assert hb.get_state("unknown-agent") == HeartbeatState.DEAD


class TestDiscovery:
    def test_build_beacon(self):
        dp = DiscoveryProtocol("agent-1", ["compute", "analyze"])
        beacon = dp.build_beacon()
        assert beacon.body.payload["action"] == "DISCOVERY"
        assert beacon.body.payload["capabilities"] == ["compute", "analyze"]

    def test_process_beacon(self):
        dp = DiscoveryProtocol("agent-1", ["compute"])
        beacon = (
            MessageBuilder()
            .sender("agent-2")
            .recipient("fleet:discovery")
            .type(MessageType.EVENT)
            .payload({
                "action": "DISCOVERY",
                "agent_id": "agent-2",
                "capabilities": ["schedule"],
                "version": "2.0",
                "timestamp": time.time(),
                "hop_count": 0,
            })
            .build()
        )
        result = dp.process_beacon(beacon)
        assert result is not None
        assert result.agent_id == "agent-2"

    def test_ignore_own_beacon(self):
        dp = DiscoveryProtocol("agent-1")
        beacon = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("fleet:discovery")
            .type(MessageType.EVENT)
            .payload({
                "action": "DISCOVERY",
                "agent_id": "agent-1",
                "capabilities": [],
                "version": "2.0",
                "timestamp": time.time(),
                "hop_count": 0,
            })
            .build()
        )
        assert dp.process_beacon(beacon) is None

    def test_find_by_capability(self):
        dp = DiscoveryProtocol("agent-1", ["compute"])
        dp.process_beacon(
            MessageBuilder()
            .sender("agent-2")
            .recipient("fleet:discovery")
            .type(MessageType.EVENT)
            .payload({
                "action": "DISCOVERY",
                "agent_id": "agent-2",
                "capabilities": ["compute", "schedule"],
                "version": "2.0",
                "timestamp": time.time(),
                "hop_count": 0,
            })
            .build()
        )
        results = dp.find_by_capability("compute")
        assert len(results) == 1
        assert results[0].agent_id == "agent-2"


class TestCapabilityNegotiation:
    def test_negotiate_capabilities(self):
        neg = CapabilityNegotiator(["compute", "analyze"])
        neg.add_remote_capabilities("agent-2", ["compute", "schedule"])
        shared = neg.negotiate("agent-2")
        assert shared == {"compute"}

    def test_negotiate_all(self):
        neg = CapabilityNegotiator(["compute"])
        neg.add_remote_capabilities("agent-2", ["compute"])
        neg.add_remote_capabilities("agent-3", ["schedule"])
        all_shared = neg.negotiate_all()
        assert all_shared["agent-2"] == {"compute"}
        assert all_shared["agent-3"] == set()


class TestFleetProtocol:
    def test_init_connection(self):
        fp = FleetProtocol("agent-1", ["compute"])
        msg = fp.init_connection("agent-2")
        assert msg.body.payload["action"] == "HELLO"

    def test_accept_connection(self):
        fp = FleetProtocol("agent-1", ["compute"])
        hello = (
            MessageBuilder()
            .sender("agent-2")
            .recipient("agent-1")
            .type(MessageType.REQUEST)
            .payload({
                "action": "HELLO",
                "session_id": "sess-1",
                "version": "2.0",
                "capabilities": ["schedule"],
            })
            .build()
        )
        result, reply = fp.accept_connection(hello)
        assert result.success is True
        assert reply is not None
        assert reply.body.payload["action"] == "HELLO_ACK"

    def test_get_fleet_status(self):
        fp = FleetProtocol("agent-1")
        status = fp.get_fleet_status()
        assert status["agent_id"] == "agent-1"
        assert status["version"] == "2.0"
        assert "heartbeat_states" in status


# ===========================================================================
# Registry Tests
# ===========================================================================

class TestAgentRecord:
    def test_fingerprint_deterministic(self):
        a = AgentRecord(agent_id="agent-1", capabilities=["compute"])
        fp1 = a.fingerprint()
        fp2 = a.fingerprint()
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_fingerprint_differs(self):
        a1 = AgentRecord(agent_id="agent-1", capabilities=["compute"])
        a2 = AgentRecord(agent_id="agent-1", capabilities=["analyze"])
        assert a1.fingerprint() != a2.fingerprint()

    def test_to_dict_roundtrip(self):
        original = AgentRecord(
            agent_id="agent-1",
            name="Test Agent",
            role="worker",
            capabilities=["compute"],
            metadata={"env": "prod"},
        )
        data = original.to_dict()
        restored = AgentRecord.from_dict(data)
        assert restored.agent_id == original.agent_id
        assert restored.name == original.name
        assert restored.capabilities == original.capabilities


class TestFleetRegistry:
    def test_register_and_get_agent(self):
        reg = FleetRegistry()
        agent = AgentRecord(agent_id="agent-1", name="Alpha", capabilities=["compute"])
        reg.register_agent(agent)

        retrieved = reg.get_agent("agent-1")
        assert retrieved is not None
        assert retrieved.name == "Alpha"
        assert retrieved.generation == 1

    def test_register_updates_generation(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="agent-1"))
        reg.register_agent(AgentRecord(agent_id="agent-1", capabilities=["new-cap"]))
        assert reg.get_agent("agent-1").generation == 2
        assert "new-cap" in reg.get_agent("agent-1").capabilities

    def test_unregister_agent(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="agent-1", capabilities=["compute"]))
        assert reg.unregister_agent("agent-1") is True
        assert reg.get_agent("agent-1") is None
        assert reg.get_service("compute") is None

    def test_find_by_capability(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["compute", "analyze"]))
        reg.register_agent(AgentRecord(agent_id="a2", capabilities=["schedule"]))
        reg.register_agent(AgentRecord(agent_id="a3", capabilities=["compute"]))

        results = reg.find_agents_by_capability("compute")
        assert len(results) == 2
        assert {a.agent_id for a in results} == {"a1", "a3"}

    def test_find_by_role(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", role="worker"))
        reg.register_agent(AgentRecord(agent_id="a2", role="keeper"))
        reg.register_agent(AgentRecord(agent_id="a3", role="worker"))

        results = reg.find_agents_by_role("worker")
        assert len(results) == 2

    def test_find_by_name(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", name="Alpha Agent"))
        reg.register_agent(AgentRecord(agent_id="a2", name="Beta Worker"))

        results = reg.find_agents_by_name("alpha")
        assert len(results) == 1
        assert results[0].agent_id == "a1"

    def test_service_registry(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["compute"]))
        reg.register_agent(AgentRecord(agent_id="a2", capabilities=["compute"]))

        service = reg.get_service("compute")
        assert service is not None
        assert sorted(service.provider_ids) == ["a1", "a2"]

    def test_health_registry(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1"))
        reg.update_health(HealthRecord(agent_id="a1", status="healthy", latency_ms=5.0))

        health = reg.get_health("a1")
        assert health is not None
        assert health.latency_ms == 5.0

    def test_healthy_agents(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1"))
        reg.register_agent(AgentRecord(agent_id="a2"))
        reg.update_health(HealthRecord(agent_id="a1", status="healthy"))
        reg.update_health(HealthRecord(agent_id="a2", status="unhealthy"))

        healthy = reg.get_healthy_agents()
        assert healthy == ["a1"]
        unhealthy = reg.get_unhealthy_agents()
        assert unhealthy == ["a2"]

    def test_registry_sync(self):
        reg1 = FleetRegistry()
        reg1.register_agent(AgentRecord(agent_id="a1", name="Alpha"))

        # Simulate remote changes with higher generation
        reg2 = FleetRegistry()
        reg2.register_agent(AgentRecord(agent_id="a1", name="Alpha"))
        reg2.register_agent(AgentRecord(agent_id="a1", name="Alpha Updated"))  # gen=2
        reg2.register_agent(AgentRecord(agent_id="a2", name="Beta"))

        snapshot = reg2.get_snapshot()
        success, conflicts = reg1.apply_snapshot(snapshot)

        assert success is True
        assert reg1.get_agent("a2") is not None
        assert reg1.get_agent("a1").name == "Alpha Updated"

    def test_anti_entropy_detection(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["compute"]))

        # Create a conflicting snapshot with same generation but different data
        remote_snapshot = {
            "agents": {
                "a1": AgentRecord(agent_id="a1", capabilities=["analyze"], generation=1).to_dict()
            }
        }
        conflicts = reg.detect_conflicts(remote_snapshot)
        assert len(conflicts) > 0

    def test_generic_query(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["compute"]))

        assert len(reg.query("all")) == 1
        assert len(reg.query("capability", capability="compute")) == 1
        assert len(reg.query("capability", capability="nonexistent")) == 0
        assert len(reg.query("role", role="coordinator")) == 0

    def test_snapshot_contains_all_data(self):
        reg = FleetRegistry()
        reg.register_agent(AgentRecord(agent_id="a1", capabilities=["compute"]))
        reg.update_health(HealthRecord(agent_id="a1", status="healthy"))

        snapshot = reg.get_snapshot()
        assert "a1" in snapshot["agents"]
        assert "compute" in snapshot["services"]
        assert "a1" in snapshot["health"]


# ===========================================================================
# Bottle Tests
# ===========================================================================

class TestDeliveryCondition:
    def test_immediate_condition(self):
        cond = DeliveryCondition(condition_type=DeliveryConditionType.IMMEDIATE.value)
        assert cond.is_met({}) is True

    def test_agent_online_condition(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.AGENT_ONLINE.value,
            target="agent-2",
        )
        assert cond.is_met({"online_agents": {"agent-2"}}) is True
        assert cond.is_met({"online_agents": {"agent-1"}}) is False

    def test_after_time_condition(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.AFTER_TIME.value,
            threshold=time.time() - 10,
        )
        assert cond.is_met({"current_time": time.time()}) is True

    def test_after_time_not_yet(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.AFTER_TIME.value,
            threshold=time.time() + 3600,
        )
        assert cond.is_met({"current_time": time.time()}) is False

    def test_after_delay_condition(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.AFTER_DELAY.value,
            threshold=5,
        )
        context = {
            "current_time": time.time(),
            "bottle_created_time": time.time() - 10,
        }
        assert cond.is_met(context) is True

    def test_on_event_condition(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.ON_EVENT.value,
            target="deployment_complete",
        )
        assert cond.is_met({"events_fired": {"deployment_complete"}}) is True
        assert cond.is_met({"events_fired": set()}) is False

    def test_capability_available_condition(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.CAPABILITY_AVAILABLE.value,
            target="compute",
        )
        caps = {"agent-1": ["compute", "analyze"]}
        assert cond.is_met({"available_capabilities": caps}) is True
        assert cond.is_met({"available_capabilities": {}}) is False

    def test_condition_serialization(self):
        cond = DeliveryCondition(
            condition_type=DeliveryConditionType.AGENT_ONLINE.value,
            target="agent-1",
        )
        data = cond.to_dict()
        restored = DeliveryCondition.from_dict(data)
        assert restored.condition_type == cond.condition_type
        assert restored.target == cond.target


class TestBottle:
    def test_create_bottle(self):
        b = Bottle(sender="agent-1", intended_recipient="agent-2", payload={"msg": "hello"})
        assert b.bottle_id is not None
        assert b.status == BottleStatus.PENDING.value
        assert b.hops == 0

    def test_bottle_expiry(self):
        b = Bottle(ttl=0)
        b.created_at = time.time() - 1
        assert b.is_expired() is True

    def test_bottle_not_expired(self):
        b = Bottle(ttl=3600)
        assert b.is_expired() is False

    def test_deliverable_immediate(self):
        b = Bottle(sender="a", intended_recipient="b", payload={})
        assert b.is_deliverable({}) is True

    def test_deliverable_with_condition(self):
        b = Bottle(
            sender="a",
            intended_recipient="b",
            payload={},
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                    target="b",
                )
            ],
        )
        assert b.is_deliverable({"online_agents": {"b"}}) is True
        assert b.is_deliverable({"online_agents": set()}) is False

    def test_can_relay(self):
        b = Bottle(max_hops=5)
        assert b.can_relay() is True
        b.hops = 5
        assert b.can_relay() is False

    def test_to_fleet_message(self):
        b = Bottle(sender="a", intended_recipient="b", payload={"data": "test"})
        msg = b.to_fleet_message()
        assert msg.header.sender == "a"
        assert msg.body.payload["bottle_id"] == b.bottle_id

    def test_serialization_roundtrip(self):
        b = Bottle(
            sender="a",
            intended_recipient="b",
            payload={"key": "value"},
            conditions=[
                DeliveryCondition(condition_type=DeliveryConditionType.ON_EVENT.value, target="go"),
            ],
        )
        data = b.to_dict()
        restored = Bottle.from_dict(data)
        assert restored.sender == "a"
        assert restored.payload == {"key": "value"}
        assert len(restored.conditions) == 1


class TestBottleInbox:
    def test_add_and_retrieve(self):
        inbox = BottleInbox("agent-1")
        b = Bottle(bottle_id="b1", sender="agent-2", intended_recipient="agent-1")
        assert inbox.add(b) is True
        assert inbox.count() == 1

        retrieved = inbox.retrieve("b1")
        assert retrieved is not None
        assert inbox.count() == 0

    def test_duplicate_rejected(self):
        inbox = BottleInbox("agent-1")
        b = Bottle(bottle_id="b1")
        assert inbox.add(b) is True
        assert inbox.add(b) is False

    def test_capacity_limit(self):
        inbox = BottleInbox("agent-1", max_capacity=2)
        assert inbox.add(Bottle(bottle_id="b1")) is True
        assert inbox.add(Bottle(bottle_id="b2")) is True
        assert inbox.add(Bottle(bottle_id="b3")) is False

    def test_retrieve_by_priority(self):
        inbox = BottleInbox("agent-1")
        b1 = Bottle(bottle_id="b1", priority=0)  # low
        b2 = Bottle(bottle_id="b2", priority=3)  # critical
        b3 = Bottle(bottle_id="b3", priority=1)  # normal
        inbox.add(b1)
        inbox.add(b2)
        inbox.add(b3)

        bottles = inbox.retrieve_by_priority()
        assert [b.bottle_id for b in bottles] == ["b2", "b3", "b1"]

    def test_cleanup_expired(self):
        inbox = BottleInbox("agent-1")
        b1 = Bottle(bottle_id="b1", ttl=3600)
        b2 = Bottle(bottle_id="b2", ttl=0)
        b2.created_at = time.time() - 1
        inbox.add(b1)
        inbox.add(b2)

        removed = inbox.cleanup_expired()
        assert removed == 1
        assert inbox.count() == 1


class TestBottleRouter:
    def test_immediate_delivery(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            payload={"msg": "hello"},
        )
        postmark = router.send(bottle)
        assert postmark.status == BottleStatus.DELIVERED.value

        inbox = router.get_inbox("agent-2")
        assert inbox.count() == 1

    def test_conditional_delivery_pending(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            payload={},
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                    target="agent-2",
                )
            ],
        )
        postmark = router.send(bottle)
        assert postmark.status == BottleStatus.PENDING.value
        assert router.get_pending_count() == 1

    def test_process_pending_delivers_when_condition_met(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            payload={},
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                    target="agent-2",
                )
            ],
        )
        router.send(bottle)

        # Agent-2 comes online
        router.update_context("online_agents", {"agent-2"})
        delivered = router.process_pending()
        assert len(delivered) == 1
        assert router.get_pending_count() == 0

    def test_bottle_expiry_in_pending(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            ttl=0,
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.ON_EVENT.value,
                    target="never_happens",
                )
            ],
        )
        bottle.created_at = time.time() - 1
        router.send(bottle)

        router.process_pending()
        pm = router.get_postmark(bottle.bottle_id)
        assert pm is not None
        assert pm.status == BottleStatus.EXPIRED.value

    def test_cancel_bottle(self):
        router = BottleRouter()
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.ON_EVENT.value,
                    target="future_event",
                )
            ],
        )
        router.send(bottle)
        assert router.cancel(bottle.bottle_id) is True
        assert router.get_pending_count() == 0

    def test_relay_bottle(self):
        router = BottleRouter()
        router.set_online_agents({"agent-3"})
        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-3",
            payload={},
        )
        router.send(bottle)  # Delivered immediately since no condition

        # Test relay with a non-immediate bottle
        bottle2 = Bottle(
            sender="agent-1",
            intended_recipient="agent-3",
            payload={},
            max_hops=5,
        )
        pm = router.relay(bottle2, "relay-agent")
        assert pm is not None

    def test_router_stats(self):
        router = BottleRouter()
        router.send(Bottle(sender="a", intended_recipient="b", payload={}))
        stats = router.get_stats()
        assert stats["delivered"] == 1
        assert "inboxes" in stats


class TestBottlePostmark:
    def test_delivery_tracking(self):
        pm = BottlePostmark(bottle_id="b1")
        assert pm.status == BottleStatus.PENDING.value

        pm.mark_dispatched("agent-2")
        assert pm.status == BottleStatus.IN_TRANSIT.value
        assert "agent-2" in pm.route

        pm.mark_delivered()
        assert pm.status == BottleStatus.DELIVERED.value
        assert pm.delivery_time_ms() is not None

    def test_failure_tracking(self):
        pm = BottlePostmark(bottle_id="b1")
        pm.mark_failed("Inbox full")
        assert pm.status == BottleStatus.FAILED.value
        assert pm.failure_reason == "Inbox full"

    def test_expired_tracking(self):
        pm = BottlePostmark(bottle_id="b1")
        pm.mark_expired()
        assert pm.status == BottleStatus.EXPIRED.value


# ===========================================================================
# Security Tests
# ===========================================================================

class TestAgentIdentity:
    def test_generate_identity(self):
        identity = AgentIdentity.generate("agent-1")
        assert identity.agent_id == "agent-1"
        assert len(identity.private_key) == KEY_LENGTH
        assert len(identity.public_key) > 0

    def test_public_key_derivation_deterministic(self):
        identity = AgentIdentity.generate("agent-1")
        pk1 = identity.public_key
        pk2 = identity._derive_public_key()
        assert pk1 == pk2

    def test_export_import(self):
        original = AgentIdentity.generate("agent-1")
        exported = original.export()
        restored = AgentIdentity.import_identity(exported)
        assert restored.agent_id == original.agent_id
        assert restored.private_key == original.private_key
        assert restored.public_key == original.public_key

    def test_to_dict_excludes_private_key(self):
        identity = AgentIdentity.generate("agent-1")
        data = identity.to_dict()
        assert "private_key" not in data
        assert "public_key" in data

    def test_different_keys_for_different_agents(self):
        id1 = AgentIdentity.generate("agent-1")
        id2 = AgentIdentity.generate("agent-2")
        assert id1.private_key != id2.private_key
        assert id1.public_key != id2.public_key


class TestMessageAuthenticator:
    def test_sign_and_verify_data(self):
        key = generate_key()
        data = b"hello fleet world"
        sig = MessageAuthenticator.sign_data(data, key)
        assert MessageAuthenticator.verify_data(data, sig, key) is True

    def test_verify_wrong_key_fails(self):
        key1 = generate_key()
        key2 = generate_key()
        data = b"test message"
        sig = MessageAuthenticator.sign_data(data, key1)
        assert MessageAuthenticator.verify_data(data, sig, key2) is False

    def test_verify_tampered_data_fails(self):
        key = generate_key()
        data = b"original"
        sig = MessageAuthenticator.sign_data(data, key)
        assert MessageAuthenticator.verify_data(b"tampered", sig, key) is False

    def test_sign_message(self):
        identity = AgentIdentity.generate("agent-1")
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"action": "test"})
            .build()
        )
        sig = MessageAuthenticator.sign(msg, identity)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_sign_dict(self):
        key = generate_key()
        data = {"key": "value", "number": 42}
        sig = MessageAuthenticator.sign_message_dict(data, key)
        assert isinstance(sig, str)


class TestSessionManager:
    def test_initiate_session(self):
        identity = AgentIdentity.generate("agent-1")
        sm = SessionManager(identity)
        init_data = sm.initiate_session("agent-2")
        assert "session_id" in init_data
        assert "dh_public_value" in init_data
        assert init_data["agent_id"] == "agent-1"

    def test_complete_session(self):
        id1 = AgentIdentity.generate("agent-1")
        id2 = AgentIdentity.generate("agent-2")
        sm1 = SessionManager(id1)
        sm2 = SessionManager(id2)

        init1 = sm1.initiate_session("agent-2")
        init2 = sm2.initiate_session("agent-1")

        session1 = sm1.complete_session(init2, init1["dh_public_value"])
        session2 = sm2.complete_session(init1, init2["dh_public_value"])

        assert session1 is not None
        assert session2 is not None
        assert session1.peer_agent_id == "agent-2"
        assert session2.peer_agent_id == "agent-1"

    def test_session_expiry(self):
        identity = AgentIdentity.generate("agent-1")
        sm = SessionManager(identity)
        init = sm.initiate_session("agent-2")

        # Manually create an expired session
        session = SessionInfo(
            session_id=init["session_id"],
            peer_agent_id="agent-2",
            shared_secret=b"test",
            expires_at=time.time() - 10,
        )
        sm._sessions[init["session_id"]] = session
        assert sm.get_session(init["session_id"]) is None

    def test_cleanup_expired_sessions(self):
        identity = AgentIdentity.generate("agent-1")
        sm = SessionManager(identity)

        init = sm.initiate_session("agent-2")
        session = SessionInfo(
            session_id=init["session_id"],
            peer_agent_id="agent-2",
            shared_secret=b"test",
            expires_at=time.time() - 10,
        )
        sm._sessions[init["session_id"]] = session
        removed = sm.cleanup_expired()
        assert removed == 1


class TestTokenManager:
    def test_issue_and_validate(self):
        tm = TokenManager()
        token = tm.issue_token("agent-1", capabilities=["compute"])
        assert not token.is_expired()

        validated = tm.validate_token(token.token_id)
        assert validated is not None
        assert validated.agent_id == "agent-1"
        assert validated.has_capability("compute")

    def test_revoke_token(self):
        tm = TokenManager()
        token = tm.issue_token("agent-1")
        assert tm.revoke_token(token.token_id) is True
        assert tm.validate_token(token.token_id) is None

    def test_expired_token(self):
        tm = TokenManager()
        token = tm.issue_token("agent-1", ttl=-1)  # Already expired
        assert token.is_expired()
        assert tm.validate_token(token.token_id) is None

    def test_wildcard_capability(self):
        tm = TokenManager()
        token = tm.issue_token("agent-1", capabilities=["*"])
        assert token.has_capability("anything")
        assert token.has_capability("compute")


class TestHMACAuthenticator:
    def test_authenticate_and_verify(self):
        hmac_auth = HMACAuthenticator()
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .payload({"data": "test"})
            .build()
        )
        mac = hmac_auth.authenticate(msg)
        assert hmac_auth.verify(msg, mac) is True

    def test_verify_wrong_mac(self):
        hmac_auth = HMACAuthenticator()
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .payload({})
            .build()
        )
        assert hmac_auth.verify(msg, "invalid_mac") is False

    def test_raw_data_auth(self):
        hmac_auth = HMACAuthenticator()
        data = b"test data"
        mac = hmac_auth.authenticate_raw(data)
        assert hmac_auth.verify_raw(data, mac) is True
        assert hmac_auth.verify_raw(b"wrong data", mac) is False

    def test_different_keys_no_match(self):
        auth1 = HMACAuthenticator(generate_key())
        auth2 = HMACAuthenticator(generate_key())
        data = b"test"
        mac1 = auth1.authenticate_raw(data)
        assert auth2.verify_raw(data, mac1) is False


class TestSecretRedactor:
    def test_redact_dict(self):
        redactor = SecretRedactor()
        data = {
            "username": "admin",
            "password": "supersecret",
            "api_key": "sk-abc123xyz",
            "normal_field": "visible",
        }
        result = redactor.redact_dict(data)
        assert result["username"] == "admin"
        assert result["password"] == "[REDACTED]"
        assert result["api_key"] == "[REDACTED]"
        assert result["normal_field"] == "visible"

    def test_redact_nested_dict(self):
        redactor = SecretRedactor()
        data = {
            "config": {
                "db_password": "hidden",
                "db_host": "localhost",
            }
        }
        result = redactor.redact_dict(data)
        assert result["config"]["db_password"] == "[REDACTED]"
        assert result["config"]["db_host"] == "localhost"

    def test_redact_emails(self):
        redactor = SecretRedactor(redact_emails=True)
        text = "Contact us at admin@example.com for support."
        result = redactor.redact_string(text)
        assert "admin@example.com" not in result
        assert "[REDACTED]" in result

    def test_redact_inline_secrets(self):
        redactor = SecretRedactor()
        text = "My API key is sk-abc123def456ghi789jkl012mno345 and it's secret."
        result = redactor.redact_string(text)
        assert "sk-abc123" not in result
        assert "[REDACTED]" in result

    def test_redact_key_value_pairs(self):
        redactor = SecretRedactor()
        text = 'token=ghp_abc123def456ghi789jkl012mno and password=hunter2'
        result = redactor.redact_string(text)
        assert "[REDACTED]" in result
        assert "ghp_abc123" not in result
        assert "hunter2" not in result

    def test_audit_finds_secrets(self):
        redactor = SecretRedactor()
        text = "api_key=sk-abc123 password=test email=user@example.com"
        findings = redactor.audit(text)
        assert len(findings) > 0
        types = {f["type"] for f in findings}
        assert "sensitive_key" in types

    def test_custom_replacement(self):
        redactor = SecretRedactor(replacement="***HIDDEN***")
        data = {"password": "secret"}
        result = redactor.redact_dict(data)
        assert result["password"] == "***HIDDEN***"

    def test_no_redaction_of_ips_by_default(self):
        redactor = SecretRedactor()
        text = "Server at 192.168.1.1 is running."
        result = redactor.redact_string(text)
        assert "192.168.1.1" in result

    def test_redact_ips_when_enabled(self):
        redactor = SecretRedactor(redact_ips=True)
        text = "Server at 192.168.1.1 is running."
        result = redactor.redact_string(text)
        assert "192.168.1.1" not in result

    def test_redact_message_payload(self):
        redactor = SecretRedactor()
        msg = (
            MessageBuilder()
            .sender("a")
            .recipient("b")
            .type(MessageType.REQUEST)
            .payload({"password": "secret", "data": "public"})
            .build()
        )
        redacted = redactor.redact_message(msg)
        assert redacted.body.payload["password"] == "[REDACTED]"
        assert redacted.body.payload["data"] == "public"


# ===========================================================================
# CLI Tests
# ===========================================================================

class TestCLI:
    def test_ping(self):
        from fleet_protocol.cli import cmd_ping, build_parser
        parser = build_parser()
        args = parser.parse_args(["ping", "agent-1"])
        assert args.func(args) == 0

    def test_broadcast(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["broadcast", "hello fleet"])
        assert args.func(args) == 0

    def test_send(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["send", "agent-2", "hello there"])
        assert args.func(args) == 0

    def test_inbox(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["inbox"])
        assert args.func(args) == 0

    def test_registry_list(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["registry", "list"])
        assert args.func(args) == 0

    def test_registry_query(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["registry", "query", "--capability", "compute"])
        assert args.func(args) == 0

    def test_bottle_send(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "bottle", "send", "agent-2",
            "--payload", '{"msg": "hello"}',
        ])
        assert args.func(args) == 0

    def test_bottle_send_with_condition(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "bottle", "send", "agent-2",
            "--payload", '{"msg": "delayed"}',
            "--when", "agent_online:agent-2",
        ])
        assert args.func(args) == 0

    def test_keygen(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["keygen", "--agent-id", "test-agent"])
        assert args.func(args) == 0

    def test_sign_and_verify_file(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()

        # Create a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello Fleet Protocol!")
            temp_file = f.name

        try:
            # Sign
            args = parser.parse_args(["sign", temp_file])
            assert args.func(args) == 0
            assert os.path.exists(temp_file + ".sig")

            # Verify (format check only)
            args = parser.parse_args(["verify", temp_file, temp_file + ".sig"])
            assert args.func(args) == 0
        finally:
            os.unlink(temp_file)
            if os.path.exists(temp_file + ".sig"):
                os.unlink(temp_file + ".sig")

    def test_sign_nonexistent_file(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["sign", "/nonexistent/file.txt"])
        assert args.func(args) == 1

    def test_no_command_prints_help(self):
        from fleet_protocol.cli import build_parser, main
        assert main([]) == 0

    def test_version(self):
        from fleet_protocol.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--version"])


# ===========================================================================
# Utility Tests
# ===========================================================================

class TestUtilities:
    def test_hash_data(self):
        h1 = hash_data(b"test")
        h2 = hash_data(b"test")
        assert h1 == h2
        assert h1 != hash_data(b"different")

    def test_generate_key_length(self):
        key = generate_key()
        assert len(key) == KEY_LENGTH

    def test_generate_key_randomness(self):
        k1 = generate_key()
        k2 = generate_key()
        assert k1 != k2

    def test_b64encode_decode(self):
        data = b"hello fleet"
        encoded = b64encode(data)
        decoded = b64decode(encoded)
        assert decoded == data

    def test_b64decode_with_padding(self):
        data = b"test"
        encoded = b64encode(data)
        # Remove padding
        encoded_no_pad = encoded.rstrip("=")
        decoded = b64decode(encoded_no_pad)
        assert decoded == data


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestIntegration:
    def test_full_message_lifecycle(self):
        """Test message creation, signing, serialization, and deserialization."""
        identity = AgentIdentity.generate("agent-1")

        # Create message
        msg = (
            MessageBuilder()
            .sender("agent-1")
            .recipient("agent-2")
            .type(MessageType.REQUEST)
            .payload({"action": "deploy", "version": "1.0"})
            .requires_ack(True)
            .build()
        )

        # Validate
        is_valid, errors = MessageValidator.validate(msg)
        assert is_valid

        # Sign
        sig = MessageAuthenticator.sign(msg, identity)

        # Serialize to JSON
        json_str = msg.to_json()

        # Deserialize
        restored = FleetMessage.from_json(json_str)
        assert restored.header.sender == "agent-1"
        assert restored.body.payload["action"] == "deploy"

    def test_registry_sync_roundtrip(self):
        """Test registry creation, snapshot, and restore."""
        reg1 = FleetRegistry()
        reg1.register_agent(AgentRecord(agent_id="a1", capabilities=["compute"]))
        reg1.register_agent(AgentRecord(agent_id="a2", capabilities=["analyze"]))
        reg1.update_health(HealthRecord(agent_id="a1", status="healthy"))

        snapshot = reg1.get_snapshot()

        reg2 = FleetRegistry()
        success, conflicts = reg2.apply_snapshot(snapshot)
        assert success
        assert reg2.agent_count() == 2
        assert reg2.get_service("compute") is not None

    def test_bottle_with_security_context(self):
        """Test bottle delivery with security and condition evaluation."""
        router = BottleRouter()
        router.set_online_agents({"agent-2"})
        router.set_available_capabilities({"agent-2": ["compute"]})

        bottle = Bottle(
            sender="agent-1",
            intended_recipient="agent-2",
            payload={"action": "compute_task"},
            conditions=[
                DeliveryCondition(
                    condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                    target="agent-2",
                ),
                DeliveryCondition(
                    condition_type=DeliveryConditionType.CAPABILITY_AVAILABLE.value,
                    target="compute",
                ),
            ],
        )

        postmark = router.send(bottle)
        assert postmark.status == BottleStatus.DELIVERED.value

        inbox = router.get_inbox("agent-2")
        retrieved = inbox.retrieve(bottle.bottle_id)
        assert retrieved is not None
        assert retrieved.payload["action"] == "compute_task"

    def test_secret_redaction_in_message(self):
        """Test that secrets in messages can be redacted."""
        redactor = SecretRedactor()
        msg = (
            MessageBuilder()
            .sender("keeper")
            .recipient("agent-1")
            .type(MessageType.RESPONSE)
            .payload({
                "result": "ok",
                "credentials": {
                    "db_password": "supersecret123",
                    "api_key": "sk-abcdef123456",
                },
                "public_info": "this is fine",
            })
            .build()
        )

        redacted = redactor.redact_message(msg)
        assert redacted.body.payload["result"] == "ok"
        assert redacted.body.payload["credentials"]["db_password"] == "[REDACTED]"
        assert redacted.body.payload["credentials"]["api_key"] == "[REDACTED]"
        assert redacted.body.payload["public_info"] == "this is fine"
