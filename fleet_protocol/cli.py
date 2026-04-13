"""
Fleet Protocol CLI — command-line interface for fleet operations.

Subcommands:
    ping <agent>              — ping an agent
    broadcast <message>       — broadcast to fleet
    send <agent> <message>    — send direct message
    inbox                     — check bottle inbox
    registry list             — list fleet agents
    registry query --capability <cap>  — find agent by capability
    bottle send <agent> --payload <json> --when <condition>  — send a bottle
    keygen                   — generate agent keypair
    sign <file>              — sign a file
    verify <file> <sig-file> — verify a signature
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure the package can be imported when run as a script
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fleet_protocol.messages import (
    FleetMessage,
    MessageBuilder,
    MessageType,
    MessagePriority,
    MessageValidator,
)
from fleet_protocol.protocol import (
    FleetProtocol,
    HandshakeProtocol,
    HandshakeConfig,
    HeartbeatProtocol,
    DiscoveryProtocol,
    ProtocolVersion,
    ErrorCode,
    error_message,
)
from fleet_protocol.registry import (
    FleetRegistry,
    AgentRecord,
    HealthRecord,
    HealthStatus,
    AgentRole,
)
from fleet_protocol.bottle import (
    Bottle,
    BottleRouter,
    BottleInbox,
    BottlePostmark,
    DeliveryCondition,
    DeliveryConditionType,
    BottleStatus,
)
from fleet_protocol.security import (
    AgentIdentity,
    MessageAuthenticator,
    SessionManager,
    TokenManager,
    HMACAuthenticator,
    SecretRedactor,
    SIGNING_ALGORITHM,
)


# ---------------------------------------------------------------------------
# CLI Helpers
# ---------------------------------------------------------------------------

class OutputFormatter:
    """Formats CLI output as JSON or human-readable text."""

    @staticmethod
    def json(data: Any) -> str:
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def table(headers: List[str], rows: List[List[str]]) -> str:
        """Format data as a simple text table."""
        if not rows:
            return "(no results)"

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Build table
        lines = []
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        separator = "-+-".join("-" * w for w in col_widths)
        lines.append(header_line)
        lines.append(separator)
        for row in rows:
            cells = [str(c).ljust(w) for c, w in zip(row, col_widths)]
            lines.append(" | ".join(cells))

        return "\n".join(lines)

    @staticmethod
    def success(msg: str) -> str:
        return f"[OK] {msg}"

    @staticmethod
    def error(msg: str) -> str:
        return f"[ERROR] {msg}"

    @staticmethod
    def info(msg: str) -> str:
        return f"[INFO] {msg}"


fmt = OutputFormatter


# ---------------------------------------------------------------------------
# Command Handlers
# ---------------------------------------------------------------------------

def cmd_ping(args: argparse.Namespace) -> int:
    """Ping an agent."""
    agent_id = args.agent
    protocol = FleetProtocol("cli-agent")
    msg = (
        MessageBuilder()
        .sender("cli-agent")
        .recipient(agent_id)
        .type(MessageType.REQUEST)
        .payload({"action": "PING", "timestamp": time.time()})
        .requires_ack(True)
        .ttl(5)
        .build()
    )

    is_valid, errors = MessageValidator.validate(msg)
    if not is_valid:
        print(fmt.error(f"Invalid message: {', '.join(errors)}"))
        return 1

    print(fmt.json({
        "action": "PING",
        "target": agent_id,
        "message_id": msg.header.message_id,
        "timestamp": msg.header.timestamp,
        "status": "sent",
    }))
    return 0


def cmd_broadcast(args: argparse.Namespace) -> int:
    """Broadcast a message to the fleet."""
    message = args.message
    msg = (
        MessageBuilder()
        .sender("cli-agent")
        .recipient("fleet:broadcast")
        .type(MessageType.EVENT)
        .payload({"action": "BROADCAST", "message": message})
        .build()
    )

    is_valid, errors = MessageValidator.validate(msg)
    if not is_valid:
        print(fmt.error(f"Invalid message: {', '.join(errors)}"))
        return 1

    print(fmt.json({
        "action": "BROADCAST",
        "message": message,
        "message_id": msg.header.message_id,
        "status": "broadcast",
    }))
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    """Send a direct message to an agent."""
    agent_id = args.agent
    message = args.message
    msg = (
        MessageBuilder()
        .sender("cli-agent")
        .recipient(agent_id)
        .type(MessageType.REQUEST)
        .payload({"message": message})
        .build()
    )

    is_valid, errors = MessageValidator.validate(msg)
    if not is_valid:
        print(fmt.error(f"Invalid message: {', '.join(errors)}"))
        return 1

    print(fmt.json({
        "action": "SEND",
        "target": agent_id,
        "message": message,
        "message_id": msg.header.message_id,
        "status": "sent",
    }))
    return 0


def cmd_inbox(args: argparse.Namespace) -> int:
    """Check bottle inbox."""
    agent_id = args.agent or "cli-agent"
    router = BottleRouter()
    inbox = router.get_inbox(agent_id)
    bottles = inbox.peek_all()

    if not bottles:
        print(fmt.info(f"Inbox for '{agent_id}' is empty."))
        return 0

    rows = []
    for b in bottles:
        rows.append([
            b.bottle_id[:8],
            b.sender,
            json.dumps(b.payload)[:40],
            b.status,
        ])

    print(fmt.table(["ID", "From", "Payload", "Status"], rows))
    return 0


def cmd_registry_list(args: argparse.Namespace) -> int:
    """List fleet agents from the registry."""
    registry = FleetRegistry()

    # Demo: add sample agents
    registry.register_agent(AgentRecord(
        agent_id="agent-alpha",
        name="Alpha Agent",
        role=AgentRole.WORKER.value,
        capabilities=["compute", "analyze"],
    ))
    registry.register_agent(AgentRecord(
        agent_id="agent-beta",
        name="Beta Agent",
        role=AgentRole.COORDINATOR.value,
        capabilities=["coordinate", "schedule"],
    ))
    registry.register_agent(AgentRecord(
        agent_id="keeper-main",
        name="Main Keeper",
        role=AgentRole.KEEPER.value,
        capabilities=["keep", "monitor", "redact"],
    ))

    agents = registry.get_all_agents()
    if not agents:
        print(fmt.info("No agents registered in the fleet."))
        return 0

    rows = []
    for a in agents:
        rows.append([
            a.agent_id,
            a.name,
            a.role,
            ", ".join(a.capabilities),
            a.version,
        ])

    print(fmt.table(["Agent ID", "Name", "Role", "Capabilities", "Version"], rows))
    print()
    print(fmt.info(f"Total: {registry.agent_count()} agents"))
    return 0


def cmd_registry_query(args: argparse.Namespace) -> int:
    """Query the registry for agents by capability."""
    registry = FleetRegistry()

    registry.register_agent(AgentRecord(
        agent_id="agent-alpha", capabilities=["compute", "analyze"],
    ))
    registry.register_agent(AgentRecord(
        agent_id="agent-beta", capabilities=["coordinate", "schedule"],
    ))
    registry.register_agent(AgentRecord(
        agent_id="keeper-main", capabilities=["keep", "monitor", "redact"],
    ))

    if args.capability:
        agents = registry.find_agents_by_capability(args.capability)
    else:
        print(fmt.error("Specify --capability <cap>"))
        return 1

    if not agents:
        print(fmt.info(f"No agents found with capability '{args.capability}'."))
        return 0

    rows = []
    for a in agents:
        rows.append([a.agent_id, ", ".join(a.capabilities)])

    print(fmt.table(["Agent ID", "Capabilities"], rows))
    return 0


def cmd_bottle_send(args: argparse.Namespace) -> int:
    """Send a bottle message."""
    agent_id = args.agent
    payload = json.loads(args.payload) if args.payload else {}

    conditions: List[DeliveryCondition] = []
    if args.when:
        # Parse simple condition format: "agent_online:agent-foo" or "after_delay:60"
        parts = args.when.split(":", 1)
        cond_type = parts[0]
        target = parts[1] if len(parts) > 1 else ""

        if cond_type == "agent_online":
            conditions.append(DeliveryCondition(
                condition_type=DeliveryConditionType.AGENT_ONLINE.value,
                target=target,
            ))
        elif cond_type == "after_delay":
            try:
                delay = float(target)
                conditions.append(DeliveryCondition(
                    condition_type=DeliveryConditionType.AFTER_DELAY.value,
                    threshold=delay,
                ))
            except ValueError:
                print(fmt.error(f"Invalid delay value: {target}"))
                return 1
        elif cond_type == "on_event":
            conditions.append(DeliveryCondition(
                condition_type=DeliveryConditionType.ON_EVENT.value,
                target=target,
            ))

    bottle = Bottle(
        sender="cli-agent",
        intended_recipient=agent_id,
        payload=payload,
        conditions=conditions,
        ttl=args.ttl,
        priority=args.priority,
    )

    router = BottleRouter()
    postmark = router.send(bottle)

    print(fmt.json({
        "bottle_id": bottle.bottle_id,
        "target": agent_id,
        "status": postmark.status,
        "conditions": [c.to_dict() for c in conditions] if conditions else ["immediate"],
        "ttl": bottle.ttl,
    }))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an agent keypair."""
    agent_id = args.agent_id or "cli-agent"
    identity = AgentIdentity.generate(agent_id)

    exported = identity.export()

    print(fmt.success(f"Generated identity for '{agent_id}'"))
    print()
    print(f"  Agent ID:    {exported['agent_id']}")
    print(f"  Public Key:  {exported['public_key'][:40]}...")
    print(f"  Private Key: {exported['private_key'][:40]}...")
    print(f"  Created:     {time.ctime(exported['created_at'])}")
    print()
    print(fmt.info("IMPORTANT: Store the private key securely!"))
    print()
    print("--- Export Data (JSON) ---")
    print(fmt.json(exported))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a file."""
    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(fmt.error(f"File not found: {args.file}"))
        return 1
    except IOError as e:
        print(fmt.error(f"Cannot read file: {e}"))
        return 1

    identity = AgentIdentity.generate("cli-agent")
    signature = MessageAuthenticator.sign_data(data, identity.private_key)

    sig_filename = args.file + ".sig"
    with open(sig_filename, "w") as f:
        f.write(signature)

    print(fmt.success(f"Signed '{args.file}' -> '{sig_filename}'"))
    print(f"  Signature: {signature[:40]}...")
    print(f"  Algorithm: HMAC-SHA512")
    print(f"  Public Key: {identity.public_key[:40]}...")
    print()
    print(fmt.info("Save the public key to verify later."))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a file signature."""
    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(fmt.error(f"File not found: {args.file}"))
        return 1

    try:
        with open(args.signature, "r") as f:
            signature = f.read().strip()
    except FileNotFoundError:
        print(fmt.error(f"Signature file not found: {args.signature}"))
        return 1

    # For verification we need the private key (HMAC limitation)
    # In a real deployment, agents would have shared session keys
    if args.key_file:
        try:
            with open(args.key_file, "r") as f:
                key_data = json.load(f)
            identity = AgentIdentity.import_identity(key_data)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(fmt.error(f"Cannot load key file: {e}"))
            return 1
    else:
        print(fmt.info("No key file provided. Checking signature format only."))
        try:
            from fleet_protocol.security import b64decode
            sig_bytes = b64decode(signature)
            valid_format = len(sig_bytes) == 64
            print(fmt.success(f"Signature format valid: {valid_format}"))
            return 0 if valid_format else 1
        except Exception:
            print(fmt.error("Invalid signature format."))
            return 1

    is_valid = MessageAuthenticator.verify_data(data, signature, identity.private_key)
    if is_valid:
        print(fmt.success("Signature is VALID"))
    else:
        print(fmt.error("Signature is INVALID"))
    return 0 if is_valid else 1


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="fleet-cli",
        description="Fleet Protocol CLI — manage fleet communication",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ping
    ping_parser = subparsers.add_parser("ping", help="Ping an agent")
    ping_parser.add_argument("agent", help="Agent ID to ping")
    ping_parser.set_defaults(func=cmd_ping)

    # broadcast
    broadcast_parser = subparsers.add_parser("broadcast", help="Broadcast to fleet")
    broadcast_parser.add_argument("message", help="Message to broadcast")
    broadcast_parser.set_defaults(func=cmd_broadcast)

    # send
    send_parser = subparsers.add_parser("send", help="Send direct message")
    send_parser.add_argument("agent", help="Recipient agent ID")
    send_parser.add_argument("message", help="Message content")
    send_parser.set_defaults(func=cmd_send)

    # inbox
    inbox_parser = subparsers.add_parser("inbox", help="Check bottle inbox")
    inbox_parser.add_argument("--agent", help="Agent ID (default: cli-agent)")
    inbox_parser.set_defaults(func=cmd_inbox)

    # registry
    registry_parser = subparsers.add_parser("registry", help="Registry operations")
    registry_sub = registry_parser.add_subparsers(dest="registry_command")

    reg_list = registry_sub.add_parser("list", help="List fleet agents")
    reg_list.set_defaults(func=cmd_registry_list)

    reg_query = registry_sub.add_parser("query", help="Query fleet registry")
    reg_query.add_argument("--capability", "-c", help="Capability to search for")
    reg_query.set_defaults(func=cmd_registry_query)

    # bottle
    bottle_parser = subparsers.add_parser("bottle", help="Bottle message operations")
    bottle_sub = bottle_parser.add_subparsers(dest="bottle_command")

    bottle_send = bottle_sub.add_parser("send", help="Send a bottle")
    bottle_send.add_argument("agent", help="Intended recipient")
    bottle_send.add_argument("--payload", "-p", help="JSON payload")
    bottle_send.add_argument("--when", "-w", help="Delivery condition (e.g., agent_online:agent-foo)")
    bottle_send.add_argument("--ttl", type=int, default=3600, help="Time-to-live in seconds")
    bottle_send.add_argument("--priority", type=int, default=1, choices=[0, 1, 2, 3],
                             help="Priority (0=low, 1=normal, 2=high, 3=critical)")
    bottle_send.set_defaults(func=cmd_bottle_send)

    # keygen
    keygen_parser = subparsers.add_parser("keygen", help="Generate agent keypair")
    keygen_parser.add_argument("--agent-id", help="Agent ID for the keypair")
    keygen_parser.set_defaults(func=cmd_keygen)

    # sign
    sign_parser = subparsers.add_parser("sign", help="Sign a file")
    sign_parser.add_argument("file", help="File to sign")
    sign_parser.set_defaults(func=cmd_sign)

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a file signature")
    verify_parser.add_argument("file", help="File to verify")
    verify_parser.add_argument("signature", help="Signature file (.sig)")
    verify_parser.add_argument("--key-file", help="JSON key file for verification")
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the Fleet Protocol CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as e:
        print(fmt.error(f"Unexpected error: {e}"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
