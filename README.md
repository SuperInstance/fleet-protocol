# Fleet Protocol

![CI](https://github.com/SuperInstance/fleet-protocol/workflows/CI/badge.svg)

> The shared language, wire format, and coordination protocol for the SuperInstance fleet.

## Overview

Fleet Protocol is the foundation library that ALL standalone agents use to communicate within the SuperInstance. It provides a common message format, wire protocol, agent registry, async coordination, and security primitives — built entirely on the Python standard library.

## Modules

| Module | Description |
|---|---|
| `messages` | `FleetMessage` dataclass, message types, JSON + binary serialization, validation, builder pattern |
| `protocol` | Protocol versioning, handshake sequence, heartbeat monitoring, discovery broadcasts, capability negotiation, error codes |
| `registry` | Agent registry, service registry, health registry, sync snapshots, anti-entropy conflict detection |
| `bottle` | Message-in-a-Bottle async coordination — conditional delivery, TTL, hop counting, delivery tracking |
| `security` | Agent identity (keypair generation), HMAC message signing/verification, DH session establishment, token auth, secret redaction |
| `cli` | Command-line interface for fleet operations (ping, broadcast, send, inbox, registry, bottle, keygen, sign, verify) |

## Installation

```bash
pip install -e .
```

## Quick Start

```python
from fleet_protocol import *

# Build a message
msg = (MessageBuilder()
    .sender("agent-alpha")
    .recipient("agent-beta")
    .type(MessageType.REQUEST)
    .payload({"action": "scan", "target": "fleet"})
    .priority(MessagePriority.HIGH)
    .requires_ack(True)
    .build())

# Serialize
json_str = msg.to_json()
binary = msg.to_binary()

# Validate
valid, errors = MessageValidator.validate(msg)

# Generate identity
identity = AgentIdentity.generate("agent-alpha")

# Sign
signature = MessageAuthenticator.sign(msg, identity)
```

## CLI

```bash
fleet-cli ping agent-beta
fleet-cli broadcast "Fleet-wide announcement"
fleet-cli send agent-beta "Direct message"
fleet-cli inbox --agent agent-beta
fleet-cli registry list
fleet-cli registry query --capability compute
fleet-cli bottle send agent-beta --payload '{"task": "deploy"}' --when "agent_online:agent-beta"
fleet-cli keygen --agent-id agent-alpha
fleet-cli sign config.json
fleet-cli verify config.json config.json.sig
```

## Running Tests

```bash
cd /home/z/my-project/fleet/fleet-protocol
python -m pytest tests/ -v
```

## Design Principles

- **Stdlib only** — zero external dependencies (hashlib, hmac, secrets, json, struct, uuid)
- **Type hints everywhere** — full type annotation for IDE support and static analysis
- **Rock solid** — comprehensive test suite with integration tests
- **Secure by default** — HMAC signing, session keys, secret redaction built-in
