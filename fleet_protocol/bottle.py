"""
Message-in-a-Bottle Protocol — async coordination for fleet agents.

The "bottle" message system provides delayed, directed messaging with
conditional delivery, TTL management, hop counting, and delivery confirmation.
"""

from __future__ import annotations

import copy
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from fleet_protocol.messages import (
    FleetMessage,
    MessageBuilder,
    MessageType,
    MessagePriority,
    MessageValidator,
)


# ---------------------------------------------------------------------------
# Bottle Delivery Conditions
# ---------------------------------------------------------------------------

class DeliveryConditionType(str, Enum):
    """Types of delivery conditions for bottles."""
    AGENT_ONLINE = "agent_online"          # when agent X is online
    AFTER_TIME = "after_time"              # after timestamp T
    AFTER_DELAY = "after_delay"            # after delay D seconds from now
    ON_EVENT = "on_event"                  # when event E occurs
    CAPABILITY_AVAILABLE = "capability_available"  # when capability C is available
    IMMEDIATE = "immediate"                # deliver immediately (default)
    ON_ACK = "on_ack"                      # when another message is acknowledged


@dataclass
class DeliveryCondition:
    """
    A condition that must be met before a bottle is delivered.

    Attributes:
        condition_type: The type of condition.
        target: The target of the condition (agent ID, capability name, event name, etc.).
        threshold: A numeric threshold (timestamp, delay in seconds).
        requires_all: If True, ALL conditions must be met; if False, ANY suffices.
    """
    condition_type: str = DeliveryConditionType.IMMEDIATE.value
    target: str = ""
    threshold: float = 0.0
    requires_all: bool = False

    def is_met(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate whether this condition is met given the current context.

        Context keys:
            - "online_agents": Set[str] — agents currently online
            - "available_capabilities": Dict[str, List[str]] — agent -> capabilities
            - "events_fired": Set[str] — events that have occurred
            - "current_time": float — current timestamp
            - "acked_messages": Set[str] — message IDs that have been acked
        """
        now = context.get("current_time", time.time())

        if self.condition_type == DeliveryConditionType.IMMEDIATE.value:
            return True

        elif self.condition_type == DeliveryConditionType.AGENT_ONLINE.value:
            online = context.get("online_agents", set())
            return self.target in online

        elif self.condition_type == DeliveryConditionType.AFTER_TIME.value:
            return now >= self.threshold

        elif self.condition_type == DeliveryConditionType.AFTER_DELAY.value:
            created = context.get("bottle_created_time", now)
            return (now - created) >= self.threshold

        elif self.condition_type == DeliveryConditionType.ON_EVENT.value:
            events = context.get("events_fired", set())
            return self.target in events

        elif self.condition_type == DeliveryConditionType.CAPABILITY_AVAILABLE.value:
            caps = context.get("available_capabilities", {})
            for agent_id, agent_caps in caps.items():
                if self.target in agent_caps:
                    return True
            return False

        elif self.condition_type == DeliveryConditionType.ON_ACK.value:
            acked = context.get("acked_messages", set())
            return self.target in acked

        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "condition_type": self.condition_type,
            "target": self.target,
            "threshold": self.threshold,
            "requires_all": self.requires_all,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeliveryCondition:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Bottle
# ---------------------------------------------------------------------------

class BottleStatus(str, Enum):
    """Lifecycle status of a bottle."""
    PENDING = "pending"
    CONDITION_NOT_MET = "condition_not_met"
    IN_TRANSIT = "in_transit"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class Bottle:
    """
    A delayed/directed message — the "bottle" in the Message-in-a-Bottle protocol.

    Bottles carry payloads between agents with configurable delivery conditions,
    TTL, priority, and hop counting for relay scenarios.

    Attributes:
        bottle_id: Unique identifier.
        sender: Agent sending the bottle.
        intended_recipient: Agent meant to receive the bottle.
        payload: The message payload data.
        conditions: List of delivery conditions (all must be met if requires_all).
        ttl: Time-to-live in seconds.
        max_hops: Maximum relay hops allowed.
        priority: Delivery priority.
        created_at: Creation timestamp.
        status: Current lifecycle status.
        hops: Number of hops so far.
        created_time: For delay-based conditions.
    """
    bottle_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = ""
    intended_recipient: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    conditions: List[DeliveryCondition] = field(default_factory=list)
    ttl: int = 3600  # 1 hour default
    max_hops: int = 10
    priority: int = MessagePriority.NORMAL.value
    created_at: float = field(default_factory=time.time)
    status: str = BottleStatus.PENDING.value
    hops: int = 0
    created_time: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if the bottle has exceeded its TTL."""
        return (time.time() - self.created_at) > self.ttl

    def is_deliverable(self, context: Dict[str, Any]) -> bool:
        """
        Check if delivery conditions are met.

        Args:
            context: Evaluation context (online agents, events, time, etc.)
        """
        if not self.conditions:
            return True

        # Check if any condition requires_all
        requires_all = any(c.requires_all for c in self.conditions)

        # Add bottle_created_time for delay conditions
        ctx = dict(context)
        ctx["bottle_created_time"] = self.created_time

        if requires_all:
            return all(c.is_met(ctx) for c in self.conditions)
        else:
            return any(c.is_met(ctx) for c in self.conditions)

    def can_relay(self) -> bool:
        """Check if the bottle can be relayed further."""
        return self.hops < self.max_hops and not self.is_expired()

    def copy(self) -> Bottle:
        """Return a deep copy of this bottle."""
        import copy
        return copy.deepcopy(self)

    def to_fleet_message(self) -> FleetMessage:
        """Convert this bottle to a FleetMessage for transport."""
        return (
            MessageBuilder()
            .sender(self.sender)
            .recipient(self.intended_recipient)
            .type(MessageType.EVENT)
            .payload({
                "action": "BOTTLE_DELIVERY",
                "bottle_id": self.bottle_id,
                "payload": self.payload,
                "hops": self.hops,
            })
            .priority(MessagePriority(int(self.priority)))
            .ttl(self.ttl)
            .build()
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bottle_id": self.bottle_id,
            "sender": self.sender,
            "intended_recipient": self.intended_recipient,
            "payload": self.payload,
            "conditions": [c.to_dict() for c in self.conditions],
            "ttl": self.ttl,
            "max_hops": self.max_hops,
            "priority": self.priority,
            "created_at": self.created_at,
            "status": self.status,
            "hops": self.hops,
            "created_time": self.created_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Bottle:
        conditions = [
            DeliveryCondition.from_dict(c) for c in data.get("conditions", [])
        ]
        return cls(
            bottle_id=data.get("bottle_id", str(uuid.uuid4())),
            sender=data.get("sender", ""),
            intended_recipient=data.get("intended_recipient", ""),
            payload=data.get("payload", {}),
            conditions=conditions,
            ttl=data.get("ttl", 3600),
            max_hops=data.get("max_hops", 10),
            priority=data.get("priority", MessagePriority.NORMAL.value),
            created_at=data.get("created_at", time.time()),
            status=data.get("status", BottleStatus.PENDING.value),
            hops=data.get("hops", 0),
            created_time=data.get("created_time", time.time()),
        )

    def __repr__(self) -> str:
        return (
            f"Bottle(id={self.bottle_id[:8]}, "
            f"from={self.sender}, "
            f"to={self.intended_recipient}, "
            f"status={self.status})"
        )


# ---------------------------------------------------------------------------
# Bottle Postmark — delivery confirmation and tracking
# ---------------------------------------------------------------------------

@dataclass
class BottlePostmark:
    """
    Delivery confirmation record for a bottle.

    Tracks when a bottle was created, dispatched, delivered, or failed,
    along with routing information.
    """
    bottle_id: str
    status: str = BottleStatus.PENDING.value
    created_at: float = field(default_factory=time.time)
    dispatched_at: Optional[float] = None
    delivered_at: Optional[float] = None
    failed_at: Optional[float] = None
    failure_reason: str = ""
    route: List[str] = field(default_factory=list)  # agent IDs in the route
    current_holder: str = ""

    def mark_dispatched(self, holder: str) -> None:
        """Mark the bottle as dispatched to a holder."""
        self.dispatched_at = time.time()
        self.status = BottleStatus.IN_TRANSIT.value
        self.current_holder = holder
        self.route.append(holder)

    def mark_delivered(self) -> None:
        """Mark the bottle as delivered."""
        self.delivered_at = time.time()
        self.status = BottleStatus.DELIVERED.value
        self.current_holder = self.route[-1] if self.route else ""

    def mark_failed(self, reason: str) -> None:
        """Mark the bottle as failed."""
        self.failed_at = time.time()
        self.status = BottleStatus.FAILED.value
        self.failure_reason = reason

    def mark_expired(self) -> None:
        """Mark the bottle as expired."""
        self.failed_at = time.time()
        self.status = BottleStatus.EXPIRED.value
        self.failure_reason = "TTL exceeded"

    def delivery_time_ms(self) -> Optional[float]:
        """Calculate delivery time in milliseconds."""
        if self.delivered_at and self.dispatched_at:
            return (self.delivered_at - self.dispatched_at) * 1000
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bottle_id": self.bottle_id,
            "status": self.status,
            "created_at": self.created_at,
            "dispatched_at": self.dispatched_at,
            "delivered_at": self.delivered_at,
            "failed_at": self.failed_at,
            "failure_reason": self.failure_reason,
            "route": self.route,
            "current_holder": self.current_holder,
        }


# ---------------------------------------------------------------------------
# Bottle Inbox — per-agent inbox for received bottles
# ---------------------------------------------------------------------------

class BottleInbox:
    """
    Per-agent inbox for received bottles.

    Bottles are stored here until the owning agent retrieves them.
    Supports priority-based retrieval and expiration cleanup.
    """

    def __init__(self, agent_id: str, max_capacity: int = 1000) -> None:
        self.agent_id = agent_id
        self.max_capacity = max_capacity
        self._inbox: Dict[str, Bottle] = {}
        self._delivered_ids: Set[str] = set()

    def add(self, bottle: Bottle) -> bool:
        """
        Add a bottle to the inbox.

        Returns:
            True if the bottle was added, False if inbox is full or duplicate.
        """
        if bottle.bottle_id in self._inbox or bottle.bottle_id in self._delivered_ids:
            return False  # Duplicate
        if len(self._inbox) >= self.max_capacity:
            return False  # Full

        bottle.status = BottleStatus.DELIVERED.value
        self._inbox[bottle.bottle_id] = bottle
        return True

    def retrieve(self, bottle_id: str) -> Optional[Bottle]:
        """Retrieve and remove a bottle from the inbox."""
        return self._inbox.pop(bottle_id, None)

    def retrieve_all(self) -> List[Bottle]:
        """Retrieve and remove all bottles from the inbox."""
        bottles = list(self._inbox.values())
        self._inbox.clear()
        return bottles

    def retrieve_by_priority(self) -> List[Bottle]:
        """Retrieve bottles sorted by priority (highest first)."""
        bottles = sorted(
            self._inbox.values(),
            key=lambda b: b.priority,
            reverse=True,
        )
        self._inbox.clear()
        return bottles

    def peek(self, bottle_id: str) -> Optional[Bottle]:
        """Peek at a bottle without removing it."""
        return self._inbox.get(bottle_id)

    def peek_all(self) -> List[Bottle]:
        """Peek at all bottles without removing them."""
        return list(self._inbox.values())

    def count(self) -> int:
        """Return the number of bottles in the inbox."""
        return len(self._inbox)

    def cleanup_expired(self) -> int:
        """Remove expired bottles. Returns count of removed bottles."""
        expired_ids = [
            bid for bid, bottle in self._inbox.items()
            if bottle.is_expired()
        ]
        for bid in expired_ids:
            bottle = self._inbox.pop(bid)
            bottle.status = BottleStatus.EXPIRED.value
            self._delivered_ids.add(bid)
        return len(expired_ids)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capacity": self.max_capacity,
            "count": self.count(),
            "bottles": [b.to_dict() for b in self._inbox.values()],
        }


# ---------------------------------------------------------------------------
# Bottle Router — routes bottles between agents
# ---------------------------------------------------------------------------

class BottleRouter:
    """
    Routes bottles between agents in the fleet.

    Handles conditional delivery, TTL enforcement, hop counting,
    and delivery tracking via postmarks.
    """

    def __init__(self) -> None:
        self._pending: Dict[str, Bottle] = {}
        self._inboxes: Dict[str, BottleInbox] = {}
        self._postmarks: Dict[str, BottlePostmark] = {}
        self._delivery_context: Dict[str, Any] = {
            "online_agents": set(),
            "available_capabilities": {},
            "events_fired": set(),
            "acked_messages": set(),
        }

    @property
    def context(self) -> Dict[str, Any]:
        """Get the current delivery evaluation context."""
        ctx = dict(self._delivery_context)
        ctx["current_time"] = time.time()
        return ctx

    def update_context(self, key: str, value: Any) -> None:
        """Update a context variable for condition evaluation."""
        self._delivery_context[key] = value

    def fire_event(self, event_name: str) -> None:
        """Record that an event has fired."""
        self._delivery_context.setdefault("events_fired", set()).add(event_name)

    def set_online_agents(self, agent_ids: Set[str]) -> None:
        """Update the set of online agents."""
        self._delivery_context["online_agents"] = agent_ids

    def set_available_capabilities(self, caps: Dict[str, List[str]]) -> None:
        """Update available capabilities mapping."""
        self._delivery_context["available_capabilities"] = caps

    def get_inbox(self, agent_id: str) -> BottleInbox:
        """Get or create an inbox for an agent."""
        if agent_id not in self._inboxes:
            self._inboxes[agent_id] = BottleInbox(agent_id)
        return self._inboxes[agent_id]

    def send(self, bottle: Bottle) -> BottlePostmark:
        """
        Send a bottle through the router.

        The bottle will be evaluated for delivery conditions. If conditions
        are met, it is delivered immediately; otherwise, it is queued as pending.

        Returns:
            BottlePostmark tracking the bottle's delivery status.
        """
        postmark = BottlePostmark(
            bottle_id=bottle.bottle_id,
            current_holder=bottle.sender,
        )
        self._postmarks[bottle.bottle_id] = postmark

        # Check immediate deliverability
        if bottle.is_deliverable(self.context):
            self._deliver(bottle, postmark)
        else:
            bottle.status = BottleStatus.CONDITION_NOT_MET.value
            self._pending[bottle.bottle_id] = bottle

        return postmark

    def _deliver(self, bottle: Bottle, postmark: BottlePostmark) -> None:
        """Deliver a bottle to its intended recipient's inbox."""
        inbox = self.get_inbox(bottle.intended_recipient)
        success = inbox.add(bottle)

        if success:
            postmark.mark_dispatched(bottle.intended_recipient)
            postmark.mark_delivered()
            bottle.status = BottleStatus.DELIVERED.value
        else:
            postmark.mark_failed("Inbox full or duplicate")
            bottle.status = BottleStatus.FAILED.value

    def relay(self, bottle: Bottle, relay_agent: str) -> Optional[BottlePostmark]:
        """
        Relay a bottle through an intermediate agent.

        Returns:
            New postmark for the relay, or None if relay not possible.
        """
        if not bottle.can_relay():
            pm = self._postmarks.get(bottle.bottle_id)
            if pm:
                pm.mark_failed("Max hops exceeded or expired")
            return None

        relayed = bottle.copy()
        relayed.hops += 1
        relayed.status = BottleStatus.IN_TRANSIT.value

        pm = self._postmarks.get(bottle.bottle_id)
        if pm:
            pm.mark_dispatched(relay_agent)

        # Attempt delivery
        if relayed.is_deliverable(self.context):
            if pm is None:
                pm = BottlePostmark(bottle.bottle_id)
                self._postmarks[bottle.bottle_id] = pm
            pm.mark_dispatched(relay_agent)
            self._deliver(relayed, pm)
            return self._postmarks.get(bottle.bottle_id)

        return None

    def process_pending(self) -> List[Bottle]:
        """
        Evaluate all pending bottles for delivery.

        Returns:
            List of bottles that were successfully delivered.
        """
        delivered: List[Bottle] = []
        expired_ids: List[str] = []

        for bid, bottle in list(self._pending.items()):
            # Check TTL
            if bottle.is_expired():
                bottle.status = BottleStatus.EXPIRED.value
                pm = self._postmarks.get(bid)
                if pm:
                    pm.mark_expired()
                expired_ids.append(bid)
                continue

            # Check conditions
            if bottle.is_deliverable(self.context):
                pm = self._postmarks.get(bid)
                if pm is None:
                    pm = BottlePostmark(bottle_id=bid)
                    self._postmarks[bid] = pm
                self._deliver(bottle, pm)
                delivered.append(bottle)
                expired_ids.append(bid)

        for bid in expired_ids:
            self._pending.pop(bid, None)

        return delivered

    def cancel(self, bottle_id: str) -> bool:
        """Cancel a pending or in-transit bottle."""
        bottle = self._pending.pop(bottle_id, None)
        if bottle:
            bottle.status = BottleStatus.CANCELLED.value
            pm = self._postmarks.get(bottle_id)
            if pm:
                pm.mark_failed("Cancelled")
            return True
        return False

    def get_postmark(self, bottle_id: str) -> Optional[BottlePostmark]:
        """Get the delivery tracking postmark for a bottle."""
        return self._postmarks.get(bottle_id)

    def get_all_postmarks(self) -> List[BottlePostmark]:
        """Get all postmarks."""
        return list(self._postmarks.values())

    def get_pending_count(self) -> int:
        """Return the number of pending bottles."""
        return len(self._pending)

    def get_stats(self) -> Dict[str, Any]:
        """Get router statistics."""
        postmarks = list(self._postmarks.values())
        delivered = sum(1 for p in postmarks if p.status == BottleStatus.DELIVERED.value)
        failed = sum(1 for p in postmarks if p.status == BottleStatus.FAILED.value)
        expired = sum(1 for p in postmarks if p.status == BottleStatus.EXPIRED.value)
        in_transit = sum(1 for p in postmarks if p.status == BottleStatus.IN_TRANSIT.value)

        return {
            "pending": len(self._pending),
            "delivered": delivered,
            "failed": failed,
            "expired": expired,
            "in_transit": in_transit,
            "inboxes": {aid: inbox.count() for aid, inbox in self._inboxes.items()},
        }
