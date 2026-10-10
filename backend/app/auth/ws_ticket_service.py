"""
SOCRA AI — WebSocket handshake ticket service

Short-lived, single-use tickets used to authenticate WebSocket handshakes
without ever putting a JWT on the wire (or in a URL).

Flow:
1. The client calls the authenticated HTTP endpoint POST /live/ws-ticket
   with its normal JWT bearer token and receives a random ticket.
2. The client opens the WebSocket offering the ticket in the
   Sec-WebSocket-Protocol header:  socra.ticket.<ticket>
3. The server atomically consumes the ticket during the handshake. A ticket
   can be redeemed exactly once — a replay attempt finds nothing stored and
   is rejected. Tickets expire after a few seconds and expired tickets are
   pruned.

The ticket record is bound to the verified identity (sub / role / user_id)
of the JWT that was used to issue it, so a ticket can only ever open a
connection as the user who requested it.

Nothing derived from a ticket or JWT is ever logged by this module.
"""

import secrets
import threading
import time

# Subprotocol prefix used to carry a ticket in Sec-WebSocket-Protocol.
# The JWT itself is never accepted as a subprotocol and never echoed back.
TICKET_SUBPROTOCOL_PREFIX = "socra.ticket."

# Tickets are deliberately short-lived: long enough to cover one WebSocket
# handshake, far too short to be useful if leaked.
DEFAULT_TICKET_TTL_SECONDS = 30

# Cap on outstanding (un-consumed) tickets so a request flood cannot grow
# the in-memory store without bound. Oldest entries are pruned first.
_MAX_PENDING_TICKETS = 10_000


class WSTicketService:
    """In-memory, single-use, expiring WebSocket handshake tickets."""

    def __init__(self, ttl_seconds: float = DEFAULT_TICKET_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._tickets: dict = {}
        self._lock = threading.Lock()

    def issue(self, user_payload: dict):
        """Create a single-use ticket bound to an already-verified JWT payload.

        Returns (ticket, expires_in_seconds).
        """
        ticket = secrets.token_urlsafe(32)
        now = time.time()
        record = {
            # Identity the ticket is bound to (from the verified JWT).
            "sub": user_payload.get("sub"),
            "role": user_payload.get("role"),
            "user_id": user_payload.get("user_id"),
            "issued_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        with self._lock:
            self._prune_locked(now)
            # Enforce the pending cap: drop the oldest entries first so the
            # store stays bounded under unauthenticated-style floods.
            while len(self._tickets) >= _MAX_PENDING_TICKETS:
                oldest = min(self._tickets, key=lambda k: self._tickets[k]["issued_at"])
                del self._tickets[oldest]
            self._tickets[ticket] = record
        return ticket, int(self.ttl_seconds)

    def consume(self, ticket: str):
        """Atomically redeem a ticket. Returns the bound identity or None.

        The entry is removed BEFORE validation, so a ticket can never be
        redeemed twice (replay rejection) and an expired ticket cannot be
        retried either.
        """
        if not ticket:
            return None
        now = time.time()
        with self._lock:
            record = self._tickets.pop(ticket, None)
        if record is None:
            # Unknown, already used, or pruned — reject.
            return None
        if record["expires_at"] < now:
            # Expired — reject.
            return None
        return record

    def _prune_locked(self, now: float):
        expired = [k for k, rec in self._tickets.items() if rec["expires_at"] < now]
        for k in expired:
            del self._tickets[k]


def extract_ticket(subprotocol_header: str):
    """Pull the ticket out of a Sec-WebSocket-Protocol header value.

    A client may offer several protocols; only entries carrying the
    ``socra.ticket.`` prefix are considered. Returns "" when absent.
    """
    if not subprotocol_header:
        return ""
    for entry in subprotocol_header.split(","):
        entry = entry.strip()
        if entry.startswith(TICKET_SUBPROTOCOL_PREFIX):
            return entry[len(TICKET_SUBPROTOCOL_PREFIX):]
    return ""


ws_ticket_service = WSTicketService()
