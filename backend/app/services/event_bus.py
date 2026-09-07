"""
In-process publish/subscribe for live event delivery.

The collector publishes normalized events here; the SSE endpoint subscribes and
streams them to connected dashboards. Deliberately in-memory: this is a
single-backend deployment, and adding Redis or a message broker to move events
between two coroutines in the same process would be infrastructure for its own
sake.

Delivery is best-effort and non-blocking. A subscriber whose queue is full
(a dashboard on a slow link, or a browser tab that was suspended) drops the
oldest event rather than applying backpressure to ingestion — telemetry
capture must never stall because someone's browser is behind. The database
remains the complete record; the stream is a live view of it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator, Dict, Set

logger = logging.getLogger(__name__)

# Per-subscriber buffer. Roughly 10 seconds of a very busy honeypot; beyond
# that a client is better served by reloading from the API than by replaying a
# long backlog.
SUBSCRIBER_QUEUE_SIZE = 256


class EventBus:
    """Fan-out of normalized events to every connected dashboard."""

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._dropped = 0

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def dropped_count(self) -> int:
        """Events discarded because a subscriber could not keep up."""
        return self._dropped

    def publish(self, event: Dict[str, Any]) -> None:
        """
        Push an event to every subscriber.

        Synchronous and non-blocking so the ingest path can call it without
        awaiting. Safe to call with no subscribers.
        """
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest to make room; a live view should show recent
                # activity, not stall on history.
                self._dropped += 1
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except Exception:
                    pass
            except Exception as exc:
                logger.debug(f"Event publish to subscriber failed: {exc}")

    def publish_many(self, events) -> None:
        """Publish a batch, preserving order."""
        for event in events:
            self.publish(event)

    async def subscribe(self) -> AsyncIterator[Dict[str, Any]]:
        """
        Async iterator over live events for one subscriber.

        The queue is registered on entry and always removed on exit, including
        when the client disconnects and the generator is closed — otherwise
        every dropped dashboard would leak a queue that publish() keeps
        writing to.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        self._subscribers.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)


# Module-level singleton — the collector and the API share this instance.
event_bus = EventBus()
