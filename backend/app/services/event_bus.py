"""
In-process publish/subscribe for live delivery.

Publishers: the collector ("event" — normalized honeypot events), the detection
loop ("detection" — cycles that produced detections or incidents) and the
container metrics sampler ("metrics"). The SSE endpoint fans all channels out
to connected browsers. One backend process owns ingestion, so an in-memory bus
is sufficient; a multi-process deployment would put a shared broker behind this
same interface.

Delivery is non-blocking. A subscriber whose queue is full (a slow link, a
suspended tab) loses its oldest message rather than applying backpressure to
ingestion. The database stays the complete record; the stream is a live view.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator, Dict, FrozenSet, Iterable, Optional, Tuple

logger = logging.getLogger(__name__)

# Per-subscriber buffer. Roughly 10 seconds of a very busy honeypot; beyond
# that a client is better served by reloading from the API than by replaying a
# long backlog.
SUBSCRIBER_QUEUE_SIZE = 256

Message = Tuple[str, Dict[str, Any]]


class EventBus:
    """Fan-out of live messages to every connected dashboard."""

    def __init__(self) -> None:
        # queue -> channels it wants (None means every channel)
        self._subscribers: Dict[asyncio.Queue, Optional[FrozenSet[str]]] = {}
        self._dropped = 0
        self._published: Dict[str, int] = {}

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def dropped_count(self) -> int:
        """Messages discarded because a subscriber could not keep up."""
        return self._dropped

    @property
    def published_counts(self) -> Dict[str, int]:
        return dict(self._published)

    def publish(self, payload: Dict[str, Any], channel: str = "event") -> None:
        """
        Push a message to every subscriber of ``channel``.

        Synchronous and non-blocking so ingestion can call it without awaiting.
        Safe to call with no subscribers.
        """
        self._published[channel] = self._published.get(channel, 0) + 1
        message: Message = (channel, payload)
        for queue, channels in list(self._subscribers.items()):
            if channels is not None and channel not in channels:
                continue
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop the oldest to make room; a live view should show recent
                # activity, not stall on history.
                self._dropped += 1
                try:
                    queue.get_nowait()
                    queue.put_nowait(message)
                except Exception:
                    pass
            except Exception as exc:
                logger.debug(f"Publish to subscriber failed: {exc}")

    def publish_many(self, payloads: Iterable[Dict[str, Any]], channel: str = "event") -> None:
        """Publish a batch, preserving order."""
        for payload in payloads:
            self.publish(payload, channel)

    def open(self, channels: Optional[Iterable[str]] = None) -> asyncio.Queue:
        """
        Register a queue of ``(channel, payload)`` messages. Always pair with
        close(). Await ``queue.get()`` directly: cancelling that (e.g. on a
        heartbeat timeout) is safe, unlike cancelling an async generator.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        self._subscribers[queue] = frozenset(channels) if channels is not None else None
        return queue

    def close(self, queue: asyncio.Queue) -> None:
        self._subscribers.pop(queue, None)

    async def subscribe(self) -> AsyncIterator[Dict[str, Any]]:
        """Async iterator over normalized honeypot events (the "event" channel)."""
        queue = self.open(("event",))
        try:
            while True:
                _channel, payload = await queue.get()
                yield payload
        finally:
            self.close(queue)


# Module-level singleton — publishers and the API share this instance.
event_bus = EventBus()
