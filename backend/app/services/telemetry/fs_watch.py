"""
Kernel change notifications (inotify, via ctypes) for the telemetry directory,
so the collector reads a sensor's log the moment it is written instead of on a
timer. ``start()`` returns False where inotify is unavailable; callers then poll.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import os
import platform
import struct
from typing import Dict, Optional

logger = logging.getLogger(__name__)

IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

_IN_NONBLOCK = 0o4000
_IN_CLOEXEC = 0o2000000

WATCH_MASK = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF
_HEADER = struct.Struct("iIII")


class DirectoryWatcher:
    """Recursive inotify watch that wakes a waiter once per burst of changes."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.available = False
        self.last_error: Optional[str] = None
        self.notifications = 0
        self._fd: Optional[int] = None
        self._libc = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._watches: Dict[int, str] = {}
        self._changed = asyncio.Event()

    @property
    def watch_count(self) -> int:
        return len(self._watches)

    def start(self) -> bool:
        """Begin watching. Must be called from inside the running event loop."""
        if platform.system() != "Linux":
            self.last_error = "inotify is Linux-only"
            return False
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
            fd = libc.inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
        except (OSError, AttributeError) as exc:
            self.last_error = f"inotify unavailable: {exc}"
            return False
        if fd < 0:
            self.last_error = f"inotify_init1 failed: {os.strerror(ctypes.get_errno())}"
            return False

        self._libc, self._fd = libc, fd
        for root, _dirs, _files in os.walk(self.directory):
            self._add_watch(root)
        if not self._watches:
            self.last_error = self.last_error or f"nothing to watch under {self.directory}"
            self.stop()
            return False

        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(fd, self._on_readable)
        self.available = True
        logger.info(f"inotify watching {len(self._watches)} director(ies) under {self.directory}")
        return True

    def _add_watch(self, path: str) -> None:
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            self.last_error = f"inotify_add_watch({path}) failed: {os.strerror(ctypes.get_errno())}"
            logger.warning(self.last_error)
            return
        self._watches[wd] = path

    def _on_readable(self) -> None:
        try:
            data = os.read(self._fd, 64 * 1024)
        except BlockingIOError:
            return
        except OSError as exc:
            self.last_error = f"inotify read failed: {exc}"
            return

        offset = 0
        while offset + _HEADER.size <= len(data):
            wd, mask, _cookie, length = _HEADER.unpack_from(data, offset)
            name = data[offset + _HEADER.size: offset + _HEADER.size + length].rstrip(b"\0")
            offset += _HEADER.size + length

            if mask & IN_IGNORED:
                self._watches.pop(wd, None)
                continue
            # A sensor that starts logging into a new sub-directory needs its own watch.
            if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                parent = self._watches.get(wd)
                if parent:
                    for root, _dirs, _files in os.walk(os.path.join(parent, os.fsdecode(name))):
                        self._add_watch(root)

        self.notifications += 1
        self._changed.set()

    async def wait(self, timeout: float) -> bool:
        """Block until the tree changes or ``timeout`` elapses. True if it changed."""
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except asyncio.TimeoutError:
            return False
        self._changed.clear()
        return True

    def stop(self) -> None:
        if self._fd is not None:
            if self._loop is not None:
                try:
                    self._loop.remove_reader(self._fd)
                except Exception:  # noqa: BLE001 — loop already closed during shutdown
                    pass
            os.close(self._fd)
        self._fd = None
        self._watches.clear()
        self.available = False
