"""
Stage 8 — TCP transport with length-prefix framing and timing capture.

Every message is:
    | 4-byte big-endian length | payload bytes |

Timing captured at both ends:
    send_ms  — monotonic time when the sender started writing
    arrive_ms — monotonic time when the receiver finished reading

Send/arrive are compared using time.time() (wall-clock ns from
CLOCK_REALTIME) so cross-machine deltas are meaningful when NTP is in
sync. Monotonic time is also recorded for intra-machine sanity.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


MSG_HEADER_FMT = ">I"
MSG_HEADER_LEN = struct.calcsize(MSG_HEADER_FMT)
CONNECT_TIMEOUT_S = 15.0
RECV_TIMEOUT_S = 60.0


class TransportError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, n: int, deadline_s: float) -> bytes:
    parts = []
    remaining = n
    while remaining > 0:
        left = deadline_s - time.monotonic()
        if left <= 0:
            raise TransportError(f"recv timeout waiting for {remaining} bytes")
        sock.settimeout(min(left, RECV_TIMEOUT_S))
        chunk = sock.recv(remaining)
        if not chunk:
            raise TransportError(f"peer closed after {n - remaining}/{n} bytes")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def send_message(sock: socket.socket, msg_type: str, payload: dict) -> Dict:
    """Send a JSON payload. Returns timing metadata."""
    body = json.dumps({"type": msg_type, "payload": payload,
                          "send_wall_ns": time.time_ns(),
                          "send_mono_ns": time.monotonic_ns()}).encode()
    frame = struct.pack(MSG_HEADER_FMT, len(body)) + body
    t0 = time.monotonic_ns()
    sock.sendall(frame)
    t1 = time.monotonic_ns()
    return {"bytes": len(frame), "send_mono_ns": t0, "send_finish_mono_ns": t1}


def recv_message(sock: socket.socket, deadline_s: float) -> Tuple[str, dict, Dict]:
    """Receive one message. Returns (type, payload, timing)."""
    hdr = _recv_exact(sock, MSG_HEADER_LEN, deadline_s)
    (length,) = struct.unpack(MSG_HEADER_FMT, hdr)
    if length > 128 * 1024 * 1024:
        raise TransportError(f"oversize message: {length} bytes")
    body = _recv_exact(sock, length, deadline_s)
    arrive_mono_ns = time.monotonic_ns()
    arrive_wall_ns = time.time_ns()
    obj = json.loads(body)
    return obj["type"], obj["payload"], {
        "bytes": MSG_HEADER_LEN + length,
        "send_wall_ns": obj.get("send_wall_ns"),
        "send_mono_ns": obj.get("send_mono_ns"),
        "arrive_wall_ns": arrive_wall_ns,
        "arrive_mono_ns": arrive_mono_ns,
    }


@dataclass
class ConnectionEndpoint:
    region: str
    host: str
    port: int


def connect_with_retry(endpoint: ConnectionEndpoint,
                        deadline_s: float) -> socket.socket:
    last_err = None
    while time.monotonic() < deadline_s:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(min(2.0, deadline_s - time.monotonic()))
            sock.connect((endpoint.host, endpoint.port))
            return sock
        except OSError as e:
            last_err = e
            time.sleep(0.25)
    raise TransportError(
        f"connect to {endpoint.region}:{endpoint.host}:{endpoint.port} failed: {last_err}")


def open_listener(host: str, port: int) -> socket.socket:
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen(64)
    return lsock
