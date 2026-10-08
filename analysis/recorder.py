"""Record real TCP traffic through a local proxy and write it as a pcap file.

Why a proxy: capturing on a network interface (Wireshark / dumpcap / tshark -i)
needs packet-capture privileges (root, or Wireshark's ChmodBPF on macOS).  This
recorder needs none: clients connect to the proxy, which forwards every byte to
the real server and records it with a timestamp.

What is real and what is synthesised in the resulting pcap:

* REAL: every application byte exchanged on each TCP connection (HTTP, TLS,
  WebSocket), its direction and its timestamp, and the connection open/close.
* SYNTHESISED: the Ethernet / IPv4 / TCP headers (needed for the pcap format),
  segmentation of each recorded chunk into 1460-byte segments (a typical
  Ethernet MSS), and the server port, set to 80 for plain HTTP and 443 for TLS so
  Wireshark applies its standard dissectors.  Pure ACK packets are not recorded.

So payload contents, payload sizes, request/response timing and protocol
overhead (TLS records, WebSocket framing, HTTP headers) are measured; per-packet
link-layer details are not.  For a capture of the real interface use Wireshark
(see docs/phase6.md); ``traffic_analysis.py`` reads either kind of file.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

MSS = 1460
CLIENT_IP = SERVER_IP = "127.0.0.1"


@dataclass
class Connection:
    conn_id: int
    client_port: int
    opened: float
    closed: float | None = None
    # (timestamp, "c2s" | "s2c", bytes)
    chunks: list[tuple[float, str, bytes]] = field(default_factory=list)


class RecordingProxy:
    """A threaded asyncio TCP proxy that records both directions."""

    def __init__(self, upstream_port: int, upstream_host: str = "127.0.0.1"):
        self.upstream = (upstream_host, upstream_port)
        self.connections: list[Connection] = []
        self._lock = threading.Lock()
        self._loop = asyncio.new_event_loop()
        self._server = None
        self._ready = threading.Event()
        self.port = 0
        self._thread = threading.Thread(target=self._run, daemon=True)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> "RecordingProxy":
        self._thread.start()
        self._ready.wait(5)
        return self

    def stop(self) -> None:
        async def _close():
            self._server.close()
            await self._server.wait_closed()

        asyncio.run_coroutine_threadsafe(_close(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            asyncio.start_server(self._handle, "127.0.0.1", 0)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    # -- forwarding ----------------------------------------------------------
    async def _handle(self, c_reader, c_writer):
        peer_port = c_writer.get_extra_info("peername")[1]
        with self._lock:
            conn = Connection(len(self.connections), peer_port, time.time())
            self.connections.append(conn)
        try:
            u_reader, u_writer = await asyncio.open_connection(*self.upstream)
        except OSError:
            c_writer.close()
            conn.closed = time.time()
            return

        async def pump(reader, writer, direction):
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    conn.chunks.append((time.time(), direction, data))
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(
            pump(c_reader, u_writer, "c2s"), pump(u_reader, c_writer, "s2c")
        )
        conn.closed = time.time()


# ---------------------------------------------------------------------------
# pcap writing (classic libpcap format, Ethernet link type)
# ---------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _frame(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    src = socket.inet_aton(CLIENT_IP)
    dst = socket.inet_aton(SERVER_IP)
    tcp_len = 20 + len(payload)
    tcp_wo_sum = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, tcp_len)
    tcp_sum = _checksum(pseudo + tcp_wo_sum + payload)
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 65535, tcp_sum, 0)
    ip_wo_sum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, 0, 0x4000, 64, 6, 0, src, dst)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, 0, 0x4000, 64, 6,
                     _checksum(ip_wo_sum), src, dst)
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip + tcp + payload


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def write_pcap(path, connections: list[Connection], server_port: int) -> int:
    """Write the recorded connections; returns the number of packets written."""
    records: list[tuple[float, bytes]] = []
    for conn in connections:
        cport, sport = conn.client_port, server_port
        c_seq, s_seq = 1000, 5000
        t0 = conn.opened
        records.append((t0, _frame(cport, sport, c_seq, 0, SYN, b"")))
        records.append((t0 + 1e-6, _frame(sport, cport, s_seq, c_seq + 1, SYN | ACK, b"")))
        c_seq += 1
        s_seq += 1
        records.append((t0 + 2e-6, _frame(cport, sport, c_seq, s_seq, ACK, b"")))
        for ts, direction, data in conn.chunks:
            for i in range(0, len(data), MSS):
                seg = data[i:i + MSS]
                if direction == "c2s":
                    records.append((ts, _frame(cport, sport, c_seq, s_seq, PSH | ACK, seg)))
                    c_seq += len(seg)
                else:
                    records.append((ts, _frame(sport, cport, s_seq, c_seq, PSH | ACK, seg)))
                    s_seq += len(seg)
        t_end = conn.closed or (conn.chunks[-1][0] if conn.chunks else t0)
        records.append((t_end, _frame(cport, sport, c_seq, s_seq, FIN | ACK, b"")))
        records.append((t_end + 1e-6, _frame(sport, cport, s_seq, c_seq + 1, FIN | ACK, b"")))

    records.sort(key=lambda r: r[0])
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, frame in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    return len(records)
