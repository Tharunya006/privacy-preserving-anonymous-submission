"""Phase 6 analysis tooling: the recording proxy, the pcap writer and the
PyShark analyser (the analyser tests need Wireshark's tshark and are skipped
only when it is not installed)."""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from analysis.benchmark import timeit
from analysis.recorder import MSS, RecordingProxy, write_pcap
from analysis.traffic_analysis import analyse, find_tshark

TSHARK = find_tshark()
needs_tshark = pytest.mark.skipif(TSHARK is None, reason="Wireshark's tshark is not installed")

REQUEST = (b"POST /submit HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: 40\r\n\r\ntitle=SECRET-MARKER&content=Pa%21ss+word")
RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2400\r\n\r\n"
            + b"R" * 2400)


@pytest.fixture()
def fake_server():
    """A tiny HTTP-ish server answering one request per connection."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn:
                conn.recv(65536)
                conn.sendall(RESPONSE)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(2)
    srv.close()


def record_one_exchange(port):
    proxy = RecordingProxy(port).start()
    with socket.create_connection(("127.0.0.1", proxy.port)) as client:
        client.sendall(REQUEST)
        received = b""
        while len(received) < len(RESPONSE):
            chunk = client.recv(65536)
            if not chunk:
                break
            received += chunk
    time.sleep(0.2)
    proxy.stop()
    return proxy, received


class TestRecorder:
    def test_proxy_forwards_and_records_both_directions(self, fake_server):
        proxy, received = record_one_exchange(fake_server)
        assert received == RESPONSE  # the client got exactly what the server sent
        assert len(proxy.connections) == 1
        conn = proxy.connections[0]
        c2s = b"".join(d for _, direction, d in conn.chunks if direction == "c2s")
        s2c = b"".join(d for _, direction, d in conn.chunks if direction == "s2c")
        assert c2s == REQUEST and s2c == RESPONSE
        assert conn.closed is not None

    def test_pcap_is_valid_and_segments_at_the_mss(self, fake_server, tmp_path):
        proxy, _ = record_one_exchange(fake_server)
        path = tmp_path / "t.pcap"
        packets = write_pcap(path, proxy.connections, 80)
        data = path.read_bytes()
        magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
        assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 1)
        offset, frames = 24, []
        while offset < len(data):
            _, _, incl, orig = struct.unpack("<IIII", data[offset:offset + 16])
            frames.append(data[offset + 16:offset + 16 + incl])
            assert incl == orig
            offset += 16 + incl
        assert len(frames) == packets
        assert max(len(f) - 54 for f in frames) <= MSS  # 14 Ethernet + 20 IP + 20 TCP


@needs_tshark
class TestPySharkAnalysis:
    def test_markers_and_sizes_are_found(self, fake_server, tmp_path):
        proxy, _ = record_one_exchange(fake_server)
        path = tmp_path / "t.pcap"
        write_pcap(path, proxy.connections, 80)
        result = analyse(path, {"title": "SECRET-MARKER", "password": "Pa!ss word",
                                "absent": "NOT-IN-CAPTURE"}, TSHARK)
        assert result["plaintext_exposure"] == {"title": True, "password": True, "absent": False}
        assert result["http_requests_visible"] == ["POST /submit"]
        assert result["tcp_payload_bytes"]["total"] == len(REQUEST) + len(RESPONSE)
        assert result["frame_bytes"]["max"] <= MSS + 54

    def test_encrypted_payload_hides_markers(self, fake_server, tmp_path):
        """Bytes that are not plaintext (here: XOR-scrambled) do not match."""
        proxy, _ = record_one_exchange(fake_server)
        for conn in proxy.connections:
            conn.chunks = [(t, d, bytes(b ^ 0x5A for b in data)) for t, d, data in conn.chunks]
        path = tmp_path / "t.pcap"
        write_pcap(path, proxy.connections, 443)
        result = analyse(path, {"title": "SECRET-MARKER"}, TSHARK)
        assert result["plaintext_exposure"] == {"title": False}
        assert result["http_requests_visible"] == []


def test_benchmark_timer_reports_statistics():
    stats = timeit(lambda: sum(range(100)), 5)
    assert stats["runs"] == 5
    assert 0 <= stats["median_ms"] <= stats["p95_ms"]
