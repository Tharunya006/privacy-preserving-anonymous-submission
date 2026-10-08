"""Phase 6: PyShark analysis of protected vs unprotected traffic.

Reads pcap files (from ``traffic_capture.py`` or from a real Wireshark
capture), dissects them with tshark through PyShark, and reports:

* packet counts and sizes (frame and TCP payload: min / median / mean / max)
* communication overhead: header bytes, TLS handshake and record overhead,
  WebSocket framing
* timing: capture duration, HTTP response times (``http.time``), TLS handshake
  duration per connection
* plaintext exposure: each marker value (report title/body, photo EXIF camera
  serial, submission token, session cookie, journalist password) is searched for
  in the reassembled bytes of every TCP stream, in both directions
* the WebSocket messages actually sent (unprotected capture only)

Usage:
    python -m analysis.traffic_analysis                    # the two default captures
    python -m analysis.traffic_analysis my.pcap --server-port 5001 --markers markers.json

Writes analysis/results/traffic_report.md and traffic_report.json.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
from collections import defaultdict
from pathlib import Path

from urllib.parse import quote, quote_plus

import pyshark

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "analysis" / "results"
TSHARK_CANDIDATES = [
    shutil.which("tshark"),
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark",
    "C:\\Program Files\\Wireshark\\tshark.exe",
]


def find_tshark() -> str | None:
    for path in TSHARK_CANDIDATES:
        if path and Path(path).exists():
            return path
    return None


def _all(layer, name: str) -> list[str]:
    """Every occurrence of a field in a layer (PDML mode can repeat fields)."""
    field = layer.get_field(name)
    if field is None:
        return []
    return [f.get_default_value() for f in getattr(field, "all_fields", [field])]


def _stats(values: list[int]) -> dict:
    if not values:
        return {"count": 0}
    return {
        "count": len(values), "total": sum(values), "min": min(values),
        "median": statistics.median(values), "mean": round(statistics.fmean(values), 1),
        "max": max(values),
    }


def analyse(pcap: Path, search: dict[str, str], tshark: str,
            server_port: int | None = None) -> dict:
    decode_as = {f"tcp.port=={server_port}": "http"} if server_port else None
    cap = pyshark.FileCapture(str(pcap), tshark_path=tshark, decode_as=decode_as,
                              keep_packets=False)

    frame_sizes, payload_sizes, http_times = [], [], []
    streams = defaultdict(lambda: {"c2s": bytearray(), "s2c": bytearray()})
    server_ports: dict[str, int] = {}
    tls = {"handshake_bytes": 0, "app_data_bytes": 0, "other_bytes": 0, "records": 0}
    tls_hello_time, tls_first_app = {}, {}
    ws_messages, http_requests = [], []
    first_ts = last_ts = None

    for pkt in cap:
        ts = float(pkt.sniff_timestamp)
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts
        frame_sizes.append(int(pkt.length))
        if "TCP" not in pkt:
            continue
        tcp = pkt.tcp
        stream = tcp.stream
        flags_syn = tcp.flags_syn == "1" or tcp.flags_syn == "True"
        flags_ack = tcp.flags_ack == "1" or tcp.flags_ack == "True"
        if flags_syn and not flags_ack:
            server_ports[stream] = int(tcp.dstport)
        sport = server_ports.get(stream, server_port)
        direction = "s2c" if sport is not None and int(tcp.srcport) == sport else "c2s"

        length = int(tcp.len)
        if length:
            payload_sizes.append(length)
            raw = tcp.get_field_value("payload")
            if raw:
                streams[stream][direction] += bytes.fromhex(raw.replace(":", ""))

        if "HTTP" in pkt:
            http = pkt.http
            method = http.get_field_value("request_method")
            if method:
                http_requests.append(f"{method} {http.get_field_value('request_uri')}")
            t = http.get_field_value("time")
            if t:
                http_times.append(round(float(t) * 1000, 2))

        if "TLS" in pkt:
            for layer in pkt.get_multiple_layers("tls"):
                # TLS 1.3 encrypted records carry "opaque_type" (always 23) and
                # follow any plaintext handshake records in the same packet.
                types = _all(layer, "tls.record.content_type") + \
                    ["23"] * len(_all(layer, "tls.record.opaque_type"))
                lengths = _all(layer, "tls.record.length")
                for ctype, rlen in zip(types, lengths):
                    size = int(rlen) + 5  # record header
                    tls["records"] += 1
                    if ctype == "22":
                        tls["handshake_bytes"] += size
                    elif ctype == "23":
                        tls["app_data_bytes"] += size
                        if direction == "c2s":
                            tls_first_app.setdefault(stream, ts)
                    else:
                        tls["other_bytes"] += size
                if "1" in _all(layer, "tls.handshake.type"):
                    tls_hello_time.setdefault(stream, ts)

        if "WEBSOCKET" in pkt:
            for layer in pkt.get_multiple_layers("websocket"):
                text = layer.get_field_value("websocket.payload.text") or \
                    layer.get_field_value("payload_text")
                if text:
                    ws_messages.append({"direction": direction, "text": str(text)})
    cap.close()

    exposure = {}
    for name, value in search.items():
        if not value:
            continue
        # Form posts URL-encode values (e.g. "!" -> "%21"), so search every form.
        needles = {value.encode(), quote_plus(value).encode(), quote(value, safe="").encode()}
        exposure[name] = any(n in s["c2s"] or n in s["s2c"]
                             for s in streams.values() for n in needles)

    handshake_ms = [round((tls_first_app[s] - tls_hello_time[s]) * 1000, 2)
                    for s in tls_hello_time if s in tls_first_app]
    total_frame = sum(frame_sizes)
    total_payload = sum(payload_sizes)
    return {
        "file": str(pcap.relative_to(ROOT)) if pcap.is_relative_to(ROOT) else str(pcap),
        "packets": len(frame_sizes),
        "tcp_streams": len(streams) or len(server_ports),
        "duration_ms": round((last_ts - first_ts) * 1000, 1) if first_ts else 0,
        "frame_bytes": _stats(frame_sizes),
        "tcp_payload_bytes": _stats(payload_sizes),
        "header_overhead_bytes": total_frame - total_payload,
        "header_overhead_pct": round(100 * (total_frame - total_payload) / total_frame, 1) if total_frame else 0,
        "http_requests_visible": http_requests,
        "http_response_times_ms": _stats(http_times) if http_times else {"count": 0},
        "tls": {**tls, "handshake_ms": _stats(handshake_ms) if handshake_ms else {"count": 0}},
        "websocket_messages_visible": ws_messages,
        "plaintext_exposure": exposure,
    }


def _fmt_bool(found: bool) -> str:
    return "**VISIBLE**" if found else "not visible"


def report(results: list[dict], meta: dict | None) -> str:
    by_mode = {r["mode"]: r for r in results}
    http, https = by_mode.get("http"), by_mode.get("https")
    lines = ["# Phase 6 traffic analysis (generated)", ""]
    if meta:
        lines += [f"Captured: {meta.get('captured_at')}. Same scripted workflow in both runs "
                  "(journalist login + WebSocket, anonymous submission with an EXIF/GPS photo, "
                  "journalist reads/downloads/updates, source status check).", ""]
    lines += [
        "Capture method: real TCP payload bytes and timestamps recorded by "
        "`analysis/recorder.py`; Ethernet/IP/TCP headers synthesised (1460-byte MSS). "
        "Dissected with tshark via PyShark.", "",
    ]
    if http and https:
        h, s = http["analysis"], https["analysis"]
        rows = [
            ("Packets", h["packets"], s["packets"]),
            ("TCP connections", h["tcp_streams"], s["tcp_streams"]),
            ("Bytes on the wire (frames)", h["frame_bytes"]["total"], s["frame_bytes"]["total"]),
            ("Application bytes (TCP payload)", h["tcp_payload_bytes"]["total"], s["tcp_payload_bytes"]["total"]),
            ("Frame size median / mean / max", f"{h['frame_bytes']['median']} / {h['frame_bytes']['mean']} / {h['frame_bytes']['max']}",
             f"{s['frame_bytes']['median']} / {s['frame_bytes']['mean']} / {s['frame_bytes']['max']}"),
            ("Ethernet+IP+TCP header bytes", f"{h['header_overhead_bytes']} ({h['header_overhead_pct']}%)",
             f"{s['header_overhead_bytes']} ({s['header_overhead_pct']}%)"),
            ("Plaintext TLS handshake records (ClientHello/ServerHello) bytes", "-", s["tls"]["handshake_bytes"]),
            ("TLS records (all)", "-", s["tls"]["records"]),
            ("TLS handshake time per connection (median ms)", "-", s["tls"]["handshake_ms"].get("median", "-")),
            ("HTTP requests readable on the wire", len(h["http_requests_visible"]), len(s["http_requests_visible"])),
            ("WebSocket messages readable on the wire", len(h["websocket_messages_visible"]), len(s["websocket_messages_visible"])),
        ]
        extra = s["tcp_payload_bytes"]["total"] - h["tcp_payload_bytes"]["total"]
        lines += ["## Protected vs unprotected", "",
                  "| Metric | HTTP + ws:// (unprotected) | HTTPS + wss:// (protected) |",
                  "|---|---|---|"]
        lines += [f"| {a} | {b} | {c} |" for a, b, c in rows]
        lines += ["", f"TLS cost for this workflow: **{extra:+,} application bytes** "
                  f"({100 * extra / h['tcp_payload_bytes']['total']:+.1f}%). It comes from one TLS "
                  f"handshake per connection ({s['tcp_streams']} here; in TLS 1.3 the certificate "
                  "and key-exchange messages are themselves encrypted, so only the ClientHello/"
                  "ServerHello records are counted as handshake above) and about 21 bytes per "
                  "encrypted record (5-byte header + 16-byte AEAD tag).", ""]

        lines += ["## Plaintext exposure on the wire", "",
                  "| Value searched for | HTTP + ws:// | HTTPS + wss:// |", "|---|---|---|"]
        for name in h["plaintext_exposure"]:
            lines.append(f"| {name.replace('_', ' ')} | {_fmt_bool(h['plaintext_exposure'][name])} | "
                         f"{_fmt_bool(s['plaintext_exposure'].get(name, False))} |")
        lines += ["", "The photo's EXIF camera serial is visible on unprotected HTTP because "
                  "metadata is removed on the server, after upload: transport encryption (TLS) "
                  "is what protects the upload itself.", ""]

        lines += ["## Storage (Phase 5) after each run", "",
                  "| Value | Database | Evidence files |", "|---|---|---|"]
        for mode in ("http", "https"):
            scan = by_mode[mode]["storage_scan"]
            for name in scan["database"]:
                lines.append(f"| {mode}: {name.replace('_', ' ')} | {_fmt_bool(scan['database'][name])} | "
                             f"{_fmt_bool(scan['evidence files'][name])} |")
        lines += ["", "## WebSocket messages seen in the unprotected capture", ""]
        lines += [f"- `{m['direction']}` `{m['text'][:160]}`" for m in h["websocket_messages_visible"]] or ["- (none)"]
        lines += ["", "## Client-measured request times (ms)", "",
                  "| Step | HTTP | HTTPS |", "|---|---|---|"]
        for step, value in http["client_timings_ms"].items():
            lines.append(f"| {step} | {value} | {https['client_timings_ms'].get(step, '-')} |")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("pcaps", nargs="*", type=Path)
    parser.add_argument("--server-port", type=int, help="decode this TCP port as HTTP")
    parser.add_argument("--markers", type=Path, help="JSON object of name -> value to search for")
    args = parser.parse_args()

    tshark = find_tshark()
    if not tshark:
        raise SystemExit("tshark not found: install Wireshark (it includes tshark).")

    if args.pcaps:
        search = json.loads(args.markers.read_text()) if args.markers else {}
        out = [analyse(p, search, tshark, args.server_port) for p in args.pcaps]
        print(json.dumps(out, indent=2))
        return

    meta = json.loads((RESULTS / "capture_meta.json").read_text())
    results = []
    for run in meta["runs"]:
        search = {**run["search_values"], **run["secret_values"]}
        run = {**run, "analysis": analyse(ROOT / run["pcap"], search, tshark)}
        results.append(run)

    public = []
    for run in results:  # never write secret values into the report files
        clean = {k: v for k, v in run.items() if k not in ("secret_values", "search_values")}
        public.append(clean)
    (RESULTS / "traffic_report.json").write_text(json.dumps(public, indent=2))
    (RESULTS / "traffic_report.md").write_text(report(results, meta))
    print((RESULTS / "traffic_report.md").read_text())


if __name__ == "__main__":
    main()
