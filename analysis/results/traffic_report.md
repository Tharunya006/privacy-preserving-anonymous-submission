# Phase 6 traffic analysis (generated)

Captured: 2026-10-08 23:53:27 IST. Same scripted workflow in both runs (journalist login + WebSocket, anonymous submission with an EXIF/GPS photo, journalist reads/downloads/updates, source status check).

Capture method: real TCP payload bytes and timestamps recorded by `analysis/recorder.py`; Ethernet/IP/TCP headers synthesised (1460-byte MSS). Dissected with tshark via PyShark.

## Protected vs unprotected

| Metric | HTTP + ws:// (unprotected) | HTTPS + wss:// (protected) |
|---|---|---|
| Packets | 132 | 194 |
| TCP connections | 13 | 13 |
| Bytes on the wire (frames) | 68494 | 104816 |
| Application bytes (TCP payload) | 61366 | 94340 |
| Frame size median / mean / max | 60.0 / 518.9 / 1514 | 309.0 / 540.3 / 1514 |
| Ethernet+IP+TCP header bytes | 7128 (10.4%) | 10476 (10.0%) |
| Plaintext TLS handshake records (ClientHello/ServerHello) bytes | - | 8372 |
| TLS records (all) | - | 195 |
| TLS handshake time per connection (median ms) | - | 0.72 |
| HTTP requests readable on the wire | 13 | 0 |
| WebSocket messages readable on the wire | 7 | 0 |

TLS cost for this workflow: **+32,974 application bytes** (+53.7%). It comes from one TLS handshake per connection (13 here; in TLS 1.3 the certificate and key-exchange messages are themselves encrypted, so only the ClientHello/ServerHello records are counted as handshake above) and about 21 bytes per encrypted record (5-byte header + 16-byte AEAD tag).

## Plaintext exposure on the wire

| Value searched for | HTTP + ws:// | HTTPS + wss:// |
|---|---|---|
| report title | **VISIBLE** | not visible |
| report body | **VISIBLE** | not visible |
| photo exif camera | **VISIBLE** | not visible |
| submission token | **VISIBLE** | not visible |
| journalist session cookie | **VISIBLE** | not visible |
| journalist password | **VISIBLE** | not visible |

The photo's EXIF camera serial is visible on unprotected HTTP because metadata is removed on the server, after upload: transport encryption (TLS) is what protects the upload itself.

## Storage (Phase 5) after each run

| Value | Database | Evidence files |
|---|---|---|
| http: report title | not visible | not visible |
| http: report body | not visible | not visible |
| http: photo exif camera | not visible | not visible |
| http: submission token | not visible | not visible |
| https: report title | not visible | not visible |
| https: report body | not visible | not visible |
| https: photo exif camera | not visible | not visible |
| https: submission token | not visible | not visible |

## WebSocket messages seen in the unprotected capture

- `s2c` `0{"sid":"pUvxnw5-v9wMWMjTAAAA","upgrades":[],"pingTimeout":20000,"pingInterval":25000,"maxPayload":1000000}`
- `c2s` `40{}`
- `s2c` `40{"sid":"ahy7UKH89pFPfVQ7AAAB"}`
- `s2c` `42["new_submission",{"message":"A new anonymous submission has been received."}]`
- `s2c` `42["submission_status_changed",{"id":1,"status":"UNDER_REVIEW","message":"Submission #1 is now Under review."}]`
- `c2s` `41`
- `c2s` `1`

## Client-measured request times (ms)

| Step | HTTP | HTTPS |
|---|---|---|
| journalist GET /auth/login | 12.58 | 13.72 |
| journalist POST /auth/login | 89.54 | 89.78 |
| journalist WebSocket connect | 1.96 | 2.86 |
| source GET /submit | 3.07 | 3.94 |
| source POST /submit (with photo) | 14.84 | 12.52 |
| journalist GET inbox | 4.9 | 5.89 |
| journalist GET report | 5.83 | 6.81 |
| journalist GET evidence | 2.69 | 3.48 |
| journalist POST status | 5.47 | 7.11 |
| source GET /status | 2.75 | 3.49 |
| source POST /status | 1.61 | 2.53 |
