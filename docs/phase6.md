# Phase 6: Real-time Communication and Traffic Analysis

Phase 6 adds a real-time WebSocket channel (Flask-SocketIO) for authorized
journalists, and the tooling and measurements that show what the system's
protections actually do on the network and in storage: Wireshark/PyShark
traffic analysis, protected vs unprotected comparison, packet sizes, timing and
overhead, and timing of every cryptographic and scrubbing step.

The application now runs all six phases together: one Flask app, one database.

---

## 1. Where Phase 6 came from

| Part | Source |
|---|---|
| Flask-SocketIO extension, authenticated `connect` handler (authorized journalists only), `journalists` room, content-free `new_submission` event, `socketio.run` | **Bhavya**, `origin/bhavya/phase6` (commit `758bc04`), merged with her authorship preserved |
| Everything else in this document | completed during integration |

Not taken from her branch, and why:

* **The `cdn.socket.io` `<script>` on every page**, and the CSP relaxation it
  needed. Every page includes the anonymous source pages, so each source's IP
  address would have been sent to a third-party CDN. The official client is
  vendored instead (§3.4).

Gaps in her branch that were completed:

* the connection was authorized only once, at connect, so a journalist disabled
  afterwards kept receiving events;
* no tests;
* a `print()` of usernames;
* the client used CSS classes the UI redesign had replaced;
* `socketio.run` needed `allow_unsafe_werkzeug` to start outside debug mode.

## 2. What Phase 6 covers (and what it deliberately does not)

There is no synopsis document in the repository, so the scope follows the
requirements given for this phase:

| Requirement | Status |
|---|---|
| Flask-SocketIO / WebSocket real-time communication | **Implemented** (§3) |
| Wireshark capture/analysis | **Implemented**: pcap files readable in Wireshark/tshark, and a documented real-interface capture procedure (§4.5) |
| PyShark traffic analysis | **Implemented**: `analysis/traffic_analysis.py` |
| Protected vs unprotected traffic comparison | **Implemented**: HTTP + `ws://` vs HTTPS + `wss://`, same workflow (§4) |
| Packet size, timing, communication overhead | **Implemented** (§4.3, §5) |
| Protected data not exposed as plaintext (traffic and storage) | **Demonstrated and tested** (§4.2) |
| Encryption / decryption / HMAC / hashing / scrubbing timing | **Measured** (§5) |
| Tor / onion routing, traffic obfuscation, dummy traffic, random delays | **Not implemented, by decision**: nothing in the project's documented design (Phases 1-5) claims network-level anonymity, and adding one of these would not make the claim true on its own. See §8 |

---

## 3. Real-time notifications (Flask-SocketIO)

### 3.1 What happens

```
anonymous source --POST /submit--> create_submission (validate, scrub, encrypt, commit)
                                            |
                                            v
                          notify_new_submission()  (after the commit)
                                            |
           for each connected journalist socket: re-read the account from the DB
             - still JOURNALIST + AUTHORIZED, no temporary password,
               socket younger than the session lifetime?  -> emit the event
             - otherwise                                   -> disconnect it
                                            |
                                            v
 journalist's browser (vendored Socket.IO client) -> toast: "A new anonymous
 submission has been received." [Open inbox]
```

A status change made by one journalist notifies the others in the same way
(`submission_status_changed`).

### 3.2 Who may connect

The Socket.IO `connect` handler uses the same signed session cookie and the same
checks as every HTTP request (`load_current_user`: session signature, idle
timeout, account re-read from the database).

| Visitor | Result |
|---|---|
| Authorized journalist | connected |
| Anonymous visitor / anonymous source | refused (sources never even load the client) |
| Admin | refused (admins never see report content, as on HTTP) |
| Pending or disabled journalist, or temporary password not yet changed | refused |
| Expired / forged session cookie | refused |
| Request from a foreign `Origin` (cross-site WebSocket hijacking) | refused by Socket.IO's same-origin check (HTTP 400) |

**Revocation while connected:** before *every* delivery each socket's account is
re-checked; a journalist who was disabled, set back to pending, demoted or
given a temporary password is disconnected instead of receiving the event.
Sockets older than the session lifetime (30 min) are dropped the same way.

### 3.3 What is sent

| Event | Payload (complete) |
|---|---|
| `new_submission` | `{"message": "A new anonymous submission has been received."}` |
| `submission_status_changed` | `{"id": 3, "status": "UNDER_REVIEW", "message": "Submission #3 is now Under review."}` |

Never sent: report titles or text, submission tokens, evidence, file names,
keys, or anything about the source. The tests check the exact payloads, and the
unprotected capture (§4) shows these are the only messages on the wire.

A notification failure is logged and swallowed: it can never break a source's
submission. The event is emitted only after the submission is committed.

### 3.4 Client and CSP

* `phase2/static/phase2/vendor/socket.io.min.js` is the **official Socket.IO 4.8.1
  client** (MIT, licence alongside). It came from the npm registry tarball,
  verified against the registry's published SHA-512 integrity value. A test pins
  its SHA-256 and checks it contains no `eval`.
* It is loaded **only on journalist pages**. Public pages, the source pages and
  admin pages load no socket code and open no connection.
* The Content-Security-Policy is unchanged: `script-src 'self'`.

### 3.5 Running

`python app.py` starts the app with `socketio.run`. It is still Werkzeug's
development server, as before Phase 6. Flask-SocketIO runs in `threading` mode
with real WebSocket transport (via `simple-websocket`). For a real deployment,
use a production server and run one process (or add a Socket.IO message queue),
because connected sockets are tracked per process.

Optional TLS (HTTPS + WSS):

```bash
PHASE6_TLS=adhoc python app.py                               # throw-away self-signed cert (demo)
PHASE6_TLS_CERT=cert.pem PHASE6_TLS_KEY=key.pem python app.py  # your certificate
```

With TLS also set `PHASE2_COOKIE_SECURE=true`.

### 3.6 A bug found and fixed while testing over HTTPS

Since Phase 2 the app sent `Referrer-Policy: no-referrer`. Over HTTPS, Flask-WTF's
CSRF protection requires a same-origin `Referer` header, so **every form failed
with 400 over HTTPS** (login, submission, status change). It had never been run
over HTTPS before. The policy is now **`same-origin`**: the `Referer` goes only to
this site, still never to any other. Regression tests check that HTTPS forms
work with a same-origin `Referer` and are still refused without one or with a
foreign one.

---

## 4. Traffic analysis: protected vs unprotected

### 4.1 Method

```bash
pip install -r requirements.txt -r analysis/requirements.txt   # + Wireshark (for tshark)
python -m analysis.traffic_capture     # runs the app twice (HTTP, then HTTPS) and records traffic
python -m analysis.traffic_analysis    # PyShark analysis -> analysis/results/traffic_report.md
```

The **same scripted workflow** runs over both transports:
1. A journalist signs in and opens the WebSocket.
2. An anonymous source submits a report with a photo carrying EXIF/GPS data.
3. The journalist receives the event, reads the report, downloads the evidence
   and moves it to *Under review* (second event).
4. The source checks the status with the token.

**How the traffic is captured (be precise about this in the viva).** Capturing
on a network interface needs packet-capture privileges (root, or Wireshark's
ChmodBPF on macOS). `analysis/recorder.py` instead routes every connection
through a local recording proxy:

* **Real:** every application byte (HTTP, TLS, WebSocket), its direction and its
  timestamp, and connection open/close.
* **Synthesised:** the Ethernet/IP/TCP headers that the pcap format needs.
  Payloads are split into 1460-byte segments (a typical Ethernet MSS). Server
  ports 80/443 are used so Wireshark applies its standard dissectors. Pure ACKs
  are omitted.

The resulting `.pcap` files open in Wireshark and are dissected by tshark/PyShark
(HTTP, TLS 1.3 and WebSocket are all recognised). For a capture of the real
interface see §4.5; `traffic_analysis.py` reads either kind.

### 4.2 Plaintext exposure

Generated results (`analysis/results/traffic_report.md`):

| Value searched for in every TCP stream | HTTP + ws:// | HTTPS + wss:// |
|---|---|---|
| report title | **visible** | not visible |
| report body | **visible** | not visible |
| photo EXIF camera serial | **visible** | not visible |
| submission token | **visible** | not visible |
| journalist session cookie | **visible** | not visible |
| journalist password | **visible** | not visible |

| Same values in storage after each run | Database | Evidence files |
|---|---|---|
| title, body, camera serial, token | not visible | not visible |

What this shows:

* **Phase 5 encryption protects storage, not the network.** Over plain HTTP
  everything is readable on the wire, including the *original* photo with its
  EXIF data, because metadata is removed on the server, after the upload.
  **TLS is what protects data in transit.** The app must be served over HTTPS
  in any real use.
* With TLS, none of the values is visible. The WebSocket traffic is encrypted
  too (`wss://`).
* Even over unprotected `ws://`, the WebSocket messages contain no report data.
  The complete list seen in the capture is the Socket.IO handshake, the
  connect/disconnect frames, and the two content-free events from §3.3.
* Storage holds no readable marker in either run: reports and evidence are
  stored encrypted (Phase 5), and the stored photo is the scrubbed one (Phase 3).

### 4.3 Packet size and overhead (same workflow)

| Metric | HTTP + ws:// | HTTPS + wss:// |
|---|---|---|
| Packets | 132 | 194 |
| TCP connections | 13 | 13 |
| Bytes on the wire | 68,494 | 104,816 |
| Application bytes (TCP payload) | 61,366 | 94,340 |
| Frame size median / mean / max (bytes) | 60 / 519 / 1514 | 309 / 540 / 1514 |
| Ethernet + IP + TCP header bytes | 7,128 (10.4%) | 10,476 (10.0%) |
| Plaintext TLS handshake records (ClientHello/ServerHello) | - | 8,372 bytes |
| TLS records | - | 195 |
| HTTP requests readable | 13 | 0 |
| WebSocket messages readable | 7 | 0 |

**TLS overhead for this workflow: +32,974 application bytes (+53.7%).** It comes
from one handshake per connection (13 here). In TLS 1.3 the certificate and key
exchange are themselves encrypted, so only the ClientHello/ServerHello records
are counted as "handshake" above. Each encrypted record also adds about 21 bytes
(5-byte header plus 16-byte AEAD tag). Connection reuse (keep-alive, HTTP/2)
would reduce it.

### 4.4 Timing

| Step (client-measured, ms) | HTTP | HTTPS |
|---|---|---|
| journalist sign-in (POST) | ≈ 92 | ≈ 91 |
| WebSocket connect | ≈ 2 | ≈ 3 |
| source submission with photo | ≈ 12 | ≈ 12 |
| journalist opens report | ≈ 6 | ≈ 7 |
| status change (+ WebSocket event) | ≈ 5 | ≈ 7 |

The median TLS handshake was ≈ 0.7 ms per connection on loopback. Sign-in time
is dominated by the deliberate PBKDF2 cost (§5), not by the network. Exact,
regenerated numbers are in `analysis/results/traffic_report.md`; loopback timings
are much lower than real network latency.

### 4.5 Capturing the real interface with Wireshark

```bash
python app.py                                     # (or PHASE6_TLS=adhoc python app.py)
sudo tshark -i lo0 -f "tcp port 5001" -w capture.pcap  # loopback; Linux: -i lo
# ...use the site in a browser, then Ctrl+C...
python -m analysis.traffic_analysis capture.pcap --server-port 5001 --markers markers.json
```

* `markers.json` is a JSON object of values to search for, e.g.
  `{"title": "my test title"}`.
* Useful Wireshark display filters: `http.request`, `websocket`, `tls`, and
  `frame contains "my test title"`.
* On macOS the GUI can capture without `sudo` after running Wireshark's
  *Install ChmodBPF* package. That is a system security setting, so it is left
  to the user.

---

## 5. Cryptography and scrubbing timing

`python -m analysis.benchmark` gives median times in milliseconds on an Apple
Silicon Mac (arm64), Python 3.13, cryptography 50.0.2, Pillow 12.3.0. Full,
regenerated tables are in `analysis/results/benchmark.md`.

| Data size | AES-256-GCM encrypt | AES-256-GCM decrypt | HMAC-SHA-256 | SHA-256 |
|---|---|---|---|---|
| title (200 B) | 0.001 | 0.0003 | 0.0008 | 0.0003 |
| max report (20 KB) | 0.003 | 0.002 | 0.007 | 0.006 |
| 1 MB | 0.10 | 0.10 | 0.29 | 0.29 |
| max evidence (10 MB) | 1.02 | 1.01 | 2.92 | 2.91 |

| Phase 5 package | seal | open (HMAC → timestamp → decrypt) | reject tampered | size overhead |
|---|---|---|---|---|
| max report (20 KB) | 0.013 | 0.013 | 0.009 | +71 B |
| max evidence (10 MB) | 4.44 | 4.43 | 3.62 | +71 B |

| Hashing | ms |
|---|---|
| submission token: generate (192-bit) + SHA-256 | 0.001 |
| password hash, PBKDF2-SHA256 600,000 iterations (deliberately slow) | ≈ 75 |
| password verify | ≈ 75 |

| Metadata scrubbing (EXIF + GPS photo) | ms |
|---|---|
| JPEG 640×480 | 2.2 |
| JPEG 1920×1080 | 14.6 |
| JPEG 4032×3024 (12 MP phone photo) | 86.6 |
| PNG RGBA 1920×1080 | 153.1 |

**Total processing overhead per submission** (`create_submission`: validation,
scrubbing, three seals, database, audit, commit):
* about 0.26 ms for a text-only 20 KB report;
* about 94 ms with a 12 MP photo, of which scrubbing is about 87 ms and sealing
  the photo about 4.3 ms.

The benchmark uses the in-memory test database, so SQLite file-write time is not
included.

Conclusions:
* Encryption and integrity cost well under 5 ms even for the largest allowed
  file.
* Rejecting a tampered package stops at the HMAC, before any decryption.
* The visible costs are the intentional ones: password hashing (about 75 ms)
  and image re-encoding during scrubbing.

---

## 6. Cryptography summary (all phases)

| Mechanism | Where | What it does |
|---|---|---|
| **Encryption: AES-256-GCM** | `submissions/crypto.py` (`seal`) | report title, body and evidence encrypted before storage; 256-bit key; GCM tag authenticates ciphertext + context |
| **Decryption** | `open_package` | only after HMAC and timestamp checks pass; only for authorized journalists |
| **Nonce / IV** | `os.urandom(12)` per encryption | 96-bit, never reused, never hard-coded |
| **HMAC-SHA-256** | `_mac` / `open_package` | separate 256-bit key; covers version, timestamp, nonce, ciphertext, purpose and record identity; compared with `hmac.compare_digest`; checked **first** |
| **Hashing** | SHA-256 of submission tokens; PBKDF2-SHA256 (600k, salted) for staff passwords | tokens and passwords are never stored in readable form |
| **Timestamp protection** | 8-byte microsecond timestamp inside the HMAC-protected header | any change breaks the HMAC |
| **Replay protection** | `open_package` | future-dated package (> 300 s skew) or a timestamp different from the record's creation time is rejected as stale/replayed; packages copied between records fail the HMAC binding |
| **Metadata scrubbing** | `submissions/scrubber.py` (Phase 3) | in memory, before encryption; only pixels are copied |
| **Key management** | `PHASE5_ENCRYPTION_KEY`, `PHASE5_HMAC_KEY` from the environment | validated (32 bytes, distinct, not placeholder); app refuses to start without them; never in code, database or `app.config` |
| **Transport protection** | TLS (`PHASE6_TLS…`, or a reverse proxy) | the only thing that protects data on the network (§4.2) |

Details: `docs/phase5.md` (encryption) and `docs/phase3.md` (scrubbing).

---

## 7. Image colour-mode behaviour (measured from the code)

The scrubber does **not** convert everything to RGB/RGBA. It decodes the image,
applies the EXIF orientation, keeps the first frame, and keeps the colour mode
whenever the output format supports it:

| Format | Modes kept as-is | Converted (only if needed) |
|---|---|---|
| JPEG | `L`, `RGB`, `CMYK` | anything else → `RGB` (JPEG cannot store alpha, so any alpha is dropped) |
| PNG | `1`, `L`, `LA`, `P`, `RGB`, `RGBA`, `I`, `I;16` | other modes → `RGBA` if transparent, else `RGB` |
| GIF | `1`, `L`, `P` (GIFs normally decode as `P`) | other → `RGB`/`RGBA` then adaptive palette `P` |
| WebP | `RGB`, `RGBA` | other → `RGBA` if transparent, else `RGB` |
| any | `PA` | → `RGBA` |

**Transparency is preserved** for RGBA, LA, palette (P with `tRNS` index) and
transparent GIFs. **Fixed in Phase 6:** PNGs using *colour-key* transparency
(`tRNS` on an RGB or greyscale image) used to come back opaque, because the key
was only copied for palette images. The key is now carried over for P, L and
RGB. It is a colour value, not metadata. A regression test covers both cases.

**Removed:** EXIF (including the GPS IFD, camera make/model/serial, dates,
software), XMP, IPTC, ICC profiles, JPEG comments, and PNG `tEXt`/`iTXt`/`zTXt`
chunks. Only pixels (plus palette and transparency key) are copied into a new
image. The output is then decoded again and rejected if any of these remain.

JPEG and WebP are re-encoded at quality 95, so they are not byte-identical to the
upload and can be larger. PNG and GIF are lossless.

---

## 8. Limitations (honest)

* **No network anonymity.** The application does not store source IP addresses,
  but the network, any proxy or hosting provider, and the development server's
  console log can see them. Tor/onion routing, traffic padding, dummy traffic
  and random delays are **not implemented**. A source who needs network
  anonymity must reach the site through Tor themselves; making the service a Tor
  onion service is a deployment step, not application code.
* **TLS is required in practice.** Without it, everything is visible on the
  network (§4.2). TLS is optional in `app.py` (`PHASE6_TLS…`), and the ad-hoc
  certificate is for demonstrations only.
* **Traffic analysis is visible even under TLS.** Packet sizes and timing still
  leak patterns: a submission with a large photo is visibly larger, and a
  real-time event follows a submission. Nothing here pads or delays traffic.
* **Capture method:** the provided pcaps record real payloads but synthesised
  link and TCP headers (§4.1); real-interface capture needs capture privileges.
* **Real-time:** sockets are tracked per process (use one process, or a Socket.IO
  message queue, when scaling), and the server is Werkzeug's development server.
* Phase 5's server-side encryption limitations still apply (see `docs/phase5.md`):
  the server holds the keys, and this is not end-to-end encryption.

---

## 9. Tests

* `tests/test_phase6.py`:
  * who may connect (journalist / anonymous / admin / temporary password /
    disabled / idle-expired / forged cookie)
  * same-origin enforcement and exact event payloads, with no content leakage
  * revocation mid-connection (disable, pending, temporary password, socket age)
  * a notification failure cannot break a submission
  * no socket client on public and admin pages; CSP still `'self'`
  * pinned vendored client
  * HTTPS form regression (`Referrer-Policy`)
  * a full **Phase 1 → 6 end-to-end** run
* `tests/test_phase6_analysis.py`:
  * the recording proxy forwards and records both directions exactly
  * pcap validity and MSS segmentation
  * PyShark finds markers, including URL-encoded ones, in plaintext traffic and
    not in scrambled traffic
* `tests/test_phase3.py`: colour-key transparency regression; the formerly
  flaky corrupted-GIF case now uses fixed bytes.

Mutation checks were also run: removing the connect check, removing the
per-delivery re-check, or reverting the transparency fix each makes these tests
fail.
