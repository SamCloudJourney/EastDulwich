# HUNT: ASP.NET Core Kestrel — HTTP/3 (QUIC) + QPACK audit

**Target:** `dotnet/aspnetcore` — `src/Servers/Kestrel/Core/src/Internal/Http3/` and the shared QPACK codec `src/Shared/runtime/Http3/QPack/`.
**Date:** 2026-10-09
**Researcher task:** authorized security research for Microsoft's public .NET bug bounty, coordinated disclosure to MSRC.
**Boundary in scope:** Network. Attacker = anonymous remote client speaking HTTP/3 over QUIC.
**Reachability requirement:** HTTP/3 must be enabled (`HttpProtocols.Http1AndHttp2AndHttp3` on the endpoint, or config). This is a common, documented, supported production config but is **not** the zero-config default (default is `Http1AndHttp2`). Noted per the bar.

## TL;DR

**Result: no finding that clears the bar with usable confidence.** The QPACK decoder and the HTTP/3 request/control frame parsers are well-guarded: integer-decode overflow is rejected, Huffman output is bounded and length-checked, the dynamic table is *disabled entirely* in the decoder (so the whole insert-count / blocked-stream / dynamic-table-accounting attack class is absent by construction), and the header-size / header-count caps that exist on the H2 path **are present and enforced on the H3 path too.**

The one genuine architectural asymmetry vs. HTTP/2 is that **Kestrel's HTTP/3 path has no application-layer equivalent of the H2 "rapid reset" mitigation** (`MaxTrackedStreams` + `EnhanceYourCalm`, the CVE-2023-44487 defense). H3 delegates stream-churn throttling entirely to QUIC's `MAX_STREAMS` flow control. This is a real difference and is documented below, but I assess it as **LOW** MSRC confidence: QUIC flow control hard-gates stream creation in a way HTTP/2 never did, which is the industry-accepted reason H3 is considered substantially more rapid-reset-resistant, and I could not build a PoC to measure real amplification because **msquic is not installed in this environment** (`ldconfig -p | grep msquic` → empty; no `libmsquic.so`). I am flagging it as an honest observation / question for MSRC, not a confident submission.

Everything else examined is clean. Sections below record *why each candidate fails the bar* so the surface isn't re-tread.

---

## Provenance (so "live in current main" is checkable)

| Item | Value |
|---|---|
| Repo | `github.com/dotnet/aspnetcore` |
| Branch | `main` |
| HEAD | `851622243f8aad5d72636142ec2414be966c2449` — 2026-10-07 — "Update reference and project inventory documentation (#69696)" |
| Working copy | `/home/user/dotnet-hunt/aspnetcore` (shallow, depth 1 → local HEAD **is** the main tip; no local history for blame) |
| Runtime QUIC source | `/home/user/dotnet-hunt/runtime/src/libraries/System.Net.Quic/` (present, inspected) |
| SDK | `/home/user/.dotnet` 10.0.100-rc.2.25502.107 |
| msquic | **NOT available** — no QUIC PoC possible; static analysis + decoder-level reasoning only |

Because the checkout is a depth-1 clone of `main`, every line cited below **is** current `main` as of 2026-10-07. I could not run `git log/blame` for "already fixed?" locally and the GitHub MCP in this session is scoped to the user's own repo only, so liveness rests on the file contents at HEAD (which is the authoritative main tip).

Key default limits modeled (from `KestrelServerLimits.cs` / `Http3Limits.cs` / `QuicTransportOptions.cs`):
- `MaxRequestHeadersTotalSize` = 32 KiB (H3 parses with a 2× grace = 64 KiB, hard 32 KiB → 431 later)
- `MaxRequestHeaderCount` = 100 (H3 parses with a 2× eager limit = 200, hard 100 → 431 later)
- `Http3.MaxRequestHeaderFieldSize` = 32 KiB → this is the `maxHeadersLength` handed to the QPACK decoder (per-string cap)
- QUIC `MaxBidirectionalStreamCount` = 100, `MaxUnidirectionalStreamCount` = 10, `MaxReadBufferSize` = 1 MiB

---

## The bar (a finding must satisfy ALL)
1. Boundary: Network; attacker = anonymous remote HTTP/3 client.
2. Real impact: remote DoS (unbounded alloc/CPU/mem from cheap input), memory corruption, cross-request/connection info disclosure, or request desync.
3. Reachable when HTTP/3 is enabled (common supported config; not the zero-config default).
4. **Live in current `main`**, not already fixed.

Nothing below clears 2+4 with confidence.

---

## QPACK decoder — `src/Shared/runtime/Http3/QPack/QPackDecoder.cs` (CLEAN)

This is the attacker-controlled request-header decoder (`Http3Stream` feeds every HEADERS/trailers frame into it). Constructed at `Http3Stream.Initialize` with `maxHeadersLength = Limits.Http3.MaxRequestHeaderFieldSize` (32 KiB).

**Dynamic table is disabled.** Every representation that would touch the dynamic table throws immediately:
- Required Insert Count ≠ 0 → `ThrowDynamicTableNotSupported()` (`OnRequiredInsertCount`, line ~745).
- Delta Base ≠ 0 → throws (`OnBase`, ~736).
- Indexed-with-dynamic, post-base index, post-base name ref → throw (`ParseCompressedHeaders` cases, `OnPostBaseIndex`/`OnIndexedHeaderNamePostBase`, ~495–518, 721–734).

Consequence: the entire class the brief flagged (insert-count / known-received-count math, dynamic-table size accounting, blocked-stream limits) **cannot be reached** — those code paths throw before any state/alloc. The encoder/decoder QPACK streams themselves are drained to `Stream.Null` (see control-stream section), so no dynamic-table state is ever built.

**Integer decode — overflow safe.** `IntegerDecoder` (`src/Shared/runtime/Http2/Hpack/IntegerDecoder.cs`) throws `HPackDecodingException` on (a) continuation that would exceed 31 bits (`BitOperations.LeadingZeroCount((uint)b) <= _m`), (b) a signed-overflow addition (`_i < 0`), and (c) overlong encodings (trailing `b == 0` with `_m/7 > 1`). Result is always a non-negative `int`. No path produces a negative or wrapped length/index.

**String length — capped before use.** `OnStringLength` (line 617) throws `net_http_headers_exceeded_length` when `length > _maxHeadersLength` (32 KiB) *before* `_stringLength` is stored, so every subsequent `ParseHeaderName/Value`, `EnsureStringCapacity`, and `ArrayPool.Rent` is bounded by 32 KiB.

**Huffman output — bounded and re-checked.** `OnString` → `Huffman.Decode` (`Huffman.cs`); input ≤ 32 KiB, max Huffman expansion 8/5, and the decoded length is re-checked `> _maxHeadersLength` → throw (line 638). Worst-case transient buffer ≈ 52 KiB per field. (Note: `Huffman.Decode` grows its output with `Array.Resize`, which orphans the ArrayPool buffer it was handed and later returns a non-pool array to the pool — a benign pool-hygiene quirk shared verbatim with dotnet/runtime, not a security issue and not H3-specific.)

**Fast-path range copy — in bounds.** The name/value "fast path" stores a `(start,length)` slice into the *current* span and, if a header name's value doesn't complete in the same segment, copies it out at the end of `DecodeInternal` (lines 244–252) from the same `data` it was measured against. Value ranges are always consumed synchronously within the same call (`ProcessHeaderValue`). No cross-segment dangling slice.

**Decoder reuse across requests — no state leak.** On a pooled/reused `Http3Stream`, `QPackDecoder.Reset()` (line 161) resets `_state`; the other fields (`_headerNameRange`, `_headerStaticIndex`, ranges, `_integerDecoder`) are always re-initialized by the next `BeginTryDecode`/`OnStringLength`/`ProcessHeaderValue` before being read, and the retained ArrayPool buffers are only read up to freshly-written lengths. No stale bytes surface into a later request.

Conclusion: no overflow, no unbounded alloc, no OOB, no cross-request disclosure. The decoder is minimal and defensive.

---

## HTTP/3 request stream — `Http3Stream.cs` (CLEAN)

- **Header size cap present on H3:** `OnHeaderCore` (line 350) accumulates `_totalParsedHeaderSize += name.Length + value.Length` and throws `Http3StreamErrorException(RequestRejected)` at `> MaxRequestHeadersTotalSize * 2` (64 KiB); hard 32 KiB re-checked in `TryParseRequest` (line 1071) → 431.
- **Header count cap present on H3:** every `OnHeader`/`OnTrailer` calls `IncrementRequestHeadersCount` (`HttpProtocol.cs` 573) → throws `TooManyHeaders` at `> _eagerRequestHeadersParsedLimit` (= `MaxRequestHeaderCount * 2` = 200 for H3); hard 100 re-checked in `TryParseRequest`. Headers and trailers share the same counter/budget, so a trailer flood can't escape the cap.
- **Fully-indexed static headers:** 1 byte on the wire but still charged full name+value length against both caps; `ThrowIfInvalidStaticIndex` (`index >= H3StaticTable.Count`) runs in the decoder before the handler, so the `Debug.Assert(index <= Count)` in `Http3Stream.OnStaticIndexedHeader` is never reached with an OOB index.
- **Frame-length accounting:** `ProcessRequestAsync` (696–709) does `RemainingLength -= framePayload.Length` where `framePayload.Length = min(available, RemainingLength)` → never negative; `TryReadFrame` returns `false` (waits) rather than emitting a 0-length payload for a non-empty frame, so no no-progress infinite loop. A HEADERS frame with a huge declared `Length` is defused by the 64 KiB content cap tripping long before the length is consumed.
- **DATA / body:** bounded by content-length (`InputRemaining`), `MaxRequestBodySize`, pipe backpressure, and `MinRequestBodyDataRate` via `Http3MessageBody`.
- **0-length DATA-frame flood (brief called this out):** a valid-request stream can be fed endless 2-byte (`type=0x00,len=0x00`) DATA frames; with no content-length each one does a `RequestBodyPipe.Writer.FlushAsync()` on an empty pipe and writes 0 body bytes, so `MaxRequestBodySize` never trips. **But** it is strictly bandwidth-gated (2 bytes/frame) and QUIC stream flow control (`MaxReadBufferSize` 1 MiB) throttles the client to the server's processing rate — a modest "CPU per received byte" cost with no super-linear blowup and no unbounded memory. Does not clear the bar.

---

## HTTP/3 control stream — `Http3ControlStream.cs` (CLEAN)

- **SETTINGS:** capped at `MaxFrameSize` 10 KiB (`CheckMaxFrameSize`, throws `FrameError`); only one SETTINGS frame accepted (`_haveReceivedSettingsFrame`); the parse loop advances ≥2 bytes/iteration over a ≤10 KiB payload. Reserved H2 setting ids (0x2/0x3/0x4/0x5 and 0x0) → `SettingsError` connection error. Unknown settings ignored per spec.
- **GOAWAY / CANCEL_PUSH / MAX_PUSH_ID:** each validated with `ParseVarIntWithFrameLengthValidation` (frame length must match the single varint, else `FrameError`); PUSH isn't implemented but frames are still parsed for error-checking. GOAWAY can be re-sent (no "already received" flag) but each is just a varint parse + idempotent `StopProcessingNextRequest` — bandwidth-gated, no amplification.
- **Unknown control frames:** `CheckMaxFrameSize` (10 KiB) then ignored; payload fully consumed each chunk.
- **Encoder/decoder streams:** `HandleEncodingDecodingTask` = `Input.CopyToAsync(Stream.Null)` — drained, never parsed into dynamic-table state. Unbounded bytes allowed but streamed to null (no memory growth), bandwidth/flow-control gated.
- **Stream-type / reserved-type handling:** duplicate control/encoder/decoder stream → `StreamCreationError` *connection* error; unknown unidirectional type → `StreamCreationError` *stream* error (stream aborts). Unidentified streams carry a `RequestHeadersTimeout` via `Http3Connection.UpdateStreamTimeouts`.

---

## The one real asymmetry: no H3 rapid-reset mitigation (LOW confidence)

**H2 has it, H3 does not.** On the HTTP/2 path (`Http2Connection.cs`):
- streams RST by the client are kept in `_streams` (moved to a `_completedStreams` drain queue) and tracked against `MaxTrackedStreams = max(MaxConcurrentStreams*2, 100)`;
- exceeding it (or `SendEnhanceYourCalmOnStartStream`) sends `ENHANCE_YOUR_CALM`, and `_enhanceYourCalmCount` accumulated over a 5-tick window past `EnhanceYourCalmMaximumCount` (default 20) → `Abort(... ENHANCE_YOUR_CALM, StreamResetLimitExceeded)` (lines 1342–1362). This is the CVE-2023-44487 defense.

On the HTTP/3 path there is **no equivalent**. Grep across `Internal/Http3/` and `Transport.Quic/src/` for `EnhanceYourCalm|rapid|StreamResetLimit|_abortedStream|calm` returns nothing. `Http3Connection.OnStreamCompleted` simply does `_activeRequestCount--; _streams.Remove(id)` with no rate/burst accounting; there is no `MaxTrackedStreams`. Request-stream concurrency is bounded **only** by QUIC `MaxBidirectionalStreamCount` (default 100) enforced by msquic.

**The attack shape (H3 analogue of rapid reset):** open a bidi stream → send a complete valid HEADERS frame (which at `Http3Stream.cs:973` does `ThreadPool.UnsafeQueueUserWorkItem(this)`, dispatching the app delegate) → immediately `RESET_STREAM`/`STOP_SENDING`. The queued work item (app execution) outlives the QUIC stream; msquic retires the reset stream and grants fresh `MAX_STREAMS` credit; the client opens another. Server-side in-flight request executions can therefore exceed the QUIC stream window, bounded by msquic's credit re-grant rate (≈ window per RTT). In `System.Net.Quic`, accepted streams land in `Channel.CreateUnbounded` (`QuicConnection.cs:150`), but streams in that queue are "open" and count against msquic's limit, so the queue itself stays bounded by the window (no managed-side unbounded-memory bug there).

**Why I rate this LOW for MSRC (honest):**
1. **QUIC hard-gates stream creation.** Unlike HTTP/2 — where a client could unilaterally create thousands of streams in a single round trip (stream creation needed no server permission, and reset streams didn't count against `MAX_CONCURRENT_STREAMS`) — an HTTP/3 client cannot open a stream without server-granted `MAX_STREAMS` credit. This gating is exactly why the original Rapid Reset disclosure and the QUIC WG consider HTTP/3 markedly more resistant; it is the de-facto mitigation and is very likely considered sufficient by design.
2. **No PoC possible here.** msquic is absent, so I cannot measure the real credit re-grant rate or demonstrate work-item pile-up. The severity hinges entirely on msquic's retire/re-grant behavior, which lives in the native lib + `System.Net.Quic`, not in aspnetcore.
3. The amplification is most meaningful only against expensive app endpoints (true of any request flood), and cooperative cancellation (`RequestAborted`) fires on reset.

I would raise this to MSRC only as a **defense-in-depth question** ("should Kestrel H3 carry an EnhanceYourCalm-style stream-churn guard, or is QUIC `MAX_STREAMS` deemed sufficient?"), not as a confident RDoS submission. It is live in `main` (no such code exists), but "live absence of a mitigation" ≠ demonstrated vulnerability.

---

## Candidates examined and dropped

| Candidate | Verdict |
|---|---|
| QPACK integer-decode overflow | Safe — 31-bit + signed-overflow + overlong-encoding checks in `IntegerDecoder`. |
| QPACK Huffman output bomb | Safe — input ≤32 KiB, 8/5 expansion, decoded length re-checked ≤32 KiB. |
| QPACK dynamic-table / insert-count / blocked-streams | N/A — dynamic table disabled; all such representations throw; encoder/decoder streams drained to null. |
| H3 header-size / header-count caps missing | Present and enforced (`_totalParsedHeaderSize`, `IncrementRequestHeadersCount`). |
| SETTINGS / GOAWAY / MAX_PUSH_ID flood or oversize | Bounded (10 KiB frame cap, single SETTINGS, varint length validation). |
| Unknown-frame / 0-length-frame flood (control + request) | Bandwidth/flow-control gated; no super-linear CPU, no unbounded memory. |
| Client `MaxFieldSectionSize` → server over-allocation | No — used only as an upper-limit *check* in `Http3FrameWriter`, never to size an allocation; response buffer is a server constant. |
| Pooled-stream QPACK decoder state leak | No — `Reset()` + fresh re-init of all read-before-write fields. |
| Managed QUIC accept-queue unbounded growth | No — unbounded channel, but entries count against msquic's stream window. |
| WebTransport unidentified-stream accept-loop blocking (#42789) | Non-default (`EnableWebTransportAndH3Datagrams`); acknowledged TODO; `RequestHeadersTimeout` bounds it. Out of default scope. |
| **H3 rapid-reset mitigation absent (vs H2 EnhanceYourCalm)** | **Real asymmetry; LOW confidence — QUIC-flow-control-mitigated by design; no PoC (no msquic).** |

---

## Honest MSRC confidence

- Memory-safety / unbounded-alloc / info-disclosure in QPACK or H3 framing: **none found** (high confidence it's clean — the decoder is minimal, the dynamic table is off, caps are present).
- H3 rapid-reset / stream-churn RDoS: **LOW** — defensible as a design gap but almost certainly accepted as QUIC-mitigated; unprovable here without msquic. Not recommended as a standalone submission; at most a hardening question to MSRC.

**Deliverable is a clean negative with one documented low-confidence observation.** No PoC artifacts were produced (no bug to drive, and the one observation needs msquic). `pocwork/` untouched for this hunt.
