# HUNT: Kestrel stream/request bookkeeping leaks under attacker churn

**Seed:** WebTransport `_pendingStreams` retention. **Pivot:** HTTP/2 (default-on), HTTP/3 (GA, opt-in), HTTP/1.1 drain.
Date: 2026-10-13. Source: `dotnet/aspnetcore` @ `851622243` (main, 2026-10-07). `origin/main` at hunt time was `77e4202be`; nothing changed in `src/Servers/Kestrel/Core/src/Internal/{Http2,Http3,WebTransport}` or `Transport.Quic/src` between the two.
Binaries exercised: shipped shared framework **Microsoft.AspNetCore.App 10.0.0-rc.2.25502.107** (Kestrel.Core `+89c8f6a1`) and **9.0.20** (GA, `+4e6235b8`).

---

## Verdict (up front)

**Nothing found here is MSRC-eligible.** The seed bug is real in the code, but under the shipped QUIC stack it's bounded per connection. It also sits behind an experimental switch and is already publicly tracked. On the default-on HTTP/2 path, the per-connection bound on app-active streams holds against client resets (Rapid Reset), server resets (MadeYouReset), sub-threshold pacing, CONTINUATION floods and zero-window slow reads.

| # | Candidate | Default-on? | Result | In current main? | MSRC odds |
|---|---|---|---|---|---|
| 1 | WebTransport `_pendingStreams` keeps reset streams (seed) | **No.** Experimental AppContext switch + HTTP/3 opt-in | The code path is real, but the "unbounded" part is **false** on the shipped stack. Retention is capped at **108 streams per connection** (99 bidi + 9 uni) because System.Net.Quic gives no stream credit back until the stream handle is closed, and Kestrel never closes WT stream handles. Retention would be unbounded only under a hypothetical QUIC credit policy: then it is 2,686 B/stream, linear, freed on close. | Unpatched (code from `b120cefca`, 2022-07-20) but **publicly known**: #42788 "Discard cancelled streams before users can accept them" | ~1% |
| 1b | WT: app-disposed streams stay in `_openStreams`; WT stream credits only come back via GC | No (same gating) | Functional/reliability bug, not a security one. It only starves the client's own session. | Unpatched | ~0% |
| 2 | HTTP/2 Rapid Reset / MadeYouReset (CVE-2023-44487 / CVE-2025-8671 class), stream accounting | **Yes** (h2 via ALPN) | **Clean.** App-active streams are capped at `MaxTrackedStreams` = 2 x 100 = **200 per connection** whoever resets the stream. No leak: 0 of 65 aborted connections still alive after draining. Same on .NET 9.0.20. | Mitigation since `5aaa64139`/`9719821d5`/`59e9ae44a` (Oct 2023) | 0% |
| 3 | HTTP/2 connection-error early return (TODO #51307): Kestrel stops tracking a connection while its aborted requests still run | Yes, but impact needs **non-default** `MaxConcurrentConnections` and an app that ignores `RequestAborted` | Measured: with `MaxConcurrentConnections=4`, 2,400 orphaned requests ran with 0 connections counted. With the default (unlimited) config it's ordinary connection churn: 200 orphaned requests per TLS handshake vs 100 for plain h2. | Deliberate (`59e9ae44a`), public (#51307 + code comment) | ~2% |
| 4 | HTTP/2 CONTINUATION / HPACK header floods | Yes | **Clean.** Heap stays flat. RequestHeadersTimeout ends the flood at 30 s. A header block over 64 KB is a connection error. | n/a | 0% |
| 5 | HTTP/2 output queues while the client withholds WINDOW_UPDATE | Yes | **Clean.** About 40 KB per stalled stream. MinResponseDataRate closes the connection at about 12 s. The output queue is bounded and aborts the connection on overflow. | n/a | 0% |
| 6 | HTTP/3 request-stream Rapid Reset / `Http3Connection` stream accounting | Opt-in, GA | **Clean on the shipped semantics.** Capped at 100 in-flight per connection by QUIC credit. Kestrel only disposes a request stream after the app finishes, so a reset returns no credit. | n/a | 0% |
| 7 | HTTP/1.1 request-body drain / upgrade | Yes | Reviewed; nothing concrete. Drain is bounded by `RequestBodyDrainTimeout` (5 s) and `MaxRequestBodySize`. | n/a | 0% |

**Main reason anything here would be rejected:** the only behaviours that go beyond a per-connection bound depend on one of the following:
- **(1)** an experimental, off-by-default feature, plus a QUIC credit policy that .NET doesn't use;
- **(3)** a non-default limit and app code that ignores `HttpContext.RequestAborted`. Both are already public.

---

## Program scope (fetched from https://www.microsoft.com/en-us/msrc/bounty-dot-net-core on 2026-10-13)

Quotes:
- **DoS is in scope:** award row "Remote Denial of Service High Medium Low $20,000 $10,000 $5,000 $10,000 $5,000 $2,500 $0 $0". Eligibility needs "Critical or Important severity".
- **Preview features:** "Any Preview Features listed in this GitHub page, whether in current supported versions or an upcoming version." The linked page (`github.com/dotnet/core/blob/main/bug-bounty-preview-scopes.md`) is stale. It lists only *.NET 6: "HTTP/3 support in the Kestrel Web Server"* and *"None"* for the next version. **WebTransport is not listed.** The page says nothing about experimental features or AppContext switches.
- **Out of scope:** "Vulnerabilities which disable or do not use any built in mitigation mechanisms", "Publicly-disclosed vulnerabilities which have already been reported to Microsoft", "Vulnerabilities in versions of .NET 5 or later, .NET Core or ASP.NET Core which are daily builds, early beta releases".
- The page never mentions "default" or "configuration".

Gating facts (verified in source):
- WebTransport needs `Microsoft.AspNetCore.Server.Kestrel.Experimental.WebTransportAndH3Datagrams` (`KestrelServerOptions.cs:228-240`, default false). The API is `[RequiresPreviewFeatures]` (CA2252).
- HTTP/3 is opt-in (`ListenOptions.DefaultHttpProtocols = Http1AndHttp2`).

---

## Method

1. **Code review** of Kestrel HTTP/2, HTTP/3, WebTransport and Transport.Quic at `851622243`.
2. **History check.** The clone was depth 1, so I deepened it with `git fetch --filter=blob:none --shallow-since=2022-06-01` (8,204 commits). No source was changed and no commit made.
3. **Binary check.** I decompiled the shipped RC2 `Kestrel.Core.dll` and `System.Net.Quic.dll` (10.0 RC2 and 9.0.20) to confirm the tested binaries match main where it matters. `WebTransportSession` is logic-identical. HTTP/2 stream accounting is identical, except main-only `0585ae7d9` (WINDOW_UPDATE on a reset stream changed from a connection error to a stream error); that change is analysed below.
4. **PoCs** (all single-process, loopback, under `pocwork/kestrel-streamleak/`):
   - `h2churn/`: real Kestrel via `WebApplication.CreateBuilder`, default limits, an HTTPS endpoint with an in-process self-signed ECDSA cert, default protocols (ALPN negotiates `h2`). The attacker is a hand-written HTTP/2 frame writer over `SslStream`. Server-side measurements:
     - an in-flight counter inside the endpoint;
     - **Kestrel's own bookkeeping**, read by reflection from the live `Http2Connection` objects (`_streams.Count`, `_clientActiveStreamCount`, `_serverActiveStreamCount`);
     - the `kestrel.active_connections` / `http.server.active_requests` meters;
     - `GC.GetTotalMemory(true)`;
     - a weak-reference leak check on every `Http2Connection` the attack touched.
     The endpoint is realistic default code: `await Task.Delay(15s)` **without** `RequestAborted`; `/slowhonor` is the control.
     `h2churn-net9/` is the same code targeting the 9.0.20 runtime.
   - `h3mem/`: msquic is unavailable here, so this runs the **real shipped Kestrel HTTP/3 + WebTransport stack** over an in-memory transport plugged into the **public** `IMultiplexedConnectionListenerFactory` extension point (`WebApplication`, `Protocols=Http3`, `UseHttps`). Everything above the transport is shipped code: `Http3Connection`, `Http3Stream`, `Http3PendingStream`, `WebTransportSession`, `WebTransportStream`, the QPACK decoder and the app. The attacker speaks real HTTP/3 + WebTransport wire format (QPACK, varints, SETTINGS `0x2b603742`/`0xffd277`, WT signals `0x41`/`0x54`).
     The transport models two things exactly as `QuicStreamContext` + System.Net.Quic do:
     - **(a) Stream-closed semantics:** `ConnectionClosed` / `IStreamClosedFeature` fire when the receive side has seen FIN/RESET and the send side has completed or got STOP_SENDING.
     - **(b) QUIC stream-ID flow control** (Kestrel defaults: 100 bidi / 10 uni), under two policies:
       - **SystemNetQuic** (what ships): credit returns only when the server closes the stream handle (`ConnectionContext.DisposeAsync`), or when SafeHandle-style finalization runs once the stream is unreachable.
       - **OnStreamClosed** (hypothetical, the seed's assumption): credit returns as soon as both directions finish.
     Kestrel validated the model the hard way. It rejected it until it supplied the same features `QuicStreamContext` does (`IPersistentStateFeature`, `ITlsConnectionFeature` falling back to the connection's features, a never-completing unused direction). This confirms the real code paths ran.

---

## Candidate 1: WebTransport `_pendingStreams` retention (seed)

### Code (main @ 851622243)
- `src/Servers/Kestrel/Core/src/Internal/WebTransport/WebTransportSession.cs`
  - `:24` `_openStreams` (ConcurrentDictionary).
  - `:26`/`:52` `_pendingStreams = Channel.CreateUnbounded<WebTransportStream>()`, with comment `:51` *"unbounded as limits to number of streams is enforced elsewhere"*.
  - `:145-164` `AddStream` writes every peer stream to **both** collections.
  - `:166-181` `AcceptStreamAsync` is the **only** reader of `_pendingStreams`.
  - `:183-193` `TryRemoveStream` removes from `_openStreams` only, then calls `DisposeAsync()`.
- `.../WebTransport/WebTransportStream.cs`
  - `:64-72` registers `TryRemoveStream` on `context.StreamContext.ConnectionClosed`.
  - `:99-119` `DisposeAsync` disposes that registration first (`:108`).
- `.../Http3/Http3Connection.cs`
  - `:394-415` / `:426-446`: peer uni/bidi streams are identified inline on the accept loop.
  - `:638-657` `CreateAndAddWebTransportStream` → `session.AddStream(...)`.

**The seed's description of the code is accurate.** A peer stream that is reset/closed before the app calls `AcceptStreamAsync` stays referenced from the unbounded channel until the session ends.

### Why the "unbounded" part is false on the shipped stack
1. Kestrel core disposes a stream's transport context (`StreamContext.DisposeAsync()`, which disposes the `QuicStream` and so closes the msquic handle) in exactly two places: `Http3Stream.cs:785` and `Http3ControlStream.cs:250`. It **never** does so for WebTransport streams. `QuicStreamContext.DisposeAsync` (`Transport.Quic/src/Internal/QuicStreamContext.cs:550-590`, `await _stream.DisposeAsync()` at `:562`) is the only path that closes the handle explicitly.
2. System.Net.Quic sets **`QUIC_STREAM_OPEN_FLAGS.DELAY_ID_FC_UPDATES` on every accepted peer stream** (`QuicConnection.HandleEventPeerStreamStarted`). I verified this in the shipped binaries (decompiled `System.Net.Quic.dll` 10.0 RC2 line 649 and 9.0.20 line 628) and in dotnet/runtime main.
3. With that flag, msquic hands back MAX_STREAMS credit **only when the app closes the handle**:
   - `msquic/src/core/stream_set.c:849` sets `Stream->Flags.DelayIdFcUpdate = TRUE`;
   - `stream.c:651`: at shutdown, credit is released only `if (!Stream->Flags.DelayIdFcUpdate || Stream->Flags.HandleClosed)`;
   - `stream.c:427`: otherwise it is released in `QuicStreamClose`.
4. A queued `WebTransportStream` keeps its transport context (and so the `QuicStream`) reachable. Its weak GCHandle lets it be finalized, but only once nothing references it, so its handle is never finalized and **its credit never comes back**.

Result: an attacker can have at most `MaxBidirectionalStreamCount - 1` (CONNECT stream) + `MaxUnidirectionalStreamCount - 1` (control stream) = **99 + 9** retained streams per connection with defaults (`QuicTransportOptions.cs:17,22`). Further opens are blocked by QUIC itself. That is the same per-connection bound that applies to legitimate concurrent streams, and it is released when the connection closes. The code comment at `:51` is therefore literally true.

### Measured (h3mem, real Kestrel 10.0 RC2, verbatim excerpt; full output in the appendix)
```
W1 [SystemNetQuic credits]   bidi WT streams opened+reset : 99  (then BLOCKED: no QUIC stream credit)
                             uni  WT streams opened+reset : 9   (then BLOCKED: no QUIC stream credit)
                             session _pendingStreams.Count : 108     _openStreams.Count : 0
                             credits returned (dispose/finalizer) : 0/0 (after a full GC)
W2 [OnStreamClosed, hypothetical]  churned 20000 : _pendingStreams= 20000  heap +51.2 MiB = 2686 B/retained stream
                             heap after client closed connection : +-0.3 MiB (retention lives as long as the connection)
```
Quantification:
- **Shipped stack:** 108 streams retained per connection, then the client cannot open more.
- **Hypothetical credit-on-close stack:** retention = 100% of streams churned, about 2.7 KB managed per stream in the model, linear in attacker effort (20,000 streams in 2.6 s), all freed on connection close. The real QUIC transport adds `QuicStreamContext`/`QuicStream`/native msquic state per stream, which I can't measure here.

The previous hunter's `pocwork/wtleak/Program.cs` is a container-only model. Its "unbounded RAM" conclusion depends on the credit-on-close premise. W2 reproduces its container result on the real binary; W1 shows the real-world bound.

### Related functional bugs found while measuring (not security)
- **W3:** if the app accepts and immediately disposes a WT stream (normal usage), `WebTransportStream.DisposeAsync` disposes the `ConnectionClosed` registration (`WebTransportStream.cs:108`). When the peer later closes the stream, `TryRemoveStream` never runs, so the stream stays in `_openStreams` for the session's lifetime. Measured: 99 left in `_openStreams`, 0 credits back even after GC, so **the session can never receive another stream**.
- **W3b:** even when the peer closes first, credits come back only through GC finalization (75 of 99 after a forced GC), because Kestrel never disposes WT transport streams.

Both only hurt the client's own connection; worth a public GitHub issue at most (the feature is experimental).

### Patched? Prior art?
- **Unpatched:** logic from `b120cefca` (2022-07-20), last touched `a4bbcba65` (2023-02-08); identical in the RC2 binary; unchanged to `origin/main` `77e4202be`.
- **Publicly known:** dotnet/aspnetcore#42788 "WebTransport PR follow-ups" (open since 2022-07-18) lists *"Discard cancelled streams before users can accept them"* and *"Limit and make sure we cleanup _webtransportSessions and _unidentifiedStreams"*.

### Eligibility: about 1%
- Experimental AppContext switch, default off.
- `[RequiresPreviewFeatures]` API, not on the bounty's preview list.
- Bounded by the default QUIC per-connection stream limits, so no amplification beyond what QUIC already allows.
- Publicly tracked since 2022.

---

## Candidate 2: HTTP/2 Rapid Reset / MadeYouReset / stream accounting (default-on)

### Code (main)
`src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs`:
- `:226` `MaxTrackedStreams => Math.Max(MaxConcurrentStreams * 2, 100)` (200 by default).
- `:1295-1390` `StartStream` adds to `_streams` before any check (`:1300`):
  - `:1332-1337` REFUSED_STREAM when `_clientActiveStreamCount > MaxConcurrentStreams`;
  - `:1342-1362` ENHANCE_YOUR_CALM when `_streams.Count > MaxTrackedStreams`;
  - more than 5 x 20 EYCs per 5-tick window → abort.
- `:348-360` a server-side stream error → `AbortStream` (`:1421-1428`, decrements the client count) + RST_STREAM. The stream **stays in `_streams`**.
- `:1447-1508`: a stream leaves `_streams` only via `UpdateCompletedStreams`/`RemoveStream`, i.e. after `OnStreamCompleted`.

`Http2Stream.cs:147-187` `CompleteStream` → `OnStreamCompleted`. That runs only when **both** the app has finished and the response is complete (`Http2OutputProducer.cs:597-657`). `DecrementActiveClientStreamCount` is idempotent per stream (`Http2Stream.cs:638-653`), so repeated server resets can't push the counter negative.

So whoever resets a stream, client or server, it keeps counting against the 200 cap while app code runs. That is why MadeYouReset doesn't break out of the bound.

Main-only `0585ae7d9` (2025-09-30) turns WINDOW_UPDATE on a client-reset stream into a stream error (`:1175-1183`). Effect: 1:1 RST_STREAM reflection, no accounting change (idempotent decrement; the stream stays in `_streams`).

### Prior fixes
- CVE-2023-44487 mitigation: `5aaa64139` (2023-09-27), `9719821d5` (2023-10-11), `59e9ae44a` (2023-10-13), "Track indicators of excessive stream resets".
- MadeYouReset (CVE-2025-8671, Aug 2025): public vendor lists don't name Kestrel and there is no Kestrel commit for it. The tests below show Kestrel's `_streams`-based cap already covers that class.

### PoC: `pocwork/kestrel-streamleak/h2churn`, Kestrel 10.0 RC2, default limits (verbatim excerpts; full output in the appendix)
```
S1 plain                : peak in-flight  100 on 1 conn; RST REFUSED_STREAMx200
S2 rapid reset          : peak in-flight  200 on 1 conn; reached app 200; RST ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, last=2147483647)
                          [conn open=False _streams=202 _clientActive=1 _serverActive=202]
S2b sustained sub-EYC   : peak in-flight  200; 150 extra streams -> 0 reached app; conn open=True
                          [conn open=True _streams=200 _clientActive=0 _serverActive=200]
S3 MadeYouReset win-ovf : peak in-flight  200 on 1 conn; reached app 200; RST FLOW_CONTROL_ERRORx300, ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, ...)
S4 MadeYouReset CL-mism : peak in-flight  200 on 1 conn; reached app 200; RST PROTOCOL_ERRORx299, ENHANCE_YOUR_CALMx99; no GOAWAY; closed=True
S5 scaling              : rapid-reset 200/conn, plain 100/conn (linear in #connections); 6816 B per in-flight request
S8 RequestAborted-aware : in-flight 0 1.5 s after 200 resets (peak 6)
S9 /fast req rate       : plain 24775/s vs rapid-reset 386/s on one conn  (rapid reset trips the output-queue guard -> connection aborted)
Leak check              : 0/65 Http2Connection objects alive after drain; heap 0.9 -> 2.9 MiB
```
- `_clientActiveStreamCount` drops to 0 under resets, but `_streams.Count` holds at 200 and **no request beyond 200 ever reaches the app**, even when the attacker paces itself under the EYC abort threshold (S2b).
- Server-generated resets (S3, S4) behave exactly like client resets.
- Nothing is left behind after aborts (weak-reference leak check).
- .NET 9.0.20 (GA) gives the same numbers (`h2churn-net9/run-net9.txt`).
- In S9, Kestrel logs `Http2QueueOperationsExceeded` at **Critical** (`KestrelTrace.Http2.cs:135`) on a client-triggerable path. That's log noise, not a vulnerability.

**Verdict: clean.** The 2x allowance (200 vs `SETTINGS_MAX_CONCURRENT_STREAMS` 100) is the documented design of the 2023 fix.

---

## Candidate 3: HTTP/2 connection-error early return (TODO #51307)

### Code
`Http2Connection.cs:464-476`: on exit, Kestrel waits for `_serverActiveStreamCount` to drain **unless** `IsEnhanceYourCalmLimitEnabled && error is Http2ConnectionErrorException`. Introduced deliberately in `59e9ae44a` (2023-10-13) with the comment *"TODO (https://github.com/dotnet/aspnetcore/issues/51307): For some reason, this loop doesn't terminate when we're trying to abort."* (#51307 "Leaking tasks when aborting HTTP/2 Connections", public, open.)

A client can raise an `Http2ConnectionErrorException` at will (here: a PING on stream 1). Kestrel then completes the connection, releasing the `MaxConcurrentConnections` slot and the `kestrel.active_connections` count, while up to 200 aborted requests keep running in an app that ignores `RequestAborted`.

### PoC (h2churn S6/S7, verbatim)
```
(a) HTTP/1.1, 1 req/conn  : orphaned    20 in  336 ms -> 1/handshake; conns still counted by Kestrel: 20
(b) H2 plain, TCP reset   : orphaned  2000 in  313 ms -> 100/handshake; conns still counted by Kestrel: 20 (held until drained)
(c) H2 reset + conn error : orphaned  4000 in  358 ms -> 200/handshake; GOAWAYs=20; conns still counted: 0 (released early, #51307 path)
S7 [NON-DEFAULT MaxConcurrentConnections=4]: plain+close orphaned 400 (limit holds); reset+conn-error orphaned 2400 with 0 conns counted (limit no longer bounds orphaned work)
```
- **Default config:** no connection limit exists, so this is ordinary connection churn, linear in TLS handshakes. 200 orphaned requests per handshake vs 100 for plain h2 and 1 for HTTP/1.1, about 6.4 KB each, all freed when the app's own delay ends.
- **Non-default `MaxConcurrentConnections`:** the limit stops bounding orphaned work (12 accepted / 0 rejected vs 4 / 8).

### Eligibility: about 2%
- Needs a non-default limit.
- Needs app code that ignores `HttpContext.RequestAborted`; the server does signal the abort.
- The behaviour is intentional and public (#51307 plus the code comment).

---

## Candidate 4: CONTINUATION / HPACK floods (h2churn `extra`, verbatim)
```
X1 empty CONTINUATION frames sent      : 7,752,000 (66.5 MiB) over 31.1 s
   connection closed by server / GOAWAY: True / GOAWAY(code=0x2, last=2147483647)     <- RequestHeadersTimeout (30 s)
   max heap during flood (vs baseline) : 1.16 MiB (baseline 0.94 MiB)
   20 x 8 KB header CONTINUATIONs      : server closed=True, GOAWAY(code=0x1, last=1) (limit: 2 x MaxRequestHeadersTotalSize = 64 KB)
```
The headers are decoded incrementally; nothing accumulates. The size limit is a connection error (`Http2Connection.cs:1606-1618`) and the count limit is 2 x `MaxRequestHeaderCount`. **Clean.**

## Candidate 5: Output buffering while WINDOW_UPDATE is withheld (h2churn `extra`, verbatim)
```
X2 app requests blocked in WriteAsync  : 100
   heap delta with 100 stalled responses: 3.78 MiB = 39599 B/stream (app tried to write 100 MiB)
   server closed the connection after  : 11.7 s (MinResponseDataRate 240 B/s, 5 s grace)
   app requests still blocked          : 0
```
- The per-stream data pipe pauses at 4 KB (`Http2OutputProducer.cs:769-782`).
- The frame-writer channel is bounded at `MaxTrackedStreams` and the connection is aborted on overflow (`Http2FrameWriter.cs:153-174`).
- The flow-control wait queue is capped (`:136-144`).
- Waiting for window updates counts toward MinResponseDataRate (`:320-333`).

**Clean.**

## Candidate 6: HTTP/3 request streams (h3mem Part 2, verbatim)
```
R  HTTP/3 rapid reset [SystemNetQuic]: 100 streams, app in-flight peak 100, then blocked by QUIC credit
R  HTTP/3 rapid reset [OnStreamClosed]: 1000 streams, app in-flight peak 1000
```
`Http3Stream.cs:751-806` waits for the app to finish (`await appCompletedTask`, `:762`) before disposing the stream context (`:785`). Combined with `DELAY_ID_FC_UPDATES`, a client reset returns no stream credit while app work runs, so HTTP/3 is structurally capped at 100 in-flight requests per connection. The unbounded row only happens under the hypothetical credit policy that .NET doesn't use. Control/unknown uni streams are disposed right after processing (`Http3ControlStream.cs:250`). **Clean.**

## Candidate 7: HTTP/1.1 drain / upgrade
`Http1MessageBody.cs:84-118` drains a request body the app didn't read under `RequestBodyDrainTimeout` (5 s, `Constants.cs:32`) and `MaxRequestBodySize`. Upgrade/WebSocket concurrency is app-level (`MaxConcurrentUpgradedConnections`, unlimited by default, by design). Nothing concrete; no PoC.

---

## Reproduction (everything above)
```bash
export PATH=/home/user/.dotnet:$PATH DOTNET_ROOT=/home/user/.dotnet
cd /home/user/EastDulwich/pocwork/kestrel-streamleak/h2churn && dotnet build -c Release
dotnet bin/Release/net10.0/h2churn.dll 15          # S1-S9 + leak check + S7 (about 4 min, foreground)
dotnet bin/Release/net10.0/h2churn.dll 15 extra    # X1 CONTINUATION flood, X2 zero-window slow read
cd ../h2churn-net9 && dotnet build -c Release && dotnet bin/Release/net9.0/h2churn.dll 15   # same against 9.0.20 (GA)
cd ../h3mem && dotnet build -c Release && dotnet bin/Release/net10.0/h3mem.dll 20000 10     # W1-W3b, HTTP/3 rapid reset
```
All traffic is loopback or in-process.

## Fidelity and limits
- **HTTP/2:** the real thing end to end (Kestrel, TLS, ALPN h2, raw frames).
- **HTTP/3/WT:** the real Kestrel stack over a modelled QUIC. The decisive QUIC property (credit only on handle close) comes from the shipped System.Net.Quic binaries plus msquic source, not from the model. The model can't measure native msquic memory per stream.
- **Harness bugs fixed and re-run** (old logs kept as `*-SUPERSEDED-*.txt`):
  - S7 first ran while the earlier mode still held the slots;
  - W2 first measured the baseline after opening a batch;
  - the first "heap after close" kept a harness reference to the session.

---

## Appendix A: `h2churn/run2.txt` (Kestrel 10.0 RC2, verbatim)
```
Runtime            : .NET 10.0.0-rc.2.25502.107
Kestrel.Core       : 10.0.0-rc.2.25502.107+89c8f6a112d37d2ea8b77821e56d170a1bccdc5a
GC                 : Server, cores=4
App endpoint /slow : await Task.Delay(15s) without RequestAborted (realistic default code)

Server A on 127.0.0.1:42373  Http2.MaxStreamsPerConnection=100  MaxConcurrentConnections=null (unlimited)  MinResponseDataRate=240B/s
Baseline managed heap after warm-up: 0.95 MiB

=== S1 baseline: 1 connection, 300 x HEADERS(END_STREAM) to /slow, no resets
   app in-flight now / peak            : 100 / 100
   server RST_STREAM codes             : RST REFUSED_STREAMx200
   Kestrel bookkeeping                 : 1 conn(s), 1 open; sum _streams.Count=100, _clientActiveStreamCount=100, _serverActiveStreamCount=100
                                         [conn open=True _streams=100 _clientActive=100 _serverActive=100]

=== S2 Rapid Reset: 1 connection, 1000 x [HEADERS(END_STREAM) + RST_STREAM(CANCEL)] to /slow
   app in-flight now / peak            : 200 / 200   (requests that reached the app: 200)
   server RST_STREAM codes             : RST ENHANCE_YOUR_CALMx100
   server GOAWAY                       : GOAWAY(code=0xb, last=2147483647)  (connection ended after 13 ms)
   Kestrel bookkeeping                 : 1 conn(s), 0 open; sum _streams.Count=202, _clientActiveStreamCount=1, _serverActiveStreamCount=202
                                         [conn open=False _streams=202 _clientActive=1 _serverActive=202]

=== S2b sustained: fill 200, then keep sending 15 [HEADERS+RST]/s for 10 s (under the 100-EYC/5-tick abort rate)
   extra streams sent during 10 s      : 150
   extra requests that reached the app : 0
   app in-flight now / peak            : 200 / 200
   server RST_STREAM codes             : RST ENHANCE_YOUR_CALMx150
   connection still open / GOAWAY      : True / no GOAWAY
   Kestrel bookkeeping                 : 1 conn(s), 1 open; sum _streams.Count=200, _clientActiveStreamCount=0, _serverActiveStreamCount=200
                                         [conn open=True _streams=200 _clientActive=0 _serverActive=200]

=== S3 MadeYouReset (WINDOW_UPDATE overflow): 1 conn, 1000 x [HEADERS(END_STREAM) + WINDOW_UPDATE(stream, 0x7fffffff)]
   app in-flight now / peak            : 200 / 200   (requests that reached the app: 200)
   server RST_STREAM codes             : RST FLOW_CONTROL_ERRORx300, ENHANCE_YOUR_CALMx100
   server GOAWAY                       : GOAWAY(code=0xb, last=2147483647)  (connection ended after 14 ms)
   Kestrel bookkeeping                 : 1 conn(s), 0 open; sum _streams.Count=202, _clientActiveStreamCount=1, _serverActiveStreamCount=202
                                         [conn open=False _streams=202 _clientActive=1 _serverActive=202]

=== S4 MadeYouReset (content-length violation): 1 conn, 1000 x [HEADERS(POST, content-length:1) + DATA("ab", END_STREAM)]
   app in-flight now / peak            : 200 / 200   (requests that reached the app: 200)
   server RST_STREAM codes             : RST PROTOCOL_ERRORx299, ENHANCE_YOUR_CALMx99
   server GOAWAY / socket closed       : no GOAWAY / True  (after 17 ms)
   Kestrel bookkeeping                 : 1 conn(s), 0 open; sum _streams.Count=202, _clientActiveStreamCount=1, _serverActiveStreamCount=202
                                         [conn open=False _streams=202 _clientActive=1 _serverActive=202]

=== S5 scaling: 8 conns x 200 [HEADERS+RST] (/slow)  and  8 conns x 100 plain HEADERS (/slow2), all held open
   in-flight via rapid-reset conns     : 1600  (= 200.0 per conn)
   in-flight via plain conns           : 800  (= 100.0 per conn)
   http.server.active_requests meter   : 2400
   EYC/GOAWAY seen on any conn         : no
   Kestrel bookkeeping                 : 16 conn(s), 16 open; sum _streams.Count=2400, _clientActiveStreamCount=800, _serverActiveStreamCount=2400
                                         [conn open=True _streams=200 _clientActive=0 _serverActive=200] [conn open=True _streams=200 _clientActive=0 _serverActive=200]  [first 2 = rapid-reset conns]
   heap delta                          : 15.60 MiB for 2400 in-flight requests = 6816 B/request

=== S6 connection churn, 20 cycles each; the app ignores RequestAborted so aborted requests keep running
   (a) HTTP/1.1, 1 req/conn            : orphaned    20 in  336 ms -> 1/handshake; conns still counted by Kestrel: 20
   (b) H2 plain, TCP reset             : orphaned  2000 in  313 ms -> 100/handshake; conns still counted by Kestrel: 20 (held until drained)
   (c) H2 reset + conn error           : orphaned  4000 in  358 ms -> 200/handshake; GOAWAYs=20; conns still counted: 0 (released early, #51307 path)
   Kestrel bookkeeping                 : 40 conn(s), 0 open; sum _streams.Count=6000, _clientActiveStreamCount=2000, _serverActiveStreamCount=6000
   heap delta                          : 36.83 MiB for 6020 orphaned requests = 6414 B/request

=== S8 control: rapid reset against /slowhonor (Task.Delay(..., RequestAborted))
   app in-flight now / peak / started  : 0 / 6 / 200

=== S9 /fast endpoint, 5 s each on 1 connection: plain (<=100 outstanding, wait for responses) vs rapid reset (never wait)
   plain: app invocations / 5 s        : 123876  (24775/s), REFUSED=0
   [server log Critical] Microsoft.AspNetCore.Server.Kestrel.Http2: Connection id "0HNP8U0H6AH08" exceeded the output operations maximum queue size. ConnectionAbortedException
   [server log Critical] Microsoft.AspNetCore.Server.Kestrel.Http2: Connection id "0HNP8U0H6AH08" exceeded the output operations maximum queue size. ConnectionAbortedException
   rapid reset: streams sent / app invocations: 6900 / 1929  (386/s)
   rapid reset: EYC RSTs / GOAWAY / closed: 17 / no GOAWAY / True
   process CPU during rapid reset (srv+cli): 0.0 s over 5 s wall

=== Leak check after all server-A scenarios drained
   Http2Connection objects touched / still alive: 65 / 0
   managed heap baseline -> now        : 0.95 MiB -> 2.92 MiB
   kestrel.active_connections meter    : 0

=== S7 NON-DEFAULT Limits.MaxConcurrentConnections=4 (server B :39549), 12 cycles per mode
   [server log Warning] Microsoft.AspNetCore.Server.Kestrel.Connections: Connection id "0HNP8U0H6AH0D" rejected because the maximum number of concurrent connections has been reached. 
   [server log Warning] Microsoft.AspNetCore.Server.Kestrel.Connections: Connection id "0HNP8U0H6AH0E" rejected because the maximum number of concurrent connections has been reached. 
   (b) H2 plain + TCP reset            : accepted 4, rejected 8; orphaned requests 400; kestrel.active_connections=4
   (c) H2 reset + conn error           : accepted 12, rejected 0; orphaned requests 2400; kestrel.active_connections=0

Kestrel log events (Debug+) counted on servers A+B:
   Critical:Http2QueueOperationsExceeded                        2
   Debug:ConnectionAccepted                                     109
   Debug:ConnectionDisconnect                                   20
   Debug:ConnectionReadFin                                      65
   Debug:ConnectionReset                                        1
   Debug:ConnectionStart                                        109
   Debug:ConnectionStop                                         109
   Debug:ConnectionWriteFin                                     72
   Debug:ConnectionWriteRst                                     37
   Debug:Http2ConnectionClosed                                  81
   Debug:Http2ConnectionError                                   35
   Debug:Http2ConnectionQueueProcessingCompleted                81
   Debug:Http2MaxConcurrentStreamsReached                       747
   Debug:Http2StreamError                                       1306
   Debug:Http2TooManyEnhanceYourCalms                           3
   Debug:HttpsConnectionEstablished                             101
   Information:RequestBodyNotEntirelyRead                       200
   Warning:ConnectionRejected                                   8

================ SUMMARY ================
S1 plain                : peak in-flight  100 on 1 conn; RST REFUSED_STREAMx200
S2 rapid reset          : peak in-flight  200 on 1 conn; reached app 200; RST ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, last=2147483647)
S2b sustained sub-EYC   : peak in-flight  200; 150 extra streams -> 0 reached app; conn open=True
S3 MadeYouReset win-ovf : peak in-flight  200 on 1 conn; reached app 200; RST FLOW_CONTROL_ERRORx300, ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, last=2147483647)
S4 MadeYouReset CL-mism : peak in-flight  200 on 1 conn; reached app 200; RST PROTOCOL_ERRORx299, ENHANCE_YOUR_CALMx99; no GOAWAY; closed=True
S5 scaling              : rapid-reset 200/conn, plain 100/conn (linear in #connections); 6816 B per in-flight request
S6 churn per handshake  : HTTP/1.1 1, H2 plain 100, H2 reset+conn-error 200 orphaned requests; ~6414 B each; all freed after the app's delay
S8 RequestAborted-aware : in-flight 0 1.5 s after 200 resets (peak 6)
S9 /fast req rate       : plain 24775/s vs rapid-reset 386/s on one conn; EYC=17, no GOAWAY
Leak check              : 0/65 Http2Connection objects alive after drain; heap 0.9 -> 2.9 MiB
S7 [NON-DEFAULT MaxConcurrentConnections=4]: plain+close orphaned 400 (limit holds); reset+conn-error orphaned 2400 with 0 conns counted (limit no longer bounds orphaned work)
```

## Appendix B: `h2churn/run-extra.txt` (verbatim)
```
Runtime            : .NET 10.0.0-rc.2.25502.107
Kestrel.Core       : 10.0.0-rc.2.25502.107+89c8f6a112d37d2ea8b77821e56d170a1bccdc5a
GC                 : Server, cores=4
App endpoint /slow : await Task.Delay(15s) without RequestAborted (realistic default code)

Server A on 127.0.0.1:38065  Http2.MaxStreamsPerConnection=100  MaxConcurrentConnections=null (unlimited)  MinResponseDataRate=240B/s
Baseline managed heap after warm-up: 0.94 MiB

=== X1 CONTINUATION flood: HEADERS(no END_HEADERS) then empty CONTINUATION frames for up to 35 s
   empty CONTINUATION frames sent      : 7,752,000 (66.5 MiB) over 31.1 s
   connection closed by server / GOAWAY: True / GOAWAY(code=0x2, last=2147483647)
   max heap during flood (vs baseline) : 1.16 MiB (baseline 0.94 MiB)
   [server log Debug] Microsoft.AspNetCore.Server.Kestrel.Http2: Connection id "0HNP8UGG0L5KO": HTTP/2 connection error. Http2ConnectionErrorException
   20 x 8 KB header CONTINUATIONs      : server closed=True, GOAWAY(code=0x1, last=1) (limit: 2 x MaxRequestHeadersTotalSize = 64 KB)

=== X2 slow read: SETTINGS_INITIAL_WINDOW_SIZE=0, 100 x GET /big (1 MiB each), never send WINDOW_UPDATE
   app requests blocked in WriteAsync  : 100
   heap delta with 100 stalled responses: 3.78 MiB = 39599 B/stream (app tried to write 100 MiB)
   server closed the connection after  : 11.7 s (MinResponseDataRate 240 B/s, 5 s grace)
   app requests still blocked          : 0
```

## Appendix C: `h2churn-net9/run-net9.txt` summary (.NET 9.0.20, verbatim)
```
Runtime            : .NET 9.0.20
Kestrel.Core       : 9.0.20+4e6235b8f9af12335ecd58a0a06b8f4105af2de0
GC                 : Server, cores=4
================ SUMMARY ================
S1 plain                : peak in-flight  100 on 1 conn; RST REFUSED_STREAMx200
S2 rapid reset          : peak in-flight  200 on 1 conn; reached app 200; RST ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, last=2147483647)
S2b sustained sub-EYC   : peak in-flight  200; 150 extra streams -> 0 reached app; conn open=True
S3 MadeYouReset win-ovf : peak in-flight  200 on 1 conn; reached app 200; RST FLOW_CONTROL_ERRORx300, ENHANCE_YOUR_CALMx100; GOAWAY(code=0xb, last=2147483647)
S4 MadeYouReset CL-mism : peak in-flight  200 on 1 conn; reached app 200; RST PROTOCOL_ERRORx275, ENHANCE_YOUR_CALMx76; no GOAWAY; closed=True
S5 scaling              : rapid-reset 200/conn, plain 100/conn (linear in #connections); 6819 B per in-flight request
S6 churn per handshake  : HTTP/1.1 1, H2 plain 100, H2 reset+conn-error 200 orphaned requests; ~6409 B each; all freed after the app's delay
S8 RequestAborted-aware : in-flight 0 1.5 s after 200 resets (peak 4)
S9 /fast req rate       : plain 24845/s vs rapid-reset 179/s on one conn; EYC=82, no GOAWAY
Leak check              : 0/65 Http2Connection objects alive after drain; heap 0.9 -> 2.1 MiB
S7 [NON-DEFAULT MaxConcurrentConnections=4]: plain+close orphaned 400 (limit holds); reset+conn-error orphaned 2400 with 0 conns counted (limit no longer bounds orphaned work)
```

## Appendix D: `h3mem/run2.txt` (real Kestrel 10.0 RC2 HTTP/3 + WebTransport over the in-memory QUIC model, verbatim)
```
Runtime      : .NET 10.0.0-rc.2.25502.107
Kestrel.Core : 10.0.0-rc.2.25502.107+89c8f6a112d37d2ea8b77821e56d170a1bccdc5a
GC           : Server

Part 1: WebTransport server (switch ON) on in-memory transport; app accepts the session and NEVER calls AcceptStreamAsync (push-only server)

=== W1 [SystemNetQuic credits]: churn WT bidi streams (open, send WT header, wait until queued, RESET+STOP_SENDING), then WT uni streams
   session established on stream 0 (SystemNetQuic); server answered CONNECT with HEADERS
   bidi WT streams opened+reset          : 99  (then BLOCKED: no QUIC stream credit)
   uni  WT streams opened+reset          : 9  (then BLOCKED: no QUIC stream credit)
   session _pendingStreams.Count         : 108
   session _openStreams.Count            : 0
   credits returned (dispose/finalizer)  : 0/0  (after a full GC)
   new bidi stream possible after GC?    : no

=== W2 [OnStreamClosed credits, hypothetical]: churn 20000 WT bidi streams on one session
   session established on stream 0 (OnStreamClosed); server answered CONNECT with HEADERS
   churned   5000                        : _pendingStreams=  5000  _openStreams=  0  heap +   12.9 MiB  =   2696 B/retained stream  (QUIC credits in use: 1)
   churned  10000                        : _pendingStreams= 10000  _openStreams=  0  heap +   25.6 MiB  =   2689 B/retained stream  (QUIC credits in use: 1)
   churned  20000                        : _pendingStreams= 20000  _openStreams=  0  heap +   51.2 MiB  =   2686 B/retained stream  (QUIC credits in use: 1)
   heap after client closed connection   : +-0.3 MiB vs before W2 (retention lives as long as the connection)

=== W3 [SystemNetQuic credits]: app accepts + immediately disposes each WT stream, peer closes it afterwards
   session established on stream 0 (SystemNetQuic); server answered CONNECT with HEADERS
   streams opened before blocking        : 99  (accepted+disposed by app: 99)
   session _pendingStreams / _openStreams: 0 / 99   <- disposed-by-app streams stay in _openStreams
   credits back after forced GC          : 0 (finalizer)
   more streams possible after GC        : 0

=== W3b [SystemNetQuic credits]: app accepts each WT stream, peer closes it, app disposes ~300 ms later
   session established on stream 0 (SystemNetQuic); server answered CONNECT with HEADERS
   streams opened before blocking        : 99  (accepted by app: 149)
   session _pendingStreams / _openStreams: 0 / 24
   credits back after forced GC          : 75 (finalizer: Kestrel never disposes the WT transport stream)
   more streams possible after GC        : 50
   [server log Information] Microsoft.Hosting.Lifetime: Application is shutting down... : 

Part 2: HTTP/3 server (WebTransport OFF); /slow awaits 10s without RequestAborted

=== R [SystemNetQuic credits]: HTTP/3 rapid reset, HEADERS(GET /slow) then RESET_STREAM+STOP_SENDING, up to 1000 streams
   request streams opened+reset          : 100  (then BLOCKED: no QUIC stream credit)
   app in-flight now / peak              : 100 / 100
   credits returned (dispose/close)      : 0/0

=== R [OnStreamClosed credits, hypothetical]: HTTP/3 rapid reset, HEADERS(GET /slow) then RESET_STREAM+STOP_SENDING, up to 1000 streams
   request streams opened+reset          : 1000  (no limit hit)
   app in-flight now / peak              : 1000 / 1000
   credits returned (dispose/close)      : 0/1000

Server warnings/errors logged: Information:0=1

================ SUMMARY ================
W1 WT, shipped credits      : 99 bidi + 9 uni streams churned, then blocked; retained in _pendingStreams=108; _openStreams=0
W2 WT, credit-on-close (hyp): 20000 streams churned in 2555 ms -> 20000 retained in _pendingStreams, +51.2 MiB, 2686 B/stream (managed, model transport)
W3 WT, shipped credits, app accepts+disposes: blocked after 99; 99 streams left in _openStreams; 0 credits returned after GC
W3b WT, shipped credits, app disposes after peer close: blocked after 99; 75 credits only come back via GC finalisation
R  HTTP/3 rapid reset [SystemNetQuic]: 100 streams, app in-flight peak 100, then blocked by QUIC credit
R  HTTP/3 rapid reset [OnStreamClosed]: 1000 streams, app in-flight peak 1000
```
