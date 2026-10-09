# HUNT: Kestrel HTTP-layer vulnerability hunt (v2)

**Date:** 2026-10-09
**Target repo:** `/home/user/dotnet-hunt/aspnetcore` @ `85162224` (branch `main`, VersionPrefix **12.0.0**)
**Runtimes available for empirical testing:** `Microsoft.AspNetCore.App` **9.0.20** and **10.0.0-rc.2.25502.107** (SDKs 9.0.318, 10.0.100-rc.2)
**Scope:** HTTP/1, HTTP/2 (both in Kestrel's default `Http1AndHttp2`). HTTP/3/QPACK is **not** in default config and was deprioritised.

---

## TL;DR verdict

- **One genuine, empirically-proven request-smuggling vulnerability found** (CL.TE connection-reuse / missing `Connection: close`). I demonstrated **full end-to-end victim-request poisoning** against the installed **.NET 10.0.0-rc.2** runtime, and showed **.NET 9.0.20 is immune**.
- **It is already fixed** by Microsoft across every branch, **including the audited `main`**. Fix shipped in **8.0.27 / 9.0.16 / 10.0.10** (coordinated 2026 servicing wave) via a `keepAlive = false` + `AllowKeepAliveAfterCLTE` opt-out switch. **The audited repo (`main`) is NOT vulnerable.**
- Therefore, as a **bounty finding against `main`: NOT eligible** (already remediated). As an *operational* fact it still matters: anyone pinned to 8.0.0–8.0.26 / 9.0.0–9.0.15 / 10.0.0–10.0.9 (and the rc2 in this very environment) is exposed.
- **CVE-2025-55315 chunk-extension fix: verified COMPLETE** in `main` (bare-LF rejected in every extension state; confirmed empirically on rc2).
- Other heavily-audited surfaces (HPACK bounds, CONTINUATION/rapid-reset mitigations, frame padding math, header-size limits, CL/TE precedence, duplicate-CL) reviewed — **no live defect found**.

I did **not** find a novel, bounty-eligible, live-in-`main` critical bug.

---

## FINDING 1 — CL.TE request smuggling via missing RFC 9112 §6.1 connection close (ALREADY FIXED in `main`)

### Boundary / threat model
- Attacker = anonymous remote client. Victim = another client whose request shares a pooled front-end→Kestrel keep-alive connection. Standard request-smuggling model. Boundary = **Network**.
- Impact if live = cross-request poisoning: the attacker's smuggled request is served in place of the victim's (auth/authorization/CSRF bypass, cache poisoning, credential theft) — the CWE-444 class, same family as CVE-2025-55315 (9.9).

### Default reachability
- **Yes, default config.** Stock `WebApplication.CreateBuilder`, no options touched. The vulnerable path is the *default* path; in fixed builds the `Microsoft.AspNetCore.Server.Kestrel.AllowKeepAliveAfterCLTE` AppContext switch defaults OFF (safe). In vulnerable builds the switch does not exist at all.

### Byte-level detail / root cause
`Http1MessageBody.For()` resolves framing when a request carries **both** `Content-Length` and `Transfer-Encoding: chunked`. RFC 9112 §6.1 is explicit: *"the server MUST close the connection after responding to such a request to avoid the potential attacks."*

Vulnerable code (verbatim from tag **v10.0.2**, identical in the installed rc2 assembly — confirmed by `ilspycmd` decompile):
```csharp
if (headers.ContentLength.HasValue)
{
    IHeaderDictionary headerDictionary = headers;
    headerDictionary.Add("X-Content-Length", headerDictionary[HeaderNames.ContentLength]);
    headers.ContentLength = null;
    // <-- NOTHING sets keepAlive = false here
}
return new Http1ChunkedEncodingMessageBody(context, keepAlive);  // keepAlive still == true
```
`keepAlive == true` ⇒ `messageBody.RequestKeepAlive == true` ⇒ `HttpProtocol.ProcessRequests` does **not** call `DisableKeepAlive` ⇒ the `while (_keepAlive)` loop iterates again ⇒ bytes left over after Kestrel's chunked-framed body are parsed as the **next** request on the same connection.

Fixed code (`main`, and tags 8.0.27/9.0.16/10.0.10+):
```csharp
if (headers.ContentLength.HasValue)
{
    IHeaderDictionary headerDictionary = headers;
    _ = headerDictionary.TryAdd("X-Content-Length", headerDictionary[HeaderNames.ContentLength]);
    headers.ContentLength = null;
    if (!ContinueProcessingAfterCLTE)   // AppContext switch, default false
    {
        keepAlive = false;              // RFC 9112 §6.1
    }
}
```
(`main` additionally changed `Add` → `TryAdd`, see Finding 1b.)

Relevant source read directly from the audited repo: `/home/user/dotnet-hunt/aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/Http1MessageBody.cs:185-203` (has the `keepAlive = false`). Keep-alive wiring: `HttpProtocol.cs:684-687` (`if (!messageBody.RequestKeepAlive) DisableKeepAlive(...)`), `HttpProtocol.cs:650` (`while (_keepAlive)`), `HttpProtocol.cs:1458-1461` (`DisableKeepAlive` sets `_keepAlive=false`).

### PoC / measurement (EMPIRICAL)
Harness (all in `/tmp/claude-0/.../scratchpad/kestrel-hunt/`): stock Kestrel echo app on **8888** (net10.0 → runtime 10.0.0-rc.2) and **9888** (net9.0 → 9.0.20); a minimal **CL-framing front-end** (`tests/clframing_proxy.py`) that frames each request by `Content-Length` and pools ONE keep-alive backend connection across clients (represents the classic CL.TE front-end class); driver `tests/smuggle_poc.py`.

**Raw-pipelining probe (no proxy), CL+TE then a pipelined `GET /second`:**
- net10.0-rc2: **2 responses**, second is `REQ# … M=GET P=/second` → **connection reused** (no `Connection: close`).
- net9.0.20: **1 response** with `Connection: close` → **connection closed**, pipelined request discarded.

**End-to-end cross-client poisoning (CL-framing proxy in front):**
Attacker sends to the proxy:
```
POST /attacker HTTP/1.1\r\nHost: x\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n
0\r\n\r\nGET /SMUGGLED HTTP/1.1\r\nFoo: 
```
(The CL=44 body is `0\r\n\r\n` + the incomplete smuggled request line + `Foo: `. The proxy forwards all 44 body bytes + headers over the pooled connection. Kestrel uses TE: the `0\r\n\r\n` ends the body; `GET /SMUGGLED…Foo: ` is left buffered.) A separate victim then sends `GET /victim-normal HTTP/1.1`, which the proxy relays on the **same** pooled connection; it completes the smuggled request as `GET /SMUGGLED` with `Foo: GET /victim-normal HTTP/1.1`.

| Backend | Victim received | Verdict |
|---|---|---|
| **.NET 10.0.0-rc.2** (8888) | `REQ#… M=GET P=/SMUGGLED hdrs=[Host,Foo]` | **POISONED** |
| **.NET 9.0.20** (9888) | `REQ#… M=GET P=/victim-normal hdrs=[Host]` (after `Connection: close` forced a reconnect) | **CLEAN** |

The differential is caused solely by the missing `keepAlive=false`: the `AllowKeepAliveAfterCLTE=true` switch in fixed builds re-introduces exactly this vulnerable behaviour, which nails the attribution.

### Affected-version matrix (fix = `keepAlive=false` present in CL.TE branch; verified via raw.githubusercontent.com per-tag)
| Line | Vulnerable | Fixed from |
|---|---|---|
| .NET 8 (LTS) | 8.0.0 – 8.0.26 | **8.0.27** |
| .NET 9 | 9.0.0 – 9.0.15 | **9.0.16** |
| .NET 10 | 10.0.0 – 10.0.9, **10.0.0-rc.2 (installed here)** | **10.0.10** |
| `main` (v12) | — | present (fixed) |

Current latest servicing (8.0.31, 9.0.20, 10.0.12) **all have the fix.** No public CVE ID was locatable via search (CVE-2025-55315 is the *chunk-extension* issue, different). This looks like a coordinated 2026 servicing hardening (AppContext-switch signature + RFC 9112 §6.1 comment ⇒ treated as security).

### Honest MSRC-survival confidence: ~0% as a novel bounty finding
- The audited repo (`main`) **has the fix**. Every currently-shipping supported release **has the fix**. The fix is **public in the repo across all branches**, so the issue is "known/already fixed" by definition — MSRC closes these as duplicates.
- It is a *genuine* vulnerability (I proved it), but a **rediscovery of an already-remediated issue**, not a new one.
- Only non-latest/superseded builds (incl. the rc2 in this sandbox) are affected. **Not bounty-eligible.** Operationally worth an upgrade advisory for anyone on 8.0≤.26 / 9.0≤.15 / 10.0≤.9.

### Finding 1b (minor, also already fixed in `main`)
On shipped 10.0.0–10.0.9 / rc2, the CL.TE block uses `headerDictionary.Add("X-Content-Length", …)`. If the client **pre-supplies** an `X-Content-Length` header, `Add` throws `ArgumentException` (duplicate key) inside `For()`; the connection is torn down with **no HTTP response** (empirical: `POST … Transfer-Encoding: chunked / Content-Length: 5 / X-Content-Length: 99` → empty reply, socket closed). Per-connection abort only (attacker's own connection), not a server-wide DoS. `main` changed it to `TryAdd` → fixed. Not a finding.

---

## FINDING 0 (negative) — CVE-2025-55315 chunk-extension fix is COMPLETE in `main`

CVE-2025-55315 (9.9) = Kestrel accepted a **bare LF inside a chunk extension**; a front-end that treats `\n` as a line terminator → TERM.EXT desync.

The rewritten parser (`Core/src/Internal/Http/ChunkedExtensionParser.cs`) is a strict state machine. I audited every state for byte `0x0A`: it is rejected in `StartOfExtension`, `BeforeExtensionName`, `InExtensionName`, `BadWhitespaceAfterExtensionName`, `BeforeExtensionValue`, `ExtensionValueToken`, `ExtensionValueQuotedString` (qdtext ranges exclude 0x0A), `ExtensionValueQuotedPair` (ranges exclude 0x0A) and `ExtensionValueQuotedStringEnd`. **LF is accepted only in `WaitTerminatingLF`, and only immediately after a CR.** `ParseChunkedPrefix` likewise requires CR→LF after the size and rejects a bare LF (`BadChunkSizeData`).

**Empirical (rc2):** `5;x\n…`, `5;\n…`, `5\n…`, `5;x="a\nb"…`, `5;x\r…` — **all rejected** (`BadHttpRequestException` on body read; connection not reused). Fix is complete.

---

## Other surfaces audited — no live defect

- **CL vs TE precedence** (`Http1MessageBody.For`): TE-final-not-chunked → 400; `chunked,identity`/`chunkedX`/`Xchunked`/quoted `"chunked"` → 400; `identity, chunked` and tab-prefixed `\tchunked` → chunked. All RFC-correct (empirically confirmed). `GetFinalTransferCoding` (`HttpHeaders.cs:530`) classifies the *last* token and rejects trailing junk.
- **Content-Length parsing** (`HttpRequestHeaders.cs:94`): strict `1*DIGIT`, first byte must be a digit (rejects `+`/`-`/ws/hex), `consumed==length`, duplicate CL → `MultipleContentLengths` 400 (empirically confirmed `CL:5/CL:6` → 400).
- **Header-size limits** (`Http1Connection.cs:359-398`): input is trimmed to `MaxRequestHeadersTotalSize+2` (32 KB) and non-completion within that → `HeadersExceedMaxTotalSize`. Trailers share the same budget. Request line trimmed to `MaxRequestLineSize`. Bounded.
- **New non-throwing `HttpParser`** (`HttpParser.cs`, `TryParseHeaders`/`TryParseMultiSpanHeader`): multi-span buffer ≤ size budget; bare CR mid-value → reject; obs-fold → reject; space/tab before colon → reject. No infinite-loop / mis-advance found.
- **HPACK decoder** (`src/Shared/runtime/Http2/Hpack/HPackDecoder.cs`): `OnStringLength` caps string buffers at `_maxHeadersLength` (64 KB); Huffman output checked > `_maxHeadersLength`; integer decoder rejects overlong encodings; dynamic-table-size-update capped by `_maxDynamicTableSize`. No decompression bomb.
- **HTTP/2 floods**: Rapid-Reset mitigation present (`Http2Connection.cs` EnhanceYourCalm, default count 20 over 5-tick window; `MaxTrackedStreams = max(2×MaxConcurrentStreams,100)` bounds `_streams`). CONTINUATION accumulation bounded by connection-level `_totalParsedHeaderSize > 2×MaxRequestHeadersTotalSize` (`Http2Connection.cs:1615`) + `RequestHeadersTimeout`. Not empirically floored (would need an h2 frame client), but code-level mitigations are present and correct.
- **HTTP/2 frame padding math** (`Http2FrameReader.cs` + `Http2Frame.*`): `HeadersPayloadLength`/`DataPayloadLength = PayloadLength − offset − padLen`; `extendedHeaderLength > PayloadLength` → `FRAME_SIZE_ERROR`; `HeadersPayloadLength <= 0` with padding → `PROTOCOL_ERROR`. Slices stay in-bounds. No overread.

## Not fully exhausted (time-bounded; candidates for a future pass)
- HTTP/2 flood classes **empirically** (PING/SETTINGS/empty-DATA floods, CONTINUATION with 0-length frames under load) — code looks mitigated but I did not build an h2 frame fuzzer.
- Multipart/form parsing (`src/Http/WebUtilities/MultipartReaderStream.cs`, `FormReader`) under `FormOptions` defaults — reachable only when the app reads the form, so borderline for "stock `WebApplication.CreateBuilder`"; `UpdatePosition` enforces the length limits. Not deeply fuzzed.
- HTTP/3 / QPACK — **not default config**, excluded.

## Reproduction artifacts
`/tmp/claude-0/-home-user-EastDulwich/aaf86d3f-0c6c-5386-a069-bd4dffba2531/scratchpad/kestrel-hunt/`:
`app/` (net10 echo), `app9/` (net9 echo), `tests/clframing_proxy.py`, `tests/smuggle_poc.py`, `tests/t_*.py`, `h1mb_rc2.cs` (decompiled rc2 `For()` showing the missing `keepAlive=false`).
