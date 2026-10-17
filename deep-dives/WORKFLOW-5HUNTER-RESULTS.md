# 5-hunter workflow results + my own verification pass

Workflow `wf_760e1004-23b`, 2026-10-17. 15 agents planned, 44 min wall, ~1.07M subagent tokens.
**The workflow's own "0 survivors" headline is WRONG and must not be quoted.** All 9 verify
agents and the synthesis agent died on the session rate limit (reset 13:20 UTC), and my script
computed `survived = cast.length > 0 && kills.length === 0`, so zero successful verifiers →
`survived: false`. Every candidate shows `killed_by: []` — **no lens refuted anything**. The three
candidates were UNVERIFIED, not killed. I ran the verification myself afterwards; that is what
this file records.

| Agent | Outcome |
|---|---|
| hunt: Kestrel HTTP/1.1 parsing | completed — CLEAN |
| hunt: Multipart + form/FormDataMapper | completed — 1 candidate |
| hunt: Authorization LOGIC | completed — 1 candidate |
| hunt: HPACK/QPACK header decode | completed — 1 candidate |
| hunt: Insecure docs/samples ($10k) | **FAILED (rate limit) — never ran, still open** |
| 9 × verify lenses + synthesize | **FAILED (rate limit)** |

---

## VERDICT AFTER MY VERIFICATION

| # | Candidate | My verdict | Est. |
|---|---|---|---|
| **W1** | Quadratic `FormDataReader.GetKeys()` → remote CPU exhaustion | **SURVIVES all three filters** | **~20-25%** |
| W2 | HPACK indexed header field index 0 → `IndexOutOfRangeException` | REAL + NOVEL, but Low → $0 | ~5% |
| W3 | `.ShortCircuit()` ignores `FallbackPolicy` | **KILLED — documented by-design** | ~2% |

W1 is the first finding this entire session to survive Filter 1 (by-design).

---

## W1 — Quadratic form-key rescan → remote unauthenticated CPU exhaustion  ★ BEST FINDING OF THE SESSION

**Class:** Remote DoS (algorithmic complexity). **Default config: YES. Unauthenticated: YES.**

`src/Components/Endpoints/src/FormMapping/FormDataReader.cs:110-158`. `GetKeys()` linearly scans
the entire submitted form dictionary on every invocation (`foreach (var kvp in _readOnlyMemoryKeys)`
at `:117`, prefix compare at `:123`). `DictionaryConverter.TryRead` calls it once per dictionary
scope (`DictionaryConverter.cs:42`) then recurses per key (`:59-62`), so a model with a dictionary
nested two levels deep invokes it N+1 times for N form entries → **O(N² · L)**.

Both factors are attacker-chosen *inside default limits*: N ≤ `ValueCountLimit` = 1024, and
L ≤ `MaxKeyBufferSize` = 2048 chars — multipart field names carry **no** `KeyLengthLimit` at all
(`FormFeature.cs:291`). The early-exit in the `:123` compare is defeated by giving every key the
same long leading padding and putting the distinguishing index at the END; 2-byte UTF-8 padding
(U+00E9) additionally forces `OrdinalIgnoreCase` off its vectorized ASCII fast path.

### Measured, on the real shipped framework (not source copies)
Default-configuration minimal API, nothing set anywhere; 1024 multipart sections, 4.07 MB body,
**all responses HTTP 200** — fully accepted under default limits, not an error path:
```
runtime = 9.0.20
  /flat  (1 dict level) adversarial   body=4072KB 200  wall=  138ms cpu=  165ms
  /nested (2 dict levels) benign      body=4072KB 200  wall=  202ms cpu=  222ms
  /nested (2 dict levels) ADVERSARIAL body=4072KB 200  wall= 3453ms cpu= 3753ms   <<< 25x
  -- concurrency sweep (cores=4) --
    conc= 1  uploaded=  4.0MB  wall= 3.50s  serverCpu=  3.72s  cpuPerMB=0.93s
    conc= 4  uploaded= 15.9MB  wall= 3.57s  serverCpu= 13.05s  cpuPerMB=0.82s
    conc=16  uploaded= 63.6MB  wall=15.39s  serverCpu= 53.17s  cpuPerMB=0.84s
```
~0.85 CPU-s/MB adversarial vs ~0.05 benign. Extrapolated, **~3.4 MB/s (~27 Mbit/s) of upload
saturates a 4-core server indefinitely**, starving the ThreadPool and stalling unrelated requests.
Pure CPU — no memory growth, so it denies service while traffic continues rather than killing the
process.

### Patch status — rigorously established
`FormDataReader.cs` is byte-identical on `main`, `release/10.0`, `release/9.0`
(sha256 `80570c84ff585828a171102d8c38f9ed610a60950218c4fd15c010ec9c2b8f22`); `release/8.0` also
carries the lazy scan. **Unpatched on every supported branch.**

Origin: **dotnet/aspnetcore PR #66674** "[Form binding] Fix parsing of malformed keys" (merged
2026-05-14), which replaced the eager `ProcessFormKeys` (it had an infinite loop on a malformed key
like `customer[0`) with the per-prefix `GetKeys` scan. **The PR does not mention performance or
complexity** — so this is an unintended regression, which is exactly why it survives the by-design
filter.

Beautiful independent confirmation of the boundary from assembly metadata: `strings` on
`Microsoft.AspNetCore.Components.Endpoints.dll` shows `ProcessFormKeys` **present** in
10.0.0-rc.2.25502.107 (built 2025-10, pre-change) and **absent** in 9.0.20 (post-change) — matching
the measured 140 ms vs 3453 ms for the identical request. A 26.6x regression pinned to a specific PR.

Prior-report check: zero matches in issues or PRs; no CVE or advisory.

### My verification (the lenses that never ran)
- **Eligibility / by-design → SURVIVES.** PR #66674 is a correctness fix that never mentions
  performance. Nothing in Microsoft's docs advertises or warns about this cost. First finding this
  session to clear this filter.
- **Patched / public → SURVIVES.** Unpatched on all four branches, sha256-verified; no prior report.
- **Reachability → SURVIVES, with one honest narrowing.** Default config, unauthenticated, network
  bytes, measured end-to-end on the shipped runtime. **But the app's bound form model must contain a
  dictionary nested ≥2 levels deep** (`Dictionary<K,T>` where T itself holds a dictionary). A
  single-level `Dictionary<string,string>` is unaffected — 138 ms measured on the identical
  adversarial body. That is an uncommon model shape, and it materially narrows real-world exposure.

### Honest residual risk (~20-25%, below the hunter's 30%)
The kill path is **severity classification**, not validity. Amplification is bandwidth-proportional
rather than explosive (27 Mbit/s to saturate 4 cores), so MSRC may rate it Moderate — which pays
**$0** — or route it to the perf team as a regression rather than a vulnerability. The nested-model
requirement invites "requires unlikely application shape". Remote DoS pays $20k Critical / $10k–$2.5k
Important; realistic landing zone is Important-Low ≈ $2,500 if accepted at all.

**Strongest framing for a submission:** a correctness-fix PR silently introduced a 26.6x
algorithmic regression, reachable by an unauthenticated network client under entirely default
configuration, on every supported branch, with an exact pre/post boundary provable from shipped
assembly metadata. Lead with the regression and the PR attribution, not with the raw CPU number.

## W2 — HPACK indexed header field index 0 (REAL, NOVEL, worth $0)
RFC 7541 §6.1: *"The index value of 0 is not used. It MUST be treated as a decoding error."*
`HPackDecoder.OnIndexedHeaderField` (shared dotnet/runtime source, `HPackDecoder.cs:547-552`)
checks only the **upper** bound (`index <= H2StaticTable.Count`), so index 0 passes. Kestrel's
`Http2Connection.cs:1584` then does `H2StaticTable.Get(index - 1)` → `s_staticDecoderTable[-1]` →
`IndexOutOfRangeException`, which is not in the catch list, producing **GOAWAY INTERNAL_ERROR**
instead of the spec-required COMPRESSION_ERROR. Single HPACK octet `0x80`.

Unpatched on dotnet/runtime `main`, `release/10.0`, `release/9.0` (all fetched, all identical);
PoC'd on two shipped runtimes with default Kestrel config over real ALPN h2. I searched
dotnet/runtime issues myself — **no matching report**, so it is novel.

Worthless anyway, and the hunter said so plainly: the **CLR managed bounds check** catches the
negative index, so there is no memory corruption, no out-of-bounds read, no info leak, no RCE
primitive. Only the attacker's own connection is torn down; the process and other connections are
unaffected. **No amplification** — one TLS handshake plus ~40 bytes costs the attacker more than the
server loses, strictly worse for them than simply disconnecting. Residue is protocol
non-compliance plus log noise. Low → **$0**.
**Right disposition: a GitHub issue on dotnet/runtime**, not an MSRC case.

## W3 — `.ShortCircuit()` ignores `FallbackPolicy` — KILLED by Filter 1
The hunter built a genuinely clean PoC on both 10.0-RC2 and 9.0.318:
```
FallbackPolicy = RequireAuthenticatedUser()  (global auth requirement)
  GET /normal      anonymous -> 302 Found
  GET /fast        anonymous -> 200 OK   [SECRET-fast]   <<<< served unauthenticated
  GET /fast-attr   anonymous -> 500 InternalServerError
```
and established the guard (`EndpointRoutingMiddleware.cs:161-178` on release/10.0;
`AuthorizationMetadataHelper.cs:12-15` on main) considers only `IAuthorizeData`,
`AuthorizationPolicy` and `IAuthorizationRequirementData` — never `FallbackPolicy`. Unpatched on all
three branches.

**I killed it on the docs.** Microsoft's routing page states verbatim: *"Use the `ShortCircuit`
extension method to cause routing to invoke the endpoint logic immediately and then end the request.
For example, **a given route might not need to go through authentication or CORS middleware.**"*
Skipping authentication middleware is the *advertised purpose*. The documented guard is explicitly
scoped to metadata — *"endpoints that also have `[Authorize]` or `[RequireCors]` metadata… applied by
`[Authorize]` or `[EnableCors]` attributes or by `RequireCors` or `RequireAuthorization` methods"* —
and `FallbackPolicy` is documented separately, under guidance for library authors, as a **middleware**
behaviour that *"applies when the middleware can't produce a policy from authorization metadata."*
Short-circuiting means the middleware does not run, so the documented behaviours are consistent.

Developer must also explicitly opt in per route (`default_config: False`). Fourth kill this session
from Filter 1.

## Kestrel HTTP/1.1 — exemplary CLEAN, and the most reusable output here
Worth preserving in full because it closes the surface properly. The hunter sha256-verified its
working copies against GitHub `main` before investing (`HttpParser.cs`
`60e0411361f63de1…`, `Http1ChunkedEncodingMessageBody.cs` `66e98a74afbbec35…`,
`Http1Connection.cs` `29dc90cee74df5ce…`, `ChunkedExtensionParser.cs` `28396b55755f4a9f…`), then ran:
- **9,173,316 header segmentation-differential comparisons** (two seeds, inputs to 40 B over a
  CR/LF/NUL/colon/SP/TAB/hyphen/percent/0x80/0xff/semicolon/comma/quote alphabet, every single-cut
  and several two-cut segmentations, whole-buffer and incremental feed modes)
- **724,054 chunked state-machine comparisons** against an independent strict RFC 9112 §7.1 reference
  de-chunker

Result: zero "whole buffer rejects, split accepts"; zero cases where segmentation changed the decoded
body or trailer set; zero invariant violations (no CR/LF/NUL ever reached a header or trailer
name/value — which is what makes `checkForNewlineChars: false` at `Http1ParsingHandler.cs:31` safe);
no out-of-bounds; no hang.

**The high-value question answered NO:** trailers do *not* merge into request headers.
`Http1ParsingHandler.OnHeader` routes trailers to `OnTrailer`, and `HttpProtocol.OnTrailer`
(`:564-570`) appends to a separate `RequestTrailers` dictionary (`:234`). **No
trailer-overrides-header primitive exists.**

Also closed with evidence, not argument:
- **Trailer limits bypass: disproven.** `MaxRequestHeadersTotalSize` is enforced on the trailer
  section and the budget is genuinely *shared* — pre-spending 32,000 of 32,770 bytes makes an
  otherwise-fine 7 KB trailer block fail. `MaxRequestHeaderCount` likewise shares
  `_requestHeadersParsed`, and HTTP/1 enforces the exact limit (unlike H2/H3, which relax to 2x).
- **Known-header aliasing: proven impossible.** All 117 masked comparisons extracted from
  `HttpHeaders.Generated.cs:7514-7875` and brute-forced over all 256 byte values at each of the 505
  masked positions. Every position uses `0xdf` (admitting exactly one ASCII letter's two cases) or
  `0xff` (exact). **Collision-capable positions: 0.** No unknown header can alias `Host`,
  `Content-Length`, `Transfer-Encoding`, `Connection` or `Authorization`.
- Chunk-size hex accumulation is `checked` and capped at 8 digits; chunk framing bytes are charged to
  `MaxRequestBodySize`; chunk extensions need non-default `EnableChunkedExtensions` (Filter 3);
  the interned header-name cache is a fixed 91-entry set attacker names cannot grow.
- Its two own findings were self-killed as already public: **#69819** (chunk size > Int32.MaxValue →
  IOException/500, *and* pinned by upstream test `ReadThrowsGivenChunkPrefixGreaterThanMaxInt`) and
  **#69820** (control chars in header/trailer names). **I independently confirmed both issue numbers
  are real, open, and opened 2026-10-13** — the citations are genuine, not hallucinated.

## Still open
`hunt: Insecure docs/samples ($10k category)` never ran — killed by the rate limit before starting.
That category inverts Filter 1 (docs being load-bearing is the attack surface, not the defence) and
remains the most under-explored paid category available.

## Note on the workflow design
Pipelining find→verify was right, but two things bit:
1. **The 4-vCPU box caps concurrency at `min(16, 4-2)` = 2.** A 5-hunter fan-out gets ~no parallelism
   here; 2–3 deeper hunters would have been the better shape.
2. **`survived = cast.length > 0 && kills.length === 0` conflates "no verifier ran" with "refuted".**
   Safe default, but it mislabels rate-limit casualties as kills. A future script should return a
   distinct `unverified` state so the headline cannot lie.
