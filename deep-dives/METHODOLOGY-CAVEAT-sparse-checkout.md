# Methodology caveat: the local aspnetcore clone was a sparse checkout (discovered 2026-10-13)

**Why this file exists:** a hunter agent discovered that `/home/user/dotnet-hunt/aspnetcore`
was a **sparse checkout** holding only 11 of ~40 top-level `src/` directories. This
systematically undermines a class of our own earlier conclusions, so it is recorded
rather than quietly fixed.

## The defect

`git sparse-checkout list` returned only:

```
src/Antiforgery  src/Components/Endpoints  src/Grpc  src/Hosting  src/Http
src/Middleware/RateLimiting  src/Mvc  src/Security  src/Servers  src/Shared  src/Validation
```

Absent **from disk** while still present in the git tree: `src/SignalR`, `src/Identity`,
`src/DefaultBuilder`, `src/DataProtection`, `src/OpenApi`, `src/Razor`,
`src/ProjectTemplates`, `src/HttpClientFactory`, `src/StaticAssets`, `src/WebEncoders`,
`src/Analyzers`, `src/Caching`, `src/HealthChecks`, `src/Localization`, `src/Fuzzing`,
and **all of `src/Middleware` except `RateLimiting`** — i.e. `HttpOverrides` (forwarded
headers), `CORS`, `HostFiltering`, `OutputCaching`, `ResponseCaching`,
`RequestDecompression`, `HttpsPolicy`, `HttpLogging`, `HeaderPropagation`, `Diagnostics`.

The clone is also **shallow** (`git rev-list --count HEAD` == 1), so per-file `git log`
returns nothing — every local "is this already patched?" check via file history was
uninformative and must be redone against GitHub.

## Why it matters: it manufactures false negatives, silently

`grep` over a directory that does not exist reports **no matches**. That is byte-for-byte
indistinguishable from "the code is clean." Every **CLEAN** verdict this session that
rested on a local grep of an absent path is therefore **unsupported** — not necessarily
wrong, but never actually tested.

Specifically suspect (absent from disk when audited, verdicts need redoing):
CORS, HostFiltering, OutputCaching, RequestDecompression, ResponseCaching,
Data Protection, Identity UI, HttpClientFactory, and the forwarded-headers middleware
itself. Surfaces audited inside the 11 present directories (Kestrel, SignalR-adjacent
`Http.Connections` work done via built apps, routing, model binding, JsonPatch,
FormDataMapper, rate limiting, Blazor endpoints) are unaffected by this specific defect.

## What it does NOT invalidate

The empirical results stand on their own, because they came from **running apps built
against published NuGet packages**, not from this source tree:

- **Chain #1 (Aspire):** origin bypass proven against the real 13.6.1 dashboard (101 vs 403);
  impact proven in a self-contained host. Untouched.
- **Chain #2 (SignalR CSWSH):** proven with a real stock SignalR app getting a 101 upgrade
  with `Origin: evil.attacker.com`. Untouched.
- **Chain #3 (Identity reset poisoning):** proven with a real app.
- **Chain #4 (XFF spoof):** behaviour proven empirically; separately refuted as by-design.

## Post-fix verification (all three chain citations re-checked against real files)

`git sparse-checkout disable` was run; worktree went 133M -> 297M, all paths materialized.
The code citations in the chain write-ups were then verified against the actual files:

- **Chain #4** — `src/DefaultBuilder/src/ForwardedHeadersOptionsSetup.cs`: confirmed
  verbatim, including `options.KnownIPNetworks.Clear(); options.KnownProxies.Clear();`
  and the "Only loopback proxies are allowed by default" comment.
- **Chain #3** — `src/Identity/UI/.../V4/Account/ForgotPassword.cshtml.cs`: confirmed
  verbatim; `Url.Page(..., protocol: Request.Scheme)` passes **no** `host:`, so the host
  is taken from client-controlled `Request.Host`.
- **Chain #2** — re-ran the load-bearing **negative** claim against the now-present
  `src/SignalR`. Confirmed: **no `Origin`-header validation anywhere in SignalR server
  code.** All 6 case-sensitive `origin` hits are `OriginalActivity` /
  `OriginalParameterTypes` / `OriginalIssuer` / `SeekOrigin`, client-side proxy code, or
  test-app CORS startup. The absence is real, not a checkout artifact.

So the citations were substantively accurate — but that was prior knowledge of the
codebase being right, not verification. The distinction matters and is why this is logged.

## Standing rules going forward

1. The checkout is now **full**. Do not re-enable sparse checkout.
2. The clone is still **shallow**: never conclude "already patched" / "recently introduced"
   from local `git log`. Use the GitHub MCP tools or the web against `dotnet/aspnetcore`.
3. Before accepting any **CLEAN** verdict that rests on absence-of-code, confirm the files
   are on disk (`ls` the path, don't just grep it). A hunter brief should say so explicitly.
