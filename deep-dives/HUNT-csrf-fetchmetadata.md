# HUNT: cross-origin CSRF protection (Fetch Metadata) + OIDC remote sign-out

Researcher pass, authorized MSRC .NET bug bounty research. All testing local, loopback only.
Date: 2026-10-13.

---

## VERDICTS

| # | Candidate | Verdict |
|---|---|---|
| C1 | `DefaultCsrfProtection` fetch-metadata decision algorithm (default-on) | **CLEAN** |
| C2 | `HttpContext.Items` CSRF marker forgeable / confusable | **CLEAN** (sharp edge documented, not exploitable) |
| C3 | Allow-list logic: missing `Sec-Fetch-Site`, `same-site`, safe-method set, `Origin`/`Host` parsing | **CLEAN** |
| C4 | `RemoteAuthenticationAntiforgery` verdict suppression on remote-auth callback paths | **BY-DESIGN** (PR #68669) |
| C5 | OIDC remote sign-out `iss` guard is unreachable dead code (`ClaimActions.DeleteClaim("iss")`) | **REAL but LOW** — unpatched on all shipping branches; impact overlaps public issue #69630; MSRC lists "Low impact CSRF bugs" as out of scope |

**Is the new CSRF middleware default-on?** **Yes.** Auto-injected for any `WebApplication` that has
mapped endpoints, opt-out only. See the map below.

**Headline negative:** I could not find a browser-reachable bypass of the new middleware. The algorithm
closes the two classic Fetch-Metadata pitfalls (`same-site` is denied; `AllowAnyOrigin` CORS is not
treated as CSRF trust). 48 raw-socket attack vectors against the verbatim upstream implementation all
landed on the safe side. Upstream also ships 30 unit tests + 62 integration tests covering almost exactly
the attack axes in my brief (re-execute, `MapWhen`, `UsePathBase`, explicit/implicit routing, marker
stamping, post-routing-slot injection). This surface is new but it is **not** unaudited.

---

## 1. MAP OF THE NEW CSRF SURFACE

### 1.1 Why my local greps found nothing

`/home/user/dotnet-hunt/aspnetcore` is a **sparse checkout** (`git config core.sparseCheckout` -> `true`).
`git sparse-checkout list` returns `src/Antiforgery, src/Components/Endpoints, src/Grpc, src/Hosting,
src/Http, src/Middleware/RateLimiting, src/Mvc, src/Security, src/Servers, src/Shared, src/Validation`.
**`src/DefaultBuilder` is excluded** — which is exactly where the implementation lives. The local tree is
otherwise genuine main at `851622243f8aad5d72636142ec2414be966c2449` (2026-10-07).

All upstream file contents below were fetched from `raw.githubusercontent.com` and are mirrored verbatim
in `/home/user/EastDulwich/pocwork/csrf-fetchmetadata/algo/upstream/` with sha256s recorded in §5.

### 1.2 Files

Branch-relative paths in `dotnet/aspnetcore`.

| File | Role |
|---|---|
| `src/Http/Http.Abstractions/src/Antiforgery/ICsrfProtection.cs:13-25` | public interface, `ValueTask<CsrfProtectionResult> ValidateAsync(HttpContext)` |
| `src/Http/Http.Abstractions/src/Antiforgery/CsrfProtectionResult.cs:9-33` | sealed result, `Allowed()`/`Denied()` singletons |
| `src/DefaultBuilder/src/Internal/DefaultCsrfProtection.cs:10-129` | **the algorithm** (6 steps) |
| `src/DefaultBuilder/src/Internal/CsrfProtectionMiddleware.cs:16-80` | the middleware; stamps the marker, records the verdict, **does not short-circuit** |
| `src/DefaultBuilder/src/Internal/CsrfValidationException.cs` | exception stored on the feature |
| `src/Shared/SafeHttpMethods.cs:18-23` | `IsSafe` = GET \| HEAD \| OPTIONS \| TRACE \| QUERY |
| `src/Shared/MiddlewareInvokedKeys.cs:9` | `CsrfProtection = "__CsrfProtectionMiddlewareWithEndpointInvoked"` |
| `src/Shared/AntiforgeryValidationFeature.cs:11-17` | shared verdict carrier, `Valid` singleton |
| `src/DefaultBuilder/src/WebHost.cs:278-279` | `services.TryAddSingleton<ICsrfProtection, DefaultCsrfProtection>()` |
| `src/DefaultBuilder/src/WebApplicationBuilder.cs:28,477-483,497-500,520-534,571-583` | **registration / default-on** |
| `src/Http/Routing/src/EndpointRoutingMiddleware.cs:52-96` | consumes the reserved post-routing slot, validates its provenance |
| `src/Http/Routing/src/EndpointMiddleware.cs:51-57` | consumer: marker **presence** suppresses the "missing antiforgery middleware" developer error |
| `src/Http/Http/src/Features/FormFeature.cs:112-119,138-140,159-161,182-184,357-377` | consumer: blocks every form-read path when marker present AND verdict invalid |
| `src/Mvc/Mvc.ViewFeatures/src/Filters/AntiforgeryMiddlewareAuthorizationFilter.cs:14-32` | consumer: MVC 400 when verdict invalid |
| `src/Mvc/Mvc.ViewFeatures/src/Filters/AntiforgeryApplicationModelProvider.cs:29-63` | attaches that filter to controllers/actions carrying antiforgery metadata |
| `src/Components/Endpoints/src/RazorComponentEndpointInvoker.cs:232-246` | consumer: Blazor SSR 400 when verdict invalid |
| `src/Antiforgery/src/AntiforgeryMiddleware.cs:13-53` | token middleware; **nulls** any prior verdict at line 42 then overrides it |
| `src/DefaultBuilder/test/.../DefaultCsrfProtectionTests.cs` | 30 unit tests |
| `src/DefaultBuilder/test/.../CsrfProtectionIntegrationTests.cs` | 62 integration tests |

### 1.3 Registration path — default-on, opt-out

`WebApplicationBuilder.cs:477-483`:

```csharp
// Skip auto-injecting CSRF protection when the app has no endpoints registered.
if (addCsrfProtection = !WebHostUtilities.ParseBool(_builtApplication.Configuration["DisableCsrfProtection"])
    && serviceProviderIsService?.IsService(typeof(ICsrfProtection)) is true
    && !_builtApplication.Properties.ContainsKey(CsrfProtectionMiddlewareSetKey)
    && hasEndpointDataSources)
{
    _builtApplication.Properties[CsrfProtectionMiddlewareSetKey] = true;
}
```

All four conditions hold for a stock `WebApplication.CreateBuilder()` app with any mapped endpoint:
`ICsrfProtection` is registered unconditionally by `WebHost.cs:279` (part of `ConfigureWebDefaults`), the
property is unset, and `DisableCsrfProtection` is absent so `ParseBool` yields false. **No `UseXxx()` call
is required and there is no AppContext switch.** The only opt-outs are the `DisableCsrfProtection`
configuration key and per-endpoint `DisableAntiforgery()`.

Pipeline placement — the middleware must observe the *matched endpoint* (it reads per-endpoint CORS
metadata), so it is chained into a reserved post-routing slot rather than appended:

* user did **not** call `UseRouting()`: framework calls it at `WebApplicationBuilder.cs:446`;
  auth/authz are appended directly (`:527`) and CSRF is chained through
  `MiddlewareInvokedKeys.PostRoutingPipeline` (`:530-534`).
* user **did** call `UseRouting()`: auth/authz/CSRF all go into the slot (`:520-524`).
* `EndpointRoutingMiddleware.cs:54-64` wraps `_next` with that slot, so it re-runs on re-routed branches
  (`UseStatusCodePagesWithReExecute`, `UseExceptionHandler`, `UseRewriter`).

Upstream confirms default-on by test name: `CsrfProtection_AutoInjected_BlocksCrossOriginPost`,
`CsrfProtection_AutoInjected_AllowsSameOriginPost`, `CsrfProtection_AutoInjected_AllowsNonBrowserClients`,
and the negative `CsrfProtection_NotAutoInjected_WhenAppHasNoEndpointDataSources`.

### 1.4 The algorithm (`DefaultCsrfProtection.cs:13-78`)

1. `SafeHttpMethods.IsSafe(request.Method)` -> **Allow**.
2. `Sec-Fetch-Site` is `"same-origin"` or `"none"` -> **Allow**.
3. `Origin` present and the applicable CORS policy has `!AllowAnyOrigin && SupportsCredentials &&
   IsOriginAllowed(origin)` -> **Allow**.
4. `Sec-Fetch-Site` present (so: `cross-site`, `same-site`, anything else) -> **Deny**.
5. No `Sec-Fetch-Site`, `Origin` present -> string-compare `Origin` against `$"{Scheme}://{Host.Value}"`,
   `OrdinalIgnoreCase` -> Allow/Deny.
6. Neither header -> **Allow** ("non-browser client").

### 1.5 Enforcement model (important)

`CsrfProtectionMiddleware` **never short-circuits** (`:60` "This middleware does not short-circuit, but
only records the verdict"). It stamps `Items[CsrfProtection]` at `:49` and writes the verdict onto
`IAntiforgeryValidationFeature`. Rejection is done downstream:

* MVC / Razor Pages -> 400 (`AntiforgeryMiddlewareAuthorizationFilter.cs:24-28`)
* Blazor SSR -> 400 (`RazorComponentEndpointInvoker.cs:234-245`)
* minimal API form binding -> `InvalidOperationException` from `FormFeature.cs:372-377`, i.e. a 500
* `EndpointMiddleware.cs:51-57` enforces **nothing**; it only checks marker presence to decide whether to
  throw the developer-error "no antiforgery middleware" exception.

I verified `FormFeature` backstops **all four** form-read entry points (`:119, :140, :161, :184`), so the
minimal-API path has no gap.

---

## 2. CANDIDATE C1/C2/C3 — the new middleware: CLEAN

### 2.1 Method

I could not test the shipped binary: `DefaultCsrfProtection` exists only in .NET 11+/`main`, and the
container has .NET 9.0.20 and .NET 10.0.0-rc.2 runtimes only. So I compiled the **verbatim upstream source
files** (unmodified, sha256s in §5) into a real `WebApplication` on .NET 10 and drove it over a raw
`Socket` from the same process, so every request byte is controlled and parsed by real Kestrel. All eight
upstream files compile against .NET 10 with **0 warnings, 0 errors** — `HttpMethods.IsQuery` and
`Microsoft.AspNetCore.Antiforgery.IAntiforgeryMetadata` are already in
`Http.Abstractions/src/PublicAPI.Shipped.txt`.

One deliberate harness adjustment, documented in the source: .NET 10's `EndpointMiddleware` does not know
the .NET 11 marker key, so it threw its developer-error exception on every request (observed as 500s on
the first run). I set `RouteOptions.SuppressCheckForUnhandledSecurityMetadata = true`. That check is a
startup/config guard, **not** the security control; the security control is the
`IAntiforgeryValidationFeature` verdict, which is what the harness measures.

The endpoint reports exactly what real consumers read:
`marker` = `Items.ContainsKey("__CsrfProtectionMiddlewareWithEndpointInvoked")`,
`feature` = `null` | `valid` | `INVALID`. Only `INVALID` causes a real consumer to reject.

PoC: `/home/user/EastDulwich/pocwork/csrf-fetchmetadata/algo/`
Full output: `/home/user/EastDulwich/pocwork/csrf-fetchmetadata/algo-output.txt`

### 2.2 Verbatim output (excerpts; 48 vectors, final summary at the end)

```
=============== 1-safe-methods ===============
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | GET + cross-site + evil Origin
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | OPTIONS + cross-site + evil Origin
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | TRACE + cross-site + evil Origin
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | QUERY + cross-site + evil Origin
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | qUeRy + cross-site + evil Origin
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | POST + cross-site (unsafe method)
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | PUT + cross-site (unsafe method)
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | PATCH + cross-site (unsafe method)
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | DELETE + cross-site (unsafe method)
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | FROBNICATE + cross-site (unsafe method)
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | POST + X-HTTP-Method-Override: GET
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | POST + X-Method-Override: QUERY

=============== 2-secfetchsite ===============
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: [same-origin]
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: [none]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [same-site]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [cross-site]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [bogus]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [SAME-ORIGIN]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [Same-Origin]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [None]
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: [same-origin ]
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: [ same-origin]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [same-origin,cross-site]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: [cross-site,same-origin]
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Sec-Fetch-Site: ["same-origin"]
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: []
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | two SFS headers: cross-site then same-origin
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | two SFS headers: same-origin then cross-site
[??    ] status=400 marker=- feature=-       host=-                    | SFS obs-fold continuation line
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Sec-Fetch-Site: none + Origin: http://evil.example

=============== 3-cors ===============
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | cross-site from default-policy origin WITH AllowCredentials
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | cross-site from named policy WITHOUT AllowCredentials
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | trusted origin, different case
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | trusted origin with trailing dot host
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | trusted origin + evil origin (two Origin headers)

=============== 5-origin-vs-host ===============
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Origin == scheme://Host
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin cross-site
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin: null (sandboxed iframe / redirect)
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | Origin uppercase scheme+host
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin https:// but app scheme is http
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin with trailing slash
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin with userinfo
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | two Origin headers: match then evil
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | two Origin headers: evil then match
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1.:34823     | Origin trailing-dot host vs Host trailing-dot
[DENY  ] status=200 marker=1 feature=INVALID host=127.0.0.1:34823      | Origin ideographic full stop (U+3002) vs ASCII Host
[??    ] status=400 marker=- feature=-       host=-                    | ABSOLUTE-FORM target evil.example + Host header
[ALLOW ] status=200 marker=1 feature=valid   host=evil.example         | ABSOLUTE-FORM target evil.example, Host matches authority
[DENY  ] status=200 marker=1 feature=INVALID host=                     | HTTP/1.0 with NO Host header + Origin

=============== 6-no-headers ===============
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | POST with neither Sec-Fetch-Site nor Origin
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | POST form body, neither header, with Cookie

=============== 7-plumbing ===============
[SKIPPED] status=200 marker=1 feature=null    host=127.0.0.1:34823      | cross-site POST to RequiresValidation=FALSE endpoint
[NOTRUN ] status=200 marker=0 feature=null    host=127.0.0.1:34823      | cross-site POST to endpoint with NO antiforgery metadata
[ALLOW ] status=200 marker=1 feature=valid   host=127.0.0.1:34823      | SAFE method GET to RequiresValidation=TRUE endpoint

# summary: 17 expected-ALLOW matched, 30 expected-DENY matched, 1 UNEXPECTED
```

The single `UNEXPECTED` is the obs-fold vector: Kestrel rejects the folded header with **400** before the
middleware runs, which is stricter than my prediction, not weaker. My expectation string just did not
match the parser-level rejection.

### 2.3 Findings per attack question

**Q3a — missing `Sec-Fetch-Site` treated as "allow"?** Only when `Origin` is *also* absent (step 6).
With `Sec-Fetch-Site` absent but `Origin` present, step 5 compares `Origin` to `scheme://Host` and denies
a mismatch. This matters because browsers **do not** send `Sec-Fetch-*` to non-potentially-trustworthy
URLs (plain-HTTP, non-localhost), which is a common deployment; in that configuration step 5 is the
active control and it holds — a cross-site form POST carries `Origin`, so it is denied.

For step 6 to be browser-reachable, a browser would have to omit **both** headers on a state-changing
request. Per Fetch, the `Origin` header is appended for every non-GET/HEAD request; referrer policy can
degrade its *value* to the literal `null`, but `Origin: null` is a non-empty string, so it falls into
step 5 and is denied — confirmed empirically above. I found no browser path to step 6.

**Q3b — `same-site` allowed?** **No.** `same-site` is denied (step 4). The classic Fetch-Metadata pitfall
(a subdomain XSS/takeover becoming CSRF on the parent) is closed. Upstream test:
`CsrfProtection_SecFetchSiteSameSite_Denied`.

**Q3c — safe-method set.** GET, HEAD, OPTIONS, TRACE, QUERY. OPTIONS/TRACE/QUERY are not reachable as
credentialed cross-site browser writes (HTML forms do GET/POST only; `fetch` with those methods needs a
CORS preflight; `no-cors` permits only GET/HEAD/POST). Matching is case-**insensitive** via
`HttpMethods.*` (`get`, `Get`, `qUeRy` all allowed), which is correct and does not widen the set.
`X-HTTP-Method-Override` / `X-Method-Override` are **not** honored — both denied.

**Q3d — `Origin` parsing.** There is **no URI parsing at all**; step 5 is a single
`MemoryExtensions.Equals(origin, $"{Scheme}://{Host.Value}", OrdinalIgnoreCase)`. So the `Uri.Host` vs
`Uri.IdnHost` differential I proved elsewhere (U+3002/U+FF0E/U+FF61) **does not apply here** — I tested
`Origin: http://127。0。0。1:PORT` against an ASCII `Host` and it denies. `Origin: null`, trailing slash,
userinfo, duplicate `Origin` headers, scheme mismatch and port mismatch all deny. Trailing-dot is
consistent on both sides (`Host: 127.0.0.1.` + `Origin: http://127.0.0.1.` -> allow), which is
self-consistent and not attacker-influenceable from a browser.

**Q3e — is client-controlled `Host` used as the same-origin reference?** **Yes**, step 5 uses
`request.Host` and `request.Scheme`. This is the same shape as the mistake that made the Aspire Dashboard
chain work — but it is **not exploitable here**, because step 5 requires `Origin` *and* `Host` to match,
and in a browser both are derived from the same target URL: the attacker controls `Origin` (their own
page) but not `Host`. I confirmed the only way to make them match is to control both, i.e. a non-browser
client: `POST http://evil.example/t HTTP/1.1` + `Host: evil.example` + `Origin: http://evil.example`
-> allow, with `request.Host` following the absolute-form authority (`host=evil.example` in the output).
A non-browser client has no victim cookies, so this yields nothing. Noted for completeness, not a finding.

**Q2 — is the `Items` marker forgeable or confusable?** No, but there is a real sharp edge:
`CsrfProtectionMiddleware.cs:49` stamps the marker **before** the `RequiresValidation` check at `:50`, so
a request can reach the consumers with `marker=1` and **no verdict recorded at all** — measured above as
`[SKIPPED] marker=1 feature=null`. Upstream treats this as intended
(`CsrfProtection_SetsItemsMarker_EvenWhenEndpointDisabledAntiforgery`). It is not exploitable because the
only way to reach it is `RequiresValidation == false`, i.e. the developer called `DisableAntiforgery()`,
and in that same state `EndpointMiddleware.cs:54` would not have demanded a middleware anyway. Blazor
(`RazorComponentEndpointInvoker.cs:233-236`) and the MVC filter both proceed on a *null* feature by
design for the same reason.

Marker forging from outside is not possible — `HttpContext.Items` is server-side state with no
request-controlled input. The reserved post-routing slot is also hardened against app code smuggling
middleware into it: `EndpointRoutingMiddleware.cs:77-96` validates the delegate's method name
(`CreateMiddleware`), declaring assembly name (`Microsoft.AspNetCore`) **and** public key token, and
`:58-61` throws otherwise (`PostRoutingPipeline_ApplicationProvidedClosure_IsRejected`,
`PostRoutingPipeline_DelegateFromAnotherAssembly_IsRejected`, `PostRoutingPipeline_NonDelegateValue_IsRejected`).

**Re-execute / nesting survival.** I could not reproduce this faithfully in-container: the real behaviour
depends on the internal `PostRoutingPipeline` slot, which only exists in .NET 11+. Code reading shows the
design is deliberate — `WebApplicationBuilder.cs:529` says "Chain CSRF via PostRoutingPipeline so it runs
after routing on both the outer pass and any re-routed branch (e.g. UseStatusCodePagesWithReExecute)" —
and upstream has direct coverage: `CsrfProtection_UseStatusCodePagesWithReExecute_CsrfMarkerStampedOnReroutedRequest`,
`CsrfProtection_UseExceptionHandler_CsrfMarkerStampedOnErrorEndpoint`,
`CsrfProtection_UseRewriter_CsrfMarkerStampedOnRewrittenEndpoint`,
`CsrfProtection_MapWhen_MainPipelineEndpoint_CsrfMarkerStamped`,
`CsrfProtection_UsePathBase_CsrfMarkerStamped`,
`CsrfProtection_MultipleUseRouting_CsrfMarkerStamped`,
`CsrfProtection_DisabledEndpointReExecutesIntoAntiforgeryRequiredPage_DoesNotThrowMissingMiddleware`,
`Repro_BlazorTemplatePipeline_CsrfMarkerIsStampedBeforeEndpoint_WithStatusCodePagesMiddleware`.
**Honest limitation: this axis is reasoned, not measured, by me.**

**One design note worth reporting as hardening, not as a vulnerability.** Step 2 allows
`Sec-Fetch-Site: none` *before* `Origin` is ever consulted, so `Sec-Fetch-Site: none` +
`Origin: http://evil.example` is allowed (measured above). Browsers only emit `none` for
user/browser-initiated requests, so a web attacker cannot produce it; but Google's canonical
Fetch-Metadata isolation policy additionally constrains the browser-initiated case (`Sec-Fetch-Mode:
navigate` + GET). Cross-checking `Origin` when it is present would cost nothing. Not eligible on its own.

### 2.4 Patched / unpatched + release status

* Introduced by **PR #66585** "Implement Cross-Site Request Forgery Algorithm based on Fetch Metadata
  headers", merged **2026-06-05**. Follow-ups: **#67589** (Blazor passkey, 2026-07-10), **#68669**
  (remote-auth callbacks, 2026-08-21).
* `main` is now **.NET 12.0 alpha 1** (`eng/Versions.props`: `AspNetCoreMajorVersion` 12,
  `PreReleaseVersionLabel` `alpha`, iteration 1).
* **`release/11.0` exists and contains the feature**, at `PreReleaseVersionLabel` = **`rtm`**
  (`AspNetCoreMajorVersion` 11). `CsrfProtectionMiddleware.cs` is byte-identical between `main` and
  `release/11.0`. `release/10.0` does **not** have the file (HTTP 404).
* So the feature is **shipping in .NET 11**, not a daily-build-only change. `ICsrfProtection` /
  `CsrfProtectionResult` sitting in `PublicAPI.Unshipped.txt` on `main` is just the .NET 12 cycle not
  having rolled the shipped file over yet.
* **Provenance of what I tested:** `DefaultCsrfProtection.cs`, `SafeHttpMethods.cs`,
  `CsrfProtectionMiddleware.cs` and `WebApplicationBuilder.cs` are **byte-identical** between `main` and
  `release/11.0`. The `DefaultCsrfProtection.cs` I compiled and attacked has
  sha256 `633150abdc0c992e8a10a323f12a5d838e863481e97a12cc1046a00cec975812`, which matches
  `release/11.0` exactly. So the 48-vector matrix in §2.2 characterises the **.NET 11 RTM algorithm**,
  not a main-only variant.

Nothing to report here — **CLEAN**.

---

## 3. CANDIDATE C4 — remote-auth verdict suppression: BY-DESIGN

`src/Shared/RemoteAuthenticationAntiforgery.cs:23-44` nulls a failing `IAntiforgeryValidationFeature`
while a remote handler owns the request and restores it in a `finally` **only** `if (!handled)`.
Call sites: `RemoteAuthenticationHandler.cs:83` (`CallbackPath`), `OpenIdConnectHandler.cs:97`
(`RemoteSignOutPath` = `/signout-oidc`), `OpenIdConnectHandler.cs:101` (`SignedOutCallbackPath` =
`/signout-callback-oidc`).

This is deliberate and documented in-tree (`RemoteAuthenticationAntiforgery.cs:11-20`): an IdP callback is
a cross-site top-level form POST *by protocol design* (`response_mode=form_post`), so the new CSRF
middleware necessarily marks it invalid, and the handler would then fail on its first action — reading the
callback body — before any event could run, with no way for an app to opt out. It was added by
**PR #68669 "Don't apply the CSRF verdict to remote authentication callbacks"** (merged 2026-08-21).

**Can the suppression reach more than sign-out?** No. The suppression window is scoped to a single
handler invocation on a path the handler already claimed, and the restore is guaranteed by `finally`:

* `/signin-oidc` — protected independently by the `state` -> protected `AuthenticationProperties` ->
  correlation-cookie round-trip, plus `nonce` and id_token signature validation. Suppressing the
  antiforgery verdict does not weaken any of those.
* `/signout-callback-oidc` — `HandleSignOutCallbackAsync` only completes a sign-out the app itself
  initiated.
* `/signout-oidc` — reaches `HandleRemoteSignOutAsync`, which is candidate C5 below.

Verdict **BY-DESIGN**. Not reportable.

---

## 4. CANDIDATE C5 — OIDC remote sign-out: the `iss` guard is unreachable dead code

### 4.1 The defect

`OpenIdConnectOptions.cs:42-68` (constructor, default configuration):

```csharp
RemoteSignOutPath = new PathString("/signout-oidc");
...
ClaimActions.DeleteClaim("iss");     // line 60   <-- deletes iss
// note: there is NO DeleteClaim("sid")
```

`OpenIdConnectHandler.cs:920-930`, the **default** branch (`GetClaimsFromUserInfoEndpoint` is `false`),
runs every claim action over an empty JSON document:

```csharp
using (var payload = JsonDocument.Parse("{}"))
{
    var identity = (ClaimsIdentity)user!.Identity!;
    foreach (var action in Options.ClaimActions)
    {
        action.Run(payload.RootElement, identity, ClaimsIssuer);
    }
}
```

`DeleteClaimAction.Run` ignores `userData` entirely and removes the claim from the identity
unconditionally. So the ticket persisted into the auth cookie has **no `iss` claim**.

`OpenIdConnectHandler.cs:172-204` then gates remote sign-out:

```csharp
var sid = principal?.FindFirst(JwtRegisteredClaimNames.Sid)?.Value;
if (!string.IsNullOrEmpty(sid)) { /* require + compare message.Sid */ }

var iss = principal?.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;
if (!string.IsNullOrEmpty(iss)) { /* require + compare message.Iss */ }   // never entered
```

**The asymmetry that makes this matter:** OIDC Core makes `iss` **REQUIRED** in every id_token, while
`sid` is **OPTIONAL** (effectively only issued by IdPs implementing session management / front-channel
logout). So `iss` was the one binding value guaranteed to be available on every ticket — and the same
options constructor deletes it. For any IdP that does not issue `sid`, `/signout-oidc` ends up with
**no session binding at all**, and antiforgery is additionally suppressed on that path (§3).

### 4.2 PoC and verbatim output

PoC: `/home/user/EastDulwich/pocwork/csrf-fetchmetadata/oidc/` (net10.0, `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.0-rc.2).
Full output: `/home/user/EastDulwich/pocwork/csrf-fetchmetadata/oidc-output.txt`

Part 0 proves `iss` really is on the identity the handler mutates; Part 1 runs the handler's own claim-
action code path verbatim; Part 2 drives a real cookie+OIDC app over loopback.

```
################ PART 0: does a validated id_token actually put 'iss' on the identity? ################

new OpenIdConnectOptions().TokenHandler is JsonWebTokenHandler
JsonWebTokenHandler.MapInboundClaims default = False
token validated: True
claim types produced by the DEFAULT TokenHandler from a minimal id_token:
  aud, iss, sub, name, nonce, exp, iat, nbf
  identity has an 'iss' claim: True  value=https://idp.example/
  => 'iss' IS a claim on the principal the handler then runs ClaimActions over.
  (OIDC Core makes 'iss' REQUIRED in every id_token; 'sid' is OPTIONAL.)

################ PART 1: do ClaimActions strip 'iss' from the principal? ################

claims on the identity BEFORE ClaimActions run:
  sub, name, iss, sid, aud, nonce, iat, exp

OpenIdConnectOptions defaults: RemoteSignOutPath=/signout-oidc  SignedOutCallbackPath=/signout-callback-oidc  CallbackPath=/signin-oidc
GetClaimsFromUserInfoEndpoint default = False  (false => handler takes the OpenIdConnectHandler.cs:920-930 branch)

claims on the identity AFTER ClaimActions run:
  sub, name, sid

  principal.FindFirst("iss") => NULL  <<< iss guard at OpenIdConnectHandler.cs:190 can never run
  principal.FindFirst("sid") => session-abc123   <<< sid guard at OpenIdConnectHandler.cs:173 DOES run

  => ASYMMETRY CONFIRMED: "iss" is in the DeleteClaim list, "sid" is not.

################ PART 2: cross-site forced sign-out via /signout-oidc ################

# victim app on http://127.0.0.1:40933
# OIDC default remote sign-out path: /signout-oidc

=== A. ticket has NEITHER sid NOR iss  (the real default shape: 'iss' was deleted by ClaimActions,
===    and many IdPs never issue 'sid' at all)
--- A1 cross-site GET, no parameters
    ticket shape ....... none
    attack ............. GET /signout-oidc  (Origin: http://attacker.example, Sec-Fetch-Site: cross-site)
    response ........... 200 OK
    Set-Cookie deletion. YES   (1 Set-Cookie header(s))
        .AspNetCore.Cookies=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
    /whoami before ..... AUTHENTICATED as victim-user-1  (cookie len 347)
    /whoami after ...... ANONYMOUS  (cookie len 0)
    OUTCOME ............ *** SESSION TERMINATED ***

--- A2 cross-site form POST (response_mode=form_post shape)
    ticket shape ....... none
    attack ............. POST /signout-oidc  (Origin: http://attacker.example, Sec-Fetch-Site: cross-site)
    response ........... 200 OK
    Set-Cookie deletion. YES   (1 Set-Cookie header(s))
        .AspNetCore.Cookies=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
    /whoami before ..... AUTHENTICATED as victim-user-1  (cookie len 347)
    /whoami after ...... ANONYMOUS  (cookie len 0)
    OUTCOME ............ *** SESSION TERMINATED ***

=== B. ticket HAS sid  -> the sid guard is the only thing standing in the way
--- B1 cross-site GET, no sid parameter
    OUTCOME ............ session survived
--- B2 cross-site GET, wrong sid parameter
    OUTCOME ............ session survived
--- B3 cross-site GET, correct sid (attacker would have to know it)
    OUTCOME ............ *** SESSION TERMINATED ***

=== C. ticket HAS iss but no sid -> shows the iss guard IS functional code,
===    i.e. it would block the attack if ClaimActions had not deleted the claim
--- C1 cross-site GET, no iss parameter
    OUTCOME ............ session survived
--- C2 cross-site GET, wrong iss parameter
    OUTCOME ............ session survived
--- C3 cross-site GET, correct iss
    OUTCOME ............ *** SESSION TERMINATED ***
```

Group **C** is the load-bearing control: the `iss` guard is live, working code that *does* block the
cross-site request — it is simply never reached in a default configuration because the claim it reads has
been deleted. Group **B** shows the `sid` guard works, i.e. the only surviving protection is the one that
depends on an optional IdP feature.

### 4.3 Patched / unpatched

Checked `src/Security/Authentication/OpenIdConnect/src/{OpenIdConnectOptions.cs,OpenIdConnectHandler.cs}`
on four branches:

| branch | `DeleteClaim("iss")` | `DeleteClaim("sid")` | `iss` guard | `sid` guard |
|---|---|---|---|---|
| `main` (.NET 12 alpha 1) | present | **absent** | `:189` | `:172` |
| `release/11.0` (rtm) | present | **absent** | `:189` | `:172` |
| `release/10.0` | present | **absent** | `:180` | `:163` |
| `release/9.0` | present | **absent** | `:180` | `:163` |

**Unpatched on every shipping and in-development branch.** Reproduced live on .NET 10.0.0-rc.2; the same
code is in .NET 9.0.x (supported) and .NET 11 RTM.

### 4.4 Eligibility analysis

**Acceptance estimate: ~10%.**

Against the bar:

* Crosses a security boundary (cross-site attacker -> victim's authenticated session): **yes**.
* Input untrusted by default: **yes**.
* Default configuration, no opt-in switch: **yes** — default `AddOpenIdConnect`, default
  `RemoteSignOutPath`, no AppContext flag.
* Documented as by-design: **no** for the `iss`/`ClaimActions` interaction specifically. But the sibling
  WS-Federation case (issue **#69635**) was filed `Docs`-only with explicit acceptance criteria of "no
  changes to runtime behavior", which signals how the team treats unauthenticated remote sign-out.
* Live in a shipping release, not already patched: **yes**, all four branches.
* Already public / already reported: **partially, and this is the killer.** Issue **#69630**
  (2026-10-01, open, `area-auth`) — "OIDC remote sign-out signs out even when SignOutScheme authenticates
  no session, bypassing sid/iss binding" — publicly describes the *same impact* (cross-origin forced
  sign-out on `/signout-oidc`) and even notes that "`RemoteSignOutPath` intentionally runs without the
  cross-origin CSRF verdict". It does **not** mention `ClaimActions.DeleteClaim("iss")`, so the mechanism
  I measured is a distinct and novel observation — but the attack outcome is already on the public record.

**Single most likely rejection reason:** MSRC's out-of-scope list includes, verbatim, **"Low impact CSRF
bugs."** Forced logout / session termination is the textbook low-impact CSRF: no data read, no data
written, no privilege gained, fully recoverable by signing in again. The award table only reaches
`Spoofing or Tampering`, which pays **$0 at Moderate and Low severity**. Combined with the overlapping
public issue #69630, I expect this to be closed as either low-severity-not-eligible or
already-reported.

**Worth sending anyway?** Marginally, as a quality/correctness report rather than a bounty submission:
the `iss` guard is dead code in every shipping version, which is a concrete, verifiable, one-line defect
(`iss` is mandatory in every id_token, so the deletion silently removes the only universal binding). It
would be better filed as a GitHub issue cross-referencing #69630 than as an MSRC case.

### 4.5 Exact reproduction steps

```
export PATH=/home/user/.dotnet:$PATH DOTNET_ROOT=/home/user/.dotnet
cd /home/user/EastDulwich/pocwork/csrf-fetchmetadata/oidc
dotnet build -c Release
dotnet run  -c Release --no-build
```

Expected: Part 0 lists `iss` among the claim types the default `JsonWebTokenHandler` produces; Part 1
shows `iss` gone and `sid` surviving after `ClaimActions`; Part 2 group A reports
`*** SESSION TERMINATED ***` for both the cross-site GET and the cross-site form POST, group B and group
C1/C2 report `session survived`.

To reproduce against a real IdP instead of the minted cookie: configure `AddOpenIdConnect` with an
`Authority` whose id_token contains `iss` (mandatory) and **no** `sid`, complete a normal sign-in, then
from an attacker-origin page load `<img src="https://victim.app/signout-oidc">` or auto-submit a form to
that path. The victim's `.AspNetCore.Cookies` is cleared. Note `SameSite=Lax` (the framework default) does
**not** stop this for the GET navigation case.

---

## 5. BOUNTY PROGRAM TERMS (fetched 2026-10-13)

`https://www.microsoft.com/en-us/msrc/bounty-dot-net-core`, fetched successfully. Verbatim:

* In scope: *"Current, supported\*, versions of Microsoft .NET and ASP.NET Core."* and
  *"Release candidates for upcoming versions of .NET."*
* Preview features in scope: *"Any Preview Features listed in this GitHub page"*, *"whether in current
  supported versions or an upcoming version."*
* Out of scope: *"Vulnerabilities in versions of .NET 5 or later, .NET Core or ASP.NET Core which are
  daily builds, early beta releases"*
* Out of scope: **"Low impact CSRF bugs."**
* Out of scope (also relevant): *"Publicly-disclosed vulnerabilities which have already been reported to
  Microsoft"*; *"Vulnerabilities requiring extensive or unlikely user actions"*; *"Sub-domain takeover"*.
* There is **no** CSRF row in the award table. The nearest is *"Spoofing or Tampering"*, scored by
  severity x security impact: Critical pays $10,000 / $5,000 / $2,500 for High / Medium / Low impact;
  Important pays $5,000 / $2,500 / $1,250; **Moderate and Low severity pay $0.**

Applied to this hunt: the new CSRF middleware is in `release/11.0` at `rtm`, so it clears the
daily-build exclusion comfortably — a genuine bypass there would have been eligible. C5 is in supported
shipping versions but runs straight into the "Low impact CSRF bugs" exclusion.

---

## 6. ARTIFACTS

```
/home/user/EastDulwich/pocwork/csrf-fetchmetadata/
├── algo/                      verbatim upstream CSRF algorithm in a real WebApplication + raw-socket attacker
│   ├── algo.csproj
│   ├── Program.cs
│   └── upstream/              UNMODIFIED dotnet/aspnetcore sources (sha256 below)
├── algo-output.txt            full 48-vector verbatim output
├── oidc/                      cookie+OIDC app, claim-action proof + forced-logout attack
│   ├── oidc.csproj
│   └── Program.cs
└── oidc-output.txt            full verbatim output
```

sha256 of the unmodified upstream copies (fetched from `raw.githubusercontent.com/dotnet/aspnetcore/main`):

```
db766af933b1267f8b790104b20a98a15cb2186a72730ced097dbca9cc063cad  CsrfProtectionMiddleware.cs
f031db4692520970b6caba0e57f20b967d7a6222f1a3dedae6cefd213726855e  CsrfProtectionResult.cs
633150abdc0c992e8a10a323f12a5d838e863481e97a12cc1046a00cec975812  DefaultCsrfProtection.cs
7c06920b8edafa57c6405183d0bd8a086a9d550385ed67f9ec8df1352c0726e9  ICsrfProtection.cs
229b061a9e143dcd73a900902191b4270fda24b8fa96f799a0877b8c93289227  SafeHttpMethods.cs
```
(plus `AntiforgeryValidationFeature.cs`, `MiddlewareInvokedKeys.cs` from the local main checkout and
`CsrfValidationException.cs` from main.)

## 7. LIMITATIONS, STATED PLAINLY

1. I tested the **verbatim upstream source** compiled against .NET 10, not the shipped .NET 11 binary.
   The decision function and the middleware are self-contained and compiled unmodified, so the measured
   decisions are the real ones; but I did not exercise the real `PostRoutingPipeline` wiring.
2. The **re-execute / branched-pipeline** axis (C2) is reasoned from source and from upstream test names,
   **not measured by me** — that wiring is .NET 11+ internal.
3. Browser-behaviour claims (when a browser omits `Sec-Fetch-Site` or `Origin`, when it emits `none`) are
   from the Fetch and Fetch-Metadata specs, not from a live browser; no browser is available here. The
   ASP.NET-side decisions those claims feed into are all measured.
4. I did not build ASP.NET Core from source (disk/time budget, per instructions).
