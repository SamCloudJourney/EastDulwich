# HUNT — ASP.NET Core Session & Cookie Authentication

**Target:** `dotnet/aspnetcore`, session + cookie-auth handling
**Repo:** `/home/user/dotnet-hunt/aspnetcore`
**HEAD:** `851622243f8aad5d72636142ec2414be966c2449` ("Update reference and project inventory documentation (#69696)") on `main`
**Clone shape:** depth-1 shallow + sparse. Because depth is 1, everything readable **is** current `main` — "live-in-main" is established by the file content at HEAD (verified by `git show HEAD:<path>`), not by diffing history. No `git log` archaeology is possible, so each finding below is judged on the HEAD source directly.
**SDK used for PoC:** `/home/user/.dotnet` → SDK `10.0.100-rc.2.25502.107`, shared framework `Microsoft.AspNetCore.App 10.0.0-rc.2.25502.107` (and `9.0.20`). The by-design behaviors tested are identical between rc.2 and HEAD for the files in scope.

---

## VERDICT

**No bounty-eligible, critical, stock-config vulnerability found.** The session and cookie-auth surfaces are hardened against the classes in the brief:

- Session IDs and the session key are 128-bit CSPRNG (`RandomNumberGenerator.Fill`).
- Cookie / bearer tickets are AEAD-protected via Data Protection with **fully isolated purpose strings** per scheme and per token-kind — cross-scheme and access-vs-refresh reuse both **fail empirically**.
- Chunked-cookie reassembly cannot forge a ticket (integrity is checked after reassembly).
- Cookie parsing has symmetric encode/decode for protected values (base64url has no `%`), last-wins duplicates, no server-side `__Host-`/`__Secure-` reliance.

The behaviors that *look* like bugs are **documented, by-design tradeoffs** that fail the bar (either not default, or explicitly a documented design decision): post-logout replay without a ticket store, indefinite sliding renewal, session fixation on the session cookie, session cookie not `Secure` by default, and an unkeyed SipHash used only for a hash-table (a DoS surface, not an identity boundary).

I attacked each of these and could not turn any into a remote identity/session cross in a stock `AddAuthentication().AddCookie()` / `AddSession()` app. Confidence this is a clean/hardened area: **high**.

---

## Empirical PoC

Project: `/home/user/EastDulwich/pocwork/cookiepoc/` (gitignored). Stock-ish config:
`AddAuthentication("SchemeA").AddCookie("SchemeA").AddCookie("SchemeB").AddBearerToken("Bearer")`, sharing the app's default Data Protection provider. Driver uses raw `Cookie:`/`Authorization:` headers (no `CookieContainer`) so values can be moved between cookie names/schemes.

```
==================== TEST 1: post-logout cookie replay (default cookie auth) ====================
Captured auth cookie: .AspNetCore.SchemeA (len=304)
whoami WITH cookie (pre-logout): {"scheme":"SchemeA","ok":true,"name":"alice","failure":null}
logout Set-Cookie: .AspNetCore.SchemeA=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
REPLAY old cookie AFTER logout: {"scheme":"SchemeA","ok":true,"name":"alice","failure":null}   <-- STILL VALID (by design)

==================== TEST 2: cross-scheme ticket reuse (A's cookie presented to B) ====================
  /b/whoami => {"scheme":"SchemeB","ok":false,"name":null,"failure":"Unprotect ticket failed"}   <-- rejected
  (sanity) /a/whoami with A cookie => {"scheme":"SchemeA","ok":true,"name":"alice","failure":null}

==================== TEST 3: bearer access-vs-refresh token isolation ====================
  access token  => {"scheme":"Bearer","ok":true,"name":"carol","failure":null}
  REFRESH token as access => {"scheme":"Bearer","ok":false,"name":null,"failure":"Unprotected token failed"}   <-- rejected
```

Interpretation: the only "success" an attacker gets (Test 1) is the documented stolen-cookie-replay property; the two confusion attacks (cross-scheme, refresh-as-access) are cryptographically blocked by distinct DP purposes.

---

## Findings by hunt ground

### 1. Session ID generation / entropy — SOLID
`src/Middleware/Session/src/SessionMiddleware.cs:71-76` — the session **key** (cookie contents) is `new Guid(RandomNumberGenerator.Fill(16 bytes))`, 128-bit CSPRNG. `src/Middleware/Session/src/DistributedSession.cs:107-119` — the session **Id** property is a separate 16-byte CSPRNG value stored inside the serialized blob. Both are unpredictable. The cookie key is also Data-Protected (`CookieProtection.Protect`, `CookieProtection.cs:12-24`), so an attacker cannot even supply a chosen 36-char key — `SessionMiddleware.cs:65-66` requires `Unprotect` to succeed and yield exactly 36 chars. **No entropy/predictability issue.**

### 2. Session fixation (the "crucial" question) — BY DESIGN, not eligible
The session key is **never regenerated**. If a valid, unprotectable cookie arrives, its key is reused verbatim (`SessionMiddleware.cs:64-82`); a new key is minted only when the cookie is absent/invalid. `ISession` (`src/Http/Http.Features/src/ISession.cs`) exposes **no regenerate/rotate API** (confirmed by grep: no `Regenerate`/`Rotate`/`RenewId`), so even a security-conscious app cannot rotate the identifier on privilege change while keeping data.

Why this is **not** a framework vuln meeting the bar:
- ASP.NET Core Session is a key/value store, **not** an authentication mechanism. Identity lives in the separate, independently-protected **auth cookie**. The two middlewares are unrelated; "login" is an app concept the session layer never sees.
- Exploiting fixation requires the attacker to *plant* a session cookie on the victim (XSS, a cousin-domain `Set-Cookie`, or HTTP MITM) **and** the app to store security-relevant state keyed only by session. That is explicitly documented as the app's responsibility.
- The session cookie's `SecurePolicy` defaults to `None` *on purpose* — there's an in-repo CodeQL suppression saying exactly this at `SessionMiddleware.cs:144` ("By design the session cookie's SecurePolicy defaults to None so sessions work over HTTP; apps set CookiePolicy or SecurePolicy.Always").

Real boundary? Only if an app misuses session as an auth store. That's not the default framework boundary. **Ineligible (by design / app responsibility).**

### 3. Cookie-auth ticket protection & cross-scheme purpose isolation — SOLID
`PostConfigureCookieAuthenticationOptions.cs:43` → `CreateProtector("…Cookies.CookieAuthenticationMiddleware", name, "v2")` where `name` = scheme name. Every other scheme uses a disjoint purpose (audited across the tree):
- Bearer access/refresh: `"…BearerToken", name, "BearerToken"` vs `… "RefreshToken"` (`BearerTokenConfigureOptions.cs:20-21`).
- OAuth/OIDC/Twitter/WsFed state: `typeof(Handler).FullName, name, "v1"` (+ OIDC's extra string protector), and those protect `PropertiesDataFormat`/types other than `AuthenticationTicket`.
- Session: `CreateProtector("SessionMiddleware")`.

The `AuthenticationTicket.AuthenticationScheme` string is **not** cryptographically bound (`TicketDataFormat`/`SecureDataFormat.Unprotect`, `SecureDataFormat.cs:56-90` — it just DP-unprotects and deserializes; it never checks the scheme), so isolation rests entirely on the DP purpose chain. Those purposes are distinct, so there is no collision. Empirically confirmed (Test 2). **No cross-scheme reuse.**

### 4. Ticket replay after logout / server-side invalidation — BY DESIGN, not eligible
Default `CookieAuthenticationOptions.SessionStore == null`. `HandleSignOutAsync` (`CookieAuthenticationHandler.cs:382-420`) only calls `CookieManager.DeleteCookie` (client-side delete). There is **no** server-side invalidation of a self-contained ticket; it stays valid until `ExpiresUtc` (`ReadCookieTicket` expiry check at `CookieAuthenticationHandler.cs:181-194`). A stolen cookie is therefore replayable post-logout (Test 1). This is the long-documented reason `ITicketStore` exists, and with a store, logout **does** remove the server record (`CookieAuthenticationHandler.cs:391-399`) and replay fails. **Ineligible (documented tradeoff).**

### 5. Sliding expiration refresh — SOLID / by design
`CheckForRefreshAsync` (`CookieAuthenticationHandler.cs:93-115`) only renews a still-valid ticket past the halfway mark; expired tickets are rejected earlier (`:184-194`) before refresh ever runs, so an expired cookie can't be revived. Renewal is unbounded in time (stolen-cookie-kept-alive) — a known, documented property of sliding expiration, not a flaw.

I also chased the subtle path where `CheckForRefreshAsync` clones the **pre-`ValidatePrincipal`** ticket into `_refreshTicket` (`:129`), then `FinishResponseAsync` (`:240-289`) re-emits it even if `ValidatePrincipal` *rejected* the principal (handler returns `NoPrincipal` at `:217-220`, but `_shouldRefresh` stays true). Result: a rejected identity gets a re-issued cookie with extended expiry. **Not exploitable** — every subsequent request still runs `ValidatePrincipal`, which keeps rejecting, so the refreshed cookie grants no access; it only bumps an expiry on a cookie that is already useless. Needs a non-default `ValidatePrincipal` anyway.

### 6. ITicketStore key handling — SOLID (and not default)
Server-side sessions are opt-in (no framework default `ITicketStore`), so this fails the stock-config bar. For correctness I still traced it: the session key lives in a `SessionIdClaim` **inside the encrypted ticket** (`CookieAuthenticationHandler.cs:167-178`), so it's unforgeable. On re-login with an existing key the handler **reuses** it via `RenewAsync` (`:340-344`, intentional per issue #22135), and the sign-out→sign-in key-reuse footgun was explicitly fixed by nulling `_sessionKey` on sign-out (`:395-398`, issue #47503). A fixation angle exists (attacker plants their own valid auth cookie pre-login; victim's login renews that key onto the victim's identity) but requires planting an encrypted cookie **and** the non-default store. **Ineligible (not default; strong preconditions).**

### 7. Chunked-cookie reassembly — SOLID
`ChunkingCookieManager.GetRequestCookie` (`src/Shared/ChunkingCookieManager/ChunkingCookieManager.cs:90-131`) reads `chunks-N`, concatenates `…C1..CN`, and bails to the raw value on the first missing chunk. `ParseChunksCount` uses `NumberStyles.None` (digits only; overflow → 0), and the loop exits at the first missing chunk, so a huge `chunks-2147483647` with no chunk cookies is not a DoS. Crucially, the reassembled string is handed to `TicketDataFormat.Unprotect`, which AEAD-verifies it — a confused/attacker-spliced reassembly just yields an invalid ticket (rejected), not a forgery. To assemble a *valid* ticket from chunks the attacker must already possess a valid ticket. **No reassembly confusion into a boundary cross.**

### 8. Cookie parsing (duplicates / prefixes / unescape) — SOLID
`CookieHeaderParserShared.TryParseValues` (`src/Http/Shared/CookieHeaderParserShared.cs:18-57`): duplicate names are **last-wins** (`store[name] = …`, `:45`), and values are `Uri.UnescapeDataString`-decoded. Protected auth values are base64url (`SecureDataFormat.cs:46` `Base64UrlTextEncoder.Encode` → alphabet `A–Za–z0–9-_`, no `%/+/=`), so unescape is a no-op and the write/read path is symmetric — no injection/corruption of tickets. `RequestCookieCollection` uses `OrdinalIgnoreCase` (`RequestCookieCollection.cs:30`); a case-variant duplicate can only *overwrite* the victim's cookie with the attacker's own value (login-CSRF flavor), not steal a session. `__Host-`/`__Secure-` prefixes are intentionally **not** enforced server-side (that's the browser's job); no framework code relies on them for a trust decision. **No parser-differential boundary cross.**

### 9. BearerToken access vs refresh isolation — SOLID
`BearerTokenHandler.HandleAuthenticateAsync` (`src/Security/Authentication/BearerToken/src/BearerTokenHandler.cs:24-56`) unprotects with `BearerTokenProtector` only and checks expiry; it never trusts the ticket's scheme string. The access and refresh protectors carry distinct purposes (`"BearerToken"` vs `"RefreshToken"`, see #3), so a refresh token presented as an access token fails to unprotect. Empirically confirmed (Test 3). **No purpose confusion.**

### 10. Out-of-scope observations (not identity/session boundary)
- **Unkeyed SipHash** (`src/Middleware/Session/src/SipHash.cs`) uses the fixed SipHash constants (no per-process seed) for `EncodedKey.GetHashCode` — the backing dictionary of **app-chosen** session value keys. This is a hash-flooding **DoS** consideration, bounded and requiring the app to key the session on attacker input; it is not a user/session identity cross, so it's outside the brief's bar.
- **`DistributedSession.Deserialize`** (`DistributedSession.cs:333-358`) trusts length prefixes from the cache (`ReadBytes` allocates `new byte[count]`), but the cache content is server-written; there is no HTTP-reachable path for an attacker to inject malformed session blobs in a default setup (even with shared Redis/SQL, only the server writes). Not remotely reachable.
- **`SecurePolicy` defaults:** auth cookie = `SameAsRequest` (Secure only over HTTPS), session cookie = `None`; both `SameSite=Lax`, `HttpOnly=true`. Documented defaults.

---

## "Already fixed?" / self-attack notes
- Shallow clone prevents `git log` checks, so I verified each item against the **HEAD source itself**; all code cited is present and active at HEAD.
- The two items most likely to look like bugs (sign-out/sign-in key reuse `#47503`; multi-request renew `#22135`) already carry their fix/rationale in-code — i.e., previously-reported issues that are resolved, matching the brief's warning about already-fixed bugs. I did not re-file them.
- I tried to weaponize: post-logout replay (works, but by-design), cross-scheme reuse (blocked), refresh-as-access (blocked), chunk-splice forgery (blocked by AEAD), case-insensitive duplicate cookie (only self-overwrite), rejected-principal refresh re-emission (no access gained). None clears the bar.

## MSRC confidence
**Do not submit.** Everything in scope is either hardened or a documented/by-design tradeoff that MSRC/ASP.NET has repeatedly classified as not-a-vulnerability (session≠auth, stolen-cookie replay, sliding renewal, session cookie over HTTP). Submitting any of these would be a known-behavior report. Confidence in "clean": **high**.
