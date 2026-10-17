# HUNT: OutputCaching — `IsCacheEntryFresh` tautology + response `Vary` ignored

Hunted directly (no subagents), 2026-10-17. Picks up the two leads a rate-limited hunter
died holding: *"the unconditional `IsCacheEntryFresh = true` after policies run, and whether
response `Vary` is honoured at all."*

Directories `ls`-verified present before auditing (per the sparse-checkout lesson):
`src/Middleware/OutputCaching`, `src/Middleware/ResponseCaching`.

## VERDICT: CLEAN / BY-DESIGN. ~0-2%. Do not submit.

| # | Candidate | Verdict |
|---|---|---|
| C1 | `IsCacheEntryFresh` set unconditionally after the policy loop | **CLEAN** — dead code from a deliberate refactor; no security impact |
| C2 | OutputCaching never reads the response `Vary` header | **BY-DESIGN** — the documented headline difference vs ResponseCaching |
| C3 | `AllowCacheLookup` gate evaluates `HttpContext.User` before auth runs | **BY-DESIGN** — documented verbatim, with its security consequence |

---

## C1 — `IsCacheEntryFresh` is a tautology, but harmless

`OutputCacheMiddleware.cs:274-282`, in `TryServeCachedResponseAsync`:
```csharp
foreach (var policy in policies)
{
    await policy.ServeFromCacheAsync(context, context.HttpContext.RequestAborted);
}

context.IsCacheEntryFresh = true;        // :279  — unconditional, AFTER the policy loop

var cachedResponse = context.CachedResponse;
if (context.IsCacheEntryFresh)           // :282  — always true; trailing `return false` unreachable
```
The shape is suspicious: the assignment lands *after* `ServeFromCacheAsync`, so it would
silently overwrite any policy that tried to mark the entry stale.

**It is not exploitable, for two independent reasons:**
1. `IsCacheEntryFresh` is `internal` (`OutputCacheContext.cs:69`) and **absent from both
   `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt`**. No third-party `IOutputCachePolicy`
   can set it. Grepped the whole middleware plus its test project: the only three occurrences
   are the declaration, the assignment, and the check. **Nothing ever sets it to `false`.**
2. Expiry is deliberately enforced elsewhere. `LoggerExtensions.cs:48` carries the tell:
   `// EventID 11 ExpirationExpiresExceeded retired.` Expiration is applied at *store* time
   (`OutputCacheMiddleware.cs:399`: `context.CachedResponseValidFor = context.ResponseExpirationTimeSpan
   ?? _options.DefaultExpirationTimeSpan`) and enforced by the store's TTL, so an expired entry
   is never returned to be served in the first place.

Residual value: it is dead code worth deleting, and the `if`/`return false` pair is misleading
to future readers. A cleanup PR, not a vulnerability.

## C2 — OutputCaching ignores the response `Vary` header. That is the design.

The behavioural divergence is real and verified:

- **ResponseCaching reads and keys on it.** `ResponseCachingMiddleware.cs:273`:
  `var varyHeaders = new StringValues(headers.GetCommaSeparatedValues(HeaderNames.Vary));`
  then normalizes for order/casing (`:300-301`) and folds it into `CachedVaryByRules` with a
  fresh `VaryByKeyPrefix` GUID (`:304-311`). HTTP-correct.
- **OutputCaching never reads it.** The *only* occurrence of `Vary` in
  `OutputCacheMiddleware.cs` is `:20`, in the `HeadersToIncludeIn304` list — copied onto 304
  responses, never consulted for keying. Varying is policy-driven only
  (`CacheVaryByRules`, `VaryByHeaderPolicy`, `VaryByQueryPolicy`, `VaryByHostPolicy`, …).

So an app that emits `Vary: Cookie` to signal "this response depends on the cookie" gets that
signal ignored by output caching.

**Why this is not eligible.** Microsoft documents it as the *headline* design difference, in
"Overview of caching in ASP.NET Core":

> "Output caching differs from response caching in the following ways: 1. **Caching behavior is
> configurable on the server.** Response caching behavior is defined with HTTP headers. … **With
> output caching, the client doesn't override the caching behavior that you configure on the
> server.**"

and on the response-caching page: output caching is recommended for UI apps because
*"the configuration determines what to cache **independent of HTTP headers**."* Ignoring HTTP
cache headers is the advertised feature, not an oversight. The response-caching page separately
warns: *"Disable caching for content that contains information for authenticated clients.
Caching should only be enabled for content that doesn't change based on a user's identity or
whether a user is signed in."*

**And the default policy independently blocks the dangerous case.** `Policies/DefaultPolicy.cs`
— *"A policy which caches un-authenticated, GET and HEAD, 200 responses"* — refuses on both sides:
- request side (`AttemptOutputCaching`): non-GET/HEAD → no; `Authorization` header present → no;
  `SecurityHelper.IsAuthenticated(User)` → no;
- response side (`ServeResponseAsync`): `Set-Cookie` present → `AllowCacheStorage = false`;
  authenticated `User` → false; status ≠ 200 → false.

A cross-user leak therefore needs an app doing custom authentication that never populates
`HttpContext.User` and emits no `Set-Cookie` (e.g. a bespoke `X-API-Key` or hand-rolled session
scheme) *and* opting that endpoint into caching. That is app error against an explicit
documented warning, not a framework defect.

## C3 — the ordering foot-gun is documented, consequence and all

There is a genuine asymmetry in `DefaultPolicy`: `AttemptOutputCaching` gates **both**
`AllowCacheLookup` and `AllowCacheStorage` on `SecurityHelper.IsAuthenticated(context.HttpContext.User)`
at `CacheRequestAsync` time. If `UseOutputCache()` is registered *before* `UseAuthentication()`,
`User` is still empty at that point, and for cookie-based auth there is no `Authorization` header
either — so a logged-in user passes the "anonymous" test and `AllowCacheLookup` stays true.
(Storage is still blocked, because `ServeResponseAsync` runs on the way back out, after auth has
populated `User`.)

Microsoft documents exactly this, with the security consequence stated:

> "In apps that use authentication or authorization, the `UseOutputCache` method must be called
> **after** the `UseAuthentication` and `UseAuthorization` methods. **Otherwise, the output caching
> middleware can serve content cached for unauthorized users instead of content for authorized
> users.**"

reinforced in the built-in middleware table: *"`UseRouting`, `UseCors`, `UseAuthentication`, and
`UseAuthorization` must come before `UseOutputCache`."*

By-design disqualifier. Same pattern that killed Chain #4.

## Limitations
- Static analysis plus documentation review; no PoC was built, because all three candidates were
  disqualified on reachability or by-design grounds before a PoC could change the verdict.
- `ResponseCaching`'s own `Vary` handling was read for contrast, not audited in its own right.
- The custom-auth-that-never-sets-`User` scenario in C2 was reasoned, not measured.

## Strategic note for future hunts
This is the **third** finding this session killed by Microsoft documenting a configuration
behaviour *together with its security consequence* (Chain #4 forwarded headers; C2; C3). Their
docs are unusually rigorous on this axis, which systematically forecloses the entire
"insecure default / secure-default gap" argument class — the class four of our chains rest on.

Implication: stop hunting configuration-shaped bugs. The remaining eligible space is where
documentation cannot pre-empt a finding — parsing and state-machine logic, memory safety,
cryptographic misuse, and authorization logic errors. Plus "Insecure documentation or samples",
which MSRC pays up to $10,000 for and which inverts this dynamic: there, the docs being
load-bearing is the attack surface rather than the defence.
