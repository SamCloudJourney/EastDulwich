# HUNT: ASP.NET Core Auth & SignalR Security Analysis

**Scope**: ASP.NET Core SignalR, Authentication/Authorization middleware, JWT Bearer, Cookie Authentication, Antiforgery  
**Repo**: `/home/user/dotnet-hunt/aspnetcore/`  
**Date**: 2026-10-07

---

## 1. SignalR Hub Method Authorization

### 1.1 Architecture Overview

SignalR authorization operates at two levels:

1. **Connection-level**: `[Authorize]` on the hub class becomes endpoint metadata via `HubEndpointRouteBuilderExtensions.MapHub<THub>()` (line 57-68 of `HubEndpointRouteBuilderExtensions.cs`). This metadata is enforced by the standard authorization middleware at HTTP connection time (negotiate/execute endpoints).

2. **Method-level**: `[Authorize]` on individual hub methods is collected by `DiscoverHubMethods()` (line 897-938 of `DefaultHubDispatcher.cs`) via `methodInfo.GetCustomAttributes(inherit: true)` and checked per-invocation in `IsHubMethodAuthorized()` (line 758-776).

### 1.2 Authorization Check Flow (Method-Level)

```
Invoke() [line 363]
  -> IsHubMethodAuthorized() [line 758]
     -> descriptor.AuthorizationMetadata.Count == 0 ? skip : check
     -> IsHubMethodAuthorizedSlow() [line 778]
        -> descriptor.GetAuthorizationPolicyAsync(policyProvider)
        -> AuthorizationPolicy.CombineAsync(policyProvider, AuthorizationMetadata)
        -> authService.AuthorizeAsync(principal, resource, authorizePolicy)
```

**Finding**: The `authorizationMetadata` passed to `HubMethodDescriptor` (line 931-933 of `DefaultHubDispatcher.cs`) includes ALL custom attributes from `methodInfo.GetCustomAttributes(inherit: true)`, not just auth attributes. However, `AuthorizationPolicy.CombineAsync` correctly filters for `IAuthorizeData` and `IAuthorizationRequirementData`. When no auth-relevant attributes exist, the policy is null, and the method correctly returns `true` (authorized). When `AuthorizationMetadata.Count == 0`, auth is skipped entirely via the fast path. **No bypass found.**

**Finding**: `EnsureNoAuthenticationSchemeSpecified()` (line 795-807) rejects any `[Authorize(AuthenticationSchemes = "...")]` on hub methods at startup. This is correct since the connection already has a fixed ClaimsPrincipal. **No bypass found.**

### 1.3 Authentication Refresh and Class-Level Auth Re-evaluation

**Key observation**: When authentication refresh occurs on a SignalR connection (long-polling reconnect, stateful WebSocket reconnect, or explicit `/refresh` endpoint):

1. `OnAuthenticationRefreshAsync` (line 197-222 of `HubConnectionHandler.cs`) validates that the user identity has NOT changed (same sub/NameIdentifier/UPN claim).
2. `HandleUserRefreshedAsync` (line 321-367) updates the user via `connection.ApplyUser(user)`.
3. `DefaultHubDispatcher.OnAuthenticationRefreshedAsync` (line 156-165) calls `hub.OnAuthenticationRefreshedAsync()` -- a virtual no-op by default.

**Potential concern**: After auth refresh, the connection-level `[Authorize]` policy (e.g., `[Authorize(Policy = "AdminOnly")]` on the hub class) is NOT re-evaluated. If a user's roles/claims change mid-connection (e.g., admin demoted to regular user), the connection persists.

**Assessment**: This is **by design**, not a vulnerability. The identity check prevents different users from taking over connections. Method-level `[Authorize]` IS re-checked per invocation with updated claims. The connection-level policy was designed for initial gate-keeping. Documentation explicitly states `OnAuthenticationRefreshedAsync` allows claims to change. **No MSRC-eligible issue.**

### 1.4 WebSocket Direct-Connect Path

WebSocket connections can bypass the negotiate endpoint entirely via `GetOrCreateConnectionAsync()` (line 1122-1142 of `HttpConnectionDispatcher.cs`). When no connection token is provided (`StringValues.IsNullOrEmpty(connectionToken)`), a new connection is created directly.

**Assessment**: This does NOT bypass authorization. The authorization middleware runs on the execute endpoint before `HttpConnectionDispatcher.ExecuteAsync()` is invoked. The hub class's `[Authorize]` attributes are endpoint metadata and are checked by the authorization middleware regardless of whether negotiate was called. **No bypass found.**

### 1.5 Connection Token Security

- Connection tokens are generated using `RandomNumberGenerator.Fill()` with 128-bit buffers (line 108-113 of `HttpConnectionManager.cs`). Cryptographically secure.
- Negotiate v1+ generates separate connectionId (public) and connectionToken (private). V0 connections have `connectionId == connectionToken`.
- The `/refresh` endpoint explicitly rejects v0 connections (line 168-174 of `HttpConnectionDispatcher.cs`) to prevent unauthorized refresh with just a public connectionId.
- `/send` and `/delete` endpoints verify connection user hasn't changed via `RejectIfConnectionUserChangedAsync()`.

**Assessment**: Connection token management is well-designed. **No vulnerability found.**

---

## 2. Authentication Middleware Ordering

### 2.1 Middleware Pipeline Checks

The antiforgery system has an explicit check for middleware ordering. In `DefaultAntiforgeryTokenGenerator.TryValidateTokenSet()`, when a token was generated for an authenticated user but the current request has no authenticated user, it returns an error (not a bypass). This detects when antiforgery middleware runs before authentication middleware.

### 2.2 Endpoint Routing Short-Circuit Check

`EndpointRoutingMiddleware` (line 212-216) checks that endpoints with `RequiresValidation: true` using form-submitting methods (POST/PUT/PATCH) cannot short-circuit before the antiforgery middleware runs. This prevents accidental exposure.

**Assessment**: The framework includes defensive checks against middleware ordering mistakes. **No vulnerability found.**

---

## 3. JWT Bearer Token Validation

### 3.1 Default Security Posture

`JwtBearerOptions` (in `JwtBearerOptions.cs`) creates `TokenValidationParameters` with Microsoft.IdentityModel library defaults:
- `RequireSignedTokens = true` (blocks "none" algorithm)
- `ValidateIssuer = true`
- `ValidateAudience = true`
- `ValidateLifetime = true`

ASP.NET Core does not expose or override algorithm validation. The `TokenValidationParameters.ValidAlgorithms` property and algorithm confusion prevention are entirely handled by Microsoft.IdentityModel, which is outside this repo.

### 3.2 OIDC Code Flow: RequireSignedTokens Disabled

In `OpenIdConnectHandler.cs` line 849, `RequireSignedTokens` is set to `false` for code flow token exchange. This is per the OpenID Connect Core 1.0 spec (section 3.1.3.7) -- the ID token in code flow is received from the token endpoint over a TLS backchannel, so signature validation is not required.

**Assessment**: This is correct per spec and has a CodeQL suppression comment. The ID token has already been validated (if received from the authorization endpoint) or is fetched over secure backchannel. **Not a vulnerability.**

### 3.3 HTTPS Metadata Enforcement

`JwtBearerPostConfigureOptions.cs` enforces HTTPS for the metadata endpoint unless `RequireHttpsMetadata = false` is explicitly set. **No bypass found.**

### 3.4 MapInboundClaims

`MapInboundClaims` defaults to `true`, which maps OIDC claims to long-form .NET claim types. This is a legacy compatibility behavior, not a security issue.

**Assessment**: JWT validation in ASP.NET Core relies on Microsoft.IdentityModel library for algorithm validation. The ASP.NET Core layer correctly delegates and does not introduce any additional attack surface. The algorithm confusion attack surface, if any, would be in Microsoft.IdentityModel (separate repo). **No MSRC-eligible issue in this repo.**

---

## 4. Cookie Authentication

### 4.1 Session Store Session Fixation Analysis

When `SessionStore` is configured and a user signs in (`HandleSignInAsync`, line 292-379 of `CookieAuthenticationHandler.cs`):

1. If `_sessionKey != null` (existing session from cookie): calls `SessionStore.RenewAsync(_sessionKey, ticket)` -- **reuses the same session key**
2. If `_sessionKey == null` (no existing session or after sign-out): calls `SessionStore.StoreAsync(ticket)` -- **generates new session key**

**Potential concern**: During a sign-in where an existing session cookie is present, the session key is NOT rotated. This means:
- If an attacker can inject a session cookie before the victim signs in, the attacker's session key would persist through the sign-in (session fixation).
- However, the session key is inside a Data Protection-encrypted cookie. An attacker would need the app's data protection keys to craft a valid cookie. This makes practical exploitation extremely unlikely.

**Mitigating factors**:
- Sign-out (`HandleSignOutAsync`, line 382-420) correctly removes the session from the store AND sets `_sessionKey = null`, so a subsequent sign-in in the same request generates a new key.
- The cookie value is data-protected, so session key injection requires key compromise.
- Session cookies have `HttpOnly` and configurable `SameSite`/`Secure` attributes.

**Assessment**: The session key reuse on re-sign-in is a defense-in-depth weakness, not a practical vulnerability. The data protection layer prevents an attacker from injecting a known session key. **Not MSRC-eligible.**

### 4.2 Sliding Expiration

`CheckForRefreshAsync` (line 93-115) renews when `timeRemaining < timeElapsed`. The window is half the expiration time. Renewal creates a new ticket with updated expiration and re-protects it. **No issue found.**

### 4.3 Cookie Path Scoping

Cookie path defaults to `PathBase` or `/` via `DefaultAntiforgeryTokenStore.cs` (line 86-97, for antiforgery) and via `CookieAuthenticationOptions` (configurable). Applications sharing the same domain with different path bases get separate cookies. **No traversal issue found.**

---

## 5. Antiforgery Token System

### 5.1 DELETE Method Gap in Middleware

**FINDING: The antiforgery middleware does not validate DELETE requests.**

The `AntiforgeryMiddleware.Invoke()` (line 13-34 of `AntiforgeryMiddleware.cs`) has this flow:

```csharp
var method = context.Request.Method;
if (!HttpExtensions.IsValidHttpMethodForForm(method))  // POST, PUT, PATCH only
{
    return _next(context);  // SKIPS validation for DELETE, CONNECT, etc.
}

if (endpoint?.Metadata.GetMetadata<IAntiforgeryMetadata>() is { RequiresValidation: true })
{
    return InvokeAwaited(context);  // Only reached for POST/PUT/PATCH
}
```

Meanwhile, `DefaultAntiforgery.IsRequestValidAsync()` (line 88-136) uses `SafeHttpMethods.IsSafe()` which returns `true` only for GET, HEAD, OPTIONS, TRACE, QUERY. DELETE is NOT safe and WOULD require token validation via the manual API.

**Gap**: An endpoint marked with `RequiresValidation: true` using HTTP DELETE will NOT have antiforgery validation via the middleware, even though the manual `IsRequestValidAsync` API would require it. The middleware silently skips DELETE because `IsValidHttpMethodForForm` returns false for DELETE.

**Assessment**: This is a design choice, not a bug per se. The middleware was designed for form-based submissions (POST/PUT/PATCH). DELETE endpoints typically use JSON APIs with bearer tokens, not form submissions. However:
- An `[RequireAntiforgeryToken]`-decorated DELETE endpoint gets a false sense of protection.
- The `EndpointRoutingMiddleware` short-circuit check (line 212-216) also only blocks POST/PUT/PATCH, allowing DELETE endpoints to short-circuit without antiforgery.

**Severity**: Low. DELETE with form bodies is uncommon, and most DELETE endpoints use JSON APIs with separate CSRF protection (bearer tokens, custom headers). This is unlikely to cross a meaningful security boundary. **Not MSRC-eligible** as the framework does not promise antiforgery coverage for DELETE requests.

### 5.2 Token Structure and Cryptographic Properties

- Security tokens are 128-bit random values.
- Cookie tokens and request tokens are Data Protection-encrypted with purpose `"Microsoft.AspNetCore.Antiforgery.AntiforgeryToken.v1"`.
- `ClaimUid` is a SHA-256 hash of unique identifier claims (sub, NameIdentifier, or UPN) with issuer included.
- Token comparison uses `CryptographicOperations.FixedTimeEquals` for `ClaimUid` matching.
- `SecurityToken` comparison uses `string.Equals` (not timing-safe), but the tokens are encrypted, so the raw value is never exposed to the attacker.

**Assessment**: Cryptographic handling is sound. **No vulnerability found.**

### 5.3 DefaultClaimUidExtractor Identity Binding

The `DefaultClaimUidExtractor` (line 31-112 of `DefaultClaimUidExtractor.cs`) selects the first matching claim type in priority order: `sub` > `NameIdentifier` > `UPN`. If none found, it falls back to hashing ALL claims (sorted by type).

**Potential concern**: If a user has claims from multiple authenticated identities, only the first matching claim type is used. An attacker who can add a lower-priority identity with a matching `sub` claim would not affect the UID since the first identity's `sub` claim is used. The fallback to all-claims hashing is deterministic and consistent.

**Assessment**: The claim extraction is consistent and doesn't allow manipulation. **No vulnerability found.**

---

## Summary of Findings

| Area | Finding | Severity | MSRC-Eligible |
|------|---------|----------|---------------|
| SignalR method auth | Auth correctly checks per-invocation with updated claims | N/A | No |
| SignalR class-level auth refresh | Not re-checked on refresh; by design | Low | No |
| SignalR connection tokens | 128-bit cryptographic random; v0 refresh blocked | N/A | No |
| WebSocket direct-connect | Authorization middleware still runs | N/A | No |
| JWT "none" algorithm | Blocked by `RequireSignedTokens=true` default | N/A | No |
| OIDC code flow unsigned | Per spec, over TLS backchannel | N/A | No |
| Cookie session fixation | Session key reuse mitigated by Data Protection | Low | No |
| Antiforgery DELETE gap | Middleware skips DELETE; by design for form methods | Low | No |
| Antiforgery token crypto | Fixed-time comparison, proper randomness, Data Protection | N/A | No |
| Auth middleware ordering | Defensive checks detect misconfiguration | N/A | No |

**Bottom line**: No Critical or Important severity MSRC-eligible vulnerabilities were found. The codebase demonstrates mature security engineering:
- SignalR uses connection tokens (private, cryptographic), enforces auth at both connection and method levels, and correctly handles auth refresh with identity pinning.
- JWT validation delegates to Microsoft.IdentityModel with secure defaults.
- Cookie authentication uses Data Protection for all cookie values, preventing session fixation.
- Antiforgery uses proper token binding with SHA-256 ClaimUid and fixed-time comparison.

The most notable design observations (not vulnerabilities):
1. SignalR class-level `[Authorize]` policy is not re-evaluated on auth refresh -- this could be surprising to developers who expect role changes to take immediate effect.
2. The antiforgery middleware's scope is limited to POST/PUT/PATCH, which may surprise developers marking DELETE endpoints with `[RequireAntiforgeryToken]`.
