# HUNT: ASP.NET Core Authentication / Authorization bypass (v2)

**Target repos (local clones):**
- `aspnetcore` @ `851622243f8aad5d72636142ec2414be966c2449` (main, 2026-10-07; shallow depth‑1, working tree clean)
- `runtime` (for crypto primitives / `System.Security.Cryptography`)

**Objective:** a CRITICAL, bounty‑eligible (.NET bug bounty, up to $40k) authentication/authorization bypass crossing a real MSRC boundary, reachable by an anonymous remote attacker against **stock/default** configuration.

---

## VERDICT (read this first)

**No critical, bounty‑eligible, default‑reachable authentication bypass was found in the in‑repo code within the stated hunting ground.** The ASP.NET Core authentication and authorization code is well‑architected, consistently **fails closed**, and every handler that accepts attacker‑controlled tokens reduces its trust to one of two roots:

1. **ASP.NET Core Data Protection** (for cookies, antiforgery tokens, OAuth/OIDC `state`, OIDC `nonce` cookies, bearer/refresh tokens) — reviewed in depth and **empirically confirmed sound** (encrypt‑then‑MAC, per‑operation subkeys, purpose‑bound AAD, constant‑time MAC, cross‑app key isolation).
2. **`Microsoft.IdentityModel.*` / `System.IdentityModel.Tokens.Jwt`** (for JWT, OIDC `id_token`, WS‑Fed SAML signature validation, `alg`/`kid`/`jku`/`x5u` handling). **This code is NOT in either cloned repo** — it is a NuGet dependency pinned to **8.19.2** (`eng/Versions.props`), a current/patched version. The classic JWT bypass classes the brief lists (`alg=none`, HS/RS confusion, signature‑skip, `jku`/`x5u` key injection) live there and **cannot be found or demonstrated from this source tree.**

This is deliberately a clean "nothing here" for the in‑repo surface, with the full trace for each candidate so the negative is auditable. A separate prior review (`HUNT-data-protection.md`) independently reached the same conclusion for the Data Protection subsystem; this review corroborates it and extends the same rigor to the handler layer.

**Confidence this survives MSRC triage as "nothing to award": high.** Confidence that I have *not* missed something subtle in the out‑of‑repo IdentityModel crypto: N/A — it is not reviewable here.

---

## Method

For each component I identified the **sink** (the security decision) and the **source** (where attacker bytes enter), traced the full path, checked default options, and checked tests/`codeql[...]` suppressions for intentional behavior. I was adversarial against my own "it's fine" conclusions (see "Looks scary but is correct"). Where a claim was load‑bearing I confirmed it empirically with a .NET 10 program.

---

## Component-by-component

### 1. JWT Bearer — `src/Security/Authentication/JwtBearer/`
- **Source:** `Authorization: Bearer <jwt>` header (`JwtBearerHandler.HandleAuthenticateAsync`, line 76–94).
- **Sink:** `tokenHandler.ValidateTokenAsync(token, tvp)` → accepts the principal only if `tokenValidationResult.IsValid` (lines 103–113). Default path uses `TokenHandlers` (`JsonWebTokenHandler`); `UseSecurityTokenValidators` defaults to `false`.
- **The actual signature/`alg`/`kid` validation is in `Microsoft.IdentityModel.JsonWebTokens` (out of repo).** Verified: no `JsonWebTokenHandler.cs`/`JwtSecurityTokenHandler.cs` anywhere under `runtime/`, and no cached DLL; it is a NuGet package (8.19.2).
- **In‑repo logic is sound:** `SetupTokenValidationParametersAsync` (239–261) clones TVP per request (no cross‑request race), and either hands the `BaseConfigurationManager` to IdentityModel (LKG path) or concatenates the discovery‑metadata issuer + signing keys. No key is ever taken from the *token's* `jku`/`x5u`/`kid` headers — `kid` only selects among configured/metadata keys inside IdentityModel. The loop only succeeds on `IsValid`; failures become `AuthenticateResult.Fail`.
- **Config‑binding path** `JwtBearerConfigureOptions` (`AddJwtBearer` + `appsettings.json`, .NET 8+): builds a fresh TVP with `ValidateIssuerSigningKey = true` and `ValidateIssuer`/`ValidateAudience` defaulting to the existing (true) values; `ValidateLifetime`/`RequireSignedTokens`/`RequireExpirationTime` keep IdentityModel's safe `true` defaults. `GetIssuerSigningKeys` only materializes **symmetric** keys from the *app's own* `SigningKeys` config section (trusted input). No attacker‑reachable weakening.
- **Default‑config reachability of a bypass:** none found in‑repo.

### 2. Cookie authentication — `src/Security/Authentication/Cookies/`
- **Source:** auth cookie value. **Sink:** `TicketDataFormat.Unprotect(cookie, GetTlsTokenBinding())` (`CookieAuthenticationHandler.ReadCookieTicket`, line 159) — Data‑Protection protected, TLS token binding mixed in as purpose.
- Expiration is enforced (184: `expiresUtc.Value < currentUtc` ⇒ `ExpiredTicket`); session‑store path removes expired server state. Sliding renewal (`CheckForRefreshAsync`) only ever *shortens*/renews within the issued lifetime. Return‑URL redirects are constrained to host‑relative (`IsHostRelative`: `path[0]=='/'` **and** `SharedUrlHelper.IsLocalUrl`, deliberately excluding `~/`).
- Forging a ticket requires the Data Protection key. **Sound.**

### 3. Antiforgery — `src/Antiforgery/`
- **Source:** request‑token (form field/header) + cookie‑token, both attacker‑supplied. **Sink:** `DefaultAntiforgery.ValidateRequestAsync` → `DefaultAntiforgeryTokenGenerator.TryValidateTokenSet`.
- `DefaultAntiforgeryTokenSerializer.Deserialize` **unprotects (MAC‑verified) before deserializing** (lines 45–70) — the parser only ever runs on authenticated bytes, so the field‑parsing logic is not attacker‑reachable. Validation requires: both tokens well‑formed (cookie vs request role), **identical embedded `SecurityToken`** (128‑bit random), matching username/claim‑UID for the current user (`CryptographicOperations.FixedTimeEquals` for the claim UID), and additional‑data check.
- Forging either token requires the key. **Sound.**

### 4. OAuth — `src/Security/Authentication/OAuth/` and the shared base `Core/src/RemoteAuthenticationHandler.cs`
- **Source:** callback query (`state`, `code`, `error`). `state` = Data‑Protection‑protected `AuthenticationProperties` (`OAuthHandler.HandleRemoteAuthenticateAsync`, 68–74) — invalid/forged ⇒ `InvalidState`.
- **CSRF:** `ValidateCorrelationId` (77) — the correlation nonce is 32 random bytes placed in the **cookie *name*** (`GenerateCorrelationId`), and the state carries the matching id; both are unforgeable without the key. Marker value compared with ordinal `string.Equals` (constant `"N"`). PKCE verifier is generated server‑side and round‑tripped in protected state.
- **Sound.**

### 5. OpenID Connect — `src/Security/Authentication/OpenIdConnect/`
- Code / hybrid / implicit flows all validated against `Options.ProtocolValidator` + IdentityModel. `state`/`nonce` are Data‑Protection protected (`ReadNonceCookie`/`WriteNonceCookie`, 1164–1213; nonce value lives in the DP‑protected cookie name). Correlation validated (732).
- The hybrid‑flow `sub` cross‑check (890) and the implicit‑flow signed‑token requirement are enforced; nonce is enforced by `ValidateAuthenticationResponse`/`ValidateTokenResponse`.
- Token signature validation is IdentityModel (out of repo). **In‑repo logic sound.**

### 6. Data Protection authenticated encryption — `src/DataProtection/.../AuthenticatedEncryption/`, `Managed/`, `Cng/`, `KeyManagement/`
- **Managed CBC+HMAC** (`ManagedAuthenticatedEncryptor`): encrypt‑then‑MAC; MAC over `IV||ciphertext` validated with `CryptoUtil.TimeConstantBuffersAreEqual` (→ `CryptographicOperations.FixedTimeEquals`) **before** `DecryptCbc` — no padding oracle. Per‑op 128‑bit key modifier feeds SP800‑108 KDF.
- **Managed/CNG GCM:** AEAD, random 96‑bit nonce + key modifier; non‑default (CBC‑HMAC is the DP default; confirmed by the `codeql[SM04193]` note).
- **`KeyRingBasedDataProtector(.Span).Unprotect`:** verifies magic header + version, selects key by GUID (all keys are the app's own), binds purposes into the AAD so cross‑purpose/cross‑app payloads fail the MAC.
- Key XML is read with `XElement.Load` / `XmlDocument` (modern .NET defaults: `XmlResolver=null`, `DtdProcessing.Prohibit` ⇒ no XXE), and the key store is the app's own repository, not remote‑attacker input — "key‑ring poisoning" requires a pre‑existing write primitive to the key store (privileged), so it is not an anonymous‑remote boundary.
- **Sound** (and independently corroborated by `HUNT-data-protection.md`).

### 7. Bearer/opaque tokens — `src/Security/Authentication/BearerToken/`
- Access vs refresh tokens use **distinct Data Protection purposes** (`BearerTokenConfigureOptions`: `(...,"BearerToken")` vs `(...,"RefreshToken")`), so a refresh token presented as `Authorization: Bearer` fails to unprotect. Expiry enforced on unprotect. **Sound** (no refresh‑as‑access replay).

### 8. Certificate auth — `src/Security/Authentication/Certificate/`
- Default `AllowedCertificateTypes = Chained` ⇒ real `X509Chain.Build` against the trust store. Self‑signed acceptance is **opt‑in** and documented as requiring app validation in the `CertificateValidated` event. `IsSelfSigned` (name‑equality) only routes policy; the chain still verifies the self‑signed signature. Not a default bypass.

### 9. Authorization pipeline — `src/Security/Authorization/`
- `AuthorizationMiddleware.Invoke`: combines endpoint metadata into a policy; `[AllowAnonymous]` runs authentication to populate `User` but skips failure/challenge (standard). `PolicyEvaluator`/`DefaultAuthorizationService`/`DefaultAuthorizationEvaluator` **fail closed**: `AuthorizationHandlerContext.HasSucceeded == !_failCalled && _succeedCalled && !PendingRequirements.Any()` — zero‑requirement or no‑op‑handler cases evaluate to **Failed**, not Success.
- **Sound.**

### 10. Negotiate / WS‑Federation — `src/Security/Authentication/{Negotiate,WsFederation}/`
- Negotiate delegates NTLM/Kerberos blob processing to the framework's `System.Net.Security.NegotiateAuthentication` (out of repo); the handler only orchestrates the handshake and persists per‑connection state.
- WS‑Fed extracts `wresult`/`wctx`, validates correlation for solicited logins, and delegates SAML signature/XML validation to IdentityModel (out of repo), accepting only on `IsValid`. In‑repo logic sound; both require non‑default opt‑in setup.

---

## "Looks scary but is correct" (adversarial self‑review)

- **`OpenIdConnectHandler` sets `validationParameters.RequireSignedTokens = false` (line 849).** Scoped to the **token‑endpoint `id_token` fetched over the TLS back‑channel** in code flow — permitted by OIDC Core §3.1.3.7 and annotated `codeql[SM04387]`. An anonymous attacker cannot inject into that back‑channel response (it is the IdP's token endpoint, authenticated by `client_secret`/PKCE). Not a bypass.
- **`RemoteAuthenticationAntiforgery.HandleWithoutAntiforgeryVerdictAsync`** suppresses an *invalid* antiforgery verdict — but only while the remote handler owns its own callback path (`ShouldHandleRequestAsync` gates on `CallbackPath == Request.Path`), which carries its own protected `state`+correlation, and the verdict is restored if the handler declines. Cross‑site `form_post` callbacks are cross‑origin *by protocol design*. Not a general antiforgery bypass.
- **OIDC remote sign‑out bypasses the `sid` check when the principal has no `sid`** (lines 166–187, documented). Worst case is a cross‑site *logout* (CSRF‑logout), which MSRC treats as low/moderate, not a critical auth bypass.
- **Antiforgery `SecurityToken` compared with `object.Equals`** (not constant‑time): both operands come from DP‑authenticated payloads, so there is no attacker‑controlled timing oracle; functional, not security‑relevant.

## Sub‑bar observations (why each fails the bar)

| Observation | Why it fails the bar |
|---|---|
| Certificate `SelfSigned` accepts any self‑signed cert | Opt‑in, non‑default (`Chained` default), documented to require event validation |
| OIDC remote‑sign‑out `sid`‑absent bypass | CSRF‑logout at most; not a user/session *elevation* |
| DP "key‑ring poisoning" via key store | Requires pre‑existing privileged write to the key repository; not anonymous‑remote |
| JWT `alg`/`kid`/`jku`/`x5u`, SAML sig‑wrapping | Lives in `Microsoft.IdentityModel` 8.19.2 — **out of repo**, current/patched |

---

## Empirical confirmation (the root of trust)

Every cookie/antiforgery/OAuth‑state/bearer unforgeability property reduces to Data Protection. I confirmed the four load‑bearing properties with a .NET 10 program against the shipped `Microsoft.AspNetCore.App` (same code as the source reviewed):

```
[PASS] round-trip (same purpose)
[PASS] cross-purpose unprotect rejected (cookie payload via antiforgery protector)
[PASS] all 928 single-bit tampered payloads rejected          # encrypt-then-MAC, no padding oracle
[PASS] cross-application unprotect rejected (different key ring)
RESULT: 4 passed, 0 failed
```

(Source: `scratchpad/dptest/Program.cs`.) This demonstrates that forging a cookie/antiforgery/state payload, tampering with one, or reusing it across purposes or across applications, all fail — i.e. the handler‑layer security that delegates to DP cannot be bypassed without the app's key.

---

## Honest confidence & what would change the answer

- **Confidence the in‑repo auth/authz surface has no critical default‑config bypass:** high. The code is mature, fails closed, and the trust reductions are clean.
- **The only places a critical JWT/SAML bypass could still exist are out of scope of these clones:** `Microsoft.IdentityModel.*` (8.19.2) and `System.Security.Cryptography` primitives. To hunt those, obtain the IdentityModel source at the pinned version and review `JsonWebTokenHandler.ValidateTokenAsync`, `JwtTokenUtilities`, key‑resolution, and `alg`/`enc` handling — that is where `alg=none`, HS/RS confusion, and `jku`/`x5u` injection would be, and none of it is reachable to read or PoC from `aspnetcore`/`runtime` here.
- A re‑hunt with a **non‑shallow** clone would also allow diffing recent security‑relevant commits, which this depth‑1 snapshot does not permit.
