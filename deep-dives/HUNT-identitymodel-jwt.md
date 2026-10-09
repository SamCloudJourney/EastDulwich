# HUNT: Microsoft.IdentityModel.* — JWT/JWE authentication-bypass audit

**Target:** `AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` (the libraries ASP.NET Core `JwtBearer` delegates all JWT signature/alg/claims validation to: `Microsoft.IdentityModel.Tokens`, `Microsoft.IdentityModel.JsonWebTokens`).
**Date:** 2026-10-09
**Researcher task:** authorized security research for Microsoft's public bug bounty, coordinated disclosure to MSRC.

## TL;DR

**Result: CLEAN. No authentication-bypass finding that meets the bar.** The default / ASP.NET-Core-stock validation path is hardened against every classic and modern JWT/JWE vector in scope (`alg=none`, RSA→HMAC algorithm confusion, signature-skip, header-key injection, issuer/audience confusion, JWE decompression bomb). Verified by code trace **and** by running the real handler against forged tokens on both the latest release (**8.23.0**) and current **dev / 9.0.0**. All forgeries are rejected; the valid control is accepted.

This is a legitimate negative result. IdentityModel is the most-attacked JWT stack in .NET and the obvious vectors have clearly been closed and regression-tested.

---

## Setup / provenance (so the "live in current source" claim is checkable)

| Item | Value |
|---|---|
| Repo | `github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet` |
| Default branch | `dev` |
| dev HEAD | `109e290c4ad70ecbc3f0697a2c950b59ba810413` — 2026-10-08 — "Forward-port WS-Trust support to dev (#3603)" |
| dev version (`build/version.props`) | **9.0.0** (preview) |
| Latest release tag | **8.23.0** = commit `8b16f418b3d587416d293e9ba34c5d310781cdb3` — 2026-09-03 (this is what an ASP.NET Core 8.x app resolves as the newest 8.x) |
| Worktrees | `/home/user/dotnet-hunt/identitymodel` (dev) and `/home/user/dotnet-hunt/im-8.23.0` (tag 8.23.0) |
| SDKs used | .NET 9.0.318 and 10.0.100-rc.2 at `/home/user/.dotnet` |

Code line references below are against the **8.23.0** tree unless noted; `src/` prefix omitted. dev was diffed against 8.23.0 and verified to carry no behavioral change in these paths (changes are cancellation-token plumbing, fail-closed logging refactors, and removal of the experimental CompositeML-DSA feature).

## The bar (a finding must satisfy ALL)
1. Real boundary: auth bypass (forge / signature-skip / accept-what-should-be-rejected).
2. Untrusted-by-default input: a JWT/JWE from an anonymous remote attacker.
3. Fires in a DEFAULT / extremely common config (stock `TokenValidationParameters`, or ASP.NET Core defaults).
4. LIVE in current source (latest tag / dev), not already fixed.

Nothing below clears criteria 1+3+4 simultaneously, so there is no finding — the sections document *why each vector fails the bar*, which is the deliverable.

---

## Default configuration that was modeled

`JsonWebTokenHandler.ValidateTokenAsync(string, TokenValidationParameters)` (the API ASP.NET Core `JwtBearerHandler` calls on .NET 8/9) with stock `TokenValidationParameters` for a single-authority app: `ValidIssuer`/`ValidAudience` set, signing key(s) = the authority's **RSA public key(s)** from JWKS, everything else at library defaults.

Library defaults — `TokenValidationParameters.cs:129-139`:
```
RequireExpirationTime = true;  RequireSignedTokens = true;  RequireAudience = true;
TryAllIssuerSigningKeys = true;  ValidateAudience = true;  ValidateIssuer = true;
ValidateIssuerSigningKey = false;  ValidateLifetime = true;
```
Verified at runtime by the PoC (`RequireSignedTokens=True`, `TryAllIssuerSigningKeys=True`, `ValidateIssuerSigningKey=False`).

---

## Vector-by-vector

### 1. `alg=none` acceptance — NOT PRESENT (blocked by default)
- **Decision code:** `JsonWebTokenHandler.ValidateToken.cs:147-157` — `if (!jwtToken.IsSigned) { if (RequireSignedTokens) throw IDX10504; else return jwtToken; }`. `RequireSignedTokens` defaults **true**, so the "return unsigned token as valid" branch is unreachable without the app explicitly opting out.
- `IsSigned` is set only when the signature segment is non-empty (`JsonWebToken.cs:603`, `:289`).
- **Live:** present in 8.23.0 and dev. **PoC:** `alg=none` token → rejected `IDX10504` ("token does not have a signature").

### 2. RSA→HMAC algorithm confusion (HS256 verified with the RSA public key as the MAC secret) — NOT PRESENT
This is the headline vector and it is firmly closed:
- **Gate:** `JsonWebTokenHandler.ValidateToken.cs:347` — before any verification, `cryptoProviderFactory.IsSupportedAlgorithm(jsonWebToken.Alg, key)` must pass, else the key is skipped (`return false`, →`IDX10511`).
- **Key-type → algorithm map:** `SupportedAlgorithms.IsSupportedAlgorithm` (`SupportedAlgorithms.cs:247-292`). An `RsaSecurityKey` / `X509SecurityKey(RSA)` / `JsonWebKey{kty=RSA}` only matches RSA signing/encryption algorithms; `HS256` is **not** among them → `false`. Symmetric keys only match HMAC. The `alg` is thus effectively pinned to the key type.
- **Second barrier:** even if an HMAC provider were requested for an RSA key, `SymmetricSignatureProvider.GetKeyBytes` (`SymmetricSignatureProvider.cs:136-148`) only extracts bytes from a `SymmetricSecurityKey` or octet `JsonWebKey` and throws for anything else.
- Note: `Validators.ValidateAlgorithm` (`Validators.cs:26-51`) is a **no-op by default** (no `AlgorithmValidator`, empty `ValidAlgorithms`) — but the `IsSupportedAlgorithm` key/alg-compat gate is what actually prevents confusion, and it is not optional.
- **Live:** present in 8.23.0 and dev. **PoC:** HS256 forgeries using the server's public key as the HMAC secret in **four** representations — SPKI-DER, PKCS1-DER, SPKI-PEM(ASCII), and the JWKS-realistic `JsonWebKey{kty=RSA}` JSON — all → rejected `IDX10511` ("Signature validation failed. Keys tried: RsaSecurityKey…"), i.e. the RSA key is enumerated but skipped by the alg gate.

### 3. Signature-skip / "try all keys" / kid-miss → no-verification — NOT PRESENT
- The **only** success exit of `ValidateSignature` is `ValidateSignature(jwtToken, key, …) == true` for a real key (`ValidateToken.cs:198-205`). Every other path throws (`:229-287`): `IDX10511` / `IDX10503` / `IDX10517` / `IDX10500`. There is no branch that returns the token as valid without a verified signature.
- `TryAllIssuerSigningKeys = true` (default) only widens the key set to all **configured/trusted** keys (`TokenUtilities.GetAllSigningKeys`) when `kid` doesn't match; each is still fully verified. A kid-miss falls back to try-all, never to skip.
- The actual crypto is delegated to the platform (`AsymmetricSignatureProvider.Verify` → `AsymmetricAdapter.Verify` over the exact `header.payload` bytes, `ValidateToken.cs:405-413`). Empty signatures are rejected.
- **PoC:** tampered-payload RS256 (valid signature reused over mutated body) → rejected `IDX10511`.

### 4. Header-supplied key injection (`kid`, `x5t`, `jku`, `x5u`, embedded `jwk`/`x5c`) — NOT PRESENT in the JWS validation path
- Signing-key resolution (`JwtTokenUtilities.ResolveTokenSigningKey`, `JwtTokenUtilities.cs:524-565`) uses **only** `kid`/`x5t` as *selectors to match against already-trusted keys* from `configuration.SigningKeys` (JWKS) and `validationParameters` keys. It never imports key material from the token.
- `jku`/`jwk`/`x5u`/`x5c` header parameters are **not consulted** for JWS signing-key resolution (grep of `TryGetHeaderValue`/`Header.Get*` in `Microsoft.IdentityModel.JsonWebTokens` for those names is empty outside the opt-in experimental path). `x5c` is parsed only off a `JsonWebKey` coming from the trusted JWKS metadata (`X509SecurityKey.cs:49`), never off the token's own header.
- (`jku`-fetch logic exists only in the separate, opt-in `Microsoft.IdentityModel.Protocols.SignedHttpRequest` / DPoP PoP `cnf` path — not JwtBearer default — and was recently hardened: redirects disabled, `jku` validation improved, per CHANGELOG 8.19.0 / 7.7.2. Out of default scope.)

### 5. JWE: decryption / decompression bomb / key-wrap confusion — NOT A DEFAULT-CONFIG BYPASS
- JWE validation requires the app to configure **private** `TokenDecryptionKey(s)` — not part of the stock OIDC JwtBearer setup (tokens are signed JWS), so JWE fails criterion 3 for the stock config.
- Even so, the code is hardened: decompression is bounded by `MaximumDeflateSize` (= `MaximumTokenSizeInBytes`) with an explicit over-read check (`DeflateCompressionProvider.cs:65-109`, throws `IDX10816`), so the classic DEF decompression bomb (historical CVE class) is mitigated and the mitigation is live. CEK unwrap uses a random-CEK fallback as a Bleichenbacher/MMA mitigation (`JsonWebTokenHandler.CreateToken.cs:1337-1343, 1387-1403`), and `enc`/`alg` are gated by `IsSupportedAlgorithm` (`JwtTokenUtilities.cs:283`).

### 6. Claims-validation confusion (issuer / audience / typ / nbf-exp / nested) — NOT A BYPASS
- **Issuer** (`Validators.cs:277-363`): exact `string.Equals` (ordinal, case-sensitive) against `ValidIssuer`/`ValidIssuers`/`configuration.Issuer`. No substring / case / slash leniency.
- **Audience** (`Validators.cs:183-222`): length-gated exact match; `IgnoreCaseWhenValidatingAudience` and `IgnoreTrailingSlashWhenValidatingAudience` both default **false** (CHANGELOG 8.22.0 confirms case-sensitive default). Trailing-slash leniency only ever allows a **one-character** `/` difference, and only when opted in.
- **typ** (`Validators.cs:571-605`): no-op unless the app sets `ValidTypes` → cannot weaken the default.
- **nested / actor** (`ValidateToken.cs:668-681`): only runs when `ValidateActor` (default false) is enabled.
- These are all claims checks that run *after* a signature is already verified; none is an authentication bypass on its own. A JSON duplicate-key / type-confusion quirk would be parsed identically for both the signature-covered bytes and the claim extraction (same parser, same byte range `[Dot1+1, Dot2)` which is exactly the signed region `[0, Dot2)` minus the header), so there is no IdentityModel-internal "validate X, expose Y" split. (A cross-service duplicate-key confusion against a *different* downstream parser is conceivable but is not an IdentityModel defect and is not demonstrable here.)

### 7. Experimental `ValidationParameters` path (opt-in, not ASP.NET Core default) — same or stricter
`src/.../Experimental/*` is the redesigned result-based API; ASP.NET Core does not use it by default. It is at least as safe: unsigned tokens are **always** rejected unless the app writes a custom resolver — there is no `RequireSignedTokens=false` escape hatch (`Experimental/JsonWebTokenHandler.ValidateSignature.cs:70-78`), and it uses the same `IsSupportedAlgorithm` gate (`:237`).

---

## PoC

Location (gitignored): `/home/user/EastDulwich/pocwork/jwt-hunt/` (NuGet **8.23.0**) and `/home/user/EastDulwich/pocwork/jwt-hunt-dev/` (references DLLs built from **dev / 9.0.0** source). Single `Program.cs`; run with `DOTNET_ROOT=/home/user/.dotnet dotnet run -c Release`.

It models the stock asymmetric JwtBearer TVP and asserts expected accept/reject. Result on **both** 8.23.0 and dev 9.0.0 (assembly versions `8.23.0.0` / `9.0.0.0`):

```
[OK ] CONTROL: valid RS256 (server-signed)        ACCEPTED   (want ACCEPT)
[OK ] ATTACK: alg=none (unsigned)                 rejected   IDX10504
[OK ] ATTACK: HS256 w/ RSA-pub-as-HMAC [SPKI-DER] rejected   IDX10511
[OK ] ATTACK: HS256 w/ RSA-pub-as-HMAC [PKCS1-DER]rejected   IDX10511
[OK ] ATTACK: HS256 w/ RSA-pub-as-HMAC [SPKI-PEM] rejected   IDX10511
[OK ] ATTACK: HS256 w/ JsonWebKey(kty=RSA)        rejected   IDX10511
[OK ] ATTACK: RS256 payload tampered              rejected   IDX10511
[OK ] ATTACK: HS256 attacker symmetric key        rejected   IDX10511
RESULT: all defenses held (forgeries rejected, valid token accepted).
```

The `IDX10511` detail ("Keys tried: …RsaSecurityKey") is the empirical fingerprint of the alg-confusion defense: the RSA key is enumerated as a candidate but rejected by `IsSupportedAlgorithm(HS256, RsaSecurityKey)` before any HMAC is computed.

---

## Adversarial self-review ("is this already fixed / am I wrong?")
- The vectors tested are exactly the ones with historical CVEs in this and sibling libraries; all show as **present and closed** in current source, not as "fixed elsewhere but reintroduced." dev↔8.23.0 diff on `ValidateToken.cs`, `Validators.cs`, `SupportedAlgorithms.cs`, `TokenValidationParameters.cs` shows no weakening.
- Recent commit history / CHANGELOG around these areas contains no open/unpatched security item; no `insecure`/`FIXME-security` markers in the decision code.
- Honest confidence that **there is no default-config auth bypass in these vectors in 8.23.0 / dev**: **high.** Equivalent confidence that an MSRC submission claiming one here would survive triage: **very low** (there is nothing to submit).

### Residual, explicitly-out-of-default-scope avenues (NOT findings; where a *non-default* bug could still live, for future hunts)
- **Multi-issuer / multi-tenant TVP** where the app trusts signing keys from several authorities with `ValidateIssuerSigningKey=false` (default) and no `tid`/issuer-to-key binding — the "right signature, wrong tenant" class the `DontFailOnMissingTid` switch exists for. Requires a non-stock multi-authority configuration.
- **SignedHttpRequest / DPoP PoP** `cnf.jku`/`jwk` key resolution (opt-in protocol, separate package) — fetches/derives keys from token-supplied material; recently hardened but a higher-surface area than JwtBearer.
- **JWE** scenarios in apps that *do* configure decryption keys.
- **Cross-parser claim confusion** against a non-IdentityModel downstream consumer of the same token.

## MSRC routing note
`Microsoft.IdentityModel.*` is very likely scoped under MSRC's **Identity** bounty, not the **.NET** bounty (it ships out-of-band on NuGet from the AzureAD org, not in the dotnet/runtime tree). Flagging per the task; moot given the clean result, but relevant if any of the residual non-default avenues above are pursued.
