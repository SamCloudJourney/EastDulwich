# HUNT v2 batch 2 — three hunters interrupted by session rate limit

**Date:** 2026-10-09
**Status:** All three agents terminated early (HTTP 429 session limit, resets 11:40pm UTC) before writing their own reports. This file captures their dying state + follow-up verification done directly in the main session.

---

## Routing / ReDoS / model binding — CLEAN (analysis completed before cutoff)

The hunter's final message confirmed all default limits are bounded:
- Request line: 8 KB; headers: 32 KB / 100 count
- Form: 1024 values; collection binding: 1024; model recursion depth: 32
- **`RegexRouteConstraint` has a 10-second `MatchTimeout`** — the hypothesis that framework regex constraints run attacker input with no timeout is FALSE. Catastrophic backtracking is bounded.

Verdict: no RDoS. The surface is comprehensively bounded by default. Nothing eligible.

## X.509 / ASN.1 — lead chased, dead-ends on reachability

The hunter died chasing: `ImportEncryptedPkcs8PrivateKey` → `PasswordBasedEncryption.Decrypt` (PBES2). It observed `NormalizeIterationCount(count)` only rejects `<= 0`, so positive PBKDF2 iteration counts up to `int.MaxValue` pass uncapped on the **standalone encrypted-PKCS#8 import** path (unlike the PKCS#12 loader path, which pre-checks via `GetKdfCount`).

**Follow-up verification (this session):**
- The PKCS#12 loader — the untrusted-by-default path (certs arrive via TLS handshake / untrusted files) — **is capped** by `Pkcs12LoaderLimits`: `MacIterationLimit` 300k, `IndividualKdfIterationLimit` 300k, `TotalKdfIterationLimit` 1M (defaults as of .NET 9). Confirmed in `X509CertificateLoader.SecurityDesign.md` and the loader tests.
- The uncapped path (`RSA/ECDsa/DSA.ImportEncryptedPkcs8PrivateKey`) has **no in-box framework consumer that feeds it untrusted data** — every caller found is the crypto API implementation itself. An app would have to pass an attacker-controlled encrypted-PKCS#8 blob to the import for this to bite.

Verdict: real uncapped iteration count, but **fails the untrusted-by-default reachability bar** (app footgun, not framework-automatic). The untrusted path is protected. Not eligible. (A standalone PBKDF2-iteration DoS advisory for apps that import untrusted encrypted PKCS#8 is the most that could be said — not a framework bug.)

## HttpClient / URI — lead UNRESOLVED (needs re-run after limit reset)

The hunter died mid-investigation of a `uri.Host` "dot behavior" it confirmed reproduces on shipping **.NET 9.0.20**. It was about to check two things that determine whether it's a real finding or a known quirk:
1. Whether the runtime's own tests acknowledge the dot behavior (→ known/by-design).
2. Whether any **in-box ASP.NET Core consumer makes a security decision on `uri.Host` before calling HttpClient** — which would amplify it from an app footgun into a framework SSRF-filter-bypass primitive.

**Not resolved.** Trailing/embedded-dot host handling (e.g. `host.example.com.` normalization, or `Uri.Host` vs the socket's connect target) is a parser/connector differential class that CAN enable SSRF allowlist bypass — but is frequently documented/by-design. This is the one lead from batch 2 worth re-running after the rate limit resets (11:40pm UTC), focused specifically on: (a) is it by-design per runtime tests, and (b) is there an in-box consumer that trusts `uri.Host`.

---

## Net for batch 2
- Routing: clean.
- X.509: dead-ends on reachability (same pattern as session).
- HttpClient/URI: **one unresolved lead** — the only live thread remaining. Re-run needed.
