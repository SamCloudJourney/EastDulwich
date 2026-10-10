# HUNT: Uri.Host vs IdnHost SSRF-filter-bypass differential

**Date:** 2026-10-10
**Status:** REAL, empirically proven primitive — but **by-design / app-footgun, NOT MSRC-eligible.**

## The differential (empirically confirmed on .NET 9.0.20 + 10 RC2)

For a host containing a Unicode "dot" variant (U+3002 ideographic full stop `。`, U+FF0E fullwidth `．`, U+FF61 halfwidth `｡`):

```
new Uri("http://169.254.169.254。/latest/meta-data")
  .Host        = "169.254.169.254。"   (Unicode dot PRESERVED)
  .IdnHost     = "169.254.169.254."    (normalized to ASCII dot -> resolves to the real IP)
  .DnsSafeHost = "169.254.169.254。"   (preserved)
```

`SocketsHttpHandler` connects using the **IdnHost-normalized** form. Proven with a `ConnectCallback`:
```
[CONNECT] SocketsHttpHandler asked to connect to: Host='169.254.169.254.' Port=...
outbound Host header: 169.254.169.254.:...
```

## The bypass

An app that does SSRF filtering on `uri.Host`:
```csharp
if (uri.Host == "169.254.169.254" || blocklist.Contains(uri.Host)) return Forbid();
await httpClient.GetAsync(uri);   // connects to IdnHost = the real metadata IP
```
is **bypassed**: `uri.Host` is `169.254.169.254。` (not in the blocklist), but HttpClient connects to `169.254.169.254.` which DNS resolves identically to `169.254.169.254` (trailing dot = FQDN). Result: cloud metadata theft / internal-service access past the filter.

Empirical result: the SSRF-filter simulation returned `False` (allowed) for both `169.254.169.254。` and `localhost．`, and the request reached the loopback listener.

## Why it is NOT MSRC-eligible

1. **By design.** The Unicode-dot → ASCII normalization is RFC-based IDNA mapping, extensively unit-tested in `System.Private.Uri/tests` (`IdnHostNameValidationTest.cs`, `IdnDnsSafeHostTest.cs`). `IdnHost` is documented as the DNS-safe form.
2. **Microsoft is aware of the split and handles it in-box where it matters.** ASP.NET Core CORS normalizes origins via exactly this comparison:
   `CorsPolicyBuilder.GetNormalizedOrigin` (`src/Middleware/CORS/src/Infrastructure/CorsPolicyBuilder.cs:71-87`) does `if (uri.IdnHost != uri.Host) { use IdnHost }`. The framework's own security-relevant host comparison already defends against this.
3. **No in-box vulnerable consumer.** No ASP.NET Core / framework code filters on `.Host` and then connects via HttpClient. The vulnerability only exists in *application* code that chooses `.Host` for a security decision.
4. **Documented correct-usage pattern.** MSRC's response will be "use `IdnHost`/`DnsSafeHost` for host comparisons, as the framework's own CORS code does." This is the same app-footgun class MSRC declines.

## Value

This is a legitimate, demonstrable **SSRF-filter-bypass technique against .NET applications** that filter on `Uri.Host`. It is worth publishing as **defensive guidance** (not a bounty submission):
- Never make allow/block decisions on `Uri.Host` for a URL you will then pass to `HttpClient`. Use `Uri.IdnHost`, or resolve + check the actual IP, or compare the post-normalization host.
- The Unicode full-stop set to watch: U+3002, U+FF0E, U+FF61 (all map to `.` under IDNA), plus the integer/hex/octal IP forms (`2130706433`, `0x7f.0.0.1`) which `Uri` *does* canonicalize in `.Host`.

## Verdict
Best-proven primitive of the hunt, but structurally the same outcome as every other candidate: **real, demonstrable, and non-eligible** because Microsoft treats it as by-design and the framework itself uses the correct-usage pattern. Not submittable to MSRC.
