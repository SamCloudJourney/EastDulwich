# Chain #4 (new): X-Forwarded-For/Proto spoofing via the env-var ForwardedHeaders default → IP-allowlist / scheme-trust bypass

**Class:** CWE-348 (use of less-trusted source) / CWE-290 (auth bypass by spoofing).
**Component:** `Microsoft.AspNetCore` default host builder — `ForwardedHeadersOptionsSetup` + `ForwardedHeadersStartupFilter`.
**Status:** demonstrated end-to-end.

---

## Root cause (Microsoft code, not app code)

When `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` (config key `ForwardedHeaders_Enabled`), the default host builder auto-adds the middleware and configures it like this:

`src/DefaultBuilder/src/ForwardedHeadersOptionsSetup.cs:27-31`
```csharp
options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
// Only loopback proxies are allowed by default. Clear that restriction because forwarders are
// being enabled by explicit configuration.
options.KnownIPNetworks.Clear();   // <-- removes the default loopback-only trust
options.KnownProxies.Clear();      // <--
```
`ForwardedHeadersStartupFilter.cs` then calls `UseForwardedHeaders()`. The result: the app applies `X-Forwarded-For` and `X-Forwarded-Proto` from **any** source — the proxy allowlist that normally bounds this (loopback only) is explicitly emptied. There is no way, via the env var alone, to also set `KnownProxies`; the convenience path is inherently "trust everyone."

## Demonstrated (default host builder, env var set, no app forwarded-headers config)
```
no header          : RemoteIpAddress=127.0.0.1  access=DENIED
spoof XFF=10.0.0.5 : RemoteIpAddress=10.0.0.5   access=GRANTED (admin)
```
A request from 127.0.0.1 (not a configured proxy) carrying `X-Forwarded-For: 10.0.0.5` made `HttpContext.Connection.RemoteIpAddress == 10.0.0.5`, passing an IP allowlist that should only accept the internal IP.

## Impact (chain)
With attacker-controlled `RemoteIpAddress`:
- **Bypass IP allowlists** on admin/internal endpoints ("only from corporate egress / 10.x / localhost").
- **Evade rate limiting / abuse controls** keyed on client IP (rotate spoofed IPs).
- **Forge audit logs / attribution** (log the victim's or an arbitrary IP).
- **Bypass IP-based authorization policies**.

With attacker-controlled `X-Forwarded-Proto: https` over plain HTTP:
- `Request.IsHttps == true` → HTTPS-redirect skipped, affects secure-cookie / HSTS / `RequireHttpsMetadata` decisions and any scheme-dependent logic.

Reachability matters: exploitable wherever the app is reachable by anything other than the one trusted proxy with the env var set — e.g. Kubernetes pods directly reachable in-cluster, service meshes, or an ingress that doesn't strip inbound `X-Forwarded-*`. `ForwardLimit` defaults to 1, so a single spoofed entry is honored.

## Honest eligibility read
- **Fatal (likely):** the env var is a documented opt-in; Microsoft's forwarded-headers docs warn to set `KnownProxies`/`KnownNetworks`. MSRC: "you enabled forwarders; secure your network/proxies" → by-design. The code comment shows the clearing is intentional.
- **Survivable:** the env-var convenience **cannot be made safe by itself** — it unconditionally clears the proxy allowlist, so every deployment using it trusts forwarded headers from any reachable source, with no in-the-box way to scope it. That is a secure-default gap in Microsoft's own enablement path, not merely an app mistake. Strongest if a Microsoft base image / PaaS sets the env var by default (VERIFY for the target deployment — commonly set in k8s/containers behind ingress; I did not confirm a base-image default in these repos). Forwarded-header/XFF spoofing is a recognized class with CVEs across the ecosystem.
- Estimate: ~15-25%. Lead with "the env-var path clears KnownProxies with no scoped alternative" + a concrete deployment (k8s) where pods are directly reachable.

## Hardening (remediation section)
Don't rely on the env var alone; configure `ForwardedHeadersOptions.KnownProxies`/`KnownNetworks` to the actual proxy, keep `ForwardLimit` correct, and ensure the edge strips inbound `X-Forwarded-*`. Microsoft could make the env-var path require an accompanying proxy/network list instead of clearing it.
