# Chain #4 (new): X-Forwarded-For/Proto spoofing via the env-var ForwardedHeaders default → IP-allowlist / scheme-trust bypass

**Class:** CWE-348 (use of less-trusted source) / CWE-290 (auth bypass by spoofing).
**Component:** `Microsoft.AspNetCore` default host builder — `ForwardedHeadersOptionsSetup` + `ForwardedHeadersStartupFilter`.
**Status:** behaviour demonstrated end-to-end, but **NOT MSRC-ELIGIBLE — REFUTED on the by-design test (2026-10-13).** Keep for reference; do not submit.

---

## ⛔ REFUTATION (supersedes the eligibility estimate at the bottom of this file)

Two checks, both negative:

### 1. Microsoft documents this exact behaviour *and* its exact security consequence
From **"Security considerations for the ASP.NET Core Kestrel web server"**, `aspnetcore-10.0` docs
(<https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/security-considerations?view=aspnetcore-10.0#deployment-topologies>), verbatim:

> "The Forwarded Headers middleware can be silently enabled with **no proxy restrictions** by setting the environment variable `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` (or `DOTNET_FORWARDEDHEADERS_ENABLED=true`, or the configuration key `ForwardedHeaders_Enabled`). When enabled this way, the framework **clears `KnownProxies` and `KnownIPNetworks`**, meaning every upstream IP is trusted. This is far more permissive than what is achievable through the C# API, where `KnownProxies` defaults to loopback only. **Verify this variable isn't set in edge deployments** — check your Dockerfiles, orchestrator configs, CI/CD pipelines, and hosting platform defaults."

> "**Key principle:** Forwarded Headers middleware should only be enabled when there is a trusted proxy in front of Kestrel. In edge deployments, enabling it allows clients to forge their identity."

This closes off the one argument this report was leaning on. The write-up below argued the env-var path "cannot be made safe by itself … that is a secure-default gap in Microsoft's own enablement path." Microsoft has pre-empted that argument in print: they document the clearing, they note it is *deliberately* more permissive than the C# API allows, they state the consequence ("allows clients to forge their identity"), and they give the remediation. That is the textbook definition of **documented as by-design**, which is an explicit disqualifier on the MSRC bar.

The breaking-change doc for .NET 8 (<https://learn.microsoft.com/aspnet/core/breaking-changes/8/forwarded-headers-unknown-proxies>) reinforces it from the other side: the *secure* default was deliberately tightened in .NET 8 so unknown proxies are ignored, and `ASPNETCORE_FORWARDEDHEADERS_ENABLED` is named as the documented opt-out for people who need the old permissive behaviour. So the permissiveness is the advertised purpose of the switch, not an oversight.

### 2. The "a Microsoft base image sets it by default" escape hatch does not exist
This was the single load-bearing unknown — if a Microsoft-shipped image or PaaS set the variable, the finding would have become default-config and survived. It does not:

- `mcr.microsoft.com/dotnet/aspnet:10.0` — fetched `dotnet/dotnet-docker` `src/aspnet/10.0/noble/amd64/Dockerfile` from `main`. It sets exactly **one** `ENV`: `ASPNET_VERSION=10.0.12`. `ASPNETCORE_FORWARDEDHEADERS_ENABLED` **does not appear anywhere in the file.**
- History confirms the intent: the variable was introduced in 2019 for Azure App Service *template* Dockerfiles, and a Microsoft maintainer told users they had to add it themselves as an app setting — i.e. caller-supplied, never image-supplied.
- Microsoft's own docs tell operators to go *looking* for it in their Dockerfiles and hosting-platform configs (quote above), which only makes sense if the platform does not set it.

### Revised verdict
- **Eligibility: ~2%** (was 15-25%). The rejection is not a judgement call — it is the documented by-design disqualifier, in a security-considerations page written specifically about this variable.
- The *behaviour* demonstrated below is real and reproducible. It remains a legitimate **deployment-hardening** finding — useful in a pentest report or an internal audit, worthless as a bounty submission.
- Nothing further to do here. Do not spend time on a submission draft.

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
- ~~Estimate: ~15-25%.~~ **SUPERSEDED — see REFUTATION at top of file; actual ~2%.** Original reasoning kept for the record: lead with "the env-var path clears KnownProxies with no scoped alternative" + a concrete deployment (k8s) where pods are directly reachable.

## Hardening (remediation section)
Don't rely on the env var alone; configure `ForwardedHeadersOptions.KnownProxies`/`KnownNetworks` to the actual proxy, keep `ForwardLimit` correct, and ensure the edge strips inbound `X-Forwarded-*`. Microsoft could make the env-var path require an accompanying proxy/network list instead of clearing it.
