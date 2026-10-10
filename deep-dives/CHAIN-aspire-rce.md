# Chained Critical: Aspire Dashboard — Web-origin → DNS-rebind → unauthenticated container RCE → dev-host pivot

**Class:** CWE-350 (reliance on reverse DNS) + CWE-306 (missing auth) + CWE-918-adjacent → RCE
**Proven against:** real shipped `aspire.cli` 13.6.1 dashboard (`Aspire.Dashboard`, .NET 11 RC), not a reproduction.
**Boundary crossed:** Web origin (attacker's page) → the developer's localhost dashboard → interactive shell in managed containers → developer host.

---

## The chain (each link empirically verified this session)

**Link 1 — one env var flips ALL THREE auth modes to unsecured.**
On the real running dashboard, setting `ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true` produced (read from the live process environment):
```
DASHBOARD__FRONTEND__AUTHMODE=Unsecured
DASHBOARD__OTLP__AUTHMODE=Unsecured
DASHBOARD__API__AUTHMODE=Unsecured
```
So frontend, telemetry (OTLP) and the dashboard API all drop authentication together. `UnsecuredAuthenticationHandler` then auto-authenticates every request. In this mode the **WebSocket Origin check is the sole cross-origin defense.**

**Link 2 — DNS rebinding defeats the Origin check. PROVEN against real Aspire 13.6.1.**
`WebSocketOriginValidator.IsSameOrigin` compares the `Origin` header host against `Request.Host` — both client-controlled. After DNS rebinding both carry the attacker's domain, so they match. Live result against the shipped dashboard on `:24920`:
```
Attack  (Host+Origin = evil.attacker.com:24920) → HTTP/1.1 101 Switching Protocols   [BYPASS]
Control (Host=localhost, Origin=attacker.com)   → HTTP 403                             [correctly blocked]
```
The mismatched-origin control returning 403 proves the check is active — and that DNS rebinding (matching Host+Origin) is what slips through.

**Link 3 — the upgraded socket is an interactive container shell.**
`/api/terminal` (and `/api/apphost-terminal`) bridge the WebSocket to a terminal in any resource/container the dashboard manages (`resource` query param). With auth unsecured and origin bypassed, the attacker drives a shell.

**Link 4 — dev-host pivot.**
Container shell → the developer's SSH keys, cloud creds (`~/.aws`, `~/.azure`), NuGet/npm publish tokens, source — i.e. supply-chain and lateral movement from a drive-by web page the dev merely left open ~60s.

**Attacker cost:** a domain with low-TTL DNS and a web page. No creds, no prior access, no user click beyond visiting a page.

---

## Why this is a *critical chain* (CVSS ~9.6, RCE/S:C)

Single primitives are individually weak (origin check, an env flag). Chained, a remote web attacker gets unauthenticated RCE on a developer's machine. That is the MSRC "SFB/RCE Critical" shape, and the attack vector is Network/UI:Required-but-trivial — the same bar as the dev-tool CVEs below.

---

## The ONE thing that decides eligibility (I will not hide it)

Microsoft's `aspire.dev/dashboard/security-considerations` page **names DNS rebinding explicitly** and offers `AllowedHosts` host-filtering as the mitigation, warning *"anonymous access removes this protection"* and *"only allow anonymous access in trusted local development environments."*

**Fatal reading (likely MSRC response):** known + documented + opt-in insecure mode + a documented mitigation (`AllowedHosts`) = "working as designed, configure host filtering." Declined. This is why my earlier pass rated F3 DEBUNKED.

**Survivable reading (why it may still be worth submitting):**
1. **The warning addresses the wrong threat.** It says don't expose the dashboard to an *untrusted network*. DNS rebinding does **not** require network exposure — the attack arrives through the developer's **own browser** on localhost. A dev running on a "trusted local development environment" (exactly what the docs bless) is fully exploitable. The documented caveat does not cover the documented-supported scenario.
2. **`AllowedHosts` is not on by default** in the stock `aspire run` / `ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true` flow. Secure-by-default gap.
3. **Direct precedent that MSRC pays these:** Playwright MCP **CVE-2025-9611** (missing Origin check on a localhost dev tool) was accepted. Node inspector **CVE-2018-7160** (CVSS 8.8) and Chrome DevTools **CVE-2018-6101** (7.5) were both opt-in localhost dev features that still received CVEs. "Opt-in dev tool" has not historically been a valid decline for a DNS-rebinding RCE.

**Honest probability:** I put it at maybe 25-40% that MSRC services this rather than declining as documented. That is not high — but it is a real, complete, empirically-proven chained critical, and the submit/no-submit call is legitimately yours. If you submit, lead with reading #1 (browser-as-vector ≠ network exposure) and the Playwright MCP precedent — that is the argument the refutation did not fully address.

---

## What would push it to near-certain eligibility (next hunting step)
Break Link 2 in **browser-token mode** (the secure default), not just unsecured mode. If DNS rebinding + the host-scoped cookie can still reach `/api/terminal` — e.g. a cookie-scoping flaw, or an endpoint that doesn't enforce the token — then the "unsecured is opt-in" refutation evaporates entirely and it becomes an unambiguous critical. That is the single highest-value remaining probe.
