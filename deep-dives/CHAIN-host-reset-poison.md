# Chain #3 (new): Host-header password-reset poisoning → account takeover (ASP.NET Core Identity default scaffold)

**Class:** CWE-640 (weak password recovery) + Host-header injection → account takeover.
**Component:** `Microsoft.AspNetCore.Identity.UI` default scaffold + default `AllowedHosts` / HostFiltering.
**Status:** framework URL-generation behavior demonstrated; a classic, historically-CVE'd class in other frameworks.

---

## The chain

1. **The scaffolded Identity UI builds the reset link from the request Host.**
   `src/Identity/UI/src/Areas/Identity/Pages/V4|V5/Account/ForgotPassword.cshtml.cs:77-83`:
   ```csharp
   var code = await _userManager.GeneratePasswordResetTokenAsync(user);
   code = WebEncoders.Base64UrlEncode(...);
   var callbackUrl = Url.Page("/Account/ResetPassword", values: new { area="Identity", code },
                              protocol: Request.Scheme)!;          // absolute URL; authority = Request.Host
   await _emailSender.SendPasswordResetLinkAsync(user, Input.Email, HtmlEncoder.Default.Encode(callbackUrl));
   ```
   `Url.Page`/`LinkGenerator` with a protocol produces an absolute URL whose host is `Request.Host`.

2. **Default config does not restrict the Host.** The ASP.NET Core project template ships `appsettings.json` with `"AllowedHosts": "*"`, and HostFiltering is not added by default, so `Request.Host` is whatever the client sends.

3. **Poison.** Attacker POSTs the victim's email to `/Identity/Account/ForgotPassword` with `Host: evil.attacker.com`. The reset email (delivered to the victim's real inbox) now contains:
   `https://evil.attacker.com/Identity/Account/ResetPassword?code=<VALID_RESET_TOKEN>`

4. **Token capture → takeover.** When the link is followed — the victim clicks it, or (notably) a mail provider / security scanner **prefetches** the link automatically — the valid reset `code` is sent to the attacker's host. Attacker replays it to the real site's ResetPassword → sets a new password → **account takeover**.

### Demonstrated (framework URL generation reflects a spoofed Host)
Minimal default-config app, `LinkGenerator.GetUriByName(httpContext, ...)` (same primitive as `Url.Page` with protocol):
```
legit  Host=app.corp.com       -> http://app.corp.com/Account/ResetPassword?code=VALID-RESET-TOKEN-FOR-victim@corp.com
ATTACK Host=evil.attacker.com  -> http://evil.attacker.com/Account/ResetPassword?code=VALID-RESET-TOKEN-FOR-victim@corp.com
```
With no HostFiltering (the default), the generated reset URL's authority is fully attacker-controlled.

---

## Impact / scope
- **Impact:** account takeover of any user whose reset link is followed/prefetched — critical for an auth system.
- **Hits:** apps using the scaffolded Identity UI (or any code doing `Url.Page/Action(protocol:)` for emailed links) with the default `AllowedHosts="*"` and a configured email sender.
- **Preconditions (honest):** (a) default/unrestricted `AllowedHosts`; (b) a working `IEmailSender`; (c) the reset link is followed or auto-prefetched (UI:R, though mail-scanner prefetch can remove the human click).

## Honest eligibility read
- **Fatal (likely):** `AllowedHosts` exists specifically to stop Host-header injection; Microsoft documents setting it for production. MSRC response: "configure AllowedHosts / host filtering" → app-misconfiguration, by-design. This is the same wall as the other chains.
- **Survivable:** the vulnerable code is **Microsoft-provided scaffold** (`Identity.UI`), it uses `Request.Host` for a security-sensitive emailed token with **no guard**, and the **default template ships `AllowedHosts="*"`** — a secure-default gap in Microsoft code + Microsoft default, not purely the developer's. Direct precedent: this exact class forced mandatory-allowlist fixes in Django (`ALLOWED_HOSTS`) and advisories in Rails/others. The framework could generate reset links from a configured canonical host rather than the request Host.
- Estimate: ~15-25%. Well-known class; strongest angle is "Microsoft scaffold + Microsoft default = takeover with zero developer mistake beyond not overriding a documented default."

## Hardening (for the report's remediation section)
Set `AllowedHosts` to the real host(s); add `UseHostFiltering`; or generate account-email links from a configured absolute base URL (not `Request.Host`). Microsoft could default the Identity UI to a configured canonical origin for emailed links.
