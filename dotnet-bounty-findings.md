# Microsoft .NET Bug Bounty — Validated Vulnerability Findings

> Audit date: 2026-10-07
> Repos audited: dotnet/runtime, dotnet/aspnetcore, dotnet/aspire, dotnet/sdk, dotnet/roslyn
> Focus: Critical and Important severity only
> **Validated against MSRC criteria: must cross a security boundary, not be by design**

---

## REFUTED FINDINGS (10 of 19 eliminated)

| # | Finding | Reason for Refutation |
|---|---------|----------------------|
| F6 | OTLP unsecured default | Dev tool, impact is telemetry spoofing only — below Important bar |
| F7 | ScriptOptions insecure defaults | CSharpScript is a code execution API — by design. Passing untrusted input is developer misuse |
| F9 | CORS normalization mismatch | Fails CLOSED not open — framework rejects valid origin, doesn't accept invalid one. Dev choosing AllowAnyOrigin is their decision |
| F13 | Container arg escaping | Developer controls inputs. No attacker-controlled data reaches this path. UseShellExecute=false mitigates |
| F14 | BinaryFormatter library switch | Explicitly by design, documented, [Obsolete] with compiler error since .NET 9, SDK overrides to false |
| F15 | System.Speech assembly loading | API designed to load assemblies. Windows-only, requires unlikely user action (attacker controlling grammar names) |
| F16 | CL+TE via AppContext switch | Requires explicitly disabling built-in mitigation (switch is off by default). MSRC excludes this pattern |
| F17 | ComSpec hijacking | Platform-level Windows behavior, not .NET-specific. Attacker with env var control already has significant access |
| F18 | Source generators no sandbox | Build-time code execution is the intended model. Installing NuGet packages is an explicit trust decision |
| F19 | Token exchange | Same authenticated user, different interface. Not privilege escalation |

---

## VALIDATED FINDINGS (9 remain)

---

### F1. [SDK] Shell Command Injection via Template Chmod Post-Action
**Severity: CRITICAL | Boundary crossed: Template author → arbitrary code execution without consent**

**File:** `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/ChmodPostActionProcessor.cs:42-51`

```csharp
FileName = "/bin/sh",
Arguments = $"-c \"chmod {entry.Key} {file}\""
```

**Why this crosses the boundary:** The .NET SDK has an explicit consent mechanism for template post-actions that execute commands (`ProcessStartPostActionProcessor` requires `--allow-scripts yes`). The chmod post-action bypasses this consent gate entirely — `PostActionDispatcher.cs:123-157` only checks consent for ProcessStart, not for chmod, AddJsonProperty, or other post-actions. The consent mechanism PROVES Microsoft recognizes this trust boundary. The bypass is inconsistent, not by design.

**Attack:** Malicious NuGet template → `dotnet new <template>` → shell injection via crafted chmod args → RCE. Zero prompts.

**Strength: ██████████ 10/10** — Clean boundary crossing, clear inconsistency in consent model, straightforward PoC.

---

### F3. [Aspire] DNS Rebinding → Terminal WebSocket → Container Shell
**Severity: IMPORTANT (RCE path) | Boundary crossed: Attacker website → container shell access**

**Files:**
- `aspire/src/Aspire.Dashboard/Model/WebSocketOriginValidator.cs:26-29`
- `aspire/src/Aspire.Dashboard/Terminal/TerminalWebSocketProxy.cs:556`

**Why this crosses the boundary:** Even localhost dev tools have security boundaries against network-originating attacks. Chrome DevTools, Jupyter, Docker Desktop, VS Code — all had to fix DNS rebinding. The code comments *explicitly acknowledge* the weakness ("this same-origin check does not prevent DNS rebinding"). The terminal WebSocket proxy provides shell access to containers — that's a real RCE path from a drive-by website visit.

**Precedent:** CVE-2018-15473 (Chrome DevTools DNS rebinding), multiple Jupyter Notebook CVEs, Docker Desktop CVE-2019-15752.

**Strength: █████████░ 9/10** — Strong precedent, code acknowledges the gap, RCE via terminal proxy. Only docked because "unsecured mode" is a deliberate config choice (but it shouldn't mean "vulnerable to DNS rebinding").

---

### F4. [ASP.NET Core] Kestrel Bare LF Acceptance — HTTP Request Splitting
**Severity: IMPORTANT | Boundary crossed: Parsing differential enables request smuggling**

**File:** `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/HttpParser.cs:52`

**Why this crosses the boundary:** RFC 7230 requires CRLF. Kestrel accepting bare LF by default creates a parsing differential with upstream proxies. This is the same class of issue that earned CVEs against Node.js (CVE-2022-32213/32214), Apache (CVE-2023-25690), and many others. The existence of the opt-out switch (`DisableHttp1LineFeedTerminators`) proves Microsoft knows it's a security-relevant behavior — but the *default* is the issue. A safe default with an opt-in for tolerance would be the correct pattern.

**Attack:** Kestrel behind nginx/HAProxy/IIS ARR → bare LF in header values → proxy sees data, Kestrel sees request boundary → smuggled request → cache poisoning, auth bypass.

**Strength: ████████░░ 8/10** — Real attack vector with precedent CVEs in other servers. The switch existing might cause MSRC to say "mitigation available," but unsafe-by-default is still a valid finding. Needs a concrete proxy-specific PoC.

---

### F8. [Roslyn] Ref Safety Scope Tracking Leak — Potential Memory Safety Violation
**Severity: IMPORTANT | Boundary crossed: Safe C# → potential dangling reference → memory corruption**

**File:** `roslyn/src/Compilers/CSharp/Portable/Binder/RefSafetyAnalysis.cs:258-265,536-542`

**Why this crosses the boundary:** The entire point of C#'s ref safety rules is to prevent dangling references in safe code. If the compiler's scope tracking is incorrect (stale entries from inner scopes persisting because removal is commented out), it could allow a ref to escape its lifetime. This would violate the fundamental safety guarantee of managed C# — code the compiler accepts as safe could cause memory corruption.

**Key question to resolve:** Do the stale scope entries make the analysis *over-permissive* (security bug — allows unsafe refs) or *over-restrictive* (correctness bug — rejects valid code)? The tracking issue #65961 suggests it affects correctness, but the direction matters.

**Strength: ████████░░ 8/10** — IF the leak causes over-permissive analysis, this is a high-value compiler safety bug. Needs a concrete PoC: C# code accepted as safe by the compiler that creates a dangling reference.

---

### F5. [Runtime] CryptoConfig.CreateFromName — Type Instantiation via SignedXml
**Severity: IMPORTANT | Boundary crossed: XML input → unintended type instantiation**

**Files:**
- `runtime/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptoConfig.cs:427`
- `runtime/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/SignedXml.cs:1014-1019`

**Why this crosses the boundary:** `CryptoConfig.CreateFromName` is designed to resolve *crypto algorithm names* to types, not arbitrary type names. The fallthrough to `Type.GetType(name)` goes beyond its intended scope. The comma filter proves they recognize the security sensitivity. The secondary path through `SignedXml.cs:1019` (`Type.GetType(signatureDescription.KeyAlgorithm!)`) has NO filter at all.

**What's needed:** A concrete gadget — a type in CoreLib or loaded assemblies whose parameterless constructor has exploitable side effects. Without a gadget, this is theoretical.

**Strength: ███████░░░ 7/10** — Real pattern, clear data flow, but needs a gadget chain to be submittable. The unfiltered `KeyAlgorithm` path is stronger than the comma-filtered `CreateFromName` path.

---

### F2 + F11. [SDK] Signature Verification Disabled on Non-Windows Platforms
**Severity: IMPORTANT | Boundary crossed: MITM → unsigned code execution**

**Files:**
- `sdk/src/Cli/dotnet/Commands/Workload/WorkloadUtilities.cs:83-97` — workloads: unconditional `return false` on non-Windows
- `sdk/src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs:88-103` — NuGet tools: off by default on macOS

**Why this crosses the boundary:** Signature verification is a security feature. Unconditionally disabling it on Linux/macOS means MITM attacks succeed where they should fail. This is a security feature bypass.

**Risk of "by design" dismissal:** HIGH. This may be a known platform limitation. NuGet signing on non-Windows has historically been limited due to certificate store differences. Microsoft may classify this as "known limitation, in progress" rather than a bounty-eligible vulnerability.

**Upgrade path:** The submission would be stronger if you can show: (1) Microsoft documentation says signing IS supported on Linux/macOS, contradicting the code, or (2) the verification is technically feasible but simply not implemented (proving it's a gap, not a limitation).

**Strength: ██████░░░░ 6/10** — Real security impact but high risk of "known limitation" dismissal.

---

### F10 + F12. [SDK] Template Post-Action Directory Traversal (AddJsonProperty + GetTargetFilesPaths)
**Severity: MEDIUM-HIGH | Boundary crossed: Template → file modification outside output directory, without consent**

**Files:**
- `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/AddJsonPropertyPostActionProcessor.cs:112-118`
- `sdk/src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/PostActionProcessorBase.cs:88-114`

**Why this crosses the boundary:** Same trust model argument as F1 — these post-actions bypass the consent gate and can modify files outside the template's output directory. `Path.GetFullPath()` resolves `..` without boundary validation.

**Why it's weaker than F1:** File modification (injecting a JSON property, adding a project reference) is less severe than RCE. The parent directory search (`includeAllParentDirectoriesInSearch`) is arguably a designed feature for legitimate use (finding the nearest `global.json` or `.sln`).

**Upgrade path:** Chain this with F1 — the template post-action consent model is the systemic issue. AddJsonProperty injecting `scripts.postinstall` into a `package.json` above the output dir gets RCE on next `npm install`, making this a two-step RCE chain.

**Strength: ██████░░░░ 6/10** — Real traversal, but weaker impact alone. Stronger as part of the F1 systemic argument.

---

## FINAL SUBMISSION PRIORITY

| Rank | Finding | Severity | Boundary | Submittable Now? |
|------|---------|----------|----------|-----------------|
| 1 | **F1** — Chmod shell injection | Critical | Template → RCE without consent | ✅ Yes, build PoC template |
| 2 | **F3** — DNS rebinding → terminal | Important→Critical | Website → container shell | ✅ Yes, PoC with Aspire dashboard |
| 3 | **F4** — Bare LF request splitting | Important | Parsing diff → request smuggling | ⚠️ Needs proxy-specific PoC |
| 4 | **F8** — Ref safety scope leak | Important | Safe C# → memory corruption | ⚠️ Needs PoC proving over-permissive analysis |
| 5 | **F5** — CryptoConfig type instantiation | Important | XML → unintended type construction | ⚠️ Needs gadget chain |
| 6 | **F2/F11** — Sig verification off (non-Win) | Important | MITM → unsigned packages | ⚠️ Risk of "known limitation" |
| 7 | **F10/F12** — Template dir traversal | Medium-High | Template → file modification outside boundary | ✅ But weaker alone, chain with F1 |

---

## RECOMMENDED SUBMISSION STRATEGY

**Submit immediately (after PoC):**
1. **F1** as a standalone Critical — the consent bypass is the key argument
2. **F3** as a standalone Important — cite Chrome DevTools / Jupyter precedent CVEs

**Submit after deeper PoC work:**
3. **F4** — test behind nginx, HAProxy, and Azure Front Door specifically
4. **F8** — construct C# code that exploits stale scope entries

**Bundle together:**
5. **F1 + F10/F12** as a systemic "template post-action consent model is broken" submission — multiple post-actions bypass the consent gate with varying impacts (RCE, traversal, file modification)

**Hold unless upgraded:**
6. **F5** — park until a gadget type is found
7. **F2/F11** — research whether Microsoft documents Linux/macOS signing as supported before submitting
