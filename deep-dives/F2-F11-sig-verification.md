# F2/F11: .NET SDK Signature Verification Disabled on Non-Windows Platforms

## Executive Summary

**MSRC Verdict Prediction: REJECT as known/documented limitation.**

Both findings describe behavior that is explicitly documented in the codebase, commented with technical rationale, has dedicated architecture documentation (SIGNING-VERIFICATION.md, NUGET-SIGNATURE-VERIFICATION.md), and has open GitHub issues dating back years. Microsoft is fully aware that workload and NuGet signature verification is not enforced on Linux/macOS. This is a deliberate engineering decision, not an overlooked vulnerability.

---

## 1. Is This Documented/Known?

### Extensively documented -- in source code AND architecture docs

**WorkloadUtilities.cs:85-97** contains a 6-line comment block explaining exactly WHY verification is disabled on non-Windows, citing three specific technical reasons:
1. No equivalent to Windows Authenticode `IsDotNetSigned()` check on Linux/macOS
2. TRP certificate bundles shipped as point-in-time snapshots can lag behind new roots
3. No MSI fallback verification layer on non-Windows (file-based installer only)

**SIGNING-VERIFICATION.md** (in-repo architecture doc) has an entire "Linux and macOS" section that states:
> "Workload signature verification is **not enforced**. `ShouldVerifySignatures()` returns `false` at compile time (`#if !TARGET_WINDOWS`), so workload callers never request verification."

**NUGET-SIGNATURE-VERIFICATION.md** contains a platform gate table explicitly showing macOS defaults to skip, Linux defaults to verify (for non-workload callers only).

### GitHub Issues

- **dotnet/sdk#55** (2016): "Signing does not work on non-Windows" -- the fundamental tracking issue
- **dotnet/sdk#24887** (2022, open): "Workloads: Better handling of package signature failures during install" -- user explicitly notes "This works fine on macOS (which does not support package signature validation yet)"
- **dotnet/sdk#46857** (referenced in code): macOS certificate store support gap
- **dotnet/sdk#38681** (2024, open): "Unable to install, update or clean unsigned preview workloads reliably"
- **dotnet/sdk#40629** (2024, open, Priority:2, Cost:M): `dotnet workload clean` fails due to invalid package signature -- demonstrating Microsoft is still actively working on signing issues

### NuGet ecosystem awareness

NuGet documentation and the NuGet/Home repo have extensive tracking of cross-platform signing limitations. The `DOTNET_NUGET_SIGNATURE_VERIFICATION` environment variable is an official opt-in/opt-out mechanism, not a hidden flag.

**Bottom line:** This is not a discovery. Microsoft engineers designed, documented, and commented this behavior. A bounty submission citing "I found that verification returns false" is citing code that says "// we return false here because..." directly above it.

---

## 2. Actual Attack Surface Mapping

### Commands affected

| Command | Platform | Verification Status | Notes |
|---------|----------|-------------------|-------|
| `dotnet workload install` | Linux | NO verification | `ShouldVerifySignatures()` returns `false` at compile time |
| `dotnet workload install` | macOS | NO verification | Same compile-time gate |
| `dotnet workload update` | Linux/macOS | NO verification | Same path through `WorkloadCommandBase` |
| `dotnet workload restore` | Linux/macOS | NO verification | Same path |
| `dotnet tool install -g` | Linux | YES by default | Tool path passes `verifySignatures: true`, platform gate allows Linux |
| `dotnet tool install -g` | macOS | NO by default | Platform gate disables unless `DOTNET_NUGET_SIGNATURE_VERIFICATION=true` |
| `dotnet restore` | Linux | YES (forwarded) | `NuGetSignatureVerificationEnabler` sets env var for forwarded NuGet commands |
| `dotnet restore` | macOS | NO | `NuGetSignatureVerificationEnabler.IsLinux()` returns false on macOS |

### FileBasedInstaller hardcoded false (F2 sub-finding)

`FileBasedInstaller.cs:65-68` hardcodes `verifyNuGetSignatures: false`. This is the non-Windows installer -- on Windows, `NetSdkMsiInstallerClient` is used instead, which relies on MSI Authenticode as primary verification. The FileBasedInstaller's hardcoded `false` is redundant with the compile-time gate in `ShouldVerifySignatures()` but creates an additional safety concern: even if `ShouldVerifySignatures()` were fixed to return `true` on Linux, the FileBasedInstaller would still skip verification.

### Network path analysis

| Attack Vector | HTTPS Mitigates? | Signature Would Mitigate? |
|--------------|-----------------|--------------------------|
| Passive MITM | Yes | Yes |
| Compromised nuget.org account | No | Partially (repo signature intact, author sig compromised) |
| Malicious private/corporate feed | No | Yes -- this is the real gap |
| DNS hijacking to fake mirror | Depends on TLS cert validation | Yes |
| CI/CD with custom package sources | No | Yes |
| Compromised proxy/CDN | Depends on TLS termination | Yes |

### The AllRepositorySigned bypass (additional weakness)

Even when `_verifySignatures` is `true`, verification only runs when `AllRepositorySigned == true` on the repository. A malicious NuGet feed that does not advertise `AllRepositorySigned` bypasses signature verification entirely, even on Windows. This is documented behavior (NUGET-SIGNATURE-VERIFICATION.md line 64-65) but compounds the attack surface.

---

## 3. Strongest Attack Scenario

### Scenario: Supply chain compromise via Linux CI/CD workload installation

**Target:** GitHub Actions / Azure DevOps Linux runner building a .NET MAUI or Blazor WASM app

**Prerequisites:**
1. Attacker controls or compromises a NuGet feed URL used in the CI pipeline's nuget.config
2. OR attacker achieves DNS/proxy-level MITM in the CI environment (corporate proxy, compromised DNS)
3. CI pipeline runs `dotnet workload install` (common for MAUI, Android, iOS, WASM, Aspire workloads)

**Attack chain:**
1. Attacker publishes tampered workload manifest and packs to the compromised feed
2. CI runner runs `dotnet workload install maui` on Linux
3. `ShouldVerifySignatures()` returns `false` (compile-time, unconditional)
4. `FileBasedInstaller` additionally hardcodes `verifyNuGetSignatures: false`
5. Tampered workload pack is extracted to `$DOTNET_ROOT/packs/` without any signature check
6. Workload packs contain `WorkloadManifest.targets` files imported via `Microsoft.NET.Sdk.ImportWorkloads.targets`
7. These targets can contain arbitrary MSBuild tasks, source generators, or analyzer references
8. Every subsequent `dotnet build` in the pipeline executes the attacker's code

**Impact:**
- Arbitrary code execution during build (source generators run in-process)
- Build output (binaries) can be silently backdoored
- Persists across all builds until workload is reinstalled
- Can exfiltrate secrets from CI environment

**Why this is still weak for MSRC:**
- Requires attacker to control/compromise a NuGet feed -- at which point the attacker can also serve malicious regular packages
- HTTPS provides transport-level integrity against most network attacks
- The attacker already needs a privileged position (compromised feed or MITM)
- On nuget.org (the default source), `AllRepositorySigned` is set but transport security (HTTPS + TLS pinning in some clients) is the primary protection

---

## 4. Would MSRC Accept or Reject?

### Precedent analysis

**Against acceptance:**
- Microsoft has explicitly documented this as unsupported ("Both layers are Windows-only for workloads")
- The MSRC bounty program excludes "known limitations that are already documented"
- NuGet signing on non-Windows has been a known gap since at least 2016 (issue #55)
- The code contains detailed comments explaining the engineering rationale
- There are in-repo architecture documents (SIGNING-VERIFICATION.md) that call out the limitation
- Microsoft's own .NET team created these docs, meaning the security implications were reviewed

**For acceptance (weak arguments):**
- The FileBasedInstaller hardcoded `false` is arguably a defense-in-depth failure that would prevent future fixes from taking effect
- The macOS `dotnet tool install` gap could be considered separately (not a "known limitation" for tools specifically)
- No CVE has been issued for this, suggesting it has not been through formal security review

**Historical MSRC patterns:**
- MSRC typically rejects "by design" behaviors even when they reduce security
- "The product behaves as documented" is a standard rejection rationale
- Supply chain attacks through already-compromised feeds are usually out of scope (the feed compromise is the vulnerability, not the verification gap)

### What would make a stronger submission

1. **A concrete exploit chain starting from an unprivileged position** -- if you could demonstrate MITM without controlling the feed or network, or package confusion/substitution attacks that signature verification would prevent
2. **Demonstrating that the hardcoded `false` in FileBasedInstaller blocks future security improvements** -- this is a real code quality issue but probably not bounty-eligible
3. **Finding that `dotnet restore` on macOS silently skips NuGet signature verification** for regular packages (not just tools/workloads) could have broader impact

---

## 5. F2 vs F11 Differentiation

### F2: Workload signature verification disabled (STRONGER)

| Aspect | Detail |
|--------|--------|
| **Scope** | ALL workload operations on ALL non-Windows platforms |
| **Mechanism** | Compile-time `#if !TARGET_WINDOWS` returns `false` unconditionally |
| **Redundancy** | FileBasedInstaller additionally hardcodes `verifyNuGetSignatures: false` |
| **Impact** | Workloads inject MSBuild targets, source generators, analyzers into ALL builds |
| **User control** | No env var to opt in -- there is no way to enable verification on Linux even if desired |
| **Documented?** | YES -- SIGNING-VERIFICATION.md explicitly calls this out |

### F11: NuGet tool signature verification (WEAKER)

| Aspect | Detail |
|--------|--------|
| **Scope** | `dotnet tool install` on macOS only (Linux verifies by default) |
| **Mechanism** | Runtime platform gate in NuGetPackageDownloader constructor |
| **User control** | Can opt in via `DOTNET_NUGET_SIGNATURE_VERIFICATION=true` |
| **Impact** | Global tools execute arbitrary code, but user explicitly chooses to install them |
| **Documented?** | YES -- NUGET-SIGNATURE-VERIFICATION.md has a platform gate table |

### Verdict: F2 is the stronger finding

F2 affects a broader surface (all workloads on all non-Windows), has no user opt-in mechanism, and workloads are more dangerous because they inject build-time code that affects ALL projects. However, F2 is also MORE documented, making it harder to argue it is unknown.

F11 on macOS is narrower but has a clearer "fix": the opt-in env var exists, suggesting Microsoft intended verification to work but left it off by default. This could be framed as a configuration default issue rather than a known limitation.

---

## 6. Chaining Assessment

### Can a compromised workload install malicious source generators?

**YES.** Workload packs contain `WorkloadManifest.targets` which are imported via `Microsoft.NET.Sdk.ImportWorkloads.targets` (line 16: `<Import Project="WorkloadManifest.targets" Sdk="Microsoft.NET.SDK.WorkloadManifestTargetsLocator"/>`). These targets can:
- Add source generators via `<Analyzer>` items
- Add custom MSBuild tasks via `<UsingTask>`
- Modify build outputs via `<Target>` elements
- Execute arbitrary commands via `<Exec>` tasks

### Can it modify the SDK itself?

**PARTIALLY.** On Linux with the file-based installer, workload packs are extracted to `$DOTNET_ROOT/packs/`. If the user has write access to the SDK directory (common in containerized CI), a malicious workload could overwrite SDK files. However, this would require the workload pack to contain files with paths that collide with existing SDK paths, which is constrained by the workload manifest schema.

### Does it persist across projects?

**YES.** Workloads are installed at the SDK level, not per-project. Once installed, a malicious workload's targets are imported for every `dotnet build` that targets the affected platform (e.g., `net8.0-android`). This persists until the workload is reinstalled or the SDK is replaced.

### Chaining with other findings

- **Chain with compromised NuGet feed:** Workload manifests reference specific package IDs and versions from NuGet feeds. If the CI uses a custom/private feed alongside nuget.org, an attacker who controls the private feed could serve a malicious workload manifest that redirects pack resolution to attacker-controlled packages.
- **Chain with CI secret exfiltration:** A malicious source generator runs in the build process and has access to environment variables, which in CI typically include secrets, tokens, and credentials.

---

## 7. Final Assessment

### Bounty Viability: LOW (estimated 10-15% chance of acceptance)

**This is almost certainly a "known limitation" that MSRC will dismiss.** The behavior is:
1. Intentionally designed (compile-time gate, not a bug)
2. Thoroughly documented (in-code comments, architecture docs, GitHub issues)
3. Rationalized (three specific technical reasons documented)
4. Tracked (multiple open issues in dotnet/sdk)

### Recommendations if submitting anyway

1. **Do NOT submit F2 and F11 separately** -- they are the same underlying issue (lack of cross-platform signing infrastructure) and splitting them looks like bounty multiplication
2. **Focus on the FileBasedInstaller hardcoded `false`** as a defense-in-depth failure -- this specific line would prevent fixes from taking effect even if `ShouldVerifySignatures()` were updated
3. **Frame as a supply chain risk to Azure customers** -- Microsoft's own CI services (Azure DevOps, GitHub Actions) run Linux by default, and Microsoft's own workload install recommendations apply
4. **Do NOT claim this as a novel finding** -- MSRC researchers can read the same comments and docs you can
5. **Consider submitting as a feature request** instead of a security vulnerability -- "enable workload signature verification on Linux" is a reasonable ask that the .NET team might already be working toward

### The real security question

The interesting question is not "is verification disabled?" (it obviously is, by design) but "what is the actual residual risk after HTTPS transport security?" If the answer is "only if feeds are compromised" then the finding reduces to "signature verification would provide defense-in-depth against feed compromise on non-Windows" -- which is true but is a design improvement suggestion, not a vulnerability.
