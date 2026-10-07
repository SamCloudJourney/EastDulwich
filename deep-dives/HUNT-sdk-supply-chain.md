# HUNT: .NET SDK Supply Chain Security

**Target:** `/home/user/dotnet-hunt/sdk2/`
**Focus:** Supply chain attack surface across NuGet packages, dotnet tools, workload installation, MSBuild tasks, template engine, and source generators
**Prior findings excluded:** F1 (chmod injection in template post-actions), F10/F12 (directory traversal in post-actions)

---

## Finding SC-1: Shell Shim Batch File Injection via `%` in Executable Path

**Severity:** Important (Elevation of Privilege / Arbitrary Code Execution)
**Boundary crossed:** NuGet package author -> user machine (code execution beyond declared tool scope)
**MSRC-eligible:** Yes

### Location

- **`src/Cli/dotnet/ShellShim/ShellShimRepository.cs`**, line 73

### Description

When a .NET tool NuGet package declares `runner="executable"` (native executable tool), the SDK generates a Windows `.cmd` batch file shim to invoke it. The generated batch content is:

```csharp
string batchContent = $"@echo off\r\n\"%~dp0{relativePathToExe}\" %*\r\n";
```

The `relativePathToExe` is computed from `Path.GetRelativePath(_shimsDirectory.Value, toolCommand.Executable.Value)` where `Executable.Value` ultimately comes from the `EntryPoint` attribute in `DotnetToolSettings.xml` inside the NuGet package (`ToolConfigurationDeserializer.cs`, line 43).

The `EntryPoint` path is not validated for batch-special characters. The only validation on the command name (`ToolConfiguration.cs`, lines 41-52) uses `Path.GetInvalidFileNameChars()`, which does NOT include `%`, `&`, `^`, `|`, `!`, `<`, `>` -- all of which are metacharacters in Windows batch/cmd interpretation.

The `%` character is valid in NTFS filenames, so a malicious NuGet package can include an executable at a path like:

```
tools/net8.0/any/%USERPROFILE%\..\..\..\Windows\System32\calc.exe
```

When the generated `.cmd` shim runs, the batch interpreter expands `%USERPROFILE%` (and any other `%VAR%` patterns) before the path is resolved, enabling:

1. **Environment variable expansion** -- `%COMSPEC%`, `%USERPROFILE%`, etc. are expanded at runtime
2. **Path manipulation** -- expanded variables can redirect execution to attacker-controlled paths
3. **Command injection** -- patterns like `%CMDCMDLINE%` or carefully crafted `%%` sequences can alter execution flow

### Attack Scenario

1. Attacker publishes a NuGet package with `runner="executable"` and `EntryPoint` containing `%` characters
2. User runs `dotnet tool install -g malicious-tool`
3. SDK generates a `.cmd` shim at `~/.dotnet/tools/malicious-tool.cmd` containing the unescaped path
4. When the user runs `malicious-tool`, the batch interpreter expands environment variables in the path before execution
5. The expanded path points to a different executable than what the user expected

### Mitigation

The `%` character in `relativePathToExe` should be escaped as `%%` before embedding in the batch file. Other batch metacharacters (`&`, `^`, `|`, `<`, `>`, `!`) in the path should also be escaped or rejected.

**Contrast with Unix:** On Unix (line 78), the same scenario uses `File.CreateSymbolicLink(shimPath, relativePathToExe)`, which does not interpret special characters, making this a Windows-only issue.

### Files

| File | Line | Role |
|------|------|------|
| `src/Cli/dotnet/ShellShim/ShellShimRepository.cs` | 73 | Generates unescaped `.cmd` shim |
| `src/Cli/dotnet/ToolPackage/ToolConfiguration.cs` | 41-52 | Validates commandName but not entryPoint |
| `src/Cli/dotnet/ToolPackage/ToolConfigurationDeserializer.cs` | 43 | Reads EntryPoint from XML without sanitization |
| `src/Cli/dotnet/ToolPackage/ToolPackageInstance.cs` | 118-121 | Passes unsanitized runner + path to ToolCommand |

---

## Finding SC-2: NuGet Signature Verification Conditional on Feed Self-Report

**Severity:** Important (Defense in Depth Bypass / Tampering)
**Boundary crossed:** Malicious feed operator -> user machine (package integrity bypass)
**MSRC-eligible:** Borderline -- depends on whether NuGet signature verification is considered a security boundary by MSRC. The feed-opt-in design may be intentional but undocumented to users.

### Location

- **`src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs`**, lines 263-291

### Description

Even when the caller explicitly requests signature verification (`verifySignatures = true`), the actual cryptographic verification is gated on the package source reporting `AllRepositorySigned == true`:

```csharp
if (!_verifySignatures)
{
    return;  // line 265 - early exit if platform-disabled
}

if (repository is not null &&
    await repository.GetResourceAsync<RepositorySignatureResource>()
        .ConfigureAwait(false) is RepositorySignatureResource resource &&
    resource.AllRepositorySigned)  // line 270 - feed must self-report
{
    // Only HERE does actual signature verification happen
}
```

This means:
1. A malicious NuGet feed that does NOT set `AllRepositorySigned` in its service index bypasses all signature verification, even when the caller (e.g., `dotnet tool install`) passes `verifySignatures: true`
2. The verification is entirely opt-in by the feed, not enforced by the client

Additionally, the constructor (line 72) defaults `verifySignatures = false`:
```csharp
public NuGetPackageDownloader(... bool verifySignatures = false ...)
```

And there is a platform gate (lines 99-103) that disables verification on macOS by default.

### Attack Scenario

1. Attacker operates a NuGet feed (or compromises a private feed) that does NOT report `AllRepositorySigned`
2. User configures this feed in their NuGet.config (common for private/enterprise feeds)
3. User runs `dotnet tool install` or `dotnet workload install` pointing at this feed
4. Despite the SDK requesting signature verification, the feed's `AllRepositorySigned = false` (or missing) causes all verification to be skipped
5. Attacker serves a tampered package that is accepted without any signature check

### Wider Impact

Multiple callers rely on this verification:
- `ToolInstallGlobalOrToolPathCommand.cs` (line 104): `verifySignatures: verifySignatures ?? true`
- `ToolPackageDownloaderBase.cs` (line 96): `verifySignatures = true` default
- Workload installation paths

But the `true` flag is meaningless if the feed does not self-report signing support.

### Files

| File | Line | Role |
|------|------|------|
| `src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs` | 72 | Default `verifySignatures = false` |
| `src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs` | 263-291 | Feed-gated verification logic |
| `src/Cli/dotnet/NugetPackageDownloader/NuGetPackageDownloader.cs` | 99-103 | macOS platform gate |
| `src/Cli/dotnet/Commands/Tool/Install/ToolInstallGlobalOrToolPathCommand.cs` | 104 | Passes `verifySignatures: true` |

---

## Finding SC-3: Workload Elevated IPC -- GlobalJsonPath Not Validated

**Severity:** Important (Elevation of Privilege -- Arbitrary File Read as SYSTEM)
**Boundary crossed:** Unelevated user process -> elevated (admin) server process
**MSRC-eligible:** Yes

### Location

- **`src/Cli/dotnet/Commands/Workload/Install/NetSdkMsiInstallerServer.cs`**, line 120
- **`src/Cli/dotnet/Commands/Workload/Install/MsiInstallerBase.cs`**, line 250

### Description

The .NET SDK workload installer uses a named pipe IPC mechanism where an unelevated client process communicates with an elevated (admin) server process. The server validates most IPC-supplied paths before using them:

- `ManifestPath` -- validated by `ValidateManifestPath()` (must be under server temp or client temp)
- `LogFile` -- validated by `ValidateLogFilePath()` (must be under temp dirs or user profile temp)
- `PackagePath` -- validated by `ValidatePackagePath()` (must be under cache root)
- `PackageId`, `PackageVersion` -- validated by `ValidatePathComponent()` (no separators or `..`)

However, `GlobalJsonPath` is NOT validated at all. When the server receives a `RecordWorkloadSetInGlobalJson` request:

```csharp
// NetSdkMsiInstallerServer.cs, line 120
case InstallRequestType.RecordWorkloadSetInGlobalJson:
    RecordWorkloadSetInGlobalJson(new SdkFeatureBand(request.SdkFeatureBand),
        request.GlobalJsonPath,      // <-- NO validation
        request.WorkloadSetVersion);
```

The `RecordWorkloadSetInGlobalJson` method (MsiInstallerBase.cs, line 250) stores the path in a JSON file without validation:

```csharp
public void RecordWorkloadSetInGlobalJson(SdkFeatureBand sdkFeatureBand,
    string globalJsonPath, string workloadSetVersion)
{
    Elevate();
    if (IsElevated)
    {
        var workloadSetsFile = new GlobalJsonWorkloadSetsFile(sdkFeatureBand, DotNetHome);
        workloadSetsFile.RecordWorkloadSetInGlobalJson(globalJsonPath, workloadSetVersion);
        // globalJsonPath is stored as a dictionary key in globaljsonworkloadsets.json
    }
}
```

Later, `GetGlobalJsonWorkloadSetVersions` iterates over stored paths and reads each one:

```csharp
// GlobalJsonWorkloadSetFile.cs, line 70
var updatedVersion = GetWorkloadVersionFromGlobalJson(kvp.Key);
```

Which calls `SdkDirectoryWorkloadManifestProvider.GlobalJsonReader.GetWorkloadVersionFromGlobalJson(globalJsonPath, out _)`, which opens the file at the arbitrary path:

```csharp
// SdkDirectoryWorkloadManifestProvider.GlobalJsonReader.cs, line 30
using var streamReader = new StreamReader(globalJsonPath, detectEncodingFromByteOrderMarks: true);
```

### Attack Scenario

The named pipe restricts connections via `PipeSecurity` to the same user SID (`WindowsUtils.CreatePipeSecurity()`), so this is exploitable by an unelevated process running as the same user who triggered the elevation:

1. User runs `dotnet workload install` which triggers UAC elevation
2. A malicious process running as the same user connects to the named pipe
3. It sends a `RecordWorkloadSetInGlobalJson` request with `GlobalJsonPath` set to an arbitrary path (e.g., `C:\Windows\System32\config\SAM` or any file only readable by admin)
4. The elevated server stores this path without validation
5. When `GetGlobalJsonWorkloadSetVersions` runs (same session or future), the elevated server reads the file at that arbitrary path
6. The file content (parsed as JSON) influences the response, potentially leaking data through error messages or workload version strings

### Impact Assessment

The direct impact is an arbitrary file read from the elevated server process. The severity depends on:
- Whether error messages or parsed values from the file are returned to the unelevated client
- Whether the pipe security effectively limits this to same-user (it does via SID check), which reduces it to unelevated->elevated within the same user rather than cross-user

The pattern is still a clear validation gap compared to the thorough validation applied to every other IPC path parameter.

### Files

| File | Line | Role |
|------|------|------|
| `src/Cli/dotnet/Commands/Workload/Install/NetSdkMsiInstallerServer.cs` | 119-121 | Dispatches without validation |
| `src/Cli/dotnet/Commands/Workload/Install/MsiInstallerBase.cs` | 250-270 | Stores path without validation |
| `src/Cli/dotnet/Commands/Workload/GlobalJsonWorkloadSetFile.cs` | 16-35 | Records arbitrary path as JSON key |
| `src/Cli/dotnet/Commands/Workload/GlobalJsonWorkloadSetFile.cs` | 70 | Reads file at stored arbitrary path |
| `src/Resolvers/.../SdkDirectoryWorkloadManifestProvider.GlobalJsonReader.cs` | 30 | Opens file via `new StreamReader(globalJsonPath)` |
| `src/Cli/dotnet/Installer/Windows/WindowsUtils.cs` | 144-282 | Validates all OTHER IPC paths |
| `src/Cli/dotnet/Installer/Windows/InstallMessageDispatcher.cs` | 211-219 | Sends GlobalJsonPath without sanitization |

---

## Finding SC-4: MSBuild Tasks and Source Generators Execute Without Sandboxing

**Severity:** By Design (Important if considered a vulnerability, but likely classified as "by design")
**Boundary crossed:** NuGet package author -> build machine (arbitrary code execution)
**MSRC-eligible:** Unlikely -- this is the documented MSBuild extensibility model

### Description

NuGet packages can include MSBuild `.targets` and `.props` files that are automatically imported during build. These files can:

1. Define `<UsingTask>` elements that load arbitrary .NET assemblies as MSBuild tasks
2. Include Roslyn source generators (`<Analyzer>` items) that execute arbitrary code during compilation
3. Run as part of `dotnet build` / `dotnet restore` with the full privileges of the build process

The SDK's analyzer infrastructure (`Microsoft.NET.Sdk.Analyzers.targets`) loads analyzers from well-known paths:

```xml
<!-- Line 124-135 -->
<ItemGroup Condition="$(EnableNETAnalyzers)">
  <Analyzer Include="$(MSBuildThisFileDirectory)..\analyzers\..." IsImplicitlyDefined="true" />
</ItemGroup>
```

But NuGet packages can add their own analyzers/generators via the `analyzers/` folder convention, and these execute within the compiler process without any sandboxing, consent prompt, or signature verification.

### Why This Is Likely Not MSRC-Eligible

This is the fundamental MSBuild extensibility model. NuGet packages have always been able to execute code during build via:
- Build tasks (custom MSBuild tasks in `.targets` files)
- Roslyn analyzers and source generators
- Build event targets (PreBuildEvent, PostBuildEvent)

Microsoft documents this as expected behavior. The security model relies on:
- NuGet package source trust (feed configuration)
- Package signing (when enabled, per SC-2 above)
- Developer review of `PackageReference` additions

However, transitive dependencies can silently introduce source generators that execute on every build, which developers may not be aware of.

### Files

| File | Line | Role |
|------|------|------|
| `src/Tasks/Microsoft.NET.Build.Tasks/targets/Microsoft.NET.Sdk.Analyzers.targets` | 123-135 | Loads SDK analyzers |
| NuGet convention: `analyzers/dotnet/cs/*.dll` | N/A | Third-party analyzers auto-loaded |

---

## Finding SC-5: `dotnet tool execute` Runs Packages Without Consent

**Severity:** Low-Moderate (depends on interaction with SC-2)
**Boundary crossed:** NuGet package author -> user machine (code execution without explicit consent)
**MSRC-eligible:** Unlikely on its own

### Location

- **`src/Cli/dotnet/Commands/Tool/Execute/ToolExecuteCommand.cs`**, lines 107-146

### Description

The `dotnet tool execute` command (also known as `dotnet tool run` for one-shot execution) downloads a NuGet package and immediately executes it as a tool without requiring explicit user confirmation:

```csharp
// Line 131
IToolPackage toolPackage = toolPackageDownloader.InstallPackage(
    new PackageLocation(...), packageId, ...);
// Line 143
var commandSpec = ToolCommandSpecCreator.CreateToolCommandSpec(toolPackage.Command, ...);
```

Combined with SC-2 (signature verification bypass on non-AllRepositorySigned feeds), this enables:

1. `dotnet tool execute some-tool` from a malicious feed
2. Package is downloaded without signature verification (if feed doesn't report AllRepositorySigned)
3. Package is immediately executed

However, `dotnet tool execute` is designed for this purpose -- it is the moral equivalent of `npx` in the Node.js ecosystem. The user explicitly invokes it knowing a package will be downloaded and run. The security model relies on the user trusting the package source.

### Why This Is Likely Not MSRC-Eligible

The command is designed to download and run packages. The user invokes it with a specific package name. This is similar to `pip install && python -m package` or `npx package`. The lack of an interactive consent prompt is a design choice, not a vulnerability.

The concern is when combined with SC-2 (signature bypass), but that is SC-2's issue, not this command's.

---

## Summary

| ID | Finding | Severity | MSRC-Eligible | Confidence |
|----|---------|----------|---------------|------------|
| SC-1 | Batch shim `%` injection | Important | **Yes** | High |
| SC-2 | Feed-gated signature bypass | Important | Borderline | High |
| SC-3 | Elevated IPC GlobalJsonPath unvalidated | Important | **Yes** | High |
| SC-4 | MSBuild/analyzer no sandbox | By Design | No | High |
| SC-5 | One-shot tool execute no consent | By Design | No | High |

**Strongest findings: SC-1 and SC-3.** Both involve concrete code paths where attacker-controlled input crosses a security boundary without adequate validation, in contrast to adjacent code paths that do validate properly.
