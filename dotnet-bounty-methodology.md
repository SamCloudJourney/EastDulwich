# Microsoft .NET Bug Bounty — Attack Methodology

> Critical and Important severity only. This is the playbook.

---

## High-Value Targets (by payout)

### 1. Remote Code Execution — up to $40,000

**Where to look:**
- **Deserialization** — BinaryFormatter, DataContractSerializer, System.Text.Json polymorphic deserialization, custom JsonConverters with unsafe type resolution
- **Template injection** — Razor views/pages, Blazor component rendering with user-controlled markup
- **Expression/code compilation** — CSharpScript, Roslyn scripting APIs, dynamic compilation endpoints
- **Native interop** — P/Invoke boundaries, unsafe code in runtime libraries, buffer overflows in native .NET runtime components
- **Assembly loading** — Assembly.Load with user-controlled paths, plugin architectures, MEF/MAF misuse in templates
- **SSRF to RCE chains** — HttpClient in server-side Blazor, WebSocket proxying in Aspire

**Techniques:**
- Fuzz deserialization endpoints with crafted type payloads
- Trace user input through to `Process.Start`, `Assembly.Load`, `Type.GetType`
- Audit Blazor Server circuits for injection points
- Review Aspire orchestration for container escape / command injection

### 2. Elevation of Privilege — up to $40,000

**Where to look:**
- **Authorization bypass** — ASP.NET Core authorization middleware ordering, policy evaluation gaps, `[Authorize]` attribute edge cases
- **Authentication flaws** — JWT validation bypasses in Microsoft.AspNetCore.Authentication, cookie authentication path traversal, Identity framework logic bugs
- **Kestrel request smuggling** — HTTP/1.1 vs HTTP/2 parsing differences, chunked encoding edge cases, header normalization gaps
- **Blazor Server** — circuit hijacking, cross-user state leakage in scoped services
- **SignalR** — hub method authorization bypass, connection ID prediction

**Techniques:**
- Send malformed HTTP requests through Kestrel to test request splitting/smuggling
- Audit middleware pipeline ordering for auth bypass scenarios
- Test Blazor DI scope isolation — can one circuit access another's scoped services?
- Fuzz SignalR hub invocations with unexpected types

### 3. Security Feature Bypass — up to $30,000

**Where to look:**
- **CORS** — ASP.NET Core CORS middleware bypass with unusual Origin headers, preflight caching abuse
- **CSP / anti-forgery** — antiforgery token generation weaknesses, token reuse across sessions
- **Data Protection API** — key derivation weaknesses, purpose string bypass, cross-application decryption
- **HTTPS enforcement** — HSTS bypass, redirect loops, mixed content in middleware
- **Rate limiting** — ASP.NET Core rate limiting middleware bypass via header manipulation

**Techniques:**
- Test CORS with edge-case origins (null, unicode, scheme variations)
- Analyze Data Protection key storage and rotation for crypto weaknesses
- Attempt antiforgery token prediction or replay
- Bypass rate limiting with X-Forwarded-For, connection reuse

### 4. Remote Denial of Service — up to $20,000

**Where to look:**
- **Algorithmic complexity** — regex in routing, JSON parsing with deeply nested objects, XML bomb equivalents in System.Text.Json
- **Resource exhaustion** — Kestrel connection limits, SignalR hub connection flooding, Blazor circuit exhaustion
- **Crash bugs** — unhandled exceptions in middleware, stack overflow in recursive parsing, OOM via unbounded allocations
- **HTTP/2 specific** — HPACK bomb, stream multiplexing abuse, SETTINGS flood

**Techniques:**
- Send deeply nested JSON to ASP.NET Core model binding
- Craft regex-killing input for route constraint patterns
- Flood SignalR with connections to test circuit/connection limits
- Test HTTP/2 frame handling for amplification attacks

---

## Attack Surface Map

```
User Input
│
├─► Kestrel (HTTP parsing, TLS, HTTP/2 frames)
│   ├─► Middleware pipeline (auth, CORS, rate limiting, routing)
│   │   ├─► MVC / Razor Pages (model binding, validation, view rendering)
│   │   ├─► Blazor Server (circuits, SignalR, component rendering)
│   │   ├─► Minimal APIs (parameter binding, filters)
│   │   └─► gRPC (protobuf deserialization, interceptors)
│   └─► Static files middleware (path traversal, MIME sniffing)
│
├─► ASP.NET Core Identity (login, registration, token generation)
│   ├─► Cookie auth (encryption, sliding expiration)
│   ├─► JWT Bearer (validation, claim mapping)
│   └─► External auth (OAuth state parameter, callback handling)
│
├─► Data layer
│   ├─► EF Core (SQL injection via raw queries, interpolation bugs)
│   ├─► System.Text.Json (deserialization, polymorphism, converters)
│   └─► Data Protection API (key management, encryption)
│
├─► Aspire (orchestration, service discovery, dashboard)
│   ├─► Container management (env var injection, port binding)
│   └─► Dashboard (auth bypass, XSS in telemetry data)
│
└─► GitHub Actions (in dotnet repos)
    ├─► Workflow injection (expression injection in PR titles/labels)
    └─► Artifact poisoning (supply chain via build outputs)
```

---

## Methodology Steps

### Phase 1: Recon
1. Clone `dotnet/runtime`, `dotnet/aspnetcore`, `dotnet/aspire` from GitHub
2. Identify recent commits touching security-sensitive code (auth, crypto, parsing)
3. Review open/closed security advisories for patterns (https://github.com/dotnet/announcements)
4. Map the dependency tree — which NuGet packages ship in-box vs third-party

### Phase 2: Static Analysis
1. Search for dangerous patterns: `Process.Start`, `Assembly.Load`, `Type.GetType`, `BinaryFormatter`, `Deserialize`, `FromSqlRaw`, `DangerousAddRef`
2. Audit input validation in model binding and parameter binding
3. Review middleware ordering assumptions in templates
4. Trace user-controlled data from HTTP request to sensitive sinks

### Phase 3: Dynamic Testing
1. Set up a fresh .NET 9+ project using default templates
2. Fuzz Kestrel with malformed HTTP requests (HTTP request smuggling)
3. Test JSON deserialization with polymorphic type payloads
4. Attempt auth bypass via middleware ordering manipulation
5. Stress-test SignalR and Blazor for resource exhaustion

### Phase 4: Exploit Development
1. Build a reliable, minimal PoC on a **fresh install** (this is what MSRC grades)
2. Document exact versions, OS, and configuration
3. Calculate real-world impact and blast radius
4. Write step-by-step reproduction — assume the reader has never seen the codebase

### Phase 5: Report
1. Submit via MSRC Researcher Portal
2. Follow the format in `dotnet-bounty-scope.md`
3. Do NOT disclose publicly — CVD is mandatory

---

## Tools

| Tool | Purpose |
|---|---|
| `dotnet-trace` / `dotnet-dump` | Runtime diagnostics, crash analysis |
| `SharpFuzz` | Coverage-guided fuzzing for .NET |
| `Burp Suite` / `mitmproxy` | HTTP interception, request tampering |
| `ILSpy` / `dnSpy` | Decompile .NET assemblies for source review |
| `Semgrep` | Custom rules for .NET security patterns |
| `CodeQL` | GitHub's static analysis, has .NET queries |
| `AFL.NET` / `libFuzzer` | Fuzzing native components of .NET runtime |
| `nuclei` | Template-based scanning for known patterns |
