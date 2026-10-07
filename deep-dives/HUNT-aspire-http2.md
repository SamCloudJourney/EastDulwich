# HUNT: Aspire Container/Dashboard + Kestrel HTTP/2 & HTTP/3

## Scope

- **Aspire**: Container command injection (`src/Aspire.Hosting/Dcp/`), service discovery poisoning, dashboard XSS (telemetry display, OTLP injection), gRPC authentication
- **Kestrel HTTP/2**: HPACK bomb, CONTINUATION flood, SETTINGS flood, rapid reset, header size limits
- **Kestrel HTTP/3**: QPACK decoding, stream management, PeerSettings defaults

Repositories:
- `/home/user/dotnet-hunt/aspire/`
- `/home/user/dotnet-hunt/aspnetcore/`

---

## Findings Summary

| # | Area | Finding | Severity | MSRC-Eligible? |
|---|------|---------|----------|----------------|
| 1 | Aspire Container | Shell execution command injection via argument concatenation | Medium | Unlikely -- developer opt-in experimental API |
| 2 | Aspire Dashboard | XSS pipeline analyzed -- properly encoded | N/A | No |
| 3 | Aspire OTLP | Unsecured auth mode allows unauthenticated telemetry injection | Low | No -- documented and warned |
| 4 | Kestrel HTTP/2 | SETTINGS frame flood -- no rate limit, 1:1 ACK amplification | Low-Med | Unlikely -- bounded by connection resources |
| 5 | Kestrel HTTP/2 | CONTINUATION frame count -- no per-stream limit | Low | No -- timeout provides protection |
| 6 | Kestrel HTTP/2 | Header size 2x grace in OnHeaderCore | Info | No -- deliberate design |
| 7 | Kestrel HTTP/3 | PeerSettings advertises uint.MaxValue header size to client | Info | No -- Kestrel enforces 32 KiB internally |

**Bottom line: No Critical/Important MSRC-eligible vulnerabilities found.** The shell execution finding is the most interesting but requires developer opt-in to an experimental API. The HTTP/2 SETTINGS flood lacks sufficient amplification for a practical DoS. All dashboard XSS surfaces are properly sanitized.

---

## Detailed Analysis

### 1. Aspire Container Shell Execution (Command Injection Surface)

**File**: `aspire/src/Aspire.Hosting/Dcp/ContainerCreator.cs` lines 241-248

```csharp
#pragma warning disable ASPIRECONTAINERSHELLEXECUTION001
if (modelContainer is ContainerResource { ShellExecution: true })
{
    spec.Args = ["-c", $"{string.Join(' ', args.Select(a => a.Value))}"];
}
```

When `ShellExecution` is `true`, all container arguments are concatenated with spaces and passed as a single string to `-c` (shell execution). This is a classic command injection pattern -- if any argument value contains shell metacharacters (`;`, `|`, `$()`, backticks), they will be interpreted by the shell.

**Argument source tracing**:
- `configuration.Arguments` comes from `ExecutionConfigurationBuilder` via `ArgumentsExecutionConfigurationGatherer`
- Arguments are populated from `CommandLineArgsCallbackAnnotation` callbacks registered via `WithArgs()` API
- Values can be `IValueProvider` instances (connection strings, parameters, endpoint references)
- Container runtime args come from `ContainerRuntimeArgsCallbackAnnotation` via `ProcessContainerRuntimeArgValues`

**Attack scenario**: If any argument value is sourced from an external dependency (e.g., a connection string from a compromised service, a parameter from environment/config), and that dependency injects shell metacharacters, the concatenation into `-c "..."` enables command execution within the container runtime context.

**Mitigating factors**:
- `ShellExecution` is marked `[Experimental("ASPIRECONTAINERSHELLEXECUTION001")]` -- requires explicit developer opt-in and suppressing an analyzer warning
- Arguments are typically developer-defined, not external user input
- The API is documented as experimental with security implications
- The `#pragma warning disable` at the call site shows awareness of the risk

**Verdict**: Design-level concern in an experimental API. Not MSRC-eligible because it requires developer opt-in. The correct fix would be proper shell escaping of individual arguments before concatenation, but the experimental status makes this a known accepted risk.

### 2. Aspire Dashboard XSS Pipeline (Thoroughly Analyzed -- Safe)

Traced the complete data flow for log content rendered as `MarkupString`:

**Render site**: `LogViewer.razor` line 101:
```razor
@((MarkupString)(context.Content ?? string.Empty))
```

**Encoding pipeline** (when `encodeForHtml: true`, which is the dashboard display path):
1. `LogParser.CreateLogEntry()` receives raw log text
2. Non-match fragments go through `WebUtility.HtmlEncode` callback
3. `AnsiParser.ConvertToHtml()` wraps content in `<span>` tags with CSS classes -- text was already HTML-encoded by step 2
4. `UrlParser.TryParse()` creates `<a>` tags -- URL in `href` is not HTML-encoded but regex `[-\w\p{L}.:%+~#*$!?&/=@]` excludes `"`, `<`, `>` preventing attribute breakout; only `https?://` scheme is matched (no `javascript:`)

**Other MarkupString sites checked**:
- `GridValue.razor` line 40: Uses `UrlParser.TryParse` with `WebUtility.HtmlEncode` callback, falls back to `WebUtility.HtmlEncode`
- `TextVisualizer.razor.cs` line 110-118: Same pattern with HtmlEncode
- `DashboardMessageBar.razor`: Content from `InteractionsProvider.GetMessageHtml` which uses `MarkdownProcessor` with `DisableHtml()` or `WebUtility.HtmlEncode`
- Interaction dialog components: All go through `GetMessageHtml` sanitization

**ConsoleLogsFetcher** (`Model/ConsoleLogsFetcher.cs` line 35) creates `LogParser` WITHOUT `encodeForHtml` -- but this is used only for log export/download, not display rendering.

**Verdict**: No XSS vulnerability found. The encoding pipeline is consistent and correct. HTML encoding happens before ANSI-to-HTML conversion, preventing injection through log content.

### 3. Aspire OTLP Authentication

**File**: `aspire/src/Aspire.Dashboard/Authentication/OtlpCompositeAuthenticationHandler.cs`

The OTLP endpoints support four auth modes: `Unsecured`, `ApiKey`, `ClientCertificate`, `OpenIdConnect`.

In `Unsecured` mode (`OtlpAuthMode.cs` line 16), only `ConnectionTypeAuthenticationHandler` is checked, which verifies the connection arrived on the OTLP port (not the frontend port). Any client that can reach the OTLP port can inject arbitrary telemetry data (traces, logs, metrics).

**Impact of telemetry injection**:
- Injected log entries would be rendered through the XSS-safe pipeline (Finding #2)
- Injected span attributes are displayed through `GridValue` (HTML-encoded)
- Markdown content goes through `MarkdownProcessor.DisableHtml()`
- No code execution path found from injected telemetry

**Mitigating factors**:
- Dashboard logs a warning when running in Unsecured mode
- UI displays a warning banner (`SuppressUnsecuredMessage` can hide it)
- Documentation explicitly covers security considerations
- In local development, OTLP port is typically only reachable from localhost

**Verdict**: Not a vulnerability -- documented behavior with appropriate warnings.

### 4. Kestrel HTTP/2 SETTINGS Frame Flood

**File**: `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs` lines 995-1067

Each non-ACK SETTINGS frame triggers:
1. Parsing the settings payload
2. Updating client settings (`_clientSettings.Update()`)
3. Sending a SETTINGS ACK frame (`_frameWriter.WriteSettingsAckAsync()`)
4. Potentially iterating over all active streams to update window sizes

```csharp
_clientSettings.Update(Http2FrameReader.ReadSettings(payload));
var ackTask = _frameWriter.WriteSettingsAckAsync();  // Always sends ACK
```

There is **no rate limit** on SETTINGS frames. A malicious client can send a high volume of SETTINGS frames, each consuming server CPU and memory for parsing, ACK generation, and potentially stream iteration.

**Comparison to CVE-2019-9515** (SETTINGS Flood): This is the exact same pattern that was assigned a CVE in other HTTP/2 implementations. However:
- Amplification is 1:1 (one ACK per SETTINGS frame)
- The processing cost per frame is bounded
- Connection-level resource limits (memory, CPU for one connection) constrain the impact
- The EnhanceYourCalm mechanism does NOT apply to SETTINGS frames (only to rapid stream creation)
- Request headers timeout does not apply to SETTINGS frames outside header parsing

**Verdict**: Theoretical DoS surface but the amplification factor is too low for a practical attack. Not MSRC-eligible as a standalone finding because a single connection's resource consumption is bounded. Would need to be combined with connection multiplication to be significant.

### 5. Kestrel HTTP/2 CONTINUATION Frame Count

**File**: `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs` lines 1200-1231

CONTINUATION frames are processed without any count limit per stream. The only protection is the `RequestHeadersTimeout`:

```csharp
// Set at HEADERS frame start:
TimeoutControl.SetTimeout(Limits.RequestHeadersTimeout, TimeoutReason.RequestHeaders);

// In ProcessContinuationFrameAsync - no count check, just decode:
return DecodeHeadersAsync(_incomingFrame.ContinuationEndHeaders, payload);
```

**Comparison to CVE-2024-27316** (CONTINUATION Flood): Kestrel's implementation is partially protected:
- `RequestHeadersTimeout` bounds the total time for header reception
- `_totalParsedHeaderSize` check (with 2x grace) bounds total header data
- HPACK decoding per frame is bounded by `MaxRequestHeaderFieldSize` (32 KiB default)

Within the timeout window, an attacker can send many tiny CONTINUATION frames (e.g., 1 byte each) to maximize per-frame overhead. Each frame triggers `ProcessContinuationFrameAsync` -> `DecodeHeadersAsync` -> `_hpackDecoder.Decode()`. The overhead is primarily in frame dispatch, not HPACK decoding (since empty/tiny payloads decode quickly).

**Verdict**: The timeout provides adequate protection. The per-frame overhead is small, and the attack window is bounded. Not MSRC-eligible.

### 6. Kestrel HTTP/2 Header Size 2x Grace

**File**: `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs` lines 1610-1618

```csharp
_totalParsedHeaderSize += name.Length + value.Length;
// Allow a 2x grace before aborting the connection.
if (_totalParsedHeaderSize > _context.ServiceContext.ServerOptions.Limits.MaxRequestHeadersTotalSize * 2)
{
    throw new Http2ConnectionErrorException(...);
}
```

The comment explains this is deliberate: the connection-level check allows 2x the configured `MaxRequestHeadersTotalSize` (default 32 KiB, so 64 KiB effective). The actual limit is enforced later at the stream level where a 431 (Request Header Fields Too Large) can be sent. The 32-byte-per-header overhead specified by RFC 7540 Section 6.5.2 is intentionally not counted, accepting "a little more than the advertised limit."

**Verdict**: Deliberate design choice documented in code comments. The 2x multiplier prevents unnecessary connection aborts for streams that slightly exceed the per-stream limit. Not a vulnerability.

### 7. Kestrel HTTP/3 PeerSettings DefaultMaxRequestHeaderFieldSize

**File**: `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http3/Http3PeerSettings.cs` line 10

```csharp
public const uint DefaultMaxRequestHeaderFieldSize = uint.MaxValue;
```

This `uint.MaxValue` (4 GiB) is the protocol-level default advertised to the client via SETTINGS_MAX_FIELD_SECTION_SIZE. The comment says "Note these are protocol defaults, not Kestrel defaults."

**Actual enforcement**: The QPackDecoder is initialized with Kestrel's limits:
```csharp
// Http3Stream.cs line 151:
QPackDecoder = new QPackDecoder(_context.ServiceContext.ServerOptions.Limits.Http3.MaxRequestHeaderFieldSize);
```

Where `Http3Limits.MaxRequestHeaderFieldSize` defaults to `32 * 1024` (32 KiB). So:
- Client sees SETTINGS saying "I accept up to 4 GiB of headers"
- Server actually enforces 32 KiB per header field

The `MaxRequestHeaderFieldSectionSize` is only sent to the client if it differs from the default (line 31):
```csharp
if (MaxRequestHeaderFieldSectionSize != DefaultMaxRequestHeaderFieldSize)
{
    list.Add(new Http3PeerSetting(Http3SettingType.MaxFieldSectionSize, MaxRequestHeaderFieldSectionSize));
}
```

Since the default IS `uint.MaxValue`, the setting is NOT sent, and per RFC 9114 Section 4.2.2, "if this value is absent, clients can assume the server imposes no limit." This is correct behavior -- Kestrel enforces its own stricter limit internally.

**Verdict**: The mismatch between advertised and enforced limits is by design. Clients that send oversized headers get their streams/connections reset. Not a vulnerability.

### 8. HTTP/2 Rapid Reset Protection (EnhanceYourCalm)

**File**: `aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs` lines 69-106, 1342-1362

Protection against CVE-2023-44487 (HTTP/2 Rapid Reset):

```csharp
internal static readonly int EnhanceYourCalmMaximumCount = 20;  // default
internal const int EnhanceYourCalmTickWindowCount = 5;           // 5 ticks (seconds)

// In StartStream:
if (_streams.Count > MaxTrackedStreams || SendEnhanceYourCalmOnStartStream)
{
    if (IsEnhanceYourCalmLimitEnabled && 
        Interlocked.Increment(ref _enhanceYourCalmCount) > 
        EnhanceYourCalmTickWindowCount * EnhanceYourCalmMaximumCount)
    {
        // Abort connection
    }
}
```

- `MaxTrackedStreams = Math.Max(MaxConcurrentStreams * 2, 100)` (default: `100 * 2 = 200`)
- Threshold: `5 * 20 = 100` stream creations while over MaxTrackedStreams before connection abort
- Counter resets every 5 ticks in `Tick()` method
- Configurable via `AppContext.SetData("Microsoft.AspNetCore.Server.Kestrel.Http2.MaxEnhanceYourCalmCount", value)`

This appears to be a solid mitigation for CVE-2023-44487. The limit is configurable, uses a sliding window, and aborts the connection cleanly.

---

## Areas Investigated Without Findings

### Service Discovery Poisoning
The `src/Microsoft.Extensions.ServiceDiscovery/` directory does not exist in this checkout. Service discovery configuration in `Aspire.Hosting` uses endpoint annotations and allocation that are set at development time, not dynamically from external sources.

### Dashboard Markdown Injection
`MarkdownProcessor.cs` line 28: `pipelineBuilder.DisableHtml()` prevents raw HTML injection through Markdig. All interaction messages go through `InteractionsProvider.GetMessageHtml()` which uses either `WebUtility.HtmlEncode` (markdown disabled) or `MarkdownProcessor` (markdown enabled with DisableHtml).

### OTLP gRPC Authentication Bypass
All OTLP gRPC services (`OtlpGrpcLogsService`, `OtlpGrpcTraceService`, `OtlpGrpcMetricsService`) use `[Authorize(Policy = OtlpAuthorization.PolicyName)]`. The policy delegates to `OtlpCompositeAuthenticationHandler`, which correctly enforces the configured auth mode. No bypass found.

### DCP Process Host
`DcpHost.cs` filters environment variables via `s_doNotInheritEnvironmentVars` to prevent certain env vars from being inherited by child processes. No injection path found.

---

## Conclusion

No Critical or Important MSRC-eligible vulnerabilities were identified in this hunt. The codebases demonstrate generally strong security practices:

1. **Aspire Dashboard**: Consistent HTML encoding pipeline with defense-in-depth (encode at source, not just at render)
2. **Kestrel HTTP/2**: Active mitigations for known attack patterns (CVE-2023-44487 rapid reset via EnhanceYourCalm)
3. **Kestrel HTTP/3**: Internal limits enforced regardless of advertised settings

The most notable finding is the shell execution command injection surface in `ContainerCreator.cs`, but this is gated behind an experimental API with analyzer warnings. The HTTP/2 SETTINGS flood lacks rate limiting but the amplification factor is insufficient for a practical DoS from a single connection.
