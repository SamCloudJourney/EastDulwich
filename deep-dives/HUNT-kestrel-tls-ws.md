# HUNT: Kestrel TLS, WebSocket, and Connection Management

## Scope

Systematic review of ASP.NET Core Kestrel server implementation for MSRC-eligible
vulnerabilities (Critical/Important severity, must cross a security boundary) across
five focus areas:

1. TLS implementation (cert validation, renegotiation, SNI, ALPN)
2. WebSocket security (upgrade validation, origin checking/CSWSH, frame handling)
3. Connection management / resource exhaustion (connection limits bypass, slowloris, state leaks)
4. gRPC-specific issues (protobuf deserialization, metadata injection, gRPC-Web translation)
5. HTTP/3 QUIC vulnerabilities (QPACK compression, 0-RTT replay, connection migration)

Repository: `/home/user/dotnet-hunt/aspnetcore/`

---

## Area 1: TLS Implementation

### Files Examined

- `src/Servers/Kestrel/Core/src/Middleware/HttpsConnectionMiddleware.cs`
- `src/Servers/Kestrel/Core/src/Internal/TlsConnectionFeature.cs`
- `src/Servers/Kestrel/Core/src/Internal/SniOptionsSelector.cs`
- `src/Servers/Kestrel/Core/src/Middleware/TlsListener.cs`

### Findings

**Certificate Validation** -- No vulnerability found.

`RemoteCertificateValidationCallback` (HttpsConnectionMiddleware.cs, lines 406-441):
- When no custom validator is configured, rejects certificates with any policy errors
- In `RequireCertificate` mode, returns false for null certificates
- Delegates to .NET's `SslStream` for the actual TLS handshake, which is well-audited

**Renegotiation** -- No vulnerability found.

`ConfigureAlpn` (HttpsConnectionMiddleware.cs, lines 388-404):
- Correctly disables renegotiation when HTTP/2 is enabled: `serverOptions.AllowRenegotiation = false`
- This prevents the well-known HTTP/2 + TLS renegotiation attack
- Delayed client certificate negotiation is explicitly blocked on HTTP/2 (`TlsConnectionFeature.cs`, line 150)

**SNI Routing** -- No vulnerability found.

`SniOptionsSelector.cs`:
- `IsValidSniServerName` rejects trailing dots and non-DNS hostnames via `Uri.CheckHostName`
- Wildcard matching: exact match -> wildcard prefix (longest first) -> wildcard "*"
- `CloneSslOptions` copies all 13 SSL properties including `AllowTlsResume`
- Server auth certificate EKU is properly validated

**TLS Client Hello Sniffing** -- No vulnerability found.

`TlsListener.cs`:
- `recordLength` is read as signed `short` via `TryReadBigEndian`, then capped:
  `(short)Math.Min((ushort)recordLength, MaxTlsPlaintextFragmentLength)`
- The cast to `ushort` before `Math.Min` correctly handles negative signed values by
  interpreting them as large unsigned values, which then get capped to 16384
- Protocol version validation covers 0x0300-0x0304 (SSL 3.0 through TLS 1.3)
- Buffer is properly restored via `AdvanceTo(buffer.Start)` after parsing

**`OnAuthenticate` Callback** -- No vulnerability found.

The `OnAuthenticate` callback is invoked AFTER SSL options are configured but BEFORE
the handshake. This is a documented extensibility point. A malicious callback could
weaken TLS settings, but this is by design -- the callback is app-level code running
in-process.

**HTTP/2 TLS Requirements** -- No vulnerability found.

`ValidateTlsRequirements` enforces TLS 1.2 minimum for HTTP/2 connections
(Http2Connection.cs, lines 515-518).

### Assessment

TLS implementation is sound. All security-relevant operations delegate to .NET's
`SslStream`, and Kestrel correctly configures it. No MSRC-eligible issues.

---

## Area 2: WebSocket Security

### Files Examined

- `src/Middleware/WebSockets/src/WebSocketMiddleware.cs`
- `src/Middleware/WebSockets/src/HandshakeHelpers.cs`
- `src/Middleware/WebSockets/src/WebSocketOptions.cs`

### Findings

**FINDING W-1: Origin Check Case-Sensitivity Mismatch (NOT MSRC-eligible)**

`WebSocketMiddleware.cs`:
- Line 42: `_allowedOrigins = _options.AllowedOrigins.Select(o => o.ToLowerInvariant()).ToList();`
  (stored lowercase)
- Line 73: `if (!_allowedOrigins.Contains(originHeader.ToString(), StringComparer.Ordinal))`
  (compared case-sensitively against raw header value)

This means if a developer configures `AllowedOrigins = ["https://example.com"]`, it gets
stored as `"https://example.com"`. A request with `Origin: https://Example.com` would be
**rejected** because the ordinal comparison fails against the lowercased stored value.

This is **over-restrictive** (false rejection), not a bypass. A legitimate mixed-case
origin gets blocked. An attacker's origin is also blocked. Not MSRC-eligible because
it does not cross a security boundary in the attacker's favor.

**FINDING W-2: Missing Origin Header Allows Bypass (NOT MSRC-eligible)**

`WebSocketMiddleware.cs`, line 70:
```csharp
if (!StringValues.IsNullOrEmpty(originHeader) && webSocketFeature.IsWebSocketRequest)
```

When no `Origin` header is present, the origin check is skipped entirely. This means
a WebSocket handshake without an Origin header bypasses origin validation.

However, this is **not exploitable from browsers** because:
- Browsers always send the `Origin` header on cross-origin WebSocket upgrade requests
- The `Origin` header was specifically designed for this purpose (RFC 6454)
- Only non-browser clients (curl, custom tools) can omit Origin, but they could also
  forge it, so server-side origin checking is defense-in-depth, not a security boundary

Not MSRC-eligible because the Origin header is a browser-enforced mechanism and
server-side validation is supplementary.

**FINDING W-3: Default Configuration Allows All Origins (NOT MSRC-eligible)**

`WebSocketOptions.cs`:
- Default: `AllowedOrigins = new List<string>()` (empty list)
- `WebSocketMiddleware.cs`: `_anyOriginAllowed = _options.AllowedOrigins.Count == 0 || _options.AllowedOrigins.Contains("*")`

Out of the box, Kestrel accepts WebSocket connections from any origin. This is by
design for backward compatibility and local development, but means apps that don't
explicitly configure origins are vulnerable to CSWSH. This is a developer
responsibility, not a framework vulnerability.

**WebSocket Handshake Validation** -- No vulnerability found.

`HandshakeHelpers.cs`:
- `IsRequestKeyValid`: Validates base64 key decodes to exactly 16 bytes
- `CreateResponseKey`: Standard RFC 6455 SHA-1 response key generation
- `ParseDeflateOptions`: Per-message deflate negotiation with duplicate parameter rejection
- `CheckSupportedWebSocketRequest`: Validates GET method, `Upgrade: websocket`,
  `Connection: Upgrade`, `Sec-WebSocket-Version`, `Sec-WebSocket-Key`

All RFC 6455 requirements are correctly enforced.

### Assessment

WebSocket implementation follows RFC 6455 correctly. The origin-checking issues found
are either over-restrictive (W-1), not exploitable from browsers (W-2), or by-design
defaults (W-3). No MSRC-eligible vulnerabilities.

---

## Area 3: Connection Management / Resource Exhaustion

### Files Examined

- `src/Servers/Kestrel/Core/src/Middleware/ConnectionLimitMiddleware.cs`
- `src/Servers/Kestrel/Core/src/Internal/Infrastructure/ResourceCounter.cs`
- `src/Servers/Kestrel/Core/src/Internal/Infrastructure/ConnectionManager.cs`
- `src/Servers/Kestrel/Core/src/Internal/Infrastructure/TransportConnectionManager.cs`
- `src/Servers/Kestrel/Core/src/Internal/Infrastructure/KestrelConnection.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http/Http1MessageBody.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http/Http1Connection.cs`

### Findings

**Connection Limit Enforcement** -- No vulnerability found.

`ResourceCounter.FiniteCounter.TryLockOne()`:
- Lock-free via `Interlocked.CompareExchange` with retry loop
- Overflow protection: checks `count != long.MaxValue`
- `ReleaseOne()` uses `Interlocked.Decrement` with Debug.Assert for negative count
- `ConnectionLimitMiddleware` releases in a `finally` block, preventing resource leaks

**Connection Tracking** -- No vulnerability found.

`ConnectionManager.cs`:
- Heartbeat-based connection monitoring via `IHeartbeatHandler`
- Weak references for connection tracking with auto-cleanup of unrooted connections
- `UpgradedConnectionCount` tracks upgraded (WebSocket) connections separately

`TransportConnectionManager.cs`:
- Dual dictionary tracking (transport-level + global)
- `AbortAllConnectionsAsync`: 1-second timeout for forced abort
- `CloseAllConnectionsAsync` uses cancellation token for graceful shutdown

**HTTP/2 DoS Protection (ENHANCE_YOUR_CALM)** -- No vulnerability found.

`Http2Connection.cs`:
- Default limit: 20 invalid frames per 5-tick window
- Exceeding 100 total (5 * 20) triggers connection abort with ENHANCE_YOUR_CALM
- `MaxTrackedStreams = max(MaxConcurrentStreams * 2, 100)` caps dictionary growth
- Stream pool: max 100 streams, 5-second expiry for reuse

**HTTP/2 PING ACK Not Verified** -- Not MSRC-eligible.

`Http2Connection.cs`, line 1104:
```csharp
// TODO: verify that payload is equal to the outgoing PING frame
```

PING ACK payloads are not verified against the original PING. Per RFC 9113 section
6.7, the receiver SHOULD verify the payload matches. However, not verifying it has no
security impact -- PING/PING ACK is used for keep-alive and RTT estimation, not for
any security-critical function.

**CL+TE Request Smuggling Prevention** -- No vulnerability found.

`Http1MessageBody.cs`:
- When both Content-Length and Transfer-Encoding are present, Transfer-Encoding wins
  (correct per RFC 9112)
- Content-Length is moved to `X-Content-Length` header
- `ContinueProcessingAfterCLTE` switch (default false): connection is closed after
  processing a CL+TE request, preventing desync with downstream servers
- Non-chunked final Transfer-Encoding is rejected with 400

This is textbook correct CL+TE handling.

**Bare LF Tracking** -- No vulnerability found.

`Http1Connection.cs` tracks bare LF line terminators (non-CRLF). This is for
compatibility logging, not a security issue.

### Assessment

Connection management is well-implemented with proper resource accounting, lock-free
concurrency, and heartbeat monitoring. HTTP/2 has explicit DoS protection
(ENHANCE_YOUR_CALM). CL+TE request smuggling is properly prevented. No MSRC-eligible
issues.

---

## Area 4: gRPC-Specific Issues

### Files Examined

- `src/Grpc/JsonTranscoding/src/Microsoft.AspNetCore.Grpc.JsonTranscoding/Internal/JsonRequestHelpers.cs`
- Searched for gRPC metadata injection, deserialization, and security patterns

### Findings

**gRPC JSON Transcoding** -- No vulnerability found.

`JsonRequestHelpers.cs`:
- Content type validation for JSON requests
- Encoding handling with transcoding streams
- gRPC status code to HTTP status mapping
- The transcoding layer translates HTTP/JSON to gRPC protocol; security relies on
  the underlying HTTP/2 transport and ASP.NET Core middleware pipeline

**gRPC Metadata** -- No vulnerability found specific to Kestrel.

gRPC metadata is carried as HTTP/2 headers, subject to the same HPACK decoding limits
and header count/size restrictions as regular HTTP/2 traffic. No separate metadata
injection vector exists at the Kestrel level.

**Protobuf Deserialization** -- Out of scope for Kestrel.

Protobuf deserialization happens in the Grpc.Net library and Google.Protobuf, not in
Kestrel. Kestrel only transports the bytes.

### Assessment

gRPC security at the Kestrel level relies on HTTP/2 transport security, which is
properly implemented. JSON transcoding adds a translation layer but does not introduce
new security boundaries. No MSRC-eligible issues.

---

## Area 5: HTTP/3 QUIC Vulnerabilities

### Files Examined

- `src/Servers/Kestrel/Core/src/Internal/Http3/Http3Connection.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http3/Http3ControlStream.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http3/Http3FrameReader.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http3/Http3Stream.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http3/QPack/DynamicTable.cs`
- `src/Servers/Kestrel/Core/src/Internal/Http3/QPack/EncoderStreamReader.cs`

### Findings

**QPACK Dynamic Table -- Stub Implementation** -- No vulnerability found.

`QPack/DynamicTable.cs`:
- `Insert` and `Resize` are static no-ops (empty methods)
- `Duplicate` throws `NotImplementedException`
- This means QPACK dynamic table entries are silently dropped, not processed
- Encoder/decoder streams are consumed but data is discarded
  (`HandleEncodingDecodingTask` copies to `Stream.Null`)

This is functionally safe -- by not implementing the dynamic table, Kestrel avoids
QPACK compression bomb attacks entirely. Headers are decoded using only the static
table, which has fixed size.

**QPACK Encoder Stream Parsing** -- No vulnerability found.

`EncoderStreamReader.cs`:
- Full QPACK encoder stream state machine parser
- Length validation against `_stringOctets.Length` (line 244-247)
- All parsed data goes into the stub `DynamicTable.Insert`, which is a no-op
- No buffer over-read or integer overflow issues identified

**0-RTT Replay Protection** -- Not applicable at Kestrel level.

`Http3Connection.cs`:
- No explicit 0-RTT replay protection at the Kestrel layer
- This is by design: 0-RTT is a QUIC transport concern, handled by `System.Net.Quic`
  and the underlying MsQuic library
- Kestrel processes HTTP/3 requests regardless of whether they arrived in 0-RTT or
  1-RTT data; application-level idempotency is the developer's responsibility

**HTTP/3 Control Stream Validation** -- No vulnerability found.

`Http3ControlStream.cs`:
- `MaxFrameSize = 10_000` for control stream frames (reasonable limit)
- Reserved HTTP/2 setting IDs (0x0-0x5) properly rejected with H3_SETTINGS_ERROR
- Settings frame ordering enforced (must be first on control stream)
- Unknown frame types ignored per HTTP/3 spec
- Only one control stream of each type allowed per connection

**HTTP/3 Stream Management** -- No vulnerability found.

`Http3Connection.cs`:
- Stream timeout enforcement for unidentified streams and header reception
- GOAWAY handling with highest opened request stream ID tracking
- WebTransport session management with proper lifecycle tracking

`Http3Stream.cs`:
- Header count limit: `_eagerRequestHeadersParsedLimit = ServerOptions.Limits.MaxRequestHeaderCount * 2`
  (2x during parsing phase, then validated down to the configured limit)
- QPackDecoder initialized with `MaxRequestHeaderFieldSize`
- Abort mechanism with completion lock prevents race conditions on stream reuse

### Assessment

HTTP/3 implementation is conservative -- the QPACK dynamic table is stubbed out,
eliminating compression bomb risks. Control stream and frame validation follow the
HTTP/3 spec. 0-RTT replay is properly delegated to the QUIC transport layer. No
MSRC-eligible issues.

---

## Cross-Cutting: HTTP/1.1 Request Smuggling

### Findings

**CL+TE Desync** -- Properly mitigated.

The `Http1MessageBody.cs` implementation:
1. When both headers present, Transfer-Encoding takes precedence (RFC 9112)
2. Content-Length is preserved as `X-Content-Length` for application awareness
3. Default behavior (`ContinueProcessingAfterCLTE = false`) closes the connection
   after the request, preventing desync with reverse proxies
4. Non-chunked final Transfer-Encoding rejected with 400

This is the strongest possible defense against CL+TE smuggling.

---

## Summary

| Area | Finding | MSRC-Eligible? | Severity |
|------|---------|----------------|----------|
| TLS | All operations delegate to SslStream; renegotiation properly disabled for HTTP/2 | No | N/A |
| WebSocket | Origin case-sensitivity mismatch (W-1) | No | Low (over-restrictive) |
| WebSocket | Missing Origin header skips check (W-2) | No | Low (browser-enforced) |
| WebSocket | Default allows all origins (W-3) | No | N/A (by design) |
| Connection Mgmt | Lock-free ResourceCounter is correct | No | N/A |
| HTTP/2 | PING ACK not verified (TODO) | No | Informational |
| HTTP/2 | ENHANCE_YOUR_CALM DoS protection present | No | N/A |
| HTTP/1 | CL+TE properly handled with connection close | No | N/A |
| gRPC | Security relies on HTTP/2 transport | No | N/A |
| HTTP/3 QPACK | Dynamic table is stub (no-op) | No | N/A |
| HTTP/3 | No 0-RTT handling (delegated to QUIC) | No | N/A |

**No MSRC-eligible vulnerabilities identified.** The Kestrel server implementation
demonstrates mature security engineering across all five focus areas. Key defenses:

1. TLS security is delegated to .NET's well-audited SslStream
2. HTTP/2 has explicit DoS protection via ENHANCE_YOUR_CALM
3. CL+TE request smuggling is properly mitigated with connection closure
4. QPACK dynamic table is intentionally stubbed, eliminating compression attacks
5. Connection limits use correct lock-free concurrency with overflow protection
6. WebSocket origin checking follows browser security model conventions
