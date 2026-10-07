# HUNT: Blazor Server Security Analysis
## ASP.NET Core Components (Server-Side Blazor)

**Target:** `/home/user/dotnet-hunt/aspnetcore/src/Components/`
**Focus:** Circuit hijacking, SignalR hub auth bypass, component rendering injection, enhanced navigation/streaming SSR

---

## Executive Summary

After thorough review of the Blazor Server circuit management, ComponentHub, renderer pipeline, streaming SSR, and related subsystems, **no MSRC-eligible vulnerability was identified that crosses a security boundary in a way that is not "by design."**

The circuit secret model is cryptographically sound (64-byte random, data-protected, fixed-time comparison). The areas that initially appeared concerning -- particularly the lack of `[Authorize]` on ComponentHub and the absence of user affinity checks during circuit reconnection -- are intentional design decisions documented in the codebase. Below I detail each investigated area, what was found, and why it does or does not qualify.

---

## Area 1: Circuit Hijacking / Cross-User State Leakage

### What Was Investigated

- **CircuitIdFactory** (`Circuits/CircuitIdFactory.cs`): Generates 64-byte cryptographic random circuit IDs, data-protected with purpose string `"Microsoft.AspNetCore.Components.Server.CircuitIdFactory,V1"`.
- **CircuitId** (`Circuits/CircuitId.cs`): Uses `CryptographicOperations.FixedTimeEquals` for comparison, preventing timing side-channels.
- **CircuitRegistry** (`Circuits/CircuitRegistry.cs`): `ConnectCore()` (line 231) looks up circuits by `circuitId.Secret` in both `ConnectedCircuits` and `DisconnectedCircuits` (a `MemoryCache`). No user identity check is performed during reconnection.
- **CircuitHost** (`Circuits/CircuitHost.cs`): `SetCircuitUser()` (line 630) replaces the circuit's `AuthenticationState` with the reconnecting user's `ClaimsPrincipal`.
- **ComponentHub** (`ComponentHub.cs`): `ConnectCircuit()` (line 240) validates only the circuit secret, then calls `circuitHost.SetCircuitUser(Context.User)`, replacing the auth identity.
- **CircuitPersistenceManager** (`Circuits/CircuitPersistenceManager.cs`): Persisted circuit state is keyed solely by `circuitId.Secret`. No user binding on cache entries.
- **HybridCacheCircuitPersistenceProvider** and **DefaultInMemoryCircuitPersistenceProvider**: Both key persisted state by `circuitId.Secret` alone.

### Observation: No User Affinity Check on Reconnection

When a client calls `ConnectCircuit(circuitIdSecret)`:
1. The secret is validated via `CircuitIdFactory.TryParseCircuitId` (data-protection unprotect)
2. The circuit is looked up by its secret
3. `SetCircuitUser(Context.User)` replaces the circuit's auth state with whoever reconnects

There is no comparison between the original circuit owner and the reconnecting user.

### Why This Is NOT MSRC-Eligible

The circuit secret is the **sole authentication factor** by design. It is:
- 64 bytes of `RandomNumberGenerator` output (512 bits of entropy)
- Data-protected before transmission
- Compared using fixed-time equality

An attacker would need to obtain the circuit secret to hijack a circuit. The only way to obtain it is:
- Network interception (requires MitM, mitigated by TLS)
- Client-side compromise (e.g., XSS, but XSS is a separate vulnerability class)
- Server-side data breach

The design is analogous to session cookies: possession of the token equals possession of the session. This is the documented security model. The `SetCircuitUser` replacement on reconnect is intentional -- it allows cookie-auth refresh scenarios (SignalR WebSocket connections outlast cookie expiration, so re-authentication on reconnect is the correct behavior). This is reinforced by:
- `OnAuthenticationRefreshedAsync()` (line 98) which explicitly calls `SetCircuitUser(Context.User)` when auth state refreshes
- `EnableAuthenticationRefresh = true` being set when mapping the hub

**Verdict:** By design. No security boundary crossed.

### Sub-observation: CircuitDisconnectMiddleware Has No Authentication

**File:** `CircuitDisconnectMiddleware.cs`

The `/_blazor/disconnect/` endpoint accepts POST requests with a `circuitId` form field and calls `Registry.TerminateAsync(circuitId)`. There is no authentication check on this endpoint.

However, the `circuitId` parameter is the **data-protected** circuit secret. An attacker cannot terminate a circuit without knowing its secret (which requires the same 512-bit entropy guess). The endpoint is used by the browser's `navigator.sendBeacon()` on page unload, where cookie-based auth may not be available.

**Verdict:** By design. The data-protected secret serves as the authorization token. DoS via brute force is computationally infeasible.

---

## Area 2: SignalR Hub Authorization Bypass

### What Was Investigated

- **ComponentHub** (`ComponentHub.cs`): `internal sealed partial class ComponentHub : Hub` -- NO `[Authorize]` attribute.
- **Hub Mapping** (`Builder/ComponentEndpointRouteBuilderExtensions.cs`): The hub is mapped without `.RequireAuthorization()`:
  ```csharp
  endpoints.MapHub<ComponentHub>(path, options => {
      options.EnableAuthenticationRefresh = true;
  });
  ```
- All hub methods: `StartCircuit`, `ConnectCircuit`, `ResumeCircuit`, `PauseCircuit`, `UpdateRootComponents`, `BeginInvokeDotNetFromJS`, `EndInvokeJSFromDotNet`, `ReceiveByteArray`, `ReceiveJSDataChunk`, `SendDotNetStreamToJS`, `OnRenderCompleted`, `OnLocationChanged`, `OnLocationChanging`.

### Observation: ComponentHub Is Open to Unauthenticated Callers

Any client can establish a SignalR connection to `/_blazor` and call any hub method without authentication.

### Why This Is NOT MSRC-Eligible

This is intentional. Blazor Server apps can be configured to allow anonymous access (e.g., a public-facing Blazor app). Authorization is enforced at the **component level** through:
- `<AuthorizeRouteView>` in the router
- `[Authorize]` attribute on page components
- `<AuthorizeView>` for conditional rendering

If an app developer wants hub-level auth, they add `[Authorize]` to their routing or use `RequireAuthorization()` on the endpoint. The framework deliberately does not enforce this at the hub level because it would break legitimate anonymous Blazor Server apps.

The hub methods that operate on circuits (`BeginInvokeDotNetFromJS`, `UpdateRootComponents`, etc.) all call `GetActiveCircuitAsync()` which requires a circuit to be bound to the connection. A circuit can only be bound via `StartCircuit` (which creates a new one with the caller's identity) or `ConnectCircuit` (which requires the circuit secret).

**Verdict:** By design. Authorization is intentionally delegated to the component layer.

---

## Area 3: Component Rendering Injection

### What Was Investigated

- **MarkupString** (`Components/src/MarkupString.cs`): A struct that wraps a string for unencoded HTML output. Explicit opt-in via constructor or cast.
- **RenderTreeBuilder** (`Components/src/Rendering/RenderTreeBuilder.cs`): `AddMarkupContent` writes raw HTML. Used only for compile-time literal markup or explicit `MarkupString`.
- **StaticHtmlRenderer.HtmlWriting** (`Web/src/HtmlRendering/StaticHtmlRenderer.HtmlWriting.cs`):
  - `RenderTreeFrameType.Text` -> `_htmlEncoder.Encode(output, frame.TextContent)` (SAFE)
  - `RenderTreeFrameType.Markup` -> `output.Write(frame.MarkupContent)` (RAW, by design)
  - Attribute values -> `_htmlEncoder.Encode(output, value)` (SAFE)
  - Script children use `_javaScriptEncoder` instead of `_htmlEncoder` (correct context-aware encoding)
  - Hidden form field values -> `_htmlEncoder.Encode(output, combinedFormName)` (SAFE)
- **ServerComponentDeserializer** (`Circuits/ServerComponentDeserializer.cs`): Component descriptors are data-protected. A client cannot forge component types or inject arbitrary components because:
  - Descriptors are data-protected with time-limited protection
  - Sequence numbers must be sequential
  - Invocation IDs must match across all descriptors in a batch
  - Component types are resolved from loaded assemblies only

### Observation: No Framework-Level Injection Vector

The rendering pipeline correctly HTML-encodes all text content. Raw HTML (`MarkupString`) is an explicit opt-in by the developer. The framework does not take user input and render it as raw HTML anywhere in its own code.

The `RootTypeCache` (`Shared/src/RootTypeCache.cs`) resolves component types from assembly/type pairs, but these come from data-protected descriptors that the client cannot forge.

**DotNetDispatcher** (`JSInterop/src/Infrastructure/DotNetDispatcher.cs`): Requires `[JSInvokable]` attribute on methods callable from JavaScript. Only methods explicitly marked can be invoked. Assembly-level static method invocation scans for this attribute. Instance method invocation requires a valid `DotNetObjectReference` (tracked by integer ID within the JSRuntime).

### Why This Is NOT MSRC-Eligible

- No mechanism exists for a client to inject arbitrary HTML into the rendering pipeline
- Component types are resolved from data-protected descriptors, not raw client input
- JS interop is gated behind `[JSInvokable]` attribute
- Text content is always HTML-encoded; raw markup requires explicit `MarkupString` usage by the developer

**Verdict:** No vulnerability. The framework's encoding and protection mechanisms are sound.

---

## Area 4: Enhanced Navigation / Streaming SSR

### What Was Investigated

- **EndpointHtmlRenderer.Streaming** (`Endpoints/src/Rendering/EndpointHtmlRenderer.Streaming.cs`): Streaming SSR uses `ssr-framing` headers. Error messages are HTML-encoded.
- **EndpointHtmlRenderer.Prerendering** (`Endpoints/src/Rendering/EndpointHtmlRenderer.Prerendering.cs`): SSRRenderModeBoundary handles render mode boundaries.
- **OpaqueRedirection** (`Endpoints/src/Builder/OpaqueRedirection.cs`): Redirect URLs during streaming SSR are data-protected with a time-limited protector. The unprotect endpoint validates before redirecting.
- **RazorComponentEndpointInvoker** (`Endpoints/src/RazorComponentEndpointInvoker.cs`): POST requests validate antiforgery tokens via `IAntiforgeryValidationFeature`. Without a valid token, the request is rejected.
- **RemoteNavigationManager** (`Circuits/RemoteNavigationManager.cs`): Client-provided URIs are set on `NavigationManager.Uri` without validation. However, the Router component uses `ToBaseRelativePath` which constrains routing to the app's base URI.

### Observation: Client Can Set Arbitrary NavigationManager.Uri

The `OnLocationChanged` hub method (line 576 of ComponentHub.cs) passes the client-provided URI directly to `RemoteNavigationManager.NotifyLocationChanged`, which sets `Uri = uri` (line 91 of RemoteNavigationManager.cs) without validation.

This means a malicious client can cause `NavigationManager.Uri` to return any arbitrary string on the server. If application code uses `NavigationManager.Uri` for security decisions (e.g., checking if the user is on an admin page), this could be misleading.

### Why This Is NOT MSRC-Eligible

The NavigationManager in Blazor Server is fundamentally a client-controlled value. The client is telling the server "I am at URL X" -- the server cannot independently verify this because it's the client's browser state. This is documented behavior: the Router uses `NavigationManager.Uri` for route matching, but authorization is enforced by component-level attributes (`[Authorize]`), not by URL checks.

The Router's `ToBaseRelativePath` will throw if the URI is not under the base URI, preventing out-of-app route matching. And even if route matching succeeds, `AuthorizeRouteView` still checks `[Authorize]` attributes on the matched component.

Application code that makes security decisions based on `NavigationManager.Uri` would be incorrect, but that is an application-level bug, not a framework vulnerability.

**Verdict:** By design. Client-controlled NavigationManager.Uri is expected in Blazor Server.

### Sub-observation: Form Action Attribute Injection Prevention

The `StaticHtmlRenderer.HtmlWriting.cs` properly HTML-encodes the form action attribute value (line 354):
```csharp
_htmlEncoder.Encode(output, GetRootRelativeUrlForFormAction(_navigationManager));
```
And the antiforgery middleware in `RazorComponentEndpointInvoker` validates POST requests before form processing occurs.

**Verdict:** No vulnerability.

---

## Additional Observations (Not MSRC-Eligible)

### ProtectedBrowserStorage Purpose String Predictability

**File:** `Server/src/ProtectedBrowserStorage/ProtectedBrowserStorage.cs`

The data protection purpose string is derived from `{FullTypeName}:{StoreName}:{Key}`:
```csharp
private string CreatePurposeFromKey(string key)
    => $"{GetType().FullName}:{_storeName}:{key}";
```

The purpose is predictable since the type name, store name ("localStorage" or "sessionStorage"), and key are all knowable. However, this is not a vulnerability because:
1. Data protection purposes are not secrets -- they scope the protection
2. The actual protection comes from the machine key / key ring
3. `ProtectedBrowserStorage` explicitly throws on WebAssembly to prevent client-side use

### RemoteRenderer Unacknowledged Batch Queue

**File:** `Circuits/RemoteRenderer.cs`

A client that never acknowledges render batches would cause the queue to fill up to `MaxBufferedUnacknowledgedRenderBatches`. Once full, rendering stops (line 89-109). This is explicitly handled as a resource protection mechanism, not a vulnerability.

### OnConnectedAsync Auth Refresh Callback

**File:** `ComponentHub.cs` (line 80)

```csharp
Context.Features.Get<IConnectionAuthenticationRefreshFeature>()
    ?.OnAuthenticationRefresh = static _ => Task.FromResult(true);
```

This always returns `true` for auth refresh, meaning the hub always accepts identity changes. This is intentional: ComponentHub manages its own auth state at the circuit layer and does not use SignalR's user-based routing.

---

## Summary Table

| Area | Finding | MSRC-Eligible? | Reason |
|------|---------|----------------|--------|
| Circuit reconnection without user check | By design | No | 512-bit secret is the auth factor |
| ComponentHub has no [Authorize] | By design | No | Auth delegated to component layer |
| CircuitDisconnectMiddleware no auth | By design | No | Data-protected secret serves as auth |
| Client can set NavigationManager.Uri | By design | No | Client-controlled, Router uses [Authorize] |
| MarkupString renders raw HTML | By design | No | Explicit developer opt-in |
| Component descriptors | Well-protected | No | Data-protected, time-limited, sequenced |
| JS interop dispatch | Properly gated | No | Requires [JSInvokable] attribute |
| Streaming SSR redirects | Well-protected | No | Data-protected, time-limited |
| Form submission | Well-protected | No | Antiforgery validation |
| Persisted circuit state no user binding | By design | No | Secret-based keying, same as circuit model |

---

## Conclusion

The Blazor Server security model is internally consistent and well-implemented. The core design relies on the circuit secret as the sole authentication factor (analogous to session cookies), and this secret has sufficient entropy (512 bits) with proper cryptographic protections (data protection, fixed-time comparison).

The most promising-looking leads -- no `[Authorize]` on ComponentHub and no user affinity check on reconnection -- are intentional design decisions that are consistent with how the framework handles authentication at the component layer rather than the transport layer. These would only be vulnerable if the circuit secret were leaked, which would require a separate vulnerability (XSS, MitM, etc.).

No finding meets the bar of crossing a security boundary in a way that is not "by design."
