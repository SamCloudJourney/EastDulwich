# HUNT-data-injection: EF Core & ASP.NET Core Data Handling Security Audit

**Date:** 2026-10-07
**Repos:** `/home/user/dotnet-hunt/runtime/`, `/home/user/dotnet-hunt/aspnetcore/`
**Scope:** MSRC-eligible (Critical/Important) vulnerabilities that cross a security boundary

---

## Executive Summary

Five focus areas were investigated for exploitable vulnerabilities in ASP.NET Core's data handling pipeline. No MSRC-eligible vulnerability was found. All critical attack surfaces are defended by multiple redundant layers. One focus area (EF Core SQL injection) could not be assessed because the EF Core source lives in the separate `dotnet/efcore` repository, not in the provided `runtime` or `aspnetcore` repos.

---

## Focus Area 1: EF Core SQL Injection via Interpolation

**Status:** NOT ASSESSED -- source code not present

The EF Core source (`FromSqlRaw`, `FromSqlInterpolated`, `ExecuteSqlRaw`, `ExecuteSqlInterpolated`, and `FormattableString` handling) resides in `dotnet/efcore`, which is not part of the `dotnet/runtime` or `dotnet/aspnetcore` repositories provided. This focus area requires a separate investigation against that repo.

---

## Focus Area 2: Model Binding Injection (Mass Assignment / Over-Posting)

**Status:** No MSRC-eligible vulnerability found

### Analysis

**ComplexObjectModelBinder** (`aspnetcore/src/Mvc/Mvc.Core/src/ModelBinding/Binders/ComplexObjectModelBinder.cs`):
- `CanBindItem` checks `PropertyFilterProvider`, `PropertyFilter`, `IsBindingAllowed`, and readonly status before binding each property.
- `CreateModel` rejects abstract types and types without parameterless constructors.
- No polymorphic type resolution exists -- the binder does not consult a `$type` discriminator or similar mechanism, so an attacker cannot substitute a different type at bind time.

**BindAttribute** (`aspnetcore/src/Mvc/Mvc.Core/src/BindAttribute.cs`):
- Implements an include-only list with case-sensitive `StringComparison.Ordinal` matching.
- If the `Include` list is empty, the default `PropertyFilterProvider` allows ALL properties. This is by-design: developers must explicitly opt in to property filtering.
- No case-folding bypass is possible because the comparison is ordinal.

**DefaultPropertyFilterProvider** (`aspnetcore/src/Mvc/Mvc.Core/src/ModelBinding/DefaultPropertyFilterProvider.cs`):
- When `PropertyIncludeExpressions` is null, the filter allows all properties. This is the default when no `[Bind]` attribute is applied.

**File upload filenames** (`aspnetcore/src/Http/WebUtilities/src/FileMultipartSection.cs`):
- `FileName` is taken directly from the `Content-Disposition` header via `HeaderUtilities.RemoveQuotes()`.
- No path traversal sanitization is performed on filenames.
- However, this is by-design: ASP.NET Core's `IFormFile.FileName` is documented as untrusted input, and the framework does not write uploaded files to disk automatically. The application developer is responsible for sanitizing filenames before any file-system operation.

### Conclusion

Over-posting protection is opt-in by design, not a security boundary the framework enforces. File upload filename handling is explicitly documented as the developer's responsibility. No boundary-crossing vulnerability exists.

---

## Focus Area 3: Static File Middleware Path Traversal

**Status:** No vulnerability found -- defended by multiple redundant layers

### Defense Layers Analyzed

**Layer 1: Kestrel URL Decoding** (`aspnetcore/src/Shared/UrlDecoder/UrlDecoder.cs`):
- Percent-encoded forward slashes (`%2F`) are explicitly skipped (NOT decoded) in non-form-encoding mode.
- Null bytes (`%00`) throw `InvalidOperationException`, terminating the request.
- This prevents `%2F..%2F` traversal at the server level before the path reaches any middleware.

**Layer 2: Kestrel Path Normalization** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/PathDecoder.cs`):
- Pipeline: `DecodeInPlace` -> `RemoveDotSegments` -> UTF-8 string conversion.
- Dot segments (`..`) are collapsed by Kestrel before the request reaches middleware.

**Layer 3: PathString Segment Matching** (`aspnetcore/src/Http/Http.Abstractions/src/PathString.cs`):
- `StartsWithSegments` treats backslash (`\`) as equivalent to forward slash (`/`) for segment boundary detection.
- This prevents backslash-based path confusion in prefix matching.

**Layer 4: StaticFileMiddleware / Helpers** (`aspnetcore/src/Middleware/StaticFiles/src/Helpers.cs`):
- `TryMatchPath` uses `path.StartsWithSegments(matchUrl, out subpath)`.
- The subpath extracted is what gets passed to the file provider.

**Layer 5: PhysicalFileProvider.GetFileInfo** (`runtime/src/libraries/Microsoft.Extensions.FileProviders.Physical/src/PhysicalFileProvider.cs`):
- Rejects paths with invalid path characters (`HasInvalidPathChars`).
- Rejects absolute/rooted paths (`Path.IsPathRooted`).
- Trims leading directory separators.
- Calls `GetFullPath` which applies three sub-checks:

**Layer 5a: PathNavigatesAboveRoot** (`runtime/src/libraries/Microsoft.Extensions.FileProviders.Physical/src/Internal/PathUtils.cs`):
```csharp
internal static bool PathNavigatesAboveRoot(string path)
{
    var tokenizer = new StringTokenizer(path, PathSeparators);
    int depth = 0;
    foreach (StringSegment segment in tokenizer)
    {
        if (segment.Equals(".") || segment.Equals("")) continue;
        else if (segment.Equals("..")) { depth--; if (depth == -1) return true; }
        else depth++;
    }
    return false;
}
```
Tracks directory depth through tokenized segments. Returns true if depth ever reaches -1, meaning the path would escape the root. Both `/` and `\` are used as separators via `PathSeparators`.

**Layer 5b: Path.GetFullPath Canonicalization**:
```csharp
fullPath = Path.GetFullPath(Path.Combine(Root, path));
```
Delegates to the OS for canonical path resolution, collapsing any remaining `.`/`..` sequences, symlinks, etc.

**Layer 5c: IsUnderneathRoot Prefix Check**:
```csharp
return fullPath.StartsWith(Root, StringComparison.OrdinalIgnoreCase);
```
After canonicalization, verifies the resolved path still starts with the root. `OrdinalIgnoreCase` handles Windows case-insensitivity.

### Attack Vectors Considered

| Vector | Blocked By |
|---|---|
| `../` traversal | Kestrel dot-segment removal + PathNavigatesAboveRoot + GetFullPath |
| `%2F..%2F` encoded slash | UrlDecoder skips %2F decoding |
| `%00` null byte | UrlDecoder throws InvalidOperationException |
| Backslash `..\..\` | PathSeparators includes `\`, PathString treats `\` as `/` |
| Double encoding `%252F` | Only one decode pass; %252F becomes literal `%2F` |
| Unicode normalization (overlong UTF-8) | Kestrel's UTF-8 decoder rejects overlong sequences |
| Symlink following | GetFullPath resolves symlinks, IsUnderneathRoot checks result |

### Conclusion

The static file pipeline has six redundant defense layers. No single-bypass traversal vector was identified that could defeat all layers simultaneously.

---

## Focus Area 4: Request Body Size Limits Bypass

**Status:** No vulnerability found -- chunked and multipart both enforced

### Kestrel Body Size Enforcement

**MaxRequestBodySize** (`aspnetcore/src/Servers/Kestrel/Core/src/KestrelServerLimits.cs`):
- Default: 30,000,000 bytes (~28.6 MB).
- Applied at the transport level, before any middleware.

**Content-Length bodies** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/Http1ContentLengthMessageBody.cs`):
- `OnReadStarting` compares the Content-Length header value against `MaxRequestBodySize` upfront (lines 247-252), rejecting oversized requests before reading any body data.

**Chunked bodies** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/Http1ChunkedEncodingMessageBody.cs`):
- Calls `AddAndCheckObservedBytes` in `ParseChunkedPrefix`, `ReadChunkedData`, and `ParseChunkedSuffix`.
- `AddAndCheckObservedBytes` (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/MessageBody.cs`) tracks a running total and throws `BadHttpRequestException` when `MaxRequestBodySize` is exceeded.
- There is no bypass: every chunk's data contributes to the running total.

### Request Smuggling Defense

**Content-Length + Transfer-Encoding conflict** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/Http1MessageBody.cs`):
- When both headers are present, Kestrel:
  1. Removes the Content-Length header
  2. Preserves the original value as `X-Content-Length`
  3. Closes the connection after the response (prevents pipeline poisoning)
- This follows RFC 7230 Section 3.3.3 and blocks CL/TE request smuggling.

### Multipart Form Data Limits

**FormOptions** (`aspnetcore/src/Http/Http/src/Features/FormOptions.cs`):
- `MultipartBodyLengthLimit` defaults to 128 MB -- but this is a **per-section** limit.
- `ValueCountLimit` (default 1024) caps the number of form values.

**FormFeature** (`aspnetcore/src/Http/Http/src/Features/FormFeature.cs`):
- Creates `MultipartReader` with `BodyLengthLimit` set per-section.
- Section count is checked against `ValueCountLimit`.
- Total body size is ultimately bounded by Kestrel's `MaxRequestBodySize` at the transport layer.

**MultipartReader** (`aspnetcore/src/Http/WebUtilities/src/MultipartReader.cs`):
- `BodyLengthLimit` is documented as "optional limit for the body length of each multipart section."
- Per-section, not total. But the total cannot exceed `MaxRequestBodySize` because Kestrel enforces it on the underlying stream.

### Conclusion

Chunked transfer encoding is fully enforced against `MaxRequestBodySize`. The multipart per-section limit is architecturally complemented by Kestrel's total body limit. Request smuggling via CL/TE conflict is defended. No bypass found.

---

## Focus Area 5: Response Splitting / Header Injection / Open Redirect

**Status:** No vulnerability found -- CRLF rejected, open redirect properly gated

### Header Injection Defense

**HttpCharacters** (`aspnetcore/src/Shared/ServerInfrastructure/HttpCharacters.cs`):
```csharp
private const string ControlCharsExceptHtab =
    "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u000A\u000B\u000C\u000D...";
private static readonly SearchValues<char> _allowedFieldChars =
    SearchValues.Create("\t !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" + AlphaNumeric);
```
- `\r` (0x0D) and `\n` (0x0A) are both in `ControlCharsExceptHtab` and NOT in `_allowedFieldChars`.
- `IndexOfInvalidFieldValueChar` uses `IndexOfAnyExcept(_allowedFieldChars)` -- a whitelist approach that rejects anything not in the allowed set.

**ValidateHeaderValueCharacters** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/HttpHeaders.cs`):
- Called for every response header value before serialization.
- Uses `HttpCharacters.IndexOfInvalidFieldValueChar` to reject control characters.
- Throws `InvalidOperationException` if CR, LF, or any other control character (except HTAB) is present.

**Generated header setters** (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/HttpHeaders.Generated.cs`):
- Every known response header (Location, Set-Cookie, etc.) passes through `ValidateHeaderValueCharacters`.
- Unknown headers are also validated via `ValidateHeaderNameCharacters` + `ValidateHeaderValueCharacters`.

**Redirect handling** (`aspnetcore/src/Http/Http/src/Internal/DefaultHttpResponse.cs`):
- `Redirect` sets `Headers.Location = location` without its own validation.
- Relies entirely on Kestrel's header validation, which is sufficient -- any CRLF in the location value is rejected.

### Open Redirect Analysis

**SharedUrlHelper.IsLocalUrl** (`aspnetcore/src/Shared/ResultsHelpers/SharedUrlHelper.cs`):
```csharp
internal static bool IsLocalUrl(string? url)
{
    // Rejects: null/empty, "//...", "/\...", "~//...", "~/\..."
    // Accepts: "/", "/foo", "~/", "~/foo"
    // Also rejects URLs containing ASCII control characters
}
```
- Rejects protocol-relative URLs (`//evil.com`).
- Rejects backslash variants (`/\evil.com`).
- Rejects URLs with embedded control characters (prevents tab/newline trickery).
- Only accepts paths starting with `/` or `~/` that don't immediately follow with `/` or `\`.

**LocalRedirectResultExecutor** (`aspnetcore/src/Mvc/Mvc.Core/src/Infrastructure/LocalRedirectResultExecutor.cs`):
- Enforces `IsLocalUrl` as a gate; throws `InvalidOperationException` if the URL is not local.

**RedirectResultExecutor** (`aspnetcore/src/Mvc/Mvc.Core/src/Infrastructure/RedirectResultExecutor.cs`):
- Does NOT enforce `IsLocalUrl` -- accepts any URL. This is by-design: `RedirectResult` is intended for redirects to arbitrary URLs (including external ones). Developers who want local-only redirects use `LocalRedirectResult`.

### Conclusion

CRLF injection in response headers is fully blocked by Kestrel's whitelist-based header validation. Open redirect is properly separated: `LocalRedirectResult` validates, `RedirectResult` does not (by design). No boundary-crossing vulnerability found.

---

## Summary Table

| Focus Area | MSRC-Eligible Finding | Status |
|---|---|---|
| 1. EF Core SQL injection | -- | Not assessed (source not in repos) |
| 2. Model binding injection | None | By-design behaviors, no boundary crossing |
| 3. Static file path traversal | None | 6 redundant defense layers |
| 4. Request body size bypass | None | Chunked enforced, CL/TE smuggling defended |
| 5. Response splitting / open redirect | None | CRLF whitelist-blocked, redirect properly gated |

---

## Recommendations for Further Investigation

1. **EF Core SQL injection** -- Requires access to the `dotnet/efcore` repository to assess `FromSqlRaw`/`FromSqlInterpolated` and `FormattableString` parameter handling.

2. **Unicode normalization in file paths** -- While Kestrel rejects overlong UTF-8 and `Path.GetFullPath` canonicalizes, testing with locale-specific Unicode normalization forms (NFC vs NFD) on case-insensitive filesystems could surface edge cases in the `IsUnderneathRoot` prefix check.

3. **Symlink race conditions** -- `PhysicalFileProvider.GetFullPath` resolves symlinks via `Path.GetFullPath`, but a TOCTOU window exists between path resolution and file open. This is inherent to the filesystem API and unlikely to be MSRC-eligible, but worth noting for high-security deployments.
