# HUNT: Path-traversal / arbitrary-file / archive-extraction (v2)

**Scope:** ASP.NET Core (`aspnetcore`), .NET SDK (`sdk2`), runtime (`runtime`) @ repo HEAD
(aspnetcore `85162224`, runtime `2eb71132`, sdk2 `e4ea7d5` — all ~2026-10-07).
**Toolchain for PoCs:** installed SDK `10.0.100-rc.2.25502.107`; shared runtimes `10.0.0-rc.2.25502.107` and `9.0.20`.
**Date:** 2026-10-09

---

## TL;DR / verdict

| Surface | Boundary | HEAD status |
|---|---|---|
| StaticFiles → PhysicalFileProvider | Network (serve by request path) | **Clean** — triple-layer check holds |
| Kestrel path decode/normalize | Network | **Clean** — `%2F` left encoded, `..` removed post-decode |
| StaticAssets (endpoint routing) | Network | **Clean** — serves manifest paths only; request path never maps to a file |
| MVC `PhysicalFileResult`/`VirtualFileResult` | Network | **Clean** — app-supplied path (not untrusted-by-default) |
| `System.IO.Compression` `ZipFile.ExtractToDirectory` | Archive write | **Clean** — zip-slip blocked; zip never creates symlinks |
| `System.Formats.Tar` `TarFile.ExtractToDirectory` | Archive write | **Fixed at HEAD**; a real symlink-traversal escape exists in **.NET 10 preview (RC1/RC2) only** |

**No GA-shipping, HEAD-live, default-config path traversal was found.** One genuine, high-severity
arbitrary-file-write-via-crafted-tar bug was confirmed with a working PoC, but it is a **.NET 10
*preview* regression that is already fixed in `runtime` HEAD** and **does not affect the .NET 8/9 GA
lines**. Under the stated bar ("must fire in current code / default config"), it is **not
bounty-eligible** (preview-only + already fixed in public `main`). Details and honest confidence below.

---

## FINDING (documented, NOT eligible): Tar symlink traversal in .NET 10 preview `TarFile.ExtractToDirectory`

### What it is
A crafted tar archive can make `TarFile.ExtractToDirectory` (the documented *safe* extraction API)
**silently write a regular file — and create directories — outside the destination directory**, with
no exception, in the default configuration, on **.NET 10 RC1/RC2**. This is a classic
symlink-dir + outward-child-symlink traversal (arbitrary file write → RCE-capable).

### Boundary & reachability
- **Boundary:** cross-trust **file write** outside the intended extraction root. Any process that
  extracts an attacker-supplied `.tar` (upload handler, package/artifact unpacker, CI step,
  `dotnet` tooling that unpacks tarballs) → attacker writes to arbitrary paths (drop `~/.bashrc`,
  a cron file, a web shell, overwrite a binary).
- **Input untrusted by default:** a received tar archive. Qualifies (not a "you installed a
  malicious package" trust decision).
- **Default config:** `TarFile.ExtractToDirectory(stream|path, destDir, overwriteFiles)` and the
  `TarExtractOptions` default (`HardLinkMode = PreserveLink`). No opt-in needed.
- **Documented guarantee being violated:** `TarFile.ExtractToDirectory` XML docs promise
  `ArgumentException`/`IOException` when "Extracting tar entry would have resulted in a file outside
  the specified destination directory" — `TarFile.cs:273-278, 292-297`. So a bypass is a security bug
  by Microsoft's own contract (see "Doc-stance" note below).

### The sanitization gap (why RC2 escapes)
Extraction validation lives in `runtime/src/libraries/System.Formats.Tar/src/System/Formats/Tar/TarEntry.cs`,
`GetDestinationAndLinkPaths` (HEAD lines 363-418) and the boundary check it calls.

- The **.NET 10 preview** validator is effectively **lexical-only**: it computes
  `fileDestinationPath = Path.GetFullPath(Path.Join(destDir, name))` and checks
  `StartsWith(destDir)` (`GetFullDestinationPath`, HEAD `TarEntry.cs:516-525`). It does **not** resolve
  symlinks created by earlier entries. A directory-symlink created earlier in the same archive is
  treated as a literal directory during the check, so a later file whose lexical path passes *through*
  that symlink is wrongly judged "inside."
- The **symlink target** check has the same lexical blind spot: a child symlink
  `a/b/sl/x -> ../../OUTSIDE` has a *lexical* target of `<dest>/a/OUTSIDE` (inside), so it is created —
  even though `sl` is itself a symlink to `<dest>/a`, making `x` *physically* point to the sibling
  `OUTSIDE`. Writing a file through `a/b/sl/x/...` then lands outside `dest`.

### The fix that IS present at HEAD (why HEAD is clean)
HEAD adds `FilePathEscapesDirectory` (`TarEntry.cs:423-471`) + `ResolveSymlink` (`473-486`) +
`ResolvePhysicalPath` (`490-513`). `GetDestinationAndLinkPaths` now calls `FilePathEscapesDirectory`
for both the file path and the link target (`TarEntry.cs:373, 394, 409`). It walks each component of
the (lexically-normalized) destination path and **resolves symlinks at every step**
(`ResolveLinkTarget(returnFinalTarget: true)`), rejecting the entry if any resolved step leaves the
physical destination root. This catches the outward child symlink the moment a file is written
through it. (The installed RC2 `System.Formats.Tar.dll` contains `GetDestinationAndLinkPaths` /
`GetFullDestinationPath` but **not** `FilePathEscapes*` / `ResolveSymlink` / `TarExtractOptions`
strings — i.e. RC2 predates the fix.)

### Empirical PoC results
Harnesses (kept, do not commit): `/home/user/EastDulwich/pocwork/`
- `tarrc2/` — real-library battery; attack **I** (`BuildSymlinkDirOutwardChild`) writes `pwned_I`
  into the sibling `OUTSIDE/` dir.
- `tarsweep/` — 11-variant sweep, multi-targeted `net9.0;net10.0`.
- `headsim/` — faithful verbatim port of HEAD `GetDestinationAndLinkPaths`/`FilePathEscapesDirectory`
  driving the real extraction order on a real filesystem.
- `probe/` — `ResolveLinkTarget` dangling-symlink semantics probe.

```
.NET 10.0.0-rc.2.25502.107  (sweep):  ESCAPED  J2_depth2_child_rel, N1_dir_through, R1_dblslash
                                       -> e.g. .../OUTSIDE/p_J2  (regular file, NO exception)
.NET 9.0.20          (sweep):  escapes 0  (all 11 variants contained)
HEAD (faithful sim)         :  escapes 0  (J2/N1/R1 and 6 other variants all blocked)
```
Minimal escaping archive (entry order), extracted into `<dest>` with sibling `<base>/OUTSIDE`:
```
dir      a
dir      a/b
symlink  a/b/sl  -> <dest>/a            (absolute, inside dest)
symlink  a/b/sl/x -> ../../OUTSIDE      (lexical target <dest>/a/OUTSIDE = "inside"; physical = sibling OUTSIDE)
file     a/b/sl/x/pwned                 (RC2: written to <base>/OUTSIDE/pwned, no throw)
```

### HEAD bypass attempts (all failed — HEAD is robust)
Tried against the faithful HEAD simulator and reasoning:
- Dangling outward child symlink (hope: `ResolveLinkTarget(true)` returns null → `?? info` fallback
  under-resolves). **Probed empirically:** `ResolveLinkTarget(returnFinalTarget:true)` returns the
  real (nonexistent) target for dangling links (`probe/`), so the walk still sees the outward target →
  blocked.
- Multi-hop dir-symlink chains, absolute-inside child targets, `..//..//` double-slash, directory
  entry through the symlink, hardlink-via-symlinked-dir, `-> "."` self-dir. All blocked by
  `FilePathEscapesDirectory`.

### Honest MSRC-survival confidence: **LOW (effectively nil as a new report)**
- Affects **preview/RC only**; **GA 8/9 are not vulnerable**.
- **Already fixed in public `dotnet/runtime` `main`** (the `FilePathEscapesDirectory` hardening is in
  HEAD) → known/triaged, almost certainly an in-flight servicing/CVE item.
- Fails the stated bar ("fire in current code"): the provided repo HEAD is fixed.
- *Value:* a correct, reproducible analysis + PoC, and a heads-up that currently-downloadable .NET 10
  RC2 ships the vulnerable extractor. If (and only if) the fix has not yet reached a public RC build,
  an RC-scoped report *might* be entertained, but treat as non-eligible.

---

## Negative results (checked, clean at HEAD) — with evidence

### 1. StaticFiles → PhysicalFileProvider (network serve) — clean
- `StaticFileMiddleware.Invoke` → `Helpers.TryMatchPath` → `StaticFileContext.LookupFileInfo` →
  `_fileProvider.GetFileInfo(subPath)` (`StaticFileContext.cs:117`). The middleware itself does **no**
  `..` filtering — it delegates entirely to the provider and to server-side normalization.
- `PhysicalFileProvider.GetFileInfo` (`runtime/.../Microsoft.Extensions.FileProviders.Physical/src/PhysicalFileProvider.cs:257-286`)
  applies a **triple** check: `HasInvalidPathChars` → `Path.IsPathRooted` reject →
  `GetFullPath(Combine(Root, subpath))` → `PathNavigatesAboveRoot` (`Internal/PathUtils.cs:44-71`,
  depth counter) → `IsUnderneathRoot` (`StartsWith(Root)` where `Root` keeps a trailing slash,
  line 59-61). `..` escapes are rejected both lexically (depth counter, pre-`GetFullPath`) and by the
  normalized-prefix check. No gap found on Linux; on Windows `\` is a separator so `..\` is likewise
  depth-counted and rejected.

### 2. Kestrel path decode / normalization — clean
- `PathDecoder.DecodePath` (`aspnetcore/src/Servers/Kestrel/Core/src/Internal/Http/PathDecoder.cs:12-46`)
  **percent-decodes first, then `RemoveDotSegments`** — so any `..` revealed by `%2e%2e` decoding is
  still collapsed (RFC 3986 §5.2.4, `src/Shared/PathNormalizer/PathNormalizer.cs`).
- `UrlDecoder.SkipUnescape` deliberately **does not decode `%2F`** (`UrlDecoder.cs:332-346`, and the
  char overload `:570`), so encoded-slash traversal (`..%2F..%2F`) never becomes path separators.
  Residual literal `%2F`/`\` are treated as ordinary filename chars by the provider (and `\` is
  depth-counted on Windows). Double-encoding is a non-issue (single decode pass before normalize).

### 3. StaticAssets (newer endpoint-routed delivery) — clean
- `StaticAssetsInvoker.FileInfo` serves `_fileProvider.GetFileInfo(_resource.AssetPath)` where
  `AssetPath` comes from the **compile-time manifest** (`StaticAssetsInvoker.cs:84-87`). The request
  path is used only for endpoint matching against `_resource.Route`; it never maps into a file path.
  No request-path→file traversal surface.

### 4. MVC file results — not untrusted-by-default
- `VirtualFileResultExecutor.GetFileInformation` routes through the same `PhysicalFileProvider`
  (`VirtualFileResultExecutor.cs:105-121`) → same protections; the virtual path is app-controlled.
- `PhysicalFileResultExecutor` serves an **app-supplied absolute path** and only enforces
  `Path.IsPathRooted` (`PhysicalFileResultExecutor.cs:79-82`) with no containment check — by design
  (the app chose the exact file). Feeding it user input is an app bug, not framework
  untrusted-by-default behavior. Out of scope.

### 5. Zip extraction — clean (zip-slip safe, no symlink creation)
- All entrypoints (`ZipFile.ExtractToDirectory`, `ZipArchive.ExtractToDirectory`,
  `ZipExtractionOptions` overload) funnel through `ZipArchiveEntry.ExtractRelativeToDirectory` →
  `ExtractRelativeToDirectoryCheckIfFile`
  (`System.IO.Compression.ZipFile/src/.../ZipFileExtensions.ZipArchiveEntry.Extract.cs:184-223`):
  `SanitizeEntryFilePath` → `GetFullPath(Combine(fullDest, sanitized))` → `StartsWith(destPrefix)`
  with a trailing-separator prefix (correctly avoids the `Dest` vs `Destinations` sibling-prefix
  pitfall, line 196-207). `..` is blocked.
- **Zip never creates symlinks/hardlinks** (confirmed: zero `CreateSymbolicLink`/`S_IFLNK`/
  `ReparsePoint` in `System.IO.Compression*/src`; `ExtractToFileCore` only writes file bytes and masks
  Unix mode to permission bits, line 162-178). So the symlink-traversal class does not apply to zip —
  only `..`, which is blocked. Clean on both GA and HEAD.

### 6. Multipart / request-body disk buffering — clean
- `FileBufferingReadStream.CreateTempFile` names the on-disk buffer
  `ASPNETCORE_<Guid>.tmp` (`aspnetcore/src/Http/WebUtilities/src/FileBufferingReadStream.cs:243`),
  i.e. a random GUID — **never** the client-supplied filename. The Content-Disposition `FileName`
  is surfaced only as metadata (`FileMultipartSection.FileName`, `FileMultipartSection.cs:42-44`) for
  the app to use at its discretion; the framework does not map it to a disk path. No traversal.
  `System.Net.Http` has no built-in multipart-to-disk writer keyed on untrusted names.

### 7. `SanitizeEntryFilePath` platform split (noted, not exploitable alone)
- Unix: near-noop — `entryPath.Replace('\0','_')` (`Common/src/System/IO/Archiving.Utils.Unix.cs:9`).
- Windows: strips `"*:<>?|` + control chars, preserves drive-root colon when `preserveDriveRoot`
  (`Archiving.Utils.Windows.cs:16-51`).
- This is safe because the real containment is enforced downstream by `GetFullPath` + prefix/physical
  checks, not by the sanitizer. The Windows `preserveDriveRoot` + rooted-but-not-fully-qualified
  symlink handling (`TarEntry.cs:384-390`) is Windows-specific and **not testable on this Linux host**
  — flagged as the one area a Windows-only reviewer should re-examine, though no concrete bypass is
  known.

---

## Doc-stance note (eligibility-relevant)
The task asked whether current docs still treat extraction-escape as *caller responsibility*. **They
do not** — current .NET source actively sanitizes and throws on escape for **both** formats, and
documents it:
- Zip: `IO_ExtractingResultsInOutside` throw, documented on `ExtractToDirectory`
  (`ZipFileExtensions.ZipArchive.Extract.cs:23-26`).
- Tar: `TarExtractingResultsFileOutside`/`...LinkOutside` throws, documented on
  `TarFile.ExtractToDirectory` (`TarFile.cs:273-278, 292-297`).
So extraction-escape prevention is now a **documented library guarantee**, and a bypass of it *is* a
security bug in principle. That is what makes the tar regression a real bug — it is only
*non-eligible* because it is preview-only and already fixed in `main`.

## CVE references from the brief
- **CVE-2025-55247** turned out to be the MSBuild `DownloadFile` predictable-temp-dir +
  chmod-follows-symlink DoS on Linux — i.e. the area already covered by the existing
  `F1-chmod-injection` notes, **not** a static-file/archive traversal. The CVE references in the brief
  are motivational, not live leads into unpatched code.

## PoC artifacts (not committed)
`/home/user/EastDulwich/pocwork/{tarrc2,tarsweep,headsim,probe}/` — run with
`DOTNET_ROOT=/home/user/.dotnet PATH=$DOTNET_ROOT:$PATH dotnet run -c Release [-f net9.0|net10.0]`.
