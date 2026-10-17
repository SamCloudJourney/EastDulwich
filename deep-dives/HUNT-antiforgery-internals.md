# HUNT: classic token antiforgery internals (crypto + validation logic)

Hunted directly (no subagents), 2026-10-17, loop iteration 2. Chosen to avoid overlap with the
5-hunter workflow (which owns Kestrel HTTP/1.1, multipart/FormDataMapper, HPACK/QPACK, authz
logic, docs/samples). Distinct from the earlier Fetch-Metadata CSRF audit: that covered the NEW
`ICsrfProtection` middleware, this covers the CLASSIC token system.

`ls`-verified present before auditing: `src/Antiforgery/src/Internal/` (16 files).

## VERDICT: CLEAN. No finding. ~0%.

| # | Candidate | Verdict |
|---|---|---|
| E1 | Token comparison timing side-channel | **CLEAN** — constant-time, deliberately so |
| E2 | Attacker-controlled token bytes → parser bug | **UNREACHABLE** — `Unprotect` precedes the parse |
| E3 | Base64 decode sizing → stack overflow / unbounded alloc | **CLEAN** — no variable-length `stackalloc` |
| E4 | Cookie/request token binding bypass (incl. cookie-tossing) | **CLEAN** — layered binding |
| E5 | Claims-vs-username fallback asymmetry | **CLEAN** — the asymmetry is explicitly handled |
| E6 | Claim-UID collision across users/issuers | **CLEAN** — issuer included in the hashed tuple |

---

## E1 — comparisons are constant-time on purpose
`BinaryBlob.AreByteArraysEqual` (`Internal/BinaryBlob.cs`) accumulates with `areEqual &= (a[i] == b[i])`
over the full length — no early exit — and is annotated
`[MethodImplAttribute(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]` with a
comment stating that is to keep it constant-time. Claim-UID comparison uses
`CryptographicOperations.FixedTimeEquals`. Generation uses `RandomNumberGenerator.Fill`.
`bitLength < 32 || bitLength % 8 != 0` and `data.Length != bitLength / 8` are both validated in the
constructor. Nothing to attack.

## E2 — crypto gates the parser, so the parser is unreachable
`DefaultAntiforgeryTokenSerializer.Deserialize(string)` base64url-decodes, then calls
`Unprotect` **before** the structural parse:
```csharp
_perfCryptoSystem.Unprotect(tokenBytesDecoded, ref protectBuffer);
var token = Deserialize(protectBuffer.WrittenSpan);   // authenticated bytes only
```
DataProtection is authenticated encryption, so the span reaching the inner
`Deserialize(ReadOnlySpan<byte>)` was produced under the server's own key. An attacker cannot
choose those bytes, which makes the whole documented wire format (version byte, 16-byte security
token, `IsCookieToken`, `IsClaimsBased`, 32-byte claim UID, 7-bit-length-prefixed strings)
**not attacker-controlled**. The inner parser's length guards are fine anyway
(`minCookieTokenLength = 18`, version check, bounds before each field), but they are defence in
depth rather than a boundary.

Failure handling is also sound: every exception is caught and collapsed into a single
`AntiforgeryValidationException` — the source comment says *"swallow all exceptions - homogenize
error if something went wrong"* — so there is no distinguishing oracle between "bad base64",
"bad MAC" and "bad structure".

## E3 — no variable-length `stackalloc`
The one genuinely attacker-influenced quantity before `Unprotect` is the token string's length:
```csharp
var maxTokenDecodedSize = Base64Url.GetMaxDecodedLength(serializedToken.Length);
var rent = maxTokenDecodedSize <= 256
    ? stackalloc byte[256]
    : (tokenBytesRent = ArrayPool<byte>.Shared.Rent(maxTokenDecodedSize));
```
Both `stackalloc` sites are **fixed** (`byte[256]` here and in the
`RefPooledArrayBufferWriter` ctor); the attacker-sized path goes to `ArrayPool`, not the stack.
That sidesteps the classic variable-`stackalloc` stack-overflow bug in exactly this pattern.
The pooled allocation is bounded by request limits (header size / form value length), the rented
array is only read over `[..bytesWritten]` so stale pool contents are never consumed, and it is
returned in a `finally`.

## E4 — binding is layered, and defeats cookie-tossing
`DefaultAntiforgeryTokenGenerator.TryValidateTokenSet` checks, in order: token roles are not
swapped (`!cookieToken.IsCookieToken || requestToken.IsCookieToken`); the two embedded
`SecurityToken`s are equal (constant-time, via `BinaryBlob`); the token's user matches the
current user (username or claim UID); then `AdditionalData`.

Worked through the realistic bypasses, all blocked:
- **Forge a request token matching the victim's cookie** — needs the DataProtection key. No.
- **Supply the attacker's own matching cookie+request pair** (cookie-tossing from a subdomain, the
  strongest attack here, since it satisfies the security-token equality check): blocked by the
  user binding — the attacker's token carries the attacker's username/claim UID, while
  `currentUsername` comes from the victim's auth cookie. Mismatch → rejected. This check is
  precisely what makes cookie-tossing fail.
- **Use a token minted while unauthenticated against an authenticated victim**: `requestToken.Username`
  is empty, current user is not → rejected via `IsTokenForAuthenticatedUserButCurrentUserIsNot`.
- Both parties unauthenticated → tokens match, but an unauthenticated session has no privilege to abuse.

Note the comparer choice is keyed on **`currentUsername`** (server-side), not on the token's
username, so an attacker cannot select `OrdinalIgnoreCase` vs `Ordinal` by crafting the token.
That is the correct way round. Default `OrdinalIgnoreCase` would only matter for a custom identity
store permitting two users differing solely by case — and even then the auth cookie, not the
antiforgery token, establishes identity, so it is not a privilege boundary.

## E5 — the fallback asymmetry is explicitly handled
When claims are extractable the code uses the claim UID and leaves `currentUsername` empty; when
they are not, it falls back to `authenticatedIdentity.Name`. The pairing is enforced in
`AreIdenticalClaimUids`:
```csharp
if (token.ClaimUid is null) { return !claimUidBytesExtracted; }
```
so a username-based token is accepted **only** when claims genuinely were not extracted — the
mismatch direction I was probing for is closed.

Minor code-quality nit (not a vulnerability): in the inverse case (`token.ClaimUid != null` with
`claimUidBytesExtracted == false`) the comparison runs against the `stackalloc byte[32]` buffer
that was never written, i.e. 32 zero bytes. It is safe only because `ClaimUid` is a SHA-256 output
and producing 32 zero bytes is a preimage problem — and because the token is DP-protected, so
`ClaimUid` is not attacker-chosen in the first place. An explicit
`if (!claimUidBytesExtracted) { return false; }` ahead of the length check would make the
guarantee structural rather than cryptographic. Worth a cleanup PR, nothing more.

## E6 — claim UID cannot collide across users or issuers
`DefaultClaimUidExtractor.GetUniqueIdentifierParameters` walks only `IsAuthenticated` identities and
takes the first non-empty of `sub`, `ClaimTypes.NameIdentifier`, `ClaimTypes.Upn` — all true subject
identifiers, never a display name or email. Critically it hashes the triple
**`[claim.Type, claim.Value, claim.Issuer]`**, so subject `123` from issuer A does not collide with
subject `123` from issuer B. That issuer inclusion is a subtle detail and it is correct.

## Loop note — a third structural filter, generalizing Filter 2
**Where DataProtection's `Unprotect` precedes parsing, the parser is not an attack surface.**
This rules out a whole family of otherwise-attractive targets in one stroke: antiforgery tokens,
authentication cookie tickets, Blazor circuit IDs and descriptors, and anything else
DP-protected. Chasing parser bugs behind a DP boundary is wasted effort, however unsafe the parsing
code looks — the same wall that made the OutputCaching length-prefix bug worthless, in a different
costume.

Combined with iteration 1's conclusion, the rule for picking targets is now: the parser must be fed
from bytes that are **neither framework-written nor DataProtection-authenticated**. That leaves
raw request-surface parsers — which is exactly what the 5-hunter workflow is currently sweeping —
plus crypto/logic that operates on attacker-*chosen but legitimately-obtained* material, where
authentication does not help because the attacker owns a valid token.
