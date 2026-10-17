# HUNT: OutputCaching binary format — unsafe reader + unvalidated length prefixes

Hunted directly (no subagents), 2026-10-17, loop iteration 1. First target of the post-config
strategy: memory safety and parsing, where documentation cannot pre-empt a finding.

Directories `ls`-verified present before auditing.

## VERDICT: NOT ELIGIBLE (~2%). Real robustness bugs; the trust boundary fails.

| # | Candidate | Verdict |
|---|---|---|
| D1 | `FormatterBinaryReader` bounds checking (`ref struct`, `Unsafe.Add`, no runtime bounds checks) | **CLEAN** — correct, including the overflow-safe idiom |
| D2 | Unvalidated length prefixes → arbitrary allocation from a cache entry | **REAL bug, NOT eligible** — input not untrusted by default |
| D3 | Read path has no `try`/`catch` while the write path does | **REAL bug, NOT eligible** — same boundary |

---

## D1 — the unsafe reader is correct

`FormatterBinaryReader.cs` is a hand-rolled `BinaryReader` over `ReadOnlyMemory<byte>`, held as a
`ref struct` with `private readonly ref byte _root`, reading via `Unsafe.Add(ref _root, _offset)`
and `MemoryMarshal.CreateReadOnlySpan`. **The runtime performs no bounds checking here** — every
bound is manual. It holds up:

- **The bounds idiom is the overflow-safe form.** Every sized read uses
  `if (_offset > _length - bytes) ThrowEndOfStream();` (`:134`, `:148`, `:160`, `:176`) rather than
  the naive `_offset + bytes > _length`, which would overflow for large `bytes`. Worst case
  `_length - bytes` is `0 - int.MaxValue = -2147483647`, still above `int.MinValue`, so the
  subtraction itself **cannot** underflow. Checked this explicitly; it is correct by construction.
- **Negative lengths are rejected** at every entry point:
  `ArgumentOutOfRangeException.ThrowIfNegative` in `ReadString(int)`, `Skip`, `ReadBytesSpan`,
  `ReadBytesMemory`. This matters because `Read7BitEncodedInt()` **can legitimately return a
  negative value** — the 5th byte permits up to `0b1111`, and `15 << 28 = 0xF0000000` casts to
  `-268435456`. (That is byte-compatible with `BinaryReader`, as the file comment claims.) Both
  callers that feed it straight into a sized read — `ReadString()` and `SkipString()` — land on a
  `ThrowIfNegative`.
- **Zero-length cases short-circuit before touching the raw ref** (`bytes == 0` / `count == 0`
  early returns), so an empty buffer, whose `MemoryMarshal.GetReference` is a null-ish ref, is
  never dereferenced.
- `ReadBytesMemory` uses managed `_original.Slice(...)`, which bounds-checks independently.

No memory-safety defect found. Genuine clean bill of health on the unsafe code.

## D2 — length prefixes are not cross-checked against the remaining buffer

`OutputCacheEntryFormatter.Deserialize` (`:227`) reads counts and immediately allocates on them,
with no validation that the buffer could possibly contain that many elements:

- `:259` `var headersCount = reader.Read7BitEncodedInt();` → `:267`
  `ArrayPool<(string, StringValues)>.Shared.Rent(headersCount)`
- `:273` `var valuesCount = reader.Read7BitEncodedInt();` → `:288` `var values = new string[valuesCount];`
- `:307` `segmentsCount`, `:347` `tagsCount` → same shape

Negatives *are* handled — `case < 0: throw new InvalidOperationException();` (`:277-279`) and
`if (headersCount > 0)` / `if (tagsCount > 0)` guards — so the gap is purely the upper bound.
A 6-byte entry can declare `valuesCount = 2_000_000_000`, and `new string[2e9]` is attempted
(~16 GB on 64-bit) before a single element is read. Every element requires ≥1 byte on the wire,
so a remaining-length cross-check would reject this for free.

Also unvalidated: `:249` `new DateTimeOffset(ticks, TimeSpan.FromMinutes(offsetMinutes))` with both
values straight off the wire, which throws `ArgumentOutOfRangeException` for out-of-range input.

## D3 — the read path is undefended while the write path is defended

`StoreAsync` wraps its work in `try` / `catch (OperationCanceledException)` / `catch (Exception ex)`
(`:45-67`). `GetAsync` does not: `:35` is a bare `return Deserialize(content);`. So any exception
from a malformed entry — `EndOfStreamException`, `OverflowException`, `InvalidOperationException`,
`ArgumentOutOfRangeException`, `OutOfMemoryException` — propagates through
`OutputCacheMiddleware.cs:348` into the request pipeline. One corrupt entry then yields a 500 for
every request on that cache key until it expires. That asymmetry looks like an oversight rather
than a decision, and there is no threat-model comment anywhere in
`OutputCacheEntryFormatter.cs`, `FormatterBinaryReader.cs` or `IOutputCacheStore.cs` to suggest
otherwise (grepped for untrusted/malicious/trust/tamper/corrupt: zero hits).

## Why none of it is eligible

**The input is not untrusted by default.** This format is only ever read back from
`IOutputCacheStore` — data the middleware itself serialized. The default store is in-memory, in
the same process, so there is no boundary at all. Under the documented Azure Redis configuration
the store is external, but an attacker who can write to your cache backend can already **replace
cached response bodies and headers wholesale**, which is strictly worse than provoking an OOM. The
allocation bug buys them nothing they do not already have.

That fails the MSRC requirement that input be untrusted by default, and lands squarely in the
out-of-scope entry *"Issues requiring extensive or unlikely user actions."* No request-controlled
path reaches `Deserialize`: the only caller is `GetAsync` keyed on a cache key, and request data
influences *which* key is read, never the bytes returned.

**Patch status not pursued** — pointless once the boundary fails, so no GitHub verification was run
for D2/D3.

## Worth reporting upstream anyway (not as a bounty case)
A defensive-robustness issue, correctly filed as a GitHub issue:
1. Cross-check every length prefix against `reader`'s remaining length before allocating.
2. Wrap the `Deserialize` call in `GetAsync` and treat a malformed entry as a cache miss —
   evicting it — rather than letting it 500 the endpoint until expiry. This is the one with real
   operational bite: it converts a single corrupt Redis value into a sustained endpoint outage.
3. Validate `ticks`/`offsetMinutes` before constructing the `DateTimeOffset`.

## Loop note — where to go next
Confirms the strategy shift was right in direction but exposes a second filter I had not
articulated: on internal formats, **memory-safety bugs are cheap to find and worthless**, because
the only writer is the framework. To be eligible, a parser bug needs a *network-reachable* parser.
Next iterations should target parsers fed directly from request bytes — Kestrel header/chunk
decoding, multipart form parsing, `FormDataMapper`, cookie and `StringValues` parsing, content
negotiation, HPACK/QPACK, `System.Text.Json` converter edge cases on model-bound input — rather
than anything deserializing framework-written state.
