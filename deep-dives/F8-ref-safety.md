# F8: Ref Safety Scope Tracking Leak -- Deep Dive Analysis

## Verdict: NOT EXPLOITABLE -- Over-Restrictive Direction, No Security Impact

**Bounty Eligibility: No. This is a memory/performance concern, not a safety violation.**

---

## 1. Understanding the Ref Safety Model

### What the Scope Dictionaries Track

`RefSafetyAnalysis` is a post-binding verification pass that walks the bound tree to enforce
C# ref safety rules. It maintains two dictionaries:

- `_localEscapeScopes`: Maps each `LocalSymbol` to a tuple of `(RefEscapeScope, ValEscapeScope)`,
  both of type `SafeContext`. These determine how far a reference to or value of that local can
  escape.
- `_placeholderScopes`: Maps each `BoundValuePlaceholderBase` to a `SafeContextAndLocation`.
  Placeholders represent intermediate values in compound expressions (using statements, decon-
  structions, collection builders, etc.).

### What SafeContext Means

`SafeContext` is a `uint`-backed struct representing scope depth:

| Value | Name            | Meaning                                         |
|-------|-----------------|-------------------------------------------------|
| 0     | CallingMethod   | Can escape to caller (widest -- most permissive) |
| 1     | ReturnOnly      | Can be returned but not escape via ref parameter |
| 2     | CurrentMethod   | Cannot leave the method body                     |
| 3+    | (nested scopes) | Each nested block increments by 1 (narrower)     |

**Key rule**: A wider (smaller number) SafeContext `IsConvertibleTo` any narrower (larger number)
SafeContext. So CallingMethod(0) is convertible to everything. A scope at depth 5 is NOT
convertible to depth 3.

When checking if a ref can escape, the compiler calls `escapeTo.IsConvertibleTo(target)` --
if the expression's escape scope is too narrow (large number), it cannot escape to a wider
(smaller number) target, and the compiler emits an error.

### How Scopes Are Managed

When entering a block (`VisitBlock`), the walker:
1. Calls `_localScopeDepth = _localScopeDepth.Narrower()` (increments depth, e.g., 2 -> 3)
2. Adds locals with `refEscapeScope = _localScopeDepth` (the new narrow value)

When exiting a block (`LocalScope.Dispose`):
1. Calls `RemoveLocalScopes(local)` -- which is a NO-OP (removal commented out)
2. Calls `_localScopeDepth = _localScopeDepth.Wider()` (decrements depth, e.g., 3 -> 2)

---

## 2. Direction of the Bug: Over-Restrictive (NOT Over-Permissive)

### The Stale Entry Analysis

When `RemoveLocalScopes` does not actually remove a local's entry, the stale entry retains
the **narrow inner-scope value** it was assigned at creation time.

Example scenario:
```
method body (_localScopeDepth = 2)
{
    inner block (_localScopeDepth = 3)
    {
        int x;  // Added with RefEscapeScope = 3
    }
    // After Dispose: _localScopeDepth back to 2
    // Stale entry for x remains: RefEscapeScope = 3
}
```

If the stale entry for `x` is ever looked up again, it returns scope 3 (narrow/restrictive).

Compare this to what would happen if the entry WERE removed -- the fallback in
`GetLocalScopes` (line 231):
```csharp
return _localEscapeScopes?.TryGetValue(local, out var scopes) == true
    ? scopes
    : (SafeContext.CurrentMethod, SafeContext.CallingMethod);
```

The fallback returns `CurrentMethod` (2) for RefEscapeScope and `CallingMethod` (0) for
ValEscapeScope. These are WIDER (more permissive) than the stale entry values.

**Therefore: keeping stale entries is the SAFER behavior.** Removing them would make the
analysis MORE permissive, not less. The commented-out removal would actually be the riskier
change.

### Why the Entries Are Kept (Issue #65961)

The comment on both methods says:

> Currently, analysis may require subsequent calls to GetRefEscape(), etc. for the same
> expression so we cannot remove placeholders/locals eagerly.

This happens because some bound tree patterns cause the same `BoundExpression` to be
analyzed for its escape properties more than once. For example, when checking a return
statement, the return expression's escape is computed, but the same expression may have
already been analyzed during declaration processing or argument checking. Without the
stale entry, the second lookup would hit the fallback and return a MORE PERMISSIVE scope,
potentially allowing an unsafe escape.

The stale entries are a **safety net**, not a vulnerability.

### Verification via DEBUG Assertions

The DEBUG build has explicit protection against re-visiting expressions (line 351):
```csharp
bool added = _visited.Add(expr);
RoslynDebug.Assert(added, $"Expression {expr} `{expr.Syntax}` visited more than once.");
```

This confirms that the Roslyn team is aware of the re-visit concern and actively guards
against it in Visit() calls. The GetRefEscape/GetValEscape calls that need stale data
are separate from Visit() calls.

---

## 3. Can This Be Flipped to Over-Permissive?

### Scenario Analysis

For this to become a security bug, we would need stale entries to cause a WIDER escape
scope than correct. This cannot happen because:

1. **Dictionary keys are identity-based.** `LocalSymbol` objects are unique per declaration.
   A new local in an outer scope is a different object -- it cannot collide with a stale
   entry from an inner scope, even if it has the same name.

2. **Lambdas and local functions create fresh analyzers.** Lines 378 and 387 show that
   `VisitLocalFunctionStatement` and `VisitLambda` each instantiate a new
   `RefSafetyAnalysis` with empty dictionaries. No stale entries leak across function
   boundaries.

3. **Stale values are always narrower.** Inner scopes have strictly larger depth values.
   The stale entry preserves this narrow (restrictive) value. After the scope exits and
   `_localScopeDepth` is decremented, the stale value is more restrictive than the current
   context.

4. **No mutation of stale entries.** `SetLocalScopes` has a debug assert that the key
   exists, but it is only called for locals that are currently in scope during
   `VisitLocalDeclaration`. There is no code path that would widen a stale entry's scope.

### Edge Cases Considered

- **Pattern matching with `is` declarations**: Pattern variables use `LocalScope` with the
  same Add/Remove lifecycle. Stale entries retain restrictive scopes. Not exploitable.

- **`using` statements with `await`**: These use `PlaceholderRegion` for await pattern
  placeholders. Same issue -- stale placeholder entries retain their original (correct)
  scope values.

- **Deconstruction assignments**: `VisitDeconstructionAssignmentOperator` creates
  placeholders with `GetValEscape(right)`. Stale entries preserve this value faithfully.

- **Collection expressions with spreads**: Line 1410 shows spread element placeholders.
  Same pattern -- stale entries are correct or overly restrictive.

---

## 4. Attempted PoC Construction

To exploit this, I would need to construct C# code where:
1. A local's stale scope entry causes the compiler to ACCEPT an escape that should be rejected
2. This creates a dangling ref at runtime

This is impossible with the current bug direction because stale entries are NARROWER than
correct. Any escape check against a stale entry would be MORE likely to fail (produce a
compile error), not less.

### Illustrative Non-PoC

The closest attack surface would be something like:

```csharp
ref struct RS { public Span<int> span; }

RS Escape()
{
    {
        // Inner scope: local gets RefEscapeScope = 3 (narrow)
        Span<int> inner = stackalloc int[10];
        // If stale entry somehow gave scope 0 (CallingMethod), this could escape
        // But stale entry retains scope 3 -- MORE restrictive
    }
    // Cannot reference 'inner' here -- it is out of scope at the language level
    // The bound tree will not contain a BoundLocal for 'inner' in this position
    return default;
}
```

The fundamental barrier: the bound tree respects lexical scoping. You cannot have a
`BoundLocal` node referencing a local that is out of its lexical scope. The stale dictionary
entries exist only for cases where the same in-scope expression is analyzed multiple times
during a single walk of the tree.

---

## 5. Impact Assessment

### Security Impact: None

- **Direction**: Over-restrictive (or neutral). The bug causes valid code to potentially
  be rejected, not invalid code to be accepted.
- **No dangling refs**: Cannot produce a dangling reference because stale entries never
  widen escape scopes.
- **No type confusion**: Cannot produce type confusion because the ref safety system does
  not interact with type identity.
- **No RCE path**: Without a safety violation, there is no path to memory corruption or
  arbitrary code execution.

### Actual Impact

- **Memory**: Dictionaries grow monotonically during analysis of a method body. For methods
  with many nested scopes and locals, this is a minor memory waste during compilation.
- **Correctness**: The stale entries provide CORRECT scope values for subsequent lookups,
  which is WHY they are kept. Removing them would cause incorrect (over-permissive) fallback
  behavior.
- **Performance**: Negligible. Dictionary entries are small, and method bodies rarely have
  enough locals for this to matter.

### MSRC Bounty Eligibility

**Not eligible.** This finding:
- Does not violate any safety guarantee of managed C#
- Cannot produce memory corruption
- Cannot be used to bypass ref safety checks
- Is a deliberate engineering decision, not an oversight
- The tracking issue #65961 indicates the team is aware and considers it acceptable

---

## 6. Summary

The commented-out `Remove` calls in `RemovePlaceholderScope` and `RemoveLocalScopes` are
a **deliberate safety-preserving decision**, not a vulnerability. The stale dictionary
entries retain narrow (restrictive) scope values that prevent the analysis from falling
through to an over-permissive default. Removing the entries would be the dangerous change,
not keeping them.

The Roslyn team explicitly documented this in the code comments and tracking issue #65961.
The "bug" is that the dictionaries never shrink during analysis, which is a minor memory
concern, not a security boundary violation.

**Classification: Correctness/Performance issue. Not a security vulnerability.**
**Exploitability: None.**
**Bounty potential: $0.**
