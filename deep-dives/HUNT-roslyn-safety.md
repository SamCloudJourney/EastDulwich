# HUNT: Roslyn Compiler Safety Analysis

**Target**: dotnet/roslyn (C# compiler)
**Repo**: `/home/user/dotnet-hunt/roslyn/`
**Goal**: Find MSRC-eligible vulnerabilities (Critical/Important) that cross a security boundary

## Executive Summary

After systematic investigation of six focus areas (type safety, ref struct escaping, definite assignment, source generators, scripting API, code gen corruption), **no confirmed MSRC-eligible vulnerabilities were found**. The Roslyn compiler's safety checks are thorough and well-integrated. Several design-level observations are noted below, but none cross a security boundary in a way that MSRC would accept.

---

## Focus Area 1: Type Safety Violations

### Variance Conversion Checking

**Files examined**:
- `src/Compilers/CSharp/Portable/Binder/Semantics/Conversions/ConversionsBase.cs` (lines 3041-3267)
- `src/Compilers/CSharp/Portable/Symbols/ConstraintsHelper.cs` (lines 946-1048)

**Finding**: The variance checking in `HasVariantConversionNoCycleCheck` correctly handles the `allows ref struct` constraint. Specifically:
- `HasImplicitBoxingTypeParameterConversion` (line 3280-3283) correctly returns `false` for `AllowsRefLikeType` type parameters, preventing boxing of ref structs through variance
- `IsRefLikeOrAllowsRefLikeTypeImplementingVarianceCompatibleInterface` (lines 3041-3053) handles ref structs that implement variant-compatible interfaces
- `CheckBasicConstraints` (lines 963-986) properly rejects ref struct type arguments unless the type parameter has `AllowsRefLikeType`
- Cycle detection uses `MaximumRecursionDepth = 50` which is sufficient

**Verdict**: Sound. No type confusion possible through variance + ref structs.

### Union Type Conversions (New Feature)

**Files examined**:
- `src/Compilers/CSharp/Portable/Binder/Semantics/Conversions/UserDefinedImplicitConversions.cs` (line 984+)
- `src/Compilers/CSharp/Portable/Binder/Binder.ValueChecks.cs` (lines 4618-4626, 5407-5418)

**Finding**: Union conversions (`IsUnion`) are treated identically to user-defined conversions for ref safety analysis. Both `GetValEscape` and `CheckValEscape` handle them via `GetInvocationEscapeScope`/`CheckInvocationEscape` using `MethodInvocationInfo.FromUserDefinedOrUnionConversion`. No separate code path that could miss safety checks.

**Verdict**: Sound. Union conversions inherit all safety analysis from user-defined conversions.

---

## Focus Area 2: Span Safety and Ref Struct Escaping

### `allows ref struct` Integration

**Files examined**:
- `src/Compilers/CSharp/Portable/Symbols/TypeSymbolExtensions.cs` (lines 585-588, 1516-1530)
- `src/Compilers/CSharp/Portable/Lowering/StateMachineRewriter/IteratorAndAsyncCaptureWalker.cs` (line 231, 143-156)
- `src/Compilers/CSharp/Portable/Symbols/Source/SourceMethodSymbol.cs` (lines 63-82)

**Finding**: The critical type check `IsRefLikeOrAllowsRefLikeType()` is used consistently throughout:
- `IsRestrictedType()` calls `IsRefLikeOrAllowsRefLikeType()` -- so all restricted-type checks cover `allows ref struct` type parameters
- `CaptureVariable` in `IteratorAndAsyncCaptureWalker` uses `IsRestrictedType()` to prevent capture across await/yield
- `HoistInDebugBuild` checks `IsRestrictedType()` before hoisting
- `ReportAsyncParameterErrors` in `SourceMethodSymbol` checks `IsRestrictedType()` for async parameters

**Verdict**: Sound. The `allows ref struct` feature is properly integrated into all ref struct restriction checks.

### UnscopedRefAttribute from Metadata

**Files examined**:
- `src/Compilers/CSharp/Portable/Symbols/Metadata/PE/PEParameterSymbol.cs` (lines 321-345)
- `src/Compilers/CSharp/Portable/Symbols/Metadata/PE/PEMethodSymbol.cs` (lines 1802-1815)
- `src/Compilers/CSharp/Portable/Symbols/Metadata/PE/PEPropertySymbol.cs` (lines 648-661)
- `src/Compilers/CSharp/Portable/Binder/Binder.ValueChecks.cs` (lines 1536-1544)

**Finding**: The compiler reads `[UnscopedRef]` from metadata and trusts it for ref safety analysis. When present, it sets `ScopedKind.None` and widens the escape scope. This means a malicious NuGet package could provide a DLL with `[UnscopedRef]` on inappropriate parameters, causing the consuming compiler to generate code with wider escape scopes than safe.

However, this follows the same trust model as all other metadata attributes (`readonly`, `ref`, `out`, `in`, etc.). The security boundary here is between the assembly author and consumer, which is the standard binary compatibility trust boundary. MSRC does not consider "trusting a referenced assembly" as crossing a security boundary -- if you reference a malicious DLL, any safety guarantee can be violated at the IL level regardless.

**Verdict**: By design. Not MSRC-eligible. Same trust model as all metadata.

### Spill Sequence Spiller

**Files examined**:
- `src/Compilers/CSharp/Portable/Lowering/SpillSequenceSpiller.cs` (lines 337, 440-490)

**Finding**: The spiller has special handling for `Span<T>` and `ReadOnlySpan<T>` operations (get_Item, Slice), inline array helpers, and `string` to `ReadOnlySpan<char>` conversion. Each is handled individually with explicit receiver and argument spilling. The `IsRefLikeOrAllowsRefLikeType()` check at line 337 ensures ref-like sequences are handled correctly. The `goto default` at line 477 for unrecognized ref-struct-returning calls will fall through to the general case, which asserts in debug builds for unhandled cases.

**Verdict**: Sound. Special cases are all individually handled with correct ref kinds.

### Collection Expression Escape Scope

**Files examined**:
- `src/Compilers/CSharp/Portable/Binder/Binder.ValueChecks.cs` (lines 4773-4831)

**Finding**: `GetCollectionExpressionSafeContext` has explicit handling for each collection type kind:
- `ReadOnlySpan`: CallingMethod if using RuntimeHelpers.CreateSpan (data segment), otherwise localScopeDepth
- `Span`: Always localScopeDepth (stack allocated)
- `CollectionBuilder`: Delegates to `GetValEscape(expr.CollectionCreation)` which traces through the builder method
- `ImplementsIEnumerable`: Intersects receiver scope with all element scopes

**Verdict**: Sound. Correctly models the actual allocation strategy for each collection expression kind.

---

## Focus Area 3: Definite Assignment Analysis Bypass

### Conditional Access

**Files examined**:
- `src/Compilers/CSharp/Portable/FlowAnalysis/AbstractFlowPass.cs` (lines 2587-3141)

**Finding**: Conditional access (`?.`) is handled by `VisitPossibleConditionalAccess` which returns a `stateWhenNotNull` separate from the regular state. This is used in binary operators, `is` operators, and `as` operators. The `VisitConditionalAccess` method (line 3069) properly handles nested conditional access chains by propagating `stateWhenNotNull` through the chain while joining with saved state. The null-path state correctly does not include side effects from the conditional access.

**Verdict**: Sound. The split-state model for conditional access correctly tracks assignment in both null and non-null paths.

### Local Functions

**Files examined**:
- `src/Compilers/CSharp/Portable/FlowAnalysis/DefiniteAssignment.LocalFunctions.cs`

**Finding**: Local functions use a replay-based approach. `RecordReadInLocalFunction` tracks which variables are read, and `VisitLocalFunctionUse` replays these reads at each call site. The bottom state assumes all variables assigned (safe starting point), and reads are replayed using `CheckIfAssignedDuringLocalFunctionReplay` which checks assignment at the actual call site. `skipIfUseBeforeDeclaration: false` ensures forward-referencing local functions still get proper checking.

**Verdict**: Sound. The replay approach correctly handles the interaction between local function analysis and enclosing scope definite assignment.

### Switch Expression Exhaustiveness

**Files examined**:
- `src/Compilers/CSharp/Portable/Binder/SwitchExpressionBinder.cs` (lines 61-144)
- `src/Compilers/CSharp/Portable/Lowering/LocalRewriter/LocalRewriter_SwitchExpression.cs` (lines 89, 132-143)

**Finding**: Non-exhaustive switch expressions produce only a warning (`WRN_SwitchExpressionNotExhaustive`), not an error. However, this does NOT lead to uninitialized variable access because:
- The lowering always generates a default branch that throws `SwitchExpressionException` (lines 132-143)
- A `resultTemp` local is assigned in each arm, and the default path throws before the local could be read uninitialized

**Verdict**: Sound. The throw in the default path prevents any safety issue from the warning-only exhaustiveness check.

---

## Focus Area 4: Source Generator Security

### Sandboxing

**Files examined**:
- `src/Compilers/Core/Portable/SourceGeneration/GeneratorDriver.cs`
- `src/Compilers/Core/Portable/SourceGeneration/UserFunction.cs`
- `src/Compilers/Core/Portable/SourceGeneration/GeneratorContexts.cs`
- `src/Compilers/Core/Portable/SourceGeneration/IncrementalContexts.cs`

**Finding**: Source generators run with **no sandboxing whatsoever**. They:
- Execute as regular .NET code with full framework access (file system, network, process creation)
- Receive the full `Compilation` object, giving access to all source code and referenced assemblies
- Are wrapped only in `UserFunctionException` for error reporting, not for security isolation
- The `WrapUserFunction` pattern catches exceptions but only to re-wrap them; it does not restrict capabilities

This means a malicious NuGet package containing a source generator has arbitrary code execution during compilation. However, this is a **known design choice** and is documented. Source generators are explicitly treated as trusted code because they are explicitly referenced via `<Analyzer>` or `<PackageReference>` items. The trust boundary is the package reference itself, not the compilation process.

**Verdict**: By design. Not MSRC-eligible. Source generators are trusted code by the compilation model.

---

## Focus Area 5: Scripting API Sandbox Escape

### CSharpScript Defaults

**Files examined**:
- `src/Scripting/Core/ScriptOptions.cs` (line 36)

**Finding**: `ScriptOptions.Default` sets `allowUnsafe: true`, and there is no sandboxing mechanism in the scripting API. Scripts can:
- Reference arbitrary assemblies via `MetadataReferences`
- Use custom `MetadataResolver` instances
- Execute unsafe code (pointers, fixed statements)

However, the scripting API is explicitly designed as a tool for the host application, not as a sandboxed execution environment. The host is responsible for controlling what scripts can do. There is no claim of a security boundary between the script and the host.

**Verdict**: By design. Not MSRC-eligible. The scripting API does not claim to provide a security sandbox.

---

## Focus Area 6: Compiler Crash Leading to Code Gen Corruption

### Inline Array Conversion

**Files examined**:
- `src/Compilers/CSharp/Portable/Symbols/Synthesized/SynthesizedInlineArrayAsSpanMethod.cs`
- `src/Compilers/CSharp/Portable/Symbols/Metadata/PE/PENamedTypeSymbol.cs` (lines 3110-3119)
- `src/Compilers/CSharp/Portable/Binder/Binder_Conversions.cs` (lines 600-621)

**Finding**: The inline array to Span conversion uses `MemoryMarshal.CreateSpan(ref Unsafe.As<TBuffer, TElement>(ref buffer), length)`. The `length` comes from `HasInlineArrayAttribute(out int length)` which reads from metadata and only validates `length > 0`. However, the CLR runtime uses the same `InlineArrayAttribute` for its memory layout, so the length is consistent between what the compiler trusts and what the runtime does.

The `ThrowIfInlineArrayIsNullRef` check prevents null reference issues. The synthesized method correctly handles the ref safety by using the buffer's ref escape scope.

**Verdict**: Sound. The metadata trust is consistent with the CLR runtime's interpretation.

### Extension Types and Ref Safety

**Files examined**:
- `src/Compilers/CSharp/Portable/Symbols/Source/SourceNamedTypeSymbol_Extension.cs`
- `src/Compilers/CSharp/Portable/Binder/WithExtensionParameterBinder.cs`

**Finding**: Extension types (C# 14 feature) use `WithExtensionParameterBinder` to place the extension parameter in scope. This binder only handles lookup, not ref safety. The extension parameter's ref safety is handled through the normal `ParameterSymbol` ref escape mechanisms. The `ComputeExtensionGroupingRawName` method correctly encodes `AllowsRefLikeType` in the extension grouping name for uniqueness.

**Verdict**: Sound. Extension types delegate ref safety to existing mechanisms.

---

## Overall Assessment

The Roslyn compiler's safety analysis is mature and well-tested. The key safety mechanisms are:

1. **`IsRefLikeOrAllowsRefLikeType()`** is consistently used across all ref struct restriction checks
2. **`IsRestrictedType()`** correctly chains to `IsRefLikeOrAllowsRefLikeType()` for capture/hoist checks
3. **Ref escape analysis** properly handles user-defined conversions, union conversions, inline array conversions, collection expressions, and interpolated string handlers
4. **Definite assignment** correctly handles local functions, conditional access, and switch expressions
5. **Code generation** always produces a throw for non-exhaustive switch expressions

The main "design gaps" (source generator/scripting sandbox) are explicitly by design and do not cross a security boundary as defined by MSRC.

### Areas That Were Borderline But Not Exploitable

1. **UnscopedRef from metadata**: Could widen escape scopes if a malicious DLL is referenced, but this is the standard binary trust model
2. **Switch exhaustiveness as warning**: Could theoretically allow uninitialized reads if the default throw were missing, but it is always present
3. **Inline array length from metadata**: Consistent with CLR runtime interpretation, so no mismatch possible

### Recommendations for Further Investigation (Lower Priority)

- The `MaximumRecursionDepth = 50` in variance checking could theoretically be exhausted with deeply nested generic types, but this would produce a compile-time error (not silent acceptance)
- The spiller's `goto default` for unrecognized ref-struct patterns could potentially miss a case, but Debug.Assert would catch this in development builds
