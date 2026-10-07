# F5: CryptoConfig.CreateFromName -- Type Instantiation via SignedXml

## Deep Dive: Gadget Chain Analysis

### 1. Exact Type Resolution Scope

#### CryptoConfig.CreateFromName Resolution Order

File: `src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptoConfig.cs`

When `CryptoConfig.CreateFromName(name)` is called, it follows this resolution order:

1. **`appNameHT`** (line 383): Application-registered algorithms via `CryptoConfig.AddAlgorithm()`. Contains `Type` objects directly -- no type resolution needed.

2. **`DefaultNameHT`** (line 388): Hardcoded map of ~89 entries. Values are either:
   - `Type` objects (for types in the same assembly) -- used directly, no resolution
   - `string` values (assembly-qualified names for types in other assemblies like `System.Security.Cryptography.Pkcs`) -- resolved via `Type.GetType(retvalString, false, false)` at line 396. These are TRUSTED hardcoded strings, not attacker-controlled.

3. **ECDsa special case** (line 417-422): Only matches `"ECDsa"` exactly.

4. **`Type.GetType(name, false, false)` fallback** (line 427): This is the CRITICAL path for attacker-controlled input. Without an assembly-qualified name (no comma), `Type.GetType` in .NET Core searches:
   - The **calling assembly**: `System.Security.Cryptography` (where CryptoConfig lives)
   - **System.Private.CoreLib**

   It does **NOT** search other loaded assemblies. This is a hard .NET runtime constraint.

5. **Visibility check** (line 428-430): `retvalType.IsVisible` must be true (public type in a public-visible hierarchy).

#### CryptoHelpers Filter (the gateway)

File: `src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/CryptoHelpers.cs`

All attacker-controlled input goes through `CryptoHelpers.CreateFromName<T>()` (line 67-92), which applies:

```csharp
private static readonly SearchValues<char> s_invalidChars = SearchValues.Create(",`[*&+");
```

This blocks:
- `,` -- assembly-qualified names (`System.Foo, Assembly`)
- `` ` `` -- generic types (`List`1`)
- `[` -- array types, constructed generics
- `*` -- pointer types
- `&` -- reference types
- `+` -- nested types

**Consequence**: Without commas, `Type.GetType(name)` can ONLY resolve types in CoreLib + System.Security.Cryptography. The scope is fixed and narrow.

#### The KeyAlgorithm Path (SignedXml.cs:1019)

```csharp
Type ta = Type.GetType(signatureDescription.KeyAlgorithm!)!;
```

**This is NOT attacker-controlled.** The `signatureDescription` object is created by `CryptoHelpers.CreateNonTransformFromName<SignatureDescription>(SignatureMethod)` at line 1014, which applies the full comma filter. The `KeyAlgorithm` property is set by the SignatureDescription's constructor, not by the XML input.

Built-in SignatureDescription subclasses set KeyAlgorithm to assembly-qualified names:
- `typeof(RSA).AssemblyQualifiedName` (RSAPKCS1SignatureDescription.cs:12)
- `typeof(DSA).AssemblyQualifiedName` (DSASignatureDescription.cs:14)

These are hardcoded trusted values. For this path to be attacker-controlled, the attacker would need to:
1. Get `CryptoConfig.CreateFromName` to instantiate a custom `SignatureDescription` subclass
2. That subclass would need a parameterless constructor
3. That subclass's constructor would need to set `KeyAlgorithm` to an attacker-chosen value

**This is a dead end for the built-in types.** The only reachable `SignatureDescription` via Type.GetType (without assembly qualifier) is the base class `System.Security.Cryptography.SignatureDescription`, which has an empty parameterless constructor and sets `KeyAlgorithm = null`.

If `KeyAlgorithm` is null, line 1019 would throw a NullReferenceException, which propagates up but is not a security issue.

### 2. Gadget Type Hunt

#### The Core Attack Primitive

The attacker controls `SignatureMethod` in the XML. Via `CryptoHelpers.CreateNonTransformFromName<SignatureDescription>(SignatureMethod)`:

1. Name passes the `,``[*&+` filter
2. Not found in DefaultNameHT or CreateFromKnownName
3. Falls through to `CryptoConfig.CreateFromName(name)`
4. Not found in appNameHT or DefaultNameHT
5. `Type.GetType(name, false, false)` resolves the type in CoreLib or System.Security.Cryptography
6. Type is instantiated via parameterless constructor
7. Result cast `as SignatureDescription` -- returns null for non-SignatureDescription types
8. **But the constructor already ran** (line 483 of CryptoConfig.cs)

The exception handler in CryptoHelpers (line 88: `catch (Exception) { return null; }`) swallows any exception from the constructor, but side effects before the throw persist.

#### CoreLib Types with Parameterless Constructors -- Assessment

Searched all public types in `System.Private.CoreLib/src/System/` with parameterless constructors. Findings:

| Type | Constructor Effect | Security Impact |
|------|-------------------|-----------------|
| `System.Threading.Mutex` | Creates OS kernel mutex | Resource leak only (DoS at scale) |
| `System.Threading.ThreadLocal` | Allocates TLS slot | No security impact |
| `System.Threading.SynchronizationContext` | No-op constructor | None |
| `System.Security.SecureString` | Allocates protected buffer | No security impact |
| `System.Threading.Tasks.TaskFactory` | No-op constructor | None |
| `System.Progress` | Captures SynchronizationContext | No security impact |
| Collections (ArrayList, List, etc.) | Array allocation | None |
| Exceptions (various) | String allocation | None |
| Attributes (various) | No-op | None |

**No types in CoreLib have parameterless constructors with exploitable side effects.** CoreLib types requiring OS interaction (FileStream, Process, Socket, etc.) all require parameters in their constructors.

#### System.Security.Cryptography Types -- Assessment

| Type | Constructor Effect | Security Impact |
|------|-------------------|-----------------|
| `SignatureDescription` | No-op | None |
| `X509Chain` | No-op (empty body) | None |
| `X509Store` | Sets store name to "MY" | None until Open() called |
| `RSAPKCS1SignatureDeformatter` | No-op | None |
| `DSASignatureFormatter` | No-op | None |
| Various HMAC types | **Generates random key** | Key material in memory, but inaccessible |
| AesManaged, RijndaelManaged | **Generates random key and IV** | Key material in memory, but inaccessible |

The HMAC and symmetric cipher types generate random key material in their constructors, but:
1. The object is discarded (cast `as SignatureDescription` returns null)
2. The key material is GC'd and inaccessible to the attacker
3. No network/file/process side effects occur

#### Finalizer Abuse Assessment

Several CoreLib types have finalizers (~Destructor), which run when the object is garbage-collected. Types instantiated by CryptoConfig that have finalizers:

- `System.Threading.ThreadLocal` -- finalizer cleans up TLS values
- `System.Threading.Mutex` -- releases kernel handle
- Various internal types (not reachable via IsVisible check)

Finalizer abuse would require the finalizer itself to have a security-relevant side effect when operating on a default-constructed object. None of the reachable types' finalizers do anything beyond resource cleanup.

### 3. The KeyAlgorithm Path (Unfiltered) -- Re-Analysis

The claim that `SignedXml.cs:1019` calls `Type.GetType(signatureDescription.KeyAlgorithm!)` with "NO filter" is **technically correct but misleading**.

```csharp
// Line 1014
SignatureDescription? signatureDescription = CryptoHelpers.CreateNonTransformFromName<SignatureDescription>(SignatureMethod);
// Line 1019
Type ta = Type.GetType(signatureDescription.KeyAlgorithm!)!;
```

The `KeyAlgorithm` value comes from the `SignatureDescription` object, not from the XML. The attack would require:

1. **Step 1**: Get `CryptoConfig.CreateFromName` to return an object that IS a `SignatureDescription` (passes the `as SignatureDescription` cast)
2. **Step 2**: That SignatureDescription has a `KeyAlgorithm` that resolves to a dangerous type

For Step 1, the only reachable `SignatureDescription` subclass via `Type.GetType` without assembly qualifier is the base class itself. Its parameterless constructor sets `KeyAlgorithm = null`, causing a NullReferenceException at line 1019.

**Could a custom SignatureDescription subclass exist in CoreLib or System.Security.Cryptography?**

Searched both assemblies:
- CoreLib: No SignatureDescription subclasses
- System.Security.Cryptography: No public SignatureDescription subclasses (the ones in System.Security.Cryptography.Xml are `internal`)

**Verdict: The KeyAlgorithm path is unreachable with the default runtime assemblies.**

#### Assembly-Qualified Names in KeyAlgorithm

If an attacker COULD control `KeyAlgorithm` (e.g., via a custom registered SignatureDescription), the `Type.GetType` call at line 1019 has NO character filter. Assembly-qualified names with commas would work, expanding the type resolution scope to any loaded assembly.

However, `Type.GetType` only resolves the type -- it does NOT instantiate it. Line 1019 just gets the `Type` object, then passes it to `IsKeyTheCorrectAlgorithm` which only does type hierarchy comparison. No constructor invocation occurs.

**The KeyAlgorithm path is not a gadget chain -- it never instantiates a type.**

### 4. CryptoConfig.AddAlgorithm Vector

```csharp
public static void AddAlgorithm(Type algorithm, params string[] names)
```

If an application registers a custom algorithm via `CryptoConfig.AddAlgorithm(typeof(MySignatureDescription), "my-sig-algo")`, then an attacker setting `SignatureMethod="my-sig-algo"` would:

1. Match in `appNameHT`
2. Instantiate `MySignatureDescription` via its parameterless constructor
3. Successfully cast as `SignatureDescription`
4. Use its `KeyAlgorithm`, `DigestAlgorithm`, `FormatterAlgorithm`, and `DeformatterAlgorithm` properties

**This expands the gadget surface significantly**, but it's application-specific:

- The custom SignatureDescription's `CreateDeformatter()` calls `CryptoConfig.CreateFromName(DeformatterAlgorithm!)` -- this call goes through `CryptoConfig` directly, WITHOUT the CryptoHelpers comma filter
- Similarly, `CreateDigest()` calls `CryptoConfig.CreateFromName(DigestAlgorithm!)`
- If the custom class sets `DeformatterAlgorithm` or `DigestAlgorithm` to assembly-qualified strings, those resolve via `Type.GetType` with full assembly search

However, this requires the application to have already registered a custom SignatureDescription with exploitable property values. The attacker cannot influence what AddAlgorithm registers.

**Real-world prevalence**: Applications using custom XML signature algorithms (e.g., national cryptography standards) might register custom SignatureDescription subclasses. But these would typically point to legitimate crypto implementations, not gadget types.

### 5. Attack Chain Assessment

#### Attempted Chain: Type Instantiation via SignatureMethod

**XML Payload**:
```xml
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="System.Threading.Mutex"/>
    <Reference URI="">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue>...</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>...</SignatureValue>
</Signature>
```

**Flow**:
1. `SignedXml.LoadXml()` parses the XML
2. `SignedXml.CheckSignature()` calls `CheckSignatureReturningKey()`
3. `CheckSignatureFormat()` passes (valid canonicalization)
4. `GetPublicKey()` returns a key from KeyInfo
5. `CheckSignedInfo(key)` is called
6. `CryptoHelpers.CreateNonTransformFromName<SignatureDescription>("System.Threading.Mutex")` is called
7. No match in DefaultNameHT or CreateFromKnownName
8. `CryptoConfig.CreateFromName("System.Threading.Mutex")` is called
9. No match in appNameHT or DefaultNameHT
10. `Type.GetType("System.Threading.Mutex", false, false)` -- **resolves from CoreLib**
11. Parameterless constructor found and invoked -- **creates a kernel mutex**
12. Cast `as SignatureDescription` returns null
13. CryptoHelpers returns null
14. `CheckSignedInfo` throws `CryptographicException("SignatureDescription could not be created")`

**Impact**: A single unnamed kernel mutex is created. The object is immediately eligible for GC. The finalizer releases the handle. This is a trivial resource leak, not a security vulnerability.

#### Multiple Instantiations via Multiple Paths

The attacker controls several algorithm URIs in the XML:
- `SignatureMethod` (checked in CheckSignedInfo, DoesSignatureUseTruncatedHmac)
- `DigestMethod` per Reference (checked in CheckDigestedReferences)
- `Transform Algorithm` per Reference (checked during transform chain loading)
- `CanonicalizationMethod` (checked via CanonicalizationMethodObject)

Each goes through `CryptoHelpers.CreateFromName<T>()` with the same comma filter. Different `T` types are used (SignatureDescription, HMAC, HashAlgorithm, Transform), but the constructor-fires-before-cast primitive is the same.

Even with multiple paths, the reachable types (CoreLib + System.Security.Cryptography, public, parameterless constructor, no blocked characters in name) have no exploitable constructors.

### 6. Why No Gadgets Were Found -- And What Would Change the Answer

#### Why the Attack Surface is Narrow

1. **Type.GetType without assembly qualifier**: Only searches CoreLib + calling assembly. This is the single most important limitation. Unlike .NET Framework's `Type.GetType`, .NET Core does NOT search all loaded assemblies.

2. **The comma filter in CryptoHelpers**: Blocks assembly-qualified names, preventing cross-assembly type resolution.

3. **Parameterless constructor requirement**: `CryptoConfig.CreateFromName` with no args (as called from SignedXml) requires a parameterless constructor. Dangerous types (Process, FileStream, Socket, HttpClient, etc.) all require parameters.

4. **CoreLib design**: System.Private.CoreLib types with parameterless constructors are data structures, value holders, and synchronization primitives. None perform external I/O in their constructors.

#### What Would Expand the Gadget Surface

**Scenario 1: Application registers a custom algorithm via CryptoConfig.AddAlgorithm**

If an app does:
```csharp
CryptoConfig.AddAlgorithm(typeof(MyDangerousType), "innocent-looking-uri");
```

The attacker can instantiate `MyDangerousType` by using `SignatureMethod="innocent-looking-uri"`. However:
- The attacker must know the registered URI
- The registered type must have exploitable constructor side effects
- This is an application-specific vulnerability, not a framework vulnerability

**Scenario 2: A NuGet package adds types to CoreLib or System.Security.Cryptography assembly**

This doesn't happen in .NET Core -- NuGet packages cannot inject types into framework assemblies.

**Scenario 3: .NET Framework (not .NET Core)**

In .NET Framework, `Type.GetType` has different type resolution behavior. With `Type.GetType(string)`, it may search assemblies loaded in the current AppDomain depending on version and configuration. This would significantly expand the gadget surface. However, the comma filter in CryptoHelpers (added in recent versions) would still apply.

**Scenario 4: The comma filter is bypassed**

If a way were found to bypass the CryptoHelpers filter (e.g., a path that calls CryptoConfig.CreateFromName directly without going through CryptoHelpers), assembly-qualified names would work, and any loaded assembly's types would be reachable.

Checking all callers: The `SignatureDescription.CreateDeformatter()`, `CreateFormatter()`, and `CreateDigest()` methods call `CryptoConfig.CreateFromName()` directly (NOT through CryptoHelpers). But the values passed are `DeformatterAlgorithm`, `FormatterAlgorithm`, and `DigestAlgorithm` -- properties set by the SignatureDescription's constructor, not by the attacker. To reach these paths, the attacker first needs a controlled SignatureDescription, which requires the AddAlgorithm vector above.

**Scenario 5: Future types added to CoreLib with dangerous constructors**

If a future .NET release adds a public type to CoreLib with a parameterless constructor that performs external I/O, opens files, or makes network connections, it would become a gadget. This is unlikely given CoreLib's design philosophy.

### 7. Verdict

**Finding classification: Defense-in-depth concern, not an exploitable vulnerability.**

The type instantiation primitive exists: an attacker can cause `CryptoConfig.CreateFromName` to instantiate arbitrary types in CoreLib/System.Security.Cryptography via the `Type.GetType` fallback. Constructor side effects fire before the `as T` cast check. However:

1. **No usable gadgets exist** in the reachable type scope (CoreLib + System.Security.Cryptography)
2. **The KeyAlgorithm path** (line 1019) is not attacker-controlled -- it gets its value from a SignatureDescription object's property, not from XML input
3. **The comma filter** in CryptoHelpers effectively constrains the resolution scope to two assemblies
4. **Maximum achievable impact** with default .NET runtime: creation of a few kernel objects (Mutex, EventWaitHandle) that are immediately GC'd -- trivial resource leak, no information disclosure, no code execution

**MSRC bounty eligibility**: Does not meet the bar. No security bypass, no RCE, no information disclosure. The type instantiation primitive requires gadget types that don't exist in the reachable assemblies.

**Recommendations for the report**:
- Document as a design weakness that COULD become exploitable if CoreLib adds types with dangerous parameterless constructors
- Note that the CryptoHelpers comma filter is the key defense -- any bypass of it would be a separate, potentially high-severity finding
- The `CryptoConfig.AddAlgorithm` vector is application-specific and outside the framework's threat model
- Consider filing as "information" with the note that the primitive exists and future types should be evaluated against it
