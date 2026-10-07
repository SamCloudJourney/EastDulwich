# HUNT: ASP.NET Core Data Protection API Security Analysis

**Target:** `aspnetcore/src/DataProtection/` -- cryptographic data protection subsystem  
**Objective:** MSRC-eligible vulnerabilities (Critical/Important) that cross a security boundary  
**Bounty context:** Crypto bugs worth $30K+  

---

## Executive Summary

The ASP.NET Core Data Protection API is **well-defended** against the primary cryptographic attack classes. The implementation correctly applies Encrypt-then-MAC, per-operation subkey derivation with random key modifiers, timing-safe comparison, exception homogenization, and NIST SP 800-108 KDF. After a comprehensive code review of all five focus areas, **no Critical/Important MSRC-eligible vulnerabilities were identified** that cross a security boundary through a novel implementation flaw.

Several architectural design decisions create risk in specific deployment scenarios (particularly Linux defaults and shared hosting), but these are documented behaviors rather than implementation bugs, and Microsoft would likely classify them as by-design or configuration guidance issues.

---

## Detailed Analysis by Focus Area

### 1. Key Derivation (SP800-108 CTR-HMACSHA512)

**Files reviewed:**
- `DataProtection/src/SP800_108/ManagedSP800_108_CTR_HMACSHA512.cs`
- `DataProtection/src/Managed/ManagedAuthenticatedEncryptor.cs`
- `DataProtection/src/Cng/CbcAuthenticatedEncryptor.cs`

**Finding: Correctly implemented, no weakness found.**

The KDF follows NIST SP 800-108 Section 5.1 (CTR mode with HMAC-SHA512 as PRF). The PRF input format is: `{ [i]_2 || label || 0x00 || context || [L]_2 }`.

Per-operation subkey derivation uses a 128-bit random key modifier generated via `RandomNumberGenerator.Fill`. This is mixed into the KDF context alongside the AAD template (which contains purpose strings), producing unique (encryptionSubkey, validationSubkey) pairs per operation. This means:

- **Nonce reuse is prevented** -- even if the same plaintext is encrypted twice with the same key, the random key modifier produces different subkeys and thus different ciphertext.
- **IV collision risk is negligible** -- the 128-bit key modifier provides 2^128 possible subkeys per master key.
- **Cross-purpose decryption is blocked** -- purpose strings are baked into the KDF label/AAD, so derived subkeys differ between purposes.

On .NET 10+, a FIPS minimum key length of 14 bytes is enforced (zero-extending shorter keys). This is a correctness improvement, not a vulnerability.

**Verdict:** Not exploitable.

---

### 2. Purpose String Bypass / Cross-Application Decryption

**Files reviewed:**
- `DataProtection/src/KeyManagement/KeyRingBasedDataProtector.cs` (lines 325-418, `AdditionalAuthenticatedDataTemplate`)
- `DataProtection/src/KeyManagement/KeyRingBasedDataProtectionProvider.cs`
- `Abstractions/src/DataProtectionCommonExtensions.cs`
- `DataProtection/src/Internal/HostingApplicationDiscriminator.cs`
- `DataProtection/src/DataProtectionUtilityExtensions.cs`
- `Shared/Encoding/Int7BitEncodingUtils.cs`

#### 2a. Purpose String Encoding: No collision vulnerability

Purpose strings are encoded in the AAD template as:
```
{ magicHeader (32-bit) || keyId (128-bit GUID) || purposeCount (32-bit BE) || (purpose)* }
```
where each purpose is `{ utf8ByteCount (7-bit encoded) || utf8Text }`.

The length-prefixed encoding prevents the classic prefix/suffix collision attack. For example, purposes ["AB", "CD"] and ["A", "BCD"] produce different AAD bytes because each purpose's byte count is encoded separately. The 7-bit encoding has proper overflow protection (max 5 bytes for 32-bit int, validates last byte <= 0x0F).

**Verdict:** Not exploitable.

#### 2b. Empty Purpose Strings Allowed

`CreateProtector(string purpose)` only validates `purpose != null` (via `ArgumentNullThrowHelper.ThrowIfNull`). Empty strings are accepted. However, this does not create a security vulnerability because:

- An empty purpose string still encodes as `{ 0x00 }` (length=0, no bytes) in the AAD
- The purpose count is still incremented
- Two protectors with purposes ["", "admin"] vs ["admin"] produce different AAD bytes (different purpose counts)

**Verdict:** No security boundary crossed. Low-severity correctness concern only.

#### 2c. Application Discriminator: Cross-App Decryption Risk

`HostingApplicationDiscriminator` uses `IHostEnvironment.ContentRootPath` as the application discriminator. The discriminator becomes a purpose string prefix when the `DataProtectionProvider` wraps the raw provider.

If two ASP.NET Core applications on the same machine:
1. Share the same `ContentRootPath` (or both have empty/null content root), AND
2. Share the same key storage location (default: `$HOME/.aspnet/DataProtection-Keys/`)

Then they share the same key ring and can decrypt each other's data **even when using different purpose strings**, because the purpose-string isolation only separates within a single application instance. They effectively become the same application from Data Protection's perspective.

This is a real risk in shared hosting, but Microsoft documents `SetApplicationName` as the mitigation and considers the default behavior to be by-design for single-app deployments. An attacker would need to control application deployment (same user, same machine) which is already within the same trust boundary.

**Verdict:** By-design behavior. Not MSRC-eligible because the attacker must already have same-user, same-machine access.

---

### 3. Key Storage Security

**Files reviewed:**
- `DataProtection/src/Repositories/FileSystemXmlRepository.cs`
- `DataProtection/src/Repositories/DefaultKeyStorageDirectories.cs`
- `DataProtection/src/KeyManagement/XmlKeyManager.cs` (GetFallbackKeyRepositoryEncryptorPair)
- `DataProtection/src/XmlEncryption/NullXmlEncryptor.cs`
- `DataProtection/src/Repositories/RegistryXmlRepository.cs`
- `StackExchangeRedis/src/RedisXmlRepository.cs`
- `EntityFrameworkCore/src/EntityFrameworkCoreXmlRepository.cs`

#### 3a. No Encryption at Rest on Linux (by default)

`XmlKeyManager.GetFallbackKeyRepositoryEncryptorPair()` reveals:
- **Windows:** Uses DPAPI for key encryption at rest
- **Linux/macOS:** NO encryption at rest -- `NullXmlEncryptor` used, keys stored as plaintext XML
- **Azure Web Sites:** NO encryption at rest -- comment states "Cloud DPAPI isn't yet available"

The `NullXmlEncryptor` literally stores keys with a comment `"This key is not encrypted"`.

On Linux, keys are stored at `$HOME/.aspnet/DataProtection-Keys/`. The file permission model works as follows:
1. `Directory.Create()` creates the directory inheriting parent permissions (no explicit chmod)
2. For key files: `Path.GetTempFileName()` creates a temp file with mode 0600, which is then `File.Move`'d to the target directory

The temp-file-then-rename approach does preserve 0600 permissions on the final key file. However, the **directory itself** has no explicit permission restriction. If `$HOME` is world-readable (unusual but possible in some configurations), the key directory inherits those permissions.

**Verdict:** This is documented behavior and Microsoft treats it as a configuration guidance issue. The user is expected to configure key encryption (e.g., certificate-based) for production Linux deployments. Not MSRC-eligible because:
1. On a properly configured single-user Linux system, file permissions prevent cross-user access
2. Microsoft documents this limitation
3. The security boundary is the OS file permission model, which Data Protection relies on correctly

#### 3b. Type Instantiation from Key XML (Deserialization Attack Surface)

`XmlKeyManager.CreateDeserializer()` (line 594-620) and `XmlEncryptionExtensions.CreateDecryptor()` (line 70-99) both have fallback paths that pass attacker-controlled type names to `_activator.CreateInstance<T>()`. Specifically:

```csharp
// Line 619 - fallback for unknown deserializer types
return _activator.CreateInstance<IAuthenticatedEncryptorDescriptorDeserializer>(descriptorDeserializerTypeName);

// Line 98 - fallback for unknown decryptor types
return activator.CreateInstance<IXmlDecryptor>(decryptorTypeName);
```

`SimpleActivator.CreateInstance` resolves the type via `Type.GetType(typeName, throwOnError: true)` and instantiates it, checking that it's assignable to the expected interface. An attacker who can write to the key repository could inject a malicious XML key file with a crafted `deserializerType` attribute.

**However, exploitation requires:**
1. Write access to the key repository (filesystem, Redis, DB, etc.)
2. A type implementing `IAuthenticatedEncryptorDescriptorDeserializer` or `IXmlDecryptor` with dangerous constructor side effects
3. That type must be loadable via `Type.GetType`

Similarly, `ManagedAlgorithmHelpers.FriendlyNameToType()` allows loading arbitrary types for the encryption/validation algorithm attributes, but only checks for a public parameterless constructor -- it does not instantiate the type at that point (instantiation happens later when creating the encryptor).

**Verdict:** The type constraint to specific interfaces limits the gadget chain significantly. Combined with the prerequisite of write access to the key repository (already within the trust boundary), this does not cross a security boundary. A more realistic attack with repository write access would be to simply inject a known key and derive the subkeys to forge protected data.

#### 3c. Redis and EF Core Repositories: No Built-in Protection

`RedisXmlRepository` stores keys as plaintext strings in a Redis list. `EntityFrameworkCoreXmlRepository` stores keys as plaintext XML in a database table. Neither provides encryption, authentication, or access control beyond what the underlying storage offers.

**Verdict:** By-design. The security boundary is the storage system's access control.

---

### 4. Crypto Implementation Issues

**Files reviewed:**
- `DataProtection/src/Managed/ManagedAuthenticatedEncryptor.cs`
- `DataProtection/src/Managed/AesGcmAuthenticatedEncryptor.cs`
- `DataProtection/src/Cng/CbcAuthenticatedEncryptor.cs`
- `DataProtection/src/Cng/CngGcmAuthenticatedEncryptor.cs`
- `Cryptography.Internal/src/CryptoUtil.cs`
- `DataProtection/shared/src/ExceptionExtensions.cs`

#### 4a. Encrypt-then-MAC: Correctly Implemented

The AES-CBC + HMAC scheme (both managed and CNG paths) correctly implements Encrypt-then-MAC:
1. Random IV generated per operation
2. MAC computed over `(IV || ciphertext)` -- note: key modifier is NOT included in MAC input because it's mixed into the KDF instead
3. **MAC is validated BEFORE decryption** -- this prevents padding oracle attacks
4. Timing-safe MAC comparison via `CryptographicOperations.FixedTimeEquals` on .NET Core+ and manual `NoInlining | NoOptimization` loop on older frameworks

The exception homogenization pattern wraps all non-`CryptographicException` errors:
```csharp
catch (Exception ex) when (ex.RequiresHomogenization())
{
    throw Error.Common_EncryptionFailed(ex);
}
```
where `RequiresHomogenization()` returns `!(ex is CryptographicException)`. This prevents leaking internal error details that could distinguish between padding errors and MAC errors.

**Verdict:** Not exploitable. The implementation follows cryptographic best practices.

#### 4b. AES-GCM: Nonce Reuse Prevention

The AES-GCM implementation uses:
- 128-bit random key modifier (mixed into KDF for subkey derivation)
- 96-bit random nonce per operation
- 128-bit tag size (hardcoded)

The per-operation subkey derivation via the key modifier means that even a nonce collision would produce different ciphertexts because the encryption key itself differs. The combined entropy is 128 + 96 = 224 bits per operation, making collision probability negligible.

**Verdict:** Not exploitable.

#### 4c. Timing-Safe Comparison

`CryptoUtil.TimeConstantBuffersAreEqual` on .NET Core+ delegates to `CryptographicOperations.FixedTimeEquals`, which is the gold standard. On older frameworks, a manual loop with `[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]` is used. This is not as strong as the hardware-backed version but is the standard pattern for legacy .NET.

**Verdict:** Not exploitable on modern .NET. Legacy path is as good as reasonably possible.

---

### 5. Token Format Vulnerabilities

**Files reviewed:**
- `DataProtection/src/KeyManagement/KeyRingBasedDataProtector.cs` (Protect/Unprotect/DangerousUnprotect)
- `DataProtection/src/KeyManagement/KeyRingBasedSpanDataProtector.cs`
- `DataProtection/src/KeyManagement/KeyRing.cs`
- `DataProtection/src/IPersistedDataProtector.cs`

#### 5a. Payload Format: Robust

Protected payload format: `{ MAGIC_HEADER_V0 (4 bytes) || keyId (16 bytes GUID) || encryptorSpecificPayload }`

- Magic header `0x09F0C9F0` with last nibble reserved for version (currently 0)
- Only version 0 is accepted; any other version throws `Error.ProtectionProvider_BadVersion()`
- Minimum payload size validated: `protectedData.Length < _magicHeaderKeyIdSize`
- Key ID lookup returns null for unknown keys (no timing difference)

The magic header bytes (0xF0, 0xC9) cannot appear in valid UTF-8 sequences, providing a useful error-detection mechanism if protected data is accidentally treated as a string.

**Verdict:** Not exploitable.

#### 5b. Key Ring Lookup: No Oracle

`KeyRing.GetAuthenticatedEncryptorByKeyId` performs a dictionary lookup. For an unknown key ID:
1. Returns null (not found)
2. Triggers key ring refresh if within auto-refresh window
3. If still not found, throws `Common_KeyNotFound`

The error path is the same regardless of whether the key ID is close to a valid one or entirely random. No timing oracle exists because dictionary lookup is O(1) and the same code path is followed.

**Verdict:** Not exploitable.

#### 5c. AAD Template Race Condition

`AdditionalAuthenticatedDataTemplate.GetAadForKey` uses `Volatile.Read/Write` for thread safety when caching the template for the current default key. Multiple threads could read different templates during a key rollover, but this is safe because:

1. Each thread gets a consistent view (either old key or new key)
2. The template is cloned before modification
3. Only `isProtecting: true` writes back the cached template
4. For decryption (`isProtecting: false`), a fresh clone is always returned

**Verdict:** Not exploitable. The race condition does not produce incorrect AAD values.

#### 5d. DangerousUnprotect and Revoked Keys

`IPersistedDataProtector.DangerousUnprotect` allows decryption with revoked keys when `ignoreRevocationErrors: true`. The span-based `KeyRingBasedSpanDataProtector` does NOT support this -- it always throws on revoked keys. This is documented behavior and requires the caller to explicitly opt in.

**Verdict:** By-design API. Not a vulnerability.

---

## Potential Leads Investigated and Dismissed

### Lead 1: Purpose String Length Ambiguity
**Hypothesis:** The 7-bit encoded length prefix could create ambiguous encodings for purpose strings of certain lengths, enabling cross-purpose decryption.
**Result:** The 7-bit encoding is deterministic -- each integer has exactly one valid encoding. The overflow protection (checking `shift == 35` and `b > 0x0F`) prevents malformed multi-byte encodings from decoding to valid values. Dismissed.

### Lead 2: GUID Endianness in Key ID
**Hypothesis:** Different endianness handling of the key ID GUID between platforms could cause key lookup failures or cross-platform confusion.
**Result:** On .NET Core+, `new Guid(ReadOnlySpan<byte>)` handles endianness correctly. On older platforms, `Unsafe.ReadUnaligned<Guid>` is used with an assertion that `BitConverter.IsLittleEndian`. The GUID is written and read with the same method, so round-tripping is correct within the same platform. Dismissed (not a cross-boundary issue).

### Lead 3: SecureUtf8Encoding Bypass
**Hypothesis:** Crafted purpose strings with invalid UTF-8 could bypass the encoding and produce collisions.
**Result:** `EncodingUtil.SecureUtf8Encoding` is configured with `throwOnInvalidBytes: true`. Invalid UTF-8 in purpose strings would cause an exception during AAD template construction, not a silent collision. Dismissed.

### Lead 4: File System Race in StoreElementCore
**Hypothesis:** The temp-file-then-rename pattern could be exploited via a TOCTOU race to inject malicious key data.
**Result:** The `File.Move` operation is atomic on supported filesystems. The fallback `File.Copy` path (for NFS compatibility) could theoretically allow a race, but only if the attacker has write access to the key directory, which is already within the trust boundary. Dismissed.

### Lead 5: KDF Label/Context Separation
**Hypothesis:** The label and context fields in SP800-108 could be confused if the 0x00 separator between label and context can appear within the label itself.
**Result:** The label (AAD template) contains the purpose strings which are length-prefixed, so embedded 0x00 bytes are valid content bytes. However, the KDF implementation reads the label as an opaque byte array and the separator is a fixed structural element, not derived from the input. The implementation correctly follows the NIST specification. Dismissed.

---

## Summary of Findings

| # | Area | Finding | Severity | MSRC Eligible? |
|---|------|---------|----------|----------------|
| 1 | KDF | SP800-108 correctly implemented | N/A | No |
| 2a | Purpose strings | Length-prefixed encoding prevents collisions | N/A | No |
| 2b | Purpose strings | Empty strings allowed | Low | No |
| 2c | App discriminator | Cross-app decryption when ContentRootPath shared | Medium | No (by-design) |
| 3a | Key storage | No encryption at rest on Linux/Azure default | Medium | No (documented) |
| 3b | Key storage | Type instantiation from XML (deserializer/decryptor) | Medium | No (requires write access) |
| 3c | Key storage | Redis/EF Core store keys in plaintext | Low | No (by-design) |
| 4a | Crypto | Encrypt-then-MAC correctly implemented | N/A | No |
| 4b | Crypto | AES-GCM nonce reuse prevented by per-op subkeys | N/A | No |
| 4c | Crypto | Timing-safe comparison used | N/A | No |
| 5a | Token format | Robust magic header and version validation | N/A | No |
| 5b | Token format | No key lookup oracle | N/A | No |
| 5c | Token format | AAD template race condition is safe | N/A | No |

---

## Conclusion

The ASP.NET Core Data Protection API demonstrates a mature, well-engineered cryptographic design. The core cryptographic operations (KDF, encryption, MAC, key derivation) are implemented correctly and follow established standards (NIST SP 800-108, Encrypt-then-MAC best practices). The defense-in-depth measures (exception homogenization, timing-safe comparison, per-operation random key modifiers) are properly applied throughout.

The identified concerns (no encryption at rest on Linux, application discriminator reuse, type instantiation from key XML) are all deployment-configuration issues that do not cross a security boundary through a code-level flaw. They represent design trade-offs documented by Microsoft, and exploitation requires the attacker to already be within the same trust boundary (same user on same machine, or write access to key storage).

**No MSRC-eligible vulnerabilities were found.**
