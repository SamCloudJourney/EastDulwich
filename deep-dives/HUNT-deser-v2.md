# HUNT: .NET Deserialization (CWE-502) — v2

**Target:** Microsoft .NET bug bounty (runtime + aspnetcore), deserialization RCE / privilege elevation from untrusted data.
**Repos:** `/home/user/dotnet-hunt/runtime` @ `2eb7113245` (2026-10-07), `/home/user/dotnet-hunt/aspnetcore` @ `851622243f` (2026-10-07). Both shallow (depth 1) — no usable git history.
**SDKs used for PoC:** .NET 9.0.318 / 10.0.100-rc.2 at `/home/user/.dotnet`.
**Date:** 2026-10-09.

## Verdict: NOTHING clears the bar

Every classic CWE-502 vector in the named hunting grounds is hardened in modern .NET and is either (a) disabled by default, (b) allowlist/type-fixed so attacker data cannot choose the instantiated type, (c) fed only trusted data in the framework-automatic path, or (d) protected by an authenticated data-protection envelope. I could not construct a single chain that is untrusted-by-default + arbitrary-type/gadget-reachable + reachable via normal public API. Details and the evidence that killed each lead are below so the negative is auditable.

---

## 1. System.Text.Json polymorphic deserialization — CLOSED (static + empirical)

**Boundary / source:** MVC `[FromBody]`, SignalR JSON, Blazor — all can feed attacker JSON to `JsonSerializer.Deserialize`.

**Sink examined:** `$type` type-discriminator handling, `PolymorphicTypeResolver`.

**Code trace (why it cannot instantiate attacker-chosen types):**
- `runtime/.../Serialization/Metadata/PolymorphicTypeResolver.cs` — discriminators are matched against `_discriminatorIdtoType`, a dictionary populated **only** from `polymorphismOptions.DerivedTypes` (i.e. `[JsonDerivedType]` attributes or explicit `JsonPolymorphismOptions`). `TryGetDerivedJsonTypeInfo(object typeDiscriminator,...)` returns only a pre-registered `JsonTypeInfo`, and an unknown discriminator calls `ThrowHelper.ThrowJsonException_UnrecognizedTypeDiscriminator`. **There is no `Type.GetType(discriminator)` / `Assembly.Load` anywhere in the polymorphic path.** (The only `Type.GetType` in the STJ sources is `IEnumerableConverterFactoryHelpers.GetTypeIfExists` for hard-coded well-known collection type names during converter-factory setup — not attacker-influenced.)
- `runtime/.../Metadata/JsonTypeInfo.cs:985-991` — `PolymorphicTypeResolver` is constructed **only when `PolymorphismOptions is not null`**, i.e. the developer opted in per type.
- `runtime/.../JsonConverter.MetadataHandling.cs:106` (and read path) — `$type` is read **only when `jsonTypeInfo.PolymorphicTypeResolver` is non-null**. Default types never read `$type` as metadata.

**PoC result (empirical, net9.0):** registered discriminator `"dog"` → resolves to `Dog`. Attacker-supplied `$type` = assembly-qualified name `EvilAnimal, stjtest, ...` → `JsonException: Read unrecognized type discriminator id`. Short name `"EvilAnimal"` → same rejection. `$type` on a non-polymorphic DTO → silently ignored, no type load. The `EvilAnimal` constructor (gadget stand-in) never executed in any case.

**MSRC-survival confidence of a finding here: ~0%.** This is the deliberate architectural difference from Newtonsoft `TypeNameHandling`; it is allowlist-only by design.

---

## 2. ASP.NET Core MVC XML input formatters — CLOSED

**Files:** `aspnetcore/src/Mvc/Mvc.Formatters.Xml/src/XmlSerializerInputFormatter.cs`, `XmlDataContractSerializerInputFormatter.cs`.

- **XXE:** both build the reader with `XmlDictionaryReader.CreateTextReader(stream, encoding, quotas, onClose:null)`. The WCF text reader does not support DTDs at all (no `DtdProcessing` knob; `<!DOCTYPE>` is rejected). No external entity resolution ⇒ no XXE file-read/SSRF.
- **Type confusion:** `XmlSerializer` deserializes to the fixed `context.ModelType`; it only instantiates types statically reachable from that type graph (`[XmlInclude]`), never attacker-named types. `DataContractSerializer` is built with a default `DataContractSerializerSettings` (`DataContractResolver == null`, no extra `KnownTypes`), so `xsi:type` can only select among known types derived from the declared graph — not arbitrary gadgets.
- **Reachability caveat:** neither formatter is registered by default; the app must call `AddXmlSerializerFormatters()` / `AddXmlDataContractSerializerFormatters()`. Even when enabled it is type-safe.

**MSRC-survival confidence: ~0%.** Also, DataSet/DataTable-as-model would be the only "interesting" sink and Microsoft already documents those two types as unsafe to deserialize from untrusted input (fails the bar's "not already documented" clause).

---

## 3. SignalR message deserialization — CLOSED

**Files:** `aspnetcore/src/SignalR/common/Protocols.MessagePack/src/Protocol/{MessagePackHubProtocol.cs, MessagePackHubProtocolWorker.cs, DefaultMessagePackHubProtocolWorker.cs}`, Protocols.Json, Protocols.NewtonsoftJson.

- **Type is fixed by the hub method signature:** arguments are bound via `binder.GetParameterTypes(target)` then `DeserializeObject(reader, parameterTypes[i], ...)`. The client controls the bytes and the target method name, not the CLR types.
- **MessagePack resolver is not typeless:** `CreateDefaultMessagePackSerializerOptions()` = `.WithResolver(SignalRResolver.Instance).WithSecurity(MessagePackSecurity.UntrustedData)`. `SignalRResolver` chains `DynamicEnumAsStringResolver` + `ContractlessStandardResolver` — **not** `TypelessContractlessStandardResolver`, so no .NET type names are embedded/honored in the payload. Even an `object` parameter deserializes to primitives/maps. `UntrustedData` adds hash-collision/ depth protection.
- **JSON/Newtonsoft protocols:** same signature-driven binding; Newtonsoft path inherits `TypeNameHandling.None` (see §6).

**MSRC-survival confidence: ~0%.**

---

## 4. ASP.NET Core Data Protection XML descriptors — CLOSED

**Files:** `aspnetcore/src/DataProtection/.../ConfigurationModel/*Deserializer.cs`, `StackExchangeRedis/RedisXmlRepository.cs`, `EntityFrameworkCore/EntityFrameworkCoreXmlRepository.cs`, `XmlEncryption/{EncryptedXmlDecryptor,CertificateXmlEncryptor}.cs`.

- **Source is trusted key-store, not the request:** the key-ring XML is read from the configured `IXmlRepository` (file system, Redis, EF, registry, blob) via `XElement.Parse` / `XElement.Load`. It is not attacker-supplied on a normal request path. Influencing it requires write access to the key store — a precondition MSRC treats as "already compromised."
- **No XXE:** LINQ-to-XML (`XElement.Parse/Load`) uses an `XmlReader` with `DtdProcessing.Prohibit` by default; `EncryptedXmlDecryptor`/`CertificateXmlEncryptor` load from an in-memory `XElement.CreateReader()` (no external I/O).
- The descriptor deserializers (`ManagedAuthenticatedEncryptorDescriptorDeserializer` etc.) read fixed elements/attributes into known descriptor types — no type-name-driven instantiation.

**MSRC-survival confidence: ~0%** (precondition = key-store write access).

---

## 5. BinaryFormatter / legacy formatter remnants — CLOSED

- `runtime/.../System.Runtime.Serialization.Formatters/.../BinaryFormatter.Core.cs`: `Deserialize`/`Serialize` both start with `if (!LocalAppContextSwitches.BinaryFormatterEnabled) throw new NotSupportedException(...)`. **Disabled by default**; re-enabling needs an explicit opt-in switch/MSBuild property. All remnant call sites in runtime (ClaimsPrincipal, DataSet, SettingsPropertyValue, ResourceReader, IsolatedStorage, etc.) are therefore dead-by-default and, in practice, fed trusted data.
- `aspnetcore`: **zero** references to `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `SoapFormatter` (non-test). ASP.NET Core has no ViewState.
- `runtime`: **no** `NetDataContractSerializer` (the dangerous type-name-driven serializer) in src/ref.

**MSRC-survival confidence: ~0%.** Re-enabling BinaryFormatter is a documented, explicit developer action.

---

## 6. Newtonsoft input formatter — CLOSED

`aspnetcore/src/Mvc/Mvc.NewtonsoftJson/src/JsonSerializerSettingsProvider.cs:40` hard-sets `TypeNameHandling = TypeNameHandling.None` with the comment *"Do not change this setting … prevents Json.NET from loading malicious, unsafe, or security-sensitive types."* `MaxDepth = 32`. No `$type` gadget path by default.

---

## 7. Blazor Server component deserialization — CLOSED

**Files:** `aspnetcore/src/Components/Server/src/Circuits/{ServerComponentDeserializer,ComponentParameterDeserializer}.cs`, `Shared/Components/{ComponentParametersTypeCache,ServerComponentSerializationSettings}.cs`.

- The `ServerComponent` descriptor — **assembly name, type name, parameter definitions (the parameter TYPES), and parameter values** — is carried inside a **data-protected, time-limited** payload (`_dataProtector.Unprotect`, purpose `…ComponentDescriptorSerializer,V1`, 5-min expiry). The client relays the server-generated blob; it cannot forge the type/definitions. Tampering fails `Unprotect`.
- Parameter values are deserialized with `JsonSerializer.Deserialize(json, parameterType, options)` where `parameterType` comes from the **data-protected** definitions → type-safe (STJ to a known type; see §1). `ServerComponentSerializationSettings.JsonSerializationOptions` has **no** polymorphism and no dangerous converters.
- `ComponentParametersTypeCache.ResolveType` only resolves against already-loaded assemblies (server side); the `Assembly.Load` branch is `OperatingSystem.IsBrowser()`-gated (WASM, client-side, no server trust boundary).
- The outer `RootComponentOperationBatch` JSON from `UpdateRootComponents` is **not** protected, but it deserializes to a fixed source-gen type (ints, enums, markers) — the sensitive type/parameter data is only the inner protected descriptor.

**MSRC-survival confidence: ~0%.**

---

## 8. System.Private.Xml reader defaults (the brief's explicit XXE question) — SECURE BY DEFAULT

- `XmlReaderSettings._dtdProcessing` defaults to `DtdProcessing.Prohibit` (enum value 0) ⇒ `XmlReader.Create(stream)` rejects DTDs.
- `XmlDocument._resolver` defaults to **null** ⇒ `XmlDocument.Load` performs no external entity resolution (the key .NET Core hardening vs .NET Framework).
- `XmlTextReaderImpl._dtdProcessing = DtdProcessing.Parse` **but** `_xmlResolver = null` by default ⇒ internal DTD parsed, external entities not fetched. So the legacy `XmlTextReader`/`XmlSerializer.Deserialize(TextReader)` path allows at most internal entity-expansion **DoS**, not file-read/SSRF/RCE.
- `XmlSerializer.Deserialize(Stream)` → `XmlReader.Create(stream, new XmlReaderSettings{IgnoreWhitespace=true})` ⇒ DTD prohibited.

Entity-expansion DoS on the `Deserialize(TextReader)` overload is (a) a DoS, not RCE/EoP (fails bar #1) and (b) only on an app-chosen direct call, not a framework-automatic path.

---

## Leads checked and dropped (so the negative is complete)

- DataSet/DataTable gadget via XML formatters — needs a `DataSet`/`DataTable`-typed model AND is already documented by Microsoft as unsafe (fails bar #4).
- OutputCaching uses a bespoke `FormatterBinaryReader`/`OutputCacheEntryFormatter` (hand-rolled binary, no type-name instantiation); cache is server-populated.
- TempData (`DefaultTempDataSerializer`, `BsonTempDataSerializer`) — STJ/Bson to known types; server-written.
- Session middleware stores `byte[]` keyed by string — the app, not the framework, deserializes.
- HybridCache core is not in these repos (Extensions repo); the only `*HybridCacheSerializer*` here (`SerializedRenderFragmentHybridCacheSerializer`) uses STJ to a known type.
- Antiforgery/auth tickets use custom binary readers wrapped in data-protection ⇒ attacker cannot forge without the key.

## How to attack this verdict (if revisiting)

1. Find an app-default code path that sets `AppContext`/`System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization=true` implicitly — I found none.
2. Find a framework-automatic reader that sets `DtdProcessing.Parse` **and** a non-null `XmlResolver` on untrusted input — none found in aspnetcore (zero `DtdProcessing` references outside tests).
3. Find a `JsonSerializerOptions` with a polymorphic base whose allowlist includes a type with a dangerous setter/constructor reachable from a default endpoint — would be app-specific, not a framework bug.
4. Find a hub/formatter that swaps in `TypelessContractlessStandardResolver` or `TypeNameHandling != None` by default — none found.

**Bottom line: no bounty-eligible CWE-502 finding. Clean nothing, backed by static trace + an empirical STJ PoC. Not committed/pushed.**
