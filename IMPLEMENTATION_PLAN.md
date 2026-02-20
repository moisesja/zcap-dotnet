# ZCAP-LD .NET Implementation Plan

## 📋 Complete Implementation Roadmap

### **Phase 1: Project Foundation**

**Step 1.1** - Create .NET Solution Structure
- Create solution file and three projects:
  - `ZCap.Core` - Core library (class library, .NET 9)
  - `ZCap.Tests` - Unit tests (xUnit, .NET 9)
  - `ZCap.Samples` - Example usage (console app, .NET 9)
- Add necessary NuGet packages (JSON.NET/System.Text.Json, cryptography libs)

**Step 1.2** - Setup Project Configuration
- Configure EditorConfig for code style
- Add `.gitignore` for .NET projects
- Configure test framework and coverage
- Setup build configuration (Debug/Release)

---

### **Phase 2: Core Data Models**

**Step 2.1** - Implement Base Capability Model
- Create `Capability` base class with common fields:
  - `@context` (Context)
  - `id` (Id)
  - `controller` (Controller - string or array)
  - `invocationTarget` (InvocationTarget)

**Step 2.2** - Implement Root Capability
- Create `RootCapability` class (inherits Capability)
- Enforce constraints: MUST NOT contain fields beyond base requirements
- Auto-generate id in format: `urn:zcap:root:{encodeURIComponent(invocationTarget)}`

**Step 2.3** - Implement Delegated Capability
- Create `DelegatedCapability` class (inherits Capability)
- Add fields:
  - `parentCapability` (string URI)
  - `expires` (DateTime, REQUIRED)
  - `allowedAction` (string or string[])
  - `proof` (Proof object or array)
- Add validation for expiration dates (max 3 months recommended)

**Step 2.4** - Implement Proof Model
- Create `Proof` class with fields:
  - `type` (signature type)
  - `created` (ISO8601 timestamp)
  - `verificationMethod` (URI)
  - `proofPurpose` ("capabilityDelegation" or "capabilityInvocation")
  - `capabilityChain` (string array)
  - `proofValue` (signature string)

**Step 2.5** - Implement Caveat Model
- Create `Caveat` base class/interface
- Implement specific caveat types:
  - `ExpirationCaveat` (time-based)
  - `ActionCaveat` (action restrictions)
  - Extensible for custom types

**Step 2.6** - Implement Invocation Model
- Create `CapabilityInvocation` class with:
  - `id` (identifier/nonce)
  - `action` (URI)
  - `capability` (reference to capability)
  - `proof` (invocation proof)
  - Additional properties (arguments)

---

### **Phase 3: JSON-LD Serialization**

**Step 3.1** - Configure JSON Serialization
- Setup System.Text.Json with custom converters
- Handle @context field correctly
- Support both single string and array for controller
- Ensure proper DateTime serialization (ISO8601/XSD format)

**Step 3.2** - Implement Canonical JSON-LD
- Implement or integrate JSON-LD canonicalization (for signing)
- Use RDF Dataset Canonicalization Algorithm (RDFC-1.0)
- Ensure deterministic output for signature verification

---

### **Phase 4: Cryptographic Operations**

**Step 4.1** - Implement Key Management Interface
- Create `IKeyProvider` interface for DID key resolution
- Define methods:
  - `GetPublicKey(did)` - resolve verification keys
  - `SignData(data, did)` - sign with private key
  - `VerifySignature(data, signature, publicKey)` - verify signatures

**Step 4.2** - Implement Ed25519 Signing
- Use `System.Security.Cryptography` Ed25519
- Implement Ed25519Signature2020 proof type
- Handle signature encoding (base58 or multibase)

**Step 4.3** - Implement Proof Generation
- Create `ProofGenerator` class
- Method: `CreateDelegationProof(capability, parentCapability, signingKey)`
- Method: `CreateInvocationProof(invocation, signingKey)`
- Build capability chains correctly (root ID, intermediate IDs, parent embedded)

**Step 4.4** - Implement Proof Verification
- Create `ProofVerifier` class
- Verify signature against canonical JSON-LD
- Validate proof structure and required fields

---

### **Phase 5: Delegation Logic**

**Step 5.1** - Implement Capability Delegation
- Create `CapabilityDelegator` class
- Method: `Delegate(parentCapability, newController, options)`
- Validate:
  - invocationTarget matches or extends parent
  - expiration doesn't exceed parent
  - allowedActions subset of parent (if specified)

**Step 5.2** - Implement Chain Building
- Build capabilityChain array correctly:
  - First: root capability ID (reference)
  - Middle: intermediate IDs (references)
  - Last: parent capability (fully embedded)
- Validate chain ordering

**Step 5.3** - Implement Chain Length Validation
- Enforce maximum chain length (default: 10)
- Configurable limit for different security requirements

---

### **Phase 6: Verification Engine**

**Step 6.1** - Implement Chain Traversal
- Create `ChainVerifier` class
- Traverse from leaf to root via parentCapability links
- Build ordered chain for verification

**Step 6.2** - Implement Verification Algorithm
- Recursive validation from root to leaf:
  1. Identify root capability's authorized controllers
  2. For each delegation:
     - Verify proof signature
     - Check signer is in authorized set
     - Validate caveats
     - Add new controller to authorized set
  3. Return final authorized set

**Step 6.3** - Implement Invocation Verification
- Method: `VerifyInvocation(invocation, rootCapability)`
- Check:
  - Invocation proof is valid
  - Invoker is in final authorized set
  - Requested action in allowedAction
  - invocationTarget matches
  - All caveats satisfied

**Step 6.4** - Implement Expiration Checks
- Validate all capabilities in chain not expired
- Check expiration at invocation time
- Enforce cascading expiration rules

---

### **Phase 7: Caveat Processing**

**Step 7.1** - Implement Caveat Evaluator
- Create `ICaveatEvaluator` interface
- Implement evaluators for built-in caveat types
- Registry pattern for custom caveat types

**Step 7.2** - Implement Caveat Inheritance
- Collect all caveats from root to leaf
- Ensure child caveats don't relax parent restrictions
- Validate all inherited caveats at invocation

**Step 7.3** - Implement URL-based Attenuation
- Parse and validate invocationTarget suffixes
- Rules for path/query extension
- Verify suffix follows specification constraints

---

### **Phase 8: DID Integration**

**Step 8.1** - Integrate Trinsic SDK
- Add Trinsic NuGet package
- Create `TrinsicKeyProvider` implementing `IKeyProvider`
- Handle DID document resolution

**Step 8.2** - Implement DID Key Resolution
- Resolve verificationMethod from DID documents
- Extract public keys for signature verification
- Cache resolved keys for performance

**Step 8.3** - Implement DID-based Signing
- Use Trinsic SDK for signing operations
- Support multiple signature suites
- Handle key rotation scenarios

---

### **Phase 9: Testing**

**Step 9.1** - Unit Tests for Data Models
- Test serialization/deserialization
- Test validation logic
- Test field constraints

**Step 9.2** - Unit Tests for Cryptography
- Test signature generation and verification
- Test canonical JSON-LD generation
- Test different key types

**Step 9.3** - Unit Tests for Delegation
- Test single delegation
- Test multi-level chains
- Test validation failures
- Test expiration cascading

**Step 9.4** - Unit Tests for Verification
- Test valid invocations
- Test invalid invocations (expired, wrong action, wrong target)
- Test chain verification edge cases
- Test caveat enforcement

**Step 9.5** - Integration Tests
- End-to-end capability lifecycle tests
- Multi-party delegation scenarios
- Real Trinsic SDK integration tests

---

### **Phase 10: Advanced Features**

**Step 10.1** - Implement Revocation Support
- Create revocation list data structure
- Method: `RevokeCapability(capabilityId)`
- Check revocation during verification

**Step 10.2** - Implement HTTP Invocation Support
- Parse "capability-invocation" HTTP headers
- Extract capability ID and action parameters
- Generate HTTP signatures

**Step 10.3** - Optional: gRPC Service
- Define gRPC service contracts
- Implement service methods:
  - `CreateRootCapability()`
  - `DelegateCapability()`
  - `VerifyInvocation()`

**Step 10.4** - Optional: WASM Support
- Configure for AOT compilation
- Test with .NET 9 WASI workload
- Ensure cross-platform compatibility

---

### **Phase 11: Documentation & Samples**

**Step 11.1** - Create Usage Examples
- Basic delegation example
- Multi-level chain example
- Invocation example
- Revocation example

**Step 11.2** - API Documentation
- XML documentation comments
- Generate API docs
- Usage guide

**Step 11.3** - Update README
- Installation instructions
- Quick start guide
- Architecture overview

---

### **Phase 12: Finalization**

**Step 12.1** - Security Review
- Review cryptographic implementations
- Check for timing attacks
- Validate key handling practices

**Step 12.2** - Performance Optimization
- Profile critical paths
- Optimize JSON-LD canonicalization
- Cache where appropriate

**Step 12.3** - Package for Distribution
- Create NuGet package
- Version tagging
- Release notes

---

## 🎯 Current Status

**In Progress:** Step 1.1 - Create .NET Solution Structure

## 📝 Notes

- Phases 1-6 provide core ZCAP-LD functionality
- Phases 7-12 add completeness and production-readiness
- Each step requires approval before proceeding
