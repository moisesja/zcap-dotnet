# W3C ZCAP-LD Specification Requirements Analysis

**Version**: 0.3 (CG-DRAFT)
**Source**: https://w3c-ccg.github.io/zcap-spec/
**Analysis Date**: 2026-02-20

---

## 1. Data Model Requirements

### 1.1 Root Capability Requirements

A root zcap represents the initial authority and MUST contain the following fields:

#### Required Fields (Root Capability)

| Field | Type | Description | Normative Requirement |
|-------|------|-------------|----------------------|
| `@context` | String | MUST be `"https://w3id.org/zcap/v1"` | **MUST** have this exact value |
| `id` | String (URN) | Identifier for the root capability | **MUST** be a URN; **SHOULD** follow format `urn:zcap:root:${encodeURIComponent(invocationTarget)}` |
| `controller` | String or Array of Strings | URI(s) identifying controller(s) | **MUST** be present; each value **MUST** be a URI (e.g., DID) |
| `invocationTarget` | String (URI) | Target resource URI where zcap may be invoked | **MUST** be a URI |

#### Prohibited Fields (Root Capability)

> "A root zcap MUST NOT have any other fields."

**Key Characteristics of Root Capabilities:**

1. **No Proof Required**: Root zcaps do NOT have a `proof` field because they are the root of trust
2. **No Expiration**: Root zcaps do NOT have an `expires` field
3. **No Parent**: Root zcaps do NOT have a `parentCapability` field
4. **Dereferencing**: Can be invoked by referencing only the ID; verifier MUST be able to dereference locally

**Example Root Capability:**

```json
{
  "@context": [
    "https://w3id.org/zcap/v1"
  ],
  "id": "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
  "controller": "did:key:example",
  "invocationTarget": "https://example.com/foo"
}
```

### 1.2 Delegated Capability Requirements

A delegated zcap extends authority from a parent capability and MUST contain:

#### Required Fields (Delegated Capability)

| Field | Type | Description | Normative Requirement |
|-------|------|-------------|----------------------|
| `@context` | Array | First value MUST be `"https://w3id.org/zcap/v1"`, subsequent values identify proof contexts | **MUST** be array with zcap context first |
| `id` | String (URI) | Unique identifier for the capability | **MUST** be a URI; **SHOULD** use format `urn:uuid:<uuid>` |
| `parentCapability` | String | ID of the parent zcap | **MUST** reference parent zcap ID |
| `controller` | String or Array of Strings | URI(s) identifying controller(s) | **MUST** be present; URIs that identify controller(s) |
| `invocationTarget` | String (URI) | Target resource URI | **MUST** be URI; **MUST** match or be a valid prefix of parent's `invocationTarget` |
| `expires` | String (XSD DateTime) | Expiration timestamp | **MUST** be XSD date-time format (ISO 8601); **MUST NOT** be less restrictive than parent |
| `proof` | Object or Array of Objects | Data Integrity proof(s) | **MUST** have at least one capability delegation proof |

#### Optional Fields (Delegated Capability)

| Field | Type | Description | Normative Requirement |
|-------|------|-------------|----------------------|
| `allowedAction` | String or Array of Strings | Action(s) permitted when invoking | **MUST NOT** be less restrictive than parent if present |
| `caveat` | Array of Objects | Restrictions on capability use | MAY be present; inherits all parent caveats |

**Example Delegated Capability:**

```json
{
  "@context": [
    "https://w3id.org/zcap/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "urn:uuid:cdc77118-6bfa-11ec-aceb-10bf48838a41",
  "parentCapability": "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",
  "controller": "did:key:example",
  "invocationTarget": "https://example.com/foo",
  "expires": "2021-11-03T18:33:51Z",
  "allowedAction": [
    "write",
    "read"
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2021-10-27T18:33:51Z",
    "verificationMethod": "did:key:z6MkfWKcvBiKCfNgz5UUGseNt37t4dguEvFgJ9XvX2UV6zB9#z6MkfWKcvBiKCfNgz5UUGseNt37t4dguEvFgJ9XvX2UV6zB9",
    "proofPurpose": "capabilityDelegation",
    "capabilityChain": [
      "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo"
    ],
    "proofValue": "z3t9BCQyF21MDVYmLKc9zbLreqx4wBtQnUsd5aqyoWS5FfhapRz7QjPNLcgKAornUVmJR4ZjbGpuxRFnffxX1ZjtF"
  }
}
```

### 1.3 @context Requirements

#### Root Capability Context

- **MUST** be a string with value `"https://w3id.org/zcap/v1"`
- Makes zcaps JSON-LD compatible without requiring JSON-LD processing
- "Zcaps are JSON-based, and the JSON has been chosen carefully such that it can be interpreted properly as JSON-LD as well"
- Other JSON-LD representations that deviate from the JSON expression are NOT permitted

#### Delegated Capability Context

- **MUST** be an array
- First value **MUST** be `"https://w3id.org/zcap/v1"`
- Subsequent values identify context(s) for vocabulary terms in the proof (e.g., cryptosuite contexts)
- Maximum array size should be defined (TODO in spec)

### 1.4 Field Type Specifications

#### XSD DateTime Format

- Expiration dates use XSD date-time format (ISO 8601)
- JavaScript: `new Date().toISOString()`
- Preferred: Remove millisecond precision via `new Date().toISOString().slice(0, -5) + 'Z'`
- Example: `"2021-11-03T18:33:51Z"`

#### Controller Field

- Can be a single string or an array of strings
- Each string MUST be a URI (typically a DID or DID with fragment)
- Multiple controllers grant authority to any of them
- Examples: `"did:key:example"`, `"https://social.example/alyssa#key-for-car"`

#### Invocation Target Field

- MUST be a URI
- Can be HTTP(S) URL, URN, or other URI scheme
- For delegated zcaps: can be attenuated (more specific than parent)

---

## 2. Proof Requirements

### 2.1 Capability Delegation Proof

A capability delegation proof is attached to delegated capabilities and MUST contain:

#### Required Proof Fields (Delegation)

| Field | Type | Description | Normative Requirement |
|-------|------|-------------|----------------------|
| `type` | String | Signature suite type | **MUST** be a valid DI proof type |
| `created` | String (XSD DateTime) | Timestamp when proof created | **MUST** be XSD date-time |
| `verificationMethod` | String (URI) | Key URI used to verify signature | **MUST** be URI; **MUST** be authorized by parent controller |
| `proofPurpose` | String | MUST be `"capabilityDelegation"` | **MUST** be `"capabilityDelegation"` |
| `capabilityChain` | Array | Ordered chain from root to parent | **MUST** be array; see chain requirements below |
| `proofValue` | String | Signature value | **MUST** be present (for Ed25519Signature2020) |

**Alternative signature field (older specs):**
- `jws` (String): JWS compact serialization (for Ed25519Signature2018, RsaSignature2016)
- `signatureValue` (String): base64-encoded signature

### 2.2 Capability Invocation Proof

A capability invocation proof is used when invoking a capability:

#### Required Proof Fields (Invocation)

| Field | Type | Description | Normative Requirement |
|-------|------|-------------|----------------------|
| `type` | String | Signature suite type | **MUST** be valid DI proof type |
| `created` | String (XSD DateTime) | Timestamp when proof created | **MUST** be XSD date-time |
| `creator` OR `verificationMethod` | String (URI) | Key URI that created signature | **MUST** match controller in capability chain |
| `proofPurpose` | String | MUST be `"capabilityInvocation"` | **MUST** be `"capabilityInvocation"` |
| `capability` | String or Object | For root: ID string; for delegated: full zcap object | **MUST** reference the capability being invoked |
| `signatureValue` OR `proofValue` | String | Signature value | **MUST** be present |

**Additional fields for DI proof invocation:**
- `invocationTarget` (String URI): **MUST** be included
- `capabilityAction` (String): Action being invoked; **SHOULD** be "read" or "write"

**Example Invocation Proof (embedded in invocation document):**

```json
{
  "@context": ["https://example.org/zcap/v1", "https://autopower.example/"],
  "id": "urn:uuid:ad86cb2c-e9db-434a-beae-71b82120a8a4",
  "action": "Drive",
  "proof": {
    "type": "RsaSignature2016",
    "proofPurpose": "capabilityInvocation",
    "capability": "https://whatacar.example/a-fancy-car/proc/7a397d7b",
    "created": "2016-02-08T17:13:48Z",
    "creator": "https://social.example/alyssa/#key-for-car",
    "signatureValue": "..."
  }
}
```

### 2.3 Supported Signature Types

The specification shows examples with the following signature types:

| Signature Type | Usage | Notes |
|----------------|-------|-------|
| `Ed25519Signature2018` | Delegation, Invocation | Uses `jws` field for signature |
| `Ed25519Signature2020` | Delegation, Invocation | Uses `proofValue` field; recommended |
| `RsaSignature2016` | Delegation, Invocation | Uses `signatureValue` field |

**Data Integrity Proofs:**

> "By enabling JSON-LD compatibility, DI proofs (Data Integrity Proofs, formerly known as Linked Data proofs) are used instead of JOSE-based signatures."

- Avoids base64 encapsulation overhead
- Enables CBOR-LD compression
- Keeps zcap sizes small, especially for chains

### 2.4 proofPurpose Values

| Value | Context | Description |
|-------|---------|-------------|
| `capabilityDelegation` | Delegated zcap proof | Indicates proof grants authority to controller entities |
| `capabilityInvocation` | Invocation proof | Indicates proof is invoking a capability |

### 2.5 capabilityChain Structure

**Critical Requirements:**

1. **MUST** be an array
2. **MUST** include the root zcap ID as the first entry
3. **MUST** include all intermediate delegated zcaps by ID (reference only)
4. **MUST** fully embed the immediate parent capability as the last entry (if parent is delegated)
5. Chain is ordered from root (least recent) to most recent
6. This structure ensures minimal size and allows dereferencing without network calls

**Chain Format:**

```javascript
// For a first-level delegation (parent is root):
"capabilityChain": [
  "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo"  // root by ID only
]

// For a second-level delegation:
"capabilityChain": [
  "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",  // root by ID
  {
    // Full embedded parent delegated zcap object
    "@context": [...],
    "id": "urn:uuid:first-delegation",
    "parentCapability": "urn:zcap:root:...",
    ...
  }
]

// For a third-level delegation:
"capabilityChain": [
  "urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo",  // root by ID
  "urn:uuid:first-delegation",                       // intermediate by ID
  {
    // Full embedded immediate parent (second-level delegation)
    "@context": [...],
    "id": "urn:uuid:second-delegation",
    ...
  }
]
```

**Why this structure:**

> "This ensures that delegated zcaps are of minimal size (other delegated zcaps in the chain are never repeated) and that every delegated zcap can be dereferenced directly from the chain without ever having to hit a network resource or similar."

### 2.6 Signature Encoding (proofValue)

For `Ed25519Signature2020` and similar modern suites:
- Uses `proofValue` field
- Encoded as multibase (e.g., base58-btc with `z` prefix)
- Example: `"z3t9BCQyF21MDVYmLKc9zbLreqx4wBtQnUsd5aqyoWS5FfhapRz7QjPNLcgKAornUVmJR4ZjbGpuxRFnffxX1ZjtF"`

For older suites:
- `jws` field: JWS compact serialization
- `signatureValue` field: base64-encoded

---

## 3. Delegation Requirements

### 3.1 How Delegation Chains Are Constructed

**Core Principle:**

> "A series of capability chained together in this way is called a 'capability chain' and is how delegation of capabilities are handled in ZCAP-LD."

**Delegation Process:**

1. Start with a root capability (or delegated capability you control)
2. Create a new capability document with:
   - New unique ID
   - `parentCapability` pointing to your capability's ID
   - `controller` set to the entity you're delegating to
   - `invocationTarget` equal to or more restricted than parent
   - `expires` equal to or more restrictive than parent
   - Optional `allowedAction` equal to or subset of parent
   - Optional additional `caveat` restrictions
3. Sign with a key authorized by your capability's controller
4. Embed the parent capability in the `capabilityChain` array

**Verification Requirement:**

> "A verifier MUST ensure that a delegated zcap was created by a controller of its parent capability by checking its capability delegation proof."

### 3.2 What Must Be Included in capabilityChain

**Array Contents (in order):**

1. **First element**: Root zcap ID (string reference)
2. **Middle elements**: Intermediate delegated zcap IDs (string references only)
3. **Last element**: Immediate parent delegated zcap (fully embedded object)

**Note**: If delegating directly from root, the chain contains only the root ID.

**Prohibition:**

> "A verifier MUST NOT be required to perform network requests or database queries to dereference delegated zcaps by ID when verifying the capability chain"

(However, revocation checks may still query a database by ID)

### 3.3 Parent Capability Embedding

**For Delegation Proof:**

- The immediate parent capability **MUST** be fully embedded in the `capabilityChain` array
- Other ancestors are referenced by ID only
- This eliminates N+1 base64 encoding overhead
- Enables verification without network fetches

### 3.4 Restrictions on Delegated Capabilities vs Parent

**Attenuation (Making More Restrictive):**

Delegated capabilities can only **restrict** authority, never expand it.

| Field | Restriction Rule |
|-------|------------------|
| `invocationTarget` | **MUST** match or be a valid prefix extension of parent |
| `expires` | **MUST NOT** be later than parent's expiration |
| `allowedAction` | **MUST NOT** include actions not in parent (if parent specifies) |
| `caveat` | Inherits all parent caveats; may add additional ones |

**URL Path/Query-Based Attenuation:**

> "A verifier will accept delegations (and invocations) where a suffix has been added to the parent zcap's invocation target"

**Rules:**
- Suffix **MUST** start with `/` or `?` if invocation target has no `?`
- Suffix **MUST** start with `&` if invocation target already has `?`
- This allows path and query parameter restrictions

**Examples:**

```
Parent:  https://foo.example/bars/123
Child:   https://foo.example/bars/123/bazzes/456

Parent:  https://foo.example/bars/123/bazzes/456
Child:   https://foo.example/bars/123/bazzes/456?day=tuesday

Parent:  https://foo.example/bars/123/bazzes/456?day=tuesday
Child:   https://foo.example/bars/123/bazzes/456?day=tuesday&hour=12
```

**Chain Length Limit:**

> "A verifier MUST limit the length of the capability chain to prevent long chain attacks. A verifier SHOULD limit the length of the capability chain to 10."

---

## 4. Invocation Requirements

### 4.1 Required Fields for an Invocation

An invocation is a linked data document that **MUST** have a `proof` property containing:

| Field | Requirement |
|-------|-------------|
| `proofPurpose` | **MUST** be `"capabilityInvocation"` |
| `capability` | **MUST** link to/include the capability granting authority |
| Signature verification | **MUST** validate against key from capability's `controller` |

**Invocation document:**
- **SHOULD** have an `id` (can serve as nonce)
- Other properties are arguments to the invocation

### 4.2 Invocation Methods

There are two primary ways to invoke a capability:

#### Method 1: HTTP Signature

**For Root Capability:**
- Include `capability-invocation` header with:
  - `id` parameter: root zcap ID
  - `action` parameter: capability action (SHOULD be "read" or "write")
- Request URL identifies invocation target
  - **MUST** match root zcap's invocation target OR have it as prefix (if verifier allows)
- HTTP signature key **MUST** be:
  - Private key paired with verification method matching controller, OR
  - Verification method controlled by controller and authorized for `capabilityInvocation`

**For Delegated Capability:**
- Include `capability-invocation` header with:
  - `capability` parameter: full delegated zcap serialized to JSON, gzipped, then base64url-encoded
  - Other fields as with root

#### Method 2: Data Integrity Proof

**For Root Capability:**
- Attach capability invocation proof to a document acceptable to the API
- Proof **MUST** include:
  - `invocationTarget`: intended target
  - `capability`: root zcap ID
  - `capabilityAction`: action to take (SHOULD be "read" or "write")

**For Delegated Capability:**
- Attach capability invocation proof
- `capability` property **MUST** express the full delegated zcap (object, not string)

### 4.3 How Invocation Proofs Differ from Delegation Proofs

| Aspect | Delegation Proof | Invocation Proof |
|--------|------------------|------------------|
| `proofPurpose` | `"capabilityDelegation"` | `"capabilityInvocation"` |
| `capabilityChain` | Required (array) | Not present |
| `capability` | Not present | Required (ID or full object) |
| `capabilityAction` | Not present | May be present (for DI proof method) |
| `invocationTarget` | Not present | May be present (for DI proof method) |
| Attached to | Delegated zcap | Invocation document or HTTP headers |
| Purpose | Grants authority to controller | Exercises authority |

### 4.4 Verification Rules for Invocations

**Algorithm (from spec section on Invocation):**

1. **Locate the target**: Traverse up `parentCapability` (or `previousCapability`) links until root is found
2. **Initialize authority set**: Mark target's `capabilityDelegation` cryptographic material as initially authorized
3. **Traverse chain downward** from root to invoked leaf, at each step:
   - **Verify delegation proof**: Check for valid proof with `proofPurpose` = `"capabilityDelegation"` where `creator` (or `verificationMethod`) is in the currently authorized set
   - **Validate caveats**: Check all caveats for validity
   - **Add controllers**: Add cryptographic material from `controller` field to authorized set
   - **Continue to next descendant**
4. **Verify invocation proof**: Ensure the invocation proof's key is in the authorized set
5. **Check action**: If `allowedAction` is specified, ensure invoked action is permitted
6. **Check expiration**: Ensure delegated zcaps have not expired
7. **Check invocation target**: Ensure invocation target matches or is a valid prefix

> "At this point, the invocation is considered valid and any relevant action may be performed."

**Action Validation:**

If the capability or any ancestor specifies `allowedAction`:
- Verifier **MUST** ensure the invoked action is in the allowed set
- Actions are URIs or strings (e.g., `"read"`, `"write"`, `"Drive"`)

---

## 5. Caveat Requirements

### 5.1 How Caveats Should Be Represented

Caveats are restrictions attached to capabilities:

**Field:**
- `caveat`: Array of objects

**Structure:**
- Each caveat object **MUST** have a `type` field
- Additional properties define caveat-specific parameters
- Type determines how the caveat is interpreted

**Example Caveats (from spec):**

```json
{
  "caveat": [
    {
      "type": "ValidWhileTrue",
      "uri": "https://social.example/alyssa/ben-can-still-drive"
    }
  ]
}
```

```json
{
  "caveat": [
    {
      "type": "DriveNoMoreThan",
      "kilometers": 123859
    }
  ]
}
```

### 5.2 Caveat Inheritance Rules

**Critical Requirement:**

> "Every capability document MAY add restrictions on the way the capability may be used by adding to the `caveat` property. Capabilities inherit the restrictions from all `caveat` properties of their parents, and MAY add new caveats in addition to those of their parents."

**Inheritance:**
- Child capabilities inherit **ALL** caveats from parent
- Child capabilities **MAY** add additional caveats
- Child capabilities **CANNOT** remove parent caveats
- All caveats in the entire chain must be satisfied

**Evaluation:**

> "The caveats of this capability document are checked for validity."

This check happens during the chain traversal (both at delegation creation and invocation verification).

### 5.3 Standard Caveat Types Mentioned

The spec provides examples but does not define a normative set of caveat types:

| Type | Example Fields | Purpose |
|------|----------------|---------|
| `ValidWhileTrue` | `uri`: URI to check | Remote revocation; capability valid while URI returns true |
| `DriveNoMoreThan` | `kilometers`: number | Limit usage by a measured amount |

**Note on Interpretation:**

> "The meaning of caveats are determined by their `type` and whatever other properties they have. Due to the way they are interpreted at invocation type by the target, some mutual understanding of terminology must be understood between the entity adding a caveat and the target evaluating (or any other parties observing) the invocation."

- Caveats are **application-specific**
- Target/verifier determines how to interpret and enforce
- Common types should be documented but are not in current spec

---

## 6. Verification Rules

### 6.1 Chain Verification Requirements

**Complete Chain Verification Process:**

1. **Dereference Root Capability**
   - For root zcap ID, verifier **MUST** be able to dereference locally
   - Typically involves looking up the `controller` for the resource
   - No network requests required

2. **Validate Delegated Capability Chain**
   - **MUST** verify each link in the chain
   - **MUST** ensure each delegation proof signature is valid
   - **MUST** check each proof's `verificationMethod` is authorized by parent's `controller`
   - **MUST** validate each proof's `proofPurpose` is `"capabilityDelegation"`

3. **Check Restrictions (Attenuation)**
   - **MUST** ensure `invocationTarget` is equal to or valid prefix of parent
   - **MUST** ensure `expires` is not less restrictive than parent
   - **MUST** ensure `allowedAction` is not less restrictive than parent (if specified)

4. **Validate Caveats**
   - **MUST** check all caveats from root through to leaf
   - All caveats in ancestry must be satisfied

5. **Chain Length**
   - **MUST** limit chain length to prevent attacks
   - **SHOULD** limit to 10

6. **Expiration Check**
   - **MUST** ensure delegated zcaps have not expired
   - **SHOULD** ensure expiration is not more than 3 months in future (for storage reasons)

### 6.2 Signature Verification Process

**For Capability Delegation Proof:**

1. Extract the `verificationMethod` (or `creator`) from proof
2. Resolve the verification method to a public key
   - May require DID resolution
   - Key must be authorized by parent's `controller`
3. Canonicalize the capability document (without the proof)
4. Verify the signature (`proofValue`, `jws`, or `signatureValue`) using the public key
5. Ensure signature is valid for the canonicalized document

**For Capability Invocation Proof:**

1. Extract the `verificationMethod` (or `creator`) from proof
2. Ensure this key is in the authorized set (from chain traversal)
3. Canonicalize the invocation document (without the proof)
4. Verify the signature using the public key
5. Ensure signature is valid for the canonicalized document

### 6.3 Validation Rules for Capabilities

**Root Capability Validation:**

- **MUST** have `@context` = `"https://w3id.org/zcap/v1"`
- **MUST** have `id` as URN
- **MUST** have `controller` as string or array of URIs
- **MUST** have `invocationTarget` as URI
- **MUST NOT** have any other fields
- **MUST NOT** have `proof`, `expires`, or `parentCapability`

**Delegated Capability Validation:**

- **MUST** have `@context` as array with zcap context first
- **MUST** have `id` as URI (SHOULD be urn:uuid:...)
- **MUST** have `parentCapability` as string (parent ID)
- **MUST** have `controller` as string or array of URIs
- **MUST** have `invocationTarget` matching or prefixed by parent
- **MUST** have `expires` as XSD date-time
- **MUST** have `proof` with capability delegation proof
- **MUST** ensure `allowedAction` not less restrictive than parent (if present)
- **MUST** validate proof signature and chain

**Invocation Validation:**

- Proof **MUST** have `proofPurpose` = `"capabilityInvocation"`
- Proof **MUST** reference capability via `capability` field
- Proof signature **MUST** verify with key from authorized set
- If action specified, **MUST** be in `allowedAction` (if present)
- Invocation target **MUST** match or be valid prefix of capability's target

### 6.4 Security Considerations

**From "Capabilities Are Safer" section:**

Object capabilities provide improved safety over ACLs, protecting against:

1. **Ambient Authority Problems**
   - In ACL systems, exploits can use all user privileges
   - In zcap systems, exploits limited to specific granted capabilities

2. **Confused Deputy Attacks**
   - CSRF and similar attacks exploiting ambient authority
   - Capabilities are explicit grants, not ambient

**Principle of Least Authority:**

> "Object capabilities are less vulnerable to these kinds of attacks because capabilities are an encoding of 'the principle of least authority' in software development practice."

**Chain Length Attacks:**

> "A verifier MUST limit the length of the capability chain to prevent long chain attacks."

**Revocation Storage:**

> "A verifier MUST store revoked zcaps [link to revocation] until they expire, to prevent their use."

This is why expiration dates should not be unreasonably far in the future.

**Expiration Requirements:**

> "Delegated zcaps MUST have expiration date-times to support good security hygiene practices and because zcaps support decentralized delegation."

**Network Isolation:**

> "A verifier MUST NOT be required to perform network requests or database queries to dereference delegated zcaps by ID when verifying the capability chain"

This prevents:
- Network-based attacks
- Dependency on external systems during verification
- Timing attacks via network latency

**Revocation Checks Exception:**

> "A verifier may still need to query a database for delegated zcaps to perform revocation checks by ID."

---

## 7. JSON-LD and Canonicalization

### 7.1 Canonicalization Algorithm Required

**Reference:**

> "Sign the document with Linked Data Proofs by cryptographic material which has already been granted authority on the chain"

The specification references the **Linked Data Proofs** specification:
- https://w3c-ccg.github.io/ld-proofs/

**Implication:**
- Canonicalization is required before signing
- Standard is likely **URDNA2015** (RDF Dataset Canonicalization)
- This is the algorithm used by Data Integrity proofs

### 7.2 JSON-LD Processing Requirements

**Minimal JSON-LD Processing:**

> "This field makes zcaps JSON-LD compatible, but does not mean that any other JSON-LDisms are permitted. In other words, zcaps are JSON-based, and the JSON has been chosen carefully such that it can be interpreted properly as JSON-LD as well. Other JSON-LD representations that deviate from the JSON expression of a zcap are not permitted."

**Key Points:**

1. **Zcaps are JSON-first**: The exact JSON structure matters
2. **JSON-LD compatibility is secondary**: Enables LD proofs and CBOR-LD
3. **No expansion/compaction**: Don't transform the JSON structure
4. **Canonical representation**: The JSON as written is the canonical form

**Benefits of JSON-LD Compatibility:**

1. **Data Integrity Proofs**: Can use LD proof signatures
2. **CBOR-LD Compression**: Semantic compression for smaller sizes
3. **No Base64 Encoding**: Avoids N+1 encoding overhead in chains
4. **Interoperability**: Works with existing LD proof libraries

**CBOR-LD:**

> "Additionally, JSON-LD compatibility enables CBOR-LD to be used to express zcaps — further reducing size via semantic compression."

---

## 8. Additional Normative Requirements

### 8.1 Expiration Constraints

**Maximum Duration:**

> "A verifier SHOULD ensure that an invoked delegated zcap does not have an expiration date-time that is more than three months in the future."

**Rationale:**
- Revoked zcaps must be stored until expiration
- Unreasonably long expiration = unreasonable storage burden
- Alternative mitigations: revoke all zcaps from a controller, or full key revocation

**Mandatory Expiration:**

> "Delegated zcaps MUST have expiration date-times to support good security hygiene practices and because zcaps support decentralized delegation."

### 8.2 Invocation Target Matching

**Exact Match or Prefix:**

For invocations, the request URL (or specified `invocationTarget`):
- **MUST** match the capability's `invocationTarget`, OR
- **MAY** have the capability's `invocationTarget` as a prefix (if verifier allows)

For delegations:
- Child's `invocationTarget` **MUST** equal parent's OR be a valid prefix extension

**Prefix Definition:**

> "A prefix is defined as a base URI and parent path (and optional query) (i.e., `/`-delimited and `?`/`&`-delimited)"

### 8.3 Revocation (Work in Progress)

**From spec TODOs:**

> "TODO: Add section on revocation, detailing what verifiers MUST/SHOULD do to provide revocation endpoints for zcaps."

**Proposed Pattern:**

- Root invocation target **SHOULD** have `/zcaps/revocations` subpath
- Revoke by invoking root zcap: `urn:zcap:root:<the revocations path/the zcap ID to revoke>`
- Verifier **SHOULD** set controllers for revocation to all controllers in chain
  - This allows any controller in chain to revoke
- Verifier **MUST** store revoked zcap IDs until their expiration

**Example:**

To revoke `urn:uuid:12345` under root target `https://example.com/foo`:

1. Invoke: `https://example.com/foo/zcaps/revocations/urn:uuid:12345`
2. Using root zcap: `urn:zcap:root:https%3A%2F%2Fexample.com%2Ffoo%2Fzcaps%2Frevocations%2Furn%3Auuid%3A12345`
3. Verifier stores `urn:uuid:12345` in revocation list
4. Future invocation attempts for that zcap are denied

### 8.4 Action Field

**Common Property:**

> "Targets are free to choose their own mechanisms for directing behavior, but MAY support the `action` property on invocations as one common behavioral direction technique."

**Value:**
- URI as vocabulary term
- Common values: `"read"`, `"write"`
- Application-specific values allowed

**In Capability Invocation Proof:**
- `capabilityAction`: the action being invoked (DI proof method)
- Verifier checks this against `allowedAction` in capability (if specified)

---

## 9. Implementation Checklist

Based on the specification, a compliant implementation MUST:

### Data Model
- [ ] Support root capabilities with exact field requirements
- [ ] Support delegated capabilities with all required/optional fields
- [ ] Enforce `@context` requirements (string for root, array for delegated)
- [x] Support `controller` as string or array of strings (Issue #47 deserialization + Issue #65 document-based authorization)
- [ ] Validate `invocationTarget` as URI
- [ ] Validate `expires` as XSD date-time
- [ ] Support `allowedAction` as string or array
- [ ] Support `caveat` array with type-based objects

### Proofs
- [ ] Create capability delegation proofs with required fields
- [ ] Create capability invocation proofs with required fields
- [ ] Support `Ed25519Signature2020` (recommended)
- [ ] Support `Ed25519Signature2018`, `RsaSignature2016` (legacy)
- [ ] Properly construct `capabilityChain` arrays
- [ ] Embed parent capability in chain correctly
- [ ] Set `proofPurpose` correctly for delegation vs invocation

### Delegation
- [ ] Create delegated capabilities from root or delegated parents
- [ ] Enforce attenuation rules (no expansion of authority)
- [ ] Support URL path/query-based attenuation
- [ ] Inherit all parent caveats
- [ ] Allow adding new caveats
- [ ] Enforce expiration constraints (not later than parent, max 3 months)

### Invocation
- [ ] Support HTTP signature invocation method
- [ ] Support DI proof invocation method
- [ ] Include required fields in invocation proofs
- [ ] Validate action against `allowedAction`
- [ ] Match invocation target to capability target (or valid prefix)

### Verification
- [ ] Dereference root capabilities locally (no network)
- [ ] Verify complete capability chain
- [ ] Validate each delegation proof signature
- [ ] Check each proof's verification method authorization
- [ ] Enforce attenuation rules during verification
- [ ] Validate all caveats in chain
- [ ] Check expiration timestamps
- [ ] Limit chain length to prevent attacks (max 10)
- [ ] Verify invocation proof signature
- [ ] Check invocation target and action

### Security
- [ ] Store revoked zcap IDs until expiration
- [ ] Implement revocation endpoint (SHOULD)
- [ ] No network requests during chain verification (except revocation check)
- [x] Enforce 3-month maximum expiration (SHOULD) — verifier-side, opt-in via `VerificationPolicy.EnforceMaxDelegationExpiration` (off by default), measured at verification time on the invocation/chain paths (Issue #73)
- [ ] Limit chain length to 10 (SHOULD)

### JSON-LD/Canonicalization
- [ ] Canonicalize documents before signing (URDNA2015)
- [ ] Use Data Integrity proof format
- [ ] Support CBOR-LD (optional but recommended)
- [ ] Preserve exact JSON structure (no expansion/compaction)

---

## 10. Summary of MUST/SHOULD/MAY Requirements

### MUST (Mandatory)

1. Root zcap **MUST** have `@context` = `"https://w3id.org/zcap/v1"`
2. Root zcap **MUST** have `id`, `controller`, `invocationTarget`
3. Root zcap **MUST NOT** have other fields
4. Delegated zcap **MUST** have array `@context` with zcap context first
5. Delegated zcap **MUST** have `id`, `parentCapability`, `controller`, `invocationTarget`, `expires`, `proof`
6. Delegated zcap **MUST** have at least one capability delegation proof
7. Capability chain **MUST** be array with root ID first
8. Capability chain **MUST** fully embed immediate parent
9. Verifier **MUST** ensure delegated zcap created by parent's controller
10. Verifier **MUST** ensure invocation target matches or is valid prefix of parent
11. Verifier **MUST** ensure expiration not less restrictive than parent
12. Verifier **MUST** ensure allowedAction not less restrictive than parent
13. Verifier **MUST** limit chain length to prevent attacks
14. Verifier **MUST** ensure delegated zcaps have not expired
15. Delegated zcaps **MUST** have expiration date-times
16. Invocation proof **MUST** have `proofPurpose` = `"capabilityInvocation"`
17. Delegation proof **MUST** have `proofPurpose` = `"capabilityDelegation"`
18. Verifier **MUST NOT** be required to perform network requests for chain dereferencing
19. Verifier **MUST** validate signature of each proof
20. Verifier **MUST** check all caveats in chain
21. Verifier **MUST** store revoked zcaps until expiration
22. Attenuation suffix **MUST** start with `/`, `?`, or `&` appropriately

### SHOULD (Recommended)

1. Root zcap ID **SHOULD** follow format `urn:zcap:root:${encodeURIComponent(invocationTarget)}`
2. Delegated zcap ID **SHOULD** use format `urn:uuid:<uuid>`
3. Verifier **SHOULD** limit chain length to 10
4. Verifier **SHOULD** ensure expiration not more than 3 months in future
5. Capability action **SHOULD** be "read" or "write"
6. Invocation **SHOULD** have an `id`
7. Revocation endpoint **SHOULD** be provided at `<rootTarget>/zcaps/revocations`

### MAY (Optional)

1. Delegated zcap **MAY** have `allowedAction` field
2. Any capability **MAY** add caveats
3. Targets **MAY** support `action` property on invocations
4. Proof **MAY** be object or array of objects

---

## 11. Open Questions / TODOs in Spec

The specification has several TODO notes indicating areas still under development:

1. **Chain reference links**: Many `[TODO: link to capability chains]` notes
2. **Revocation details**: Complete algorithm for revocation validation
3. **Caveat types**: Standard caveat definitions and enforcement
4. **Maximum context array size**: For `@context` in delegated zcaps
5. **Rigorous prefix definition**: More formal definition of URI prefix matching
6. **Property subsections**: Each property should have its own subsection with rules
7. **Validation algorithm**: Detailed step-by-step validation process
8. **3-month expiration rationale**: Why 3 months specifically?
9. **10-chain-length rationale**: Security exposition for 10-link limit

---

## Document Control

**Created**: 2026-02-20
**Source Specification**: W3C ZCAP-LD v0.3 (CG-DRAFT)
**URL**: https://w3c-ccg.github.io/zcap-spec/
**Purpose**: 100% compliance verification for .NET implementation
**Next Steps**: Use this document to validate implementation against all normative requirements

---

## References

1. W3C ZCAP-LD Specification: https://w3c-ccg.github.io/zcap-spec/
2. Linked Data Proofs: https://w3c-ccg.github.io/ld-proofs/
3. Data Integrity 1.0: https://w3c.github.io/vc-data-integrity/
4. Ed25519Signature2020: https://w3id.org/security/suites/ed25519-2020/v1
5. Capability Myths Demolished: http://srl.cs.jhu.edu/pubs/SRL2003-02.pdf
6. ACLs Don't: http://waterken.sourceforge.net/aclsdont/current.pdf
7. Rebooting Web of Trust Paper: https://github.com/WebOfTrustInfo/rebooting-the-web-of-trust-fall2017/blob/master/draft-documents/lds-ocap/lds-ocap.md
