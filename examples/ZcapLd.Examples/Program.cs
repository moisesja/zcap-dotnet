using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Examples;

Console.WriteLine("===========================================");
Console.WriteLine("W3C ZCAP-LD .NET Implementation Examples");
Console.WriteLine("===========================================\n");

// Initialize services
// In production, replace InMemoryDidProvider with your HSM/Key Vault-backed implementations
// of IDidSigner and IDidResolver.
var didProvider = new InMemoryDidProvider();
var signingService = new SigningService(didProvider, didProvider);
var capabilityService = new CapabilityService(signingService);
var caveatProcessor = new CaveatProcessor();
var verificationService = new VerificationService(didProvider, caveatProcessor);

// ===================================================
// Example 1: Create a Root Capability
// ===================================================
Console.WriteLine("Example 1: Creating a Root Capability");
Console.WriteLine("--------------------------------------");

var aliceDid = "did:key:z6MkAlice";
didProvider.GenerateAndRegisterKeyPair(aliceDid);

var rootCapability = await capabilityService.CreateRootCapabilityAsync(
    controller: aliceDid,

    // The invocation target is the resource or API endpoint the capability grants access to.
    invocationTarget: "https://storage.example.com/documents/report.pdf",
    allowedActions: new[] { "read", "write", "delete" }
);

Console.WriteLine($"Root Capability ID: {rootCapability.Id}");
Console.WriteLine($"Controller: {rootCapability.Controller}");
Console.WriteLine($"Invocation Target: {rootCapability.InvocationTarget}");
Console.WriteLine($"Root Allowed Actions: {(rootCapability.AllowedAction is null or { Length: 0 } ? "(none by design)" : string.Join(", ", rootCapability.AllowedAction))}");
Console.WriteLine($"Has Proof: {rootCapability.Proof != null}"); // Root capabilities have no proof
Console.WriteLine();

// ===================================================
// Example 2: Single-Level Delegation
// ===================================================
Console.WriteLine("Example 2: Single-Level Delegation");
Console.WriteLine("-----------------------------------");

var bobDid = "did:key:z6MkBob";
didProvider.GenerateAndRegisterKeyPair(bobDid);

// Alice delegates to Bob with attenuated permissions (only read and write, no delete)
var bobCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: rootCapability,
    newController: bobDid,
    allowedActions: new[] { "read", "write" }, // Attenuated - no "delete"
    expires: DateTime.UtcNow.AddDays(30)
);

Console.WriteLine($"Delegated Capability ID: {bobCapability.Id}");
Console.WriteLine($"New Controller: {bobCapability.Controller}");
Console.WriteLine($"Parent Capability: {bobCapability.ParentCapability}");
Console.WriteLine($"Allowed Actions: {string.Join(", ", bobCapability.AllowedAction)}");
Console.WriteLine($"Expires: {bobCapability.Expires}");
Console.WriteLine($"Has Proof: {bobCapability.Proof != null}"); // Delegated capabilities MUST have proof
Console.WriteLine($"Proof Type: {bobCapability.Proof?.Type}");
Console.WriteLine($"Proof Purpose: {bobCapability.Proof?.ProofPurpose}");
Console.WriteLine();

// ===================================================
// Example 3: Multi-Level Delegation Chain
// ===================================================
Console.WriteLine("Example 3: Multi-Level Delegation Chain");
Console.WriteLine("----------------------------------------");

var carolDid = "did:key:z6MkCarol";
didProvider.GenerateAndRegisterKeyPair(carolDid);

// Bob delegates to Carol with even more restricted permissions (only read)
var carolCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: bobCapability,
    newController: carolDid,
    allowedActions: new[] { "read" }, // Further attenuated - only read
    expires: DateTime.UtcNow.AddDays(15) // Shorter expiration than Bob's
);

Console.WriteLine($"Second-Level Delegation ID: {carolCapability.Id}");
Console.WriteLine($"Controller: {carolCapability.Controller}");
Console.WriteLine($"Parent: {carolCapability.ParentCapability}");
Console.WriteLine($"Allowed Actions: {string.Join(", ", carolCapability.AllowedAction)}");
Console.WriteLine($"Expires: {carolCapability.Expires}");

// Verify the capability chain
var chainValid = await verificationService.VerifyCapabilityChainAsync(carolCapability);
Console.WriteLine($"Capability Chain Valid: {chainValid}");
Console.WriteLine();

// ===================================================
// Example 4: Invocation with Verification
// ===================================================
Console.WriteLine("Example 4: Capability Invocation");
Console.WriteLine("---------------------------------");

// Carol invokes the capability to read the document
var invocation = new Invocation
{
    Capability = carolCapability.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://storage.example.com/documents/report.pdf"
};

// Sign the invocation
invocation.Proof = await signingService.SignInvocationAsync(invocation, carolDid);

Console.WriteLine($"Invocation Capability: {invocation.Capability}");
Console.WriteLine($"Requested Action: {invocation.CapabilityAction}");
Console.WriteLine($"Target: {invocation.InvocationTarget}");
Console.WriteLine($"Proof Type: {invocation.Proof.Type}");
Console.WriteLine($"Proof Purpose: {invocation.Proof.ProofPurpose}");

// Verify the invocation
var invocationValid = await verificationService.VerifyInvocationAsync(invocation, carolCapability);
Console.WriteLine($"Invocation Valid: {invocationValid}");
Console.WriteLine();

// Try an invalid invocation (action not allowed)
Console.WriteLine("Attempting invalid invocation (write action):");
var invalidInvocation = new Invocation
{
    Capability = carolCapability.Id,
    CapabilityAction = "write", // Carol only has "read" permission
    InvocationTarget = "https://storage.example.com/documents/report.pdf"
};
invalidInvocation.Proof = await signingService.SignInvocationAsync(invalidInvocation, carolDid);

var invalidInvocationValid = await verificationService.VerifyInvocationAsync(invalidInvocation, carolCapability);
Console.WriteLine($"Invalid Invocation Valid: {invalidInvocationValid} (expected: False)");
Console.WriteLine();

// ===================================================
// Example 5: Using Caveats
// ===================================================
Console.WriteLine("Example 5: Capabilities with Caveats");
Console.WriteLine("-------------------------------------");

var davidDid = "did:key:z6MkDavid";
didProvider.GenerateAndRegisterKeyPair(davidDid);

// Root first, then delegate with expiration and usage count caveats
var caveatRoot = await capabilityService.CreateRootCapabilityAsync(
    controller: davidDid,
    invocationTarget: "https://api.example.com/data",
    allowedActions: new[] { "query", "read" }
);

var caveatCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: caveatRoot,
    newController: davidDid,
    allowedActions: new[] { "query" },
    expires: DateTime.UtcNow.AddDays(1),
    caveats: new Caveat[]
    {
        new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddHours(24)
        },
        new UsageCountCaveat
        {
            MaxUses = 100,
            CurrentUses = 0
        }
    }
);

Console.WriteLine($"Capability with Caveats ID: {caveatCapability.Id}");
Console.WriteLine($"Number of Caveats: {caveatCapability.Caveat?.Length ?? 0}");
foreach (var caveat in caveatCapability.Caveat ?? Array.Empty<Caveat>())
{
    Console.WriteLine($"  - Caveat Type: {caveat.Type}");
    if (caveat is ExpirationCaveat exp)
    {
        Console.WriteLine($"    Expires: {exp.Expires:yyyy-MM-dd HH:mm:ss} UTC");
    }
    else if (caveat is UsageCountCaveat usage)
    {
        Console.WriteLine($"    Max Uses: {usage.MaxUses}");
        Console.WriteLine($"    Current Uses: {usage.CurrentUses}");
    }
}

// Test invocation with caveats
var caveatInvocation = new Invocation
{
    Capability = caveatCapability.Id,
    CapabilityAction = "query",
    InvocationTarget = "https://api.example.com/data?filter=active"
};
caveatInvocation.Proof = await signingService.SignInvocationAsync(caveatInvocation, davidDid);

var caveatInvocationValid = await verificationService.VerifyInvocationAsync(caveatInvocation, caveatCapability);
Console.WriteLine($"Caveat Invocation Valid: {caveatInvocationValid}");
Console.WriteLine();

// ===================================================
// Example 6: Attenuation Enforcement
// ===================================================
Console.WriteLine("Example 6: Attenuation Enforcement");
Console.WriteLine("-----------------------------------");

var eveDid = "did:key:z6MkEve";
var restrictedDid = "did:key:z6MkRestricted";
didProvider.GenerateAndRegisterKeyPair(eveDid);
didProvider.GenerateAndRegisterKeyPair(restrictedDid);

// Create root, then delegated parent with broad permissions
var attenuationRoot = await capabilityService.CreateRootCapabilityAsync(
    controller: eveDid,
    invocationTarget: "https://api.example.com/resources",
    allowedActions: new[] { "read", "write", "delete", "admin" }
);

var broadCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: attenuationRoot,
    newController: eveDid,
    allowedActions: new[] { "read", "write", "delete", "admin" },
    expires: DateTime.UtcNow.AddDays(30)
);

// Delegate with restricted target and actions
var restrictedCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: broadCapability,
    newController: restrictedDid,
    allowedActions: new[] { "read" }, // Significantly attenuated
    expires: DateTime.UtcNow.AddDays(7)
);

Console.WriteLine("Attenuation Example:");
Console.WriteLine($"Parent Actions: {string.Join(", ", broadCapability.AllowedAction ?? Array.Empty<string>())}");
Console.WriteLine($"Child Actions: {string.Join(", ", restrictedCapability.AllowedAction ?? Array.Empty<string>())}");
Console.WriteLine($"Properly Attenuated: {(restrictedCapability.AllowedAction?.Length ?? 0) < (broadCapability.AllowedAction?.Length ?? 0)}");

// Attempting to create invalid delegation (expanding authority)
Console.WriteLine("\nAttempting to expand authority (should fail):");
try
{
    var invalidDelegation = await capabilityService.DelegateCapabilityAsync(
        parentCapability: restrictedCapability,
        newController: "did:key:z6MkInvalid",
        allowedActions: new[] { "read", "write", "admin" }, // Trying to expand
        expires: DateTime.UtcNow.AddDays(3)
    );
    Console.WriteLine("ERROR: Delegation succeeded when it should have failed!");
}
catch (InvalidOperationException ex)
{
    Console.WriteLine($"Correctly rejected: {ex.Message}");
}
Console.WriteLine();

// ===================================================
// Example 7: Real-World Scenario - Document Sharing
// ===================================================
Console.WriteLine("Example 7: Real-World Document Sharing Scenario");
Console.WriteLine("------------------------------------------------");

// Setup: Company document management system
var companyAdminDid = "did:key:z6MkCompanyAdmin";
var managerDid = "did:key:z6MkManager";
var employeeDid = "did:key:z6MkEmployee";

didProvider.GenerateAndRegisterKeyPair(companyAdminDid);
didProvider.GenerateAndRegisterKeyPair(managerDid);
didProvider.GenerateAndRegisterKeyPair(employeeDid);

// Admin creates root capability for sensitive document
var sensitiveDoc = await capabilityService.CreateRootCapabilityAsync(
    controller: companyAdminDid,
    invocationTarget: "https://docs.company.com/confidential/q4-financials.pdf",
    allowedActions: new[] { "read", "write", "share", "delete" }
);

// Root controller creates an explicit delegated authority with full business actions.
var adminAuthority = await capabilityService.DelegateCapabilityAsync(
    parentCapability: sensitiveDoc,
    newController: companyAdminDid,
    allowedActions: new[] { "read", "write", "share", "delete" },
    expires: DateTime.UtcNow.AddMonths(3)
);

Console.WriteLine("Company Admin creates root capability for Q4 financials");
Console.WriteLine($"  Capability: {sensitiveDoc.Id}");
Console.WriteLine($"  Root Actions: {(sensitiveDoc.AllowedAction is null or { Length: 0 } ? "(none by design)" : string.Join(", ", sensitiveDoc.AllowedAction))}");
Console.WriteLine($"  Admin Authority Actions: {string.Join(", ", adminAuthority.AllowedAction ?? Array.Empty<string>())}");

// Admin delegates to Manager with sharing capability for 60 days
// Note: child expiration MUST be ≤ parent expiration (attenuation rule)
var managerAccess = await capabilityService.DelegateCapabilityAsync(
    parentCapability: adminAuthority,
    newController: managerDid,
    allowedActions: new[] { "read", "share" },
    expires: DateTime.UtcNow.AddMonths(2)
);

Console.WriteLine("\nManager receives delegation:");
Console.WriteLine($"  Capability: {managerAccess.Id}");
Console.WriteLine($"  Actions: {string.Join(", ", managerAccess.AllowedAction)}");
Console.WriteLine($"  Valid until: {managerAccess.Expires:yyyy-MM-dd}");

// Manager delegates to Employee with read-only access for 30 days
var employeeAccess = await capabilityService.DelegateCapabilityAsync(
    parentCapability: managerAccess,
    newController: employeeDid,
    allowedActions: new[] { "read" },
    expires: DateTime.UtcNow.AddMonths(1),
    caveats: new Caveat[]
    {
        new UsageCountCaveat { MaxUses = 50, CurrentUses = 0 } // Limit to 50 views
    }
);

Console.WriteLine("\nEmployee receives limited delegation:");
Console.WriteLine($"  Capability: {employeeAccess.Id}");
Console.WriteLine($"  Actions: {string.Join(", ", employeeAccess.AllowedAction)}");
Console.WriteLine($"  Valid until: {employeeAccess.Expires:yyyy-MM-dd}");
Console.WriteLine($"  Usage limit: 50 views");

// Employee attempts to read document
var employeeRead = new Invocation
{
    Capability = employeeAccess.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://docs.company.com/confidential/q4-financials.pdf"
};
employeeRead.Proof = await signingService.SignInvocationAsync(employeeRead, employeeDid);

var employeeCanRead = await verificationService.VerifyInvocationAsync(employeeRead, employeeAccess);
Console.WriteLine($"\nEmployee reads document: {(employeeCanRead ? "ALLOWED" : "DENIED")}");

// Employee attempts to share document (should fail)
var employeeShare = new Invocation
{
    Capability = employeeAccess.Id,
    CapabilityAction = "share",
    InvocationTarget = "https://docs.company.com/confidential/q4-financials.pdf"
};
employeeShare.Proof = await signingService.SignInvocationAsync(employeeShare, employeeDid);

var employeeCanShare = await verificationService.VerifyInvocationAsync(employeeShare, employeeAccess);
Console.WriteLine($"Employee shares document: {(employeeCanShare ? "ALLOWED" : "DENIED")} (expected: DENIED)");

Console.WriteLine();

// ===================================================
// Example 8: ValidWhileTrue Caveat (Remote Revocation)
// ===================================================
Console.WriteLine("Example 8: ValidWhileTrue Caveat (Remote Revocation)");
Console.WriteLine("-----------------------------------------------------");

// ValidWhileTrue is a spec-defined caveat where the delegator/controller hosts
// a revocation status endpoint. The verifier checks that endpoint at invocation
// time to confirm the capability is still valid.
//
// Flow:
//   1. Controller creates capability with ValidWhileTrue caveat pointing to their endpoint
//   2. Controller deploys revocation endpoint (e.g. MapZcapRevocationEndpoints())
//   3. Verifier configures AddZcapValidWhileTrueSupport() to enable HTTP checking
//   4. At verification time, the handler GETs the URI and checks isRevoked
//   5. Controller can revoke by POSTing to their own endpoint

var orgDid = "did:key:z6MkOrg";
var partnerDid = "did:key:z6MkPartner";
didProvider.GenerateAndRegisterKeyPair(orgDid);
didProvider.GenerateAndRegisterKeyPair(partnerDid);

// The organization creates a root capability for an API resource
var apiRoot = await capabilityService.CreateRootCapabilityAsync(
    controller: orgDid,
    invocationTarget: "https://api.org.example/v1/data",
    allowedActions: new[] { "read", "write" }
);

// Delegate to a partner with a ValidWhileTrue caveat.
// The URI points to the org's revocation status endpoint.
var partnerCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: apiRoot,
    newController: partnerDid,
    allowedActions: new[] { "read" },
    expires: DateTime.UtcNow.AddDays(30),
    caveats: new Caveat[]
    {
        new ValidWhileTrueCaveat
        {
            // In production, this would be a real URL served by MapZcapRevocationEndpoints()
            Uri = $"https://revocation.org.example/zcaps/revocations/{Uri.EscapeDataString(apiRoot.Id)}"
        }
    }
);

Console.WriteLine($"Delegated to partner: {partnerCapability.Id}");
Console.WriteLine($"  Controller: {partnerCapability.Controller}");
Console.WriteLine($"  Actions: {string.Join(", ", partnerCapability.AllowedAction)}");
Console.WriteLine($"  Caveats:");
foreach (var c in partnerCapability.Caveat)
{
    if (c is ValidWhileTrueCaveat vwt)
        Console.WriteLine($"    - ValidWhileTrue -> {vwt.Uri}");
}

// Without a handler, verification fails (fail-closed security)
Console.WriteLine("\n  Without handler (fail-closed):");
var noHandlerProcessor = new CaveatProcessor(); // no handler
var noHandlerVerifier = new VerificationService(didProvider, noHandlerProcessor);

var partnerInvocation = new Invocation
{
    Capability = partnerCapability.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://api.org.example/v1/data"
};
partnerInvocation.Proof = await signingService.SignInvocationAsync(partnerInvocation, partnerDid);

var noHandlerResult = await noHandlerVerifier.VerifyInvocationAsync(partnerInvocation, partnerCapability);
Console.WriteLine($"    Invocation valid: {noHandlerResult} (expected: False — no handler configured)");

// With a handler that confirms the capability is still valid, verification succeeds
Console.WriteLine("\n  With handler (capability NOT revoked):");
var activeHandler = new StubValidWhileTrueHandler(isActive: true);
var handlerProcessor = new CaveatProcessor(activeHandler);
var handlerVerifier = new VerificationService(didProvider, handlerProcessor);

// Re-sign with fresh nonce to avoid replay detection
var partnerInvocation2 = new Invocation
{
    Capability = partnerCapability.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://api.org.example/v1/data"
};
partnerInvocation2.Proof = await signingService.SignInvocationAsync(partnerInvocation2, partnerDid);

var activeResult = await handlerVerifier.VerifyInvocationAsync(partnerInvocation2, partnerCapability);
Console.WriteLine($"    Invocation valid: {activeResult} (expected: True — handler confirms active)");

// Simulate revocation: handler now says the capability is revoked
Console.WriteLine("\n  With handler (capability REVOKED):");
var revokedHandler = new StubValidWhileTrueHandler(isActive: false);
var revokedProcessor = new CaveatProcessor(revokedHandler);
var revokedVerifier = new VerificationService(didProvider, revokedProcessor);

var partnerInvocation3 = new Invocation
{
    Capability = partnerCapability.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://api.org.example/v1/data"
};
partnerInvocation3.Proof = await signingService.SignInvocationAsync(partnerInvocation3, partnerDid);

var revokedResult = await revokedVerifier.VerifyInvocationAsync(partnerInvocation3, partnerCapability);
Console.WriteLine($"    Invocation valid: {revokedResult} (expected: False — capability revoked)");

Console.WriteLine();

// ===================================================
// Example 9: Context Property Injection for Custom Caveats
// ===================================================
Console.WriteLine("Example 9: Context Property Injection for Custom Caveats");
Console.WriteLine("---------------------------------------------------------");

// Custom caveats often need application-specific metadata that isn't part of
// the invocation document itself (e.g. HTTP Content-Type, schema URI, caller IP).
// The 3-param VerifyInvocationAsync overload lets callers inject these properties
// into InvocationContext.Properties, where custom caveats can read them.

// Register the custom caveat so the polymorphic JSON converter can round-trip
// it across the signing boundary. In-memory pipelines work without this, but
// any HTTP-transported wire body needs the registration before deserialization
// can produce ContentTypeCaveat (vs. throwing on the abstract Caveat base).
CaveatTypeRegistry.Default.Register<ContentTypeCaveat>("ContentType");

var apiOwnerDid = "did:key:z6MkApiOwner";
var clientDid = "did:key:z6MkClient";
didProvider.GenerateAndRegisterKeyPair(apiOwnerDid);
didProvider.GenerateAndRegisterKeyPair(clientDid);

// Create root capability for an API that only accepts JSON payloads
var jsonApiRoot = await capabilityService.CreateRootCapabilityAsync(
    controller: apiOwnerDid,
    invocationTarget: "https://api.example.com/v1/records",
    allowedActions: new[] { "read", "write" }
);

// Delegate to the client with a ContentType caveat requiring application/json
var clientCapability = await capabilityService.DelegateCapabilityAsync(
    parentCapability: jsonApiRoot,
    newController: clientDid,
    allowedActions: new[] { "write" },
    expires: DateTime.UtcNow.AddDays(7),
    caveats: new Caveat[]
    {
        new ContentTypeCaveat { RequiredContentType = "application/json" }
    }
);

Console.WriteLine($"Delegated to client: {clientCapability.Id}");
Console.WriteLine($"  Actions: {string.Join(", ", clientCapability.AllowedAction)}");
Console.WriteLine($"  Caveat: ContentType must be application/json");

// Client invokes the capability
var clientInvocation = new Invocation
{
    Capability = clientCapability.Id,
    CapabilityAction = "write",
    InvocationTarget = "https://api.example.com/v1/records"
};
clientInvocation.Proof = await signingService.SignInvocationAsync(clientInvocation, clientDid);

// Verify WITH correct content type injected from the HTTP request context
Console.WriteLine("\n  With contentType = application/json:");
var jsonResult = await verificationService.VerifyInvocationAsync(
    clientInvocation,
    clientCapability,
    new Dictionary<string, object> { ["contentType"] = "application/json" });
Console.WriteLine($"    Invocation valid: {jsonResult} (expected: True)");

// Re-sign with fresh nonce, then verify with wrong content type
var clientInvocation2 = new Invocation
{
    Capability = clientCapability.Id,
    CapabilityAction = "write",
    InvocationTarget = "https://api.example.com/v1/records"
};
clientInvocation2.Proof = await signingService.SignInvocationAsync(clientInvocation2, clientDid);

Console.WriteLine("\n  With contentType = text/xml:");
var xmlResult = await verificationService.VerifyInvocationAsync(
    clientInvocation2,
    clientCapability,
    new Dictionary<string, object> { ["contentType"] = "text/xml" });
Console.WriteLine($"    Invocation valid: {xmlResult} (expected: False — wrong content type)");

// Re-sign with fresh nonce, then verify without any properties (caveat will reject)
var clientInvocation3 = new Invocation
{
    Capability = clientCapability.Id,
    CapabilityAction = "write",
    InvocationTarget = "https://api.example.com/v1/records"
};
clientInvocation3.Proof = await signingService.SignInvocationAsync(clientInvocation3, clientDid);

Console.WriteLine("\n  Without context properties (fail-closed):");
var noPropsResult = await verificationService.VerifyInvocationAsync(
    clientInvocation3,
    clientCapability);
Console.WriteLine($"    Invocation valid: {noPropsResult} (expected: False — no properties injected)");

Console.WriteLine();

// ===================================================
// Example 10: RDFC-1.0 vs JCS Canonicalization
// ===================================================
Console.WriteLine("Example 10: RDFC-1.0 vs JCS Canonicalization");
Console.WriteLine("----------------------------------------------");

// ZCAP-LD proofs can use different canonicalization methods depending on the
// crypto suite. By default, all built-in suites use JCS (JSON Canonicalization Scheme,
// RFC 8785). To use RDFC-1.0 (W3C RDF Dataset Canonicalization), you:
//   1. Create a crypto suite that declares CanonicalizationMethod = "RDFC-1.0"
//   2. Register both JCS and RDFC-1.0 canonicalizers in a DocumentCanonicalizerProvider
//   3. Pass the providers to SigningService and VerificationService full constructors

// --- Setup: register both canonicalizers ---
var canonicalizerProvider = new DocumentCanonicalizerProvider();
canonicalizerProvider.Register(new JcsDocumentCanonicalizer());     // always needed as fallback
canonicalizerProvider.Register(new RdfcDocumentCanonicalizer());    // RDFC-1.0 support

// --- Setup: register both crypto suites ---
var suiteProvider = new CryptoSuiteProvider();
suiteProvider.Register(CryptoSuite.Ed25519());       // default Ed25519 (JCS)
suiteProvider.Register(new RdfcEd25519CryptoSuite()); // Ed25519 with RDFC-1.0

// Note: Both suites have the same ProofType ("Ed25519Signature2020"), so the last
// registered wins in the provider lookup. This means signing will use RDFC-1.0 and
// verification will also resolve to RDFC-1.0 for Ed25519Signature2020 proofs.
//
// In practice, you would use one canonicalization method per deployment, or use
// different proof types to distinguish suites.

// --- Wire services with the full constructors ---
var rdfcDidProvider = new InMemoryDidProvider();
var rdfcSigningService = new SigningService(
    rdfcDidProvider, rdfcDidProvider, suiteProvider, canonicalizerProvider);
var rdfcVerificationService = new VerificationService(
    rdfcDidProvider, caveatProcessor, suiteProvider,
    new RevocationService(new InMemoryRevocationStore()),
    new InMemoryNonceStore(), canonicalizerProvider);

// --- Create and delegate a capability using RDFC-1.0 ---
var rdfcOwnerDid = "did:key:z6MkRdfcOwner";
var rdfcDelegateDid = "did:key:z6MkRdfcDelegate";
rdfcDidProvider.GenerateAndRegisterKeyPair(rdfcOwnerDid);
rdfcDidProvider.GenerateAndRegisterKeyPair(rdfcDelegateDid);

var rdfcCapabilityService = new CapabilityService(rdfcSigningService);

var rdfcRoot = await rdfcCapabilityService.CreateRootCapabilityAsync(
    controller: rdfcOwnerDid,
    invocationTarget: "https://storage.example.com/rdfc-documents",
    allowedActions: new[] { "read", "write" }
);

var rdfcDelegated = await rdfcCapabilityService.DelegateCapabilityAsync(
    parentCapability: rdfcRoot,
    newController: rdfcDelegateDid,
    allowedActions: new[] { "read" },
    expires: DateTime.UtcNow.AddDays(7)
);

Console.WriteLine($"Root Capability:      {rdfcRoot.Id}");
Console.WriteLine($"Delegated Capability: {rdfcDelegated.Id}");
Console.WriteLine($"Proof Type:           {rdfcDelegated.Proof?.Type}");

// Verify the RDFC-1.0 delegation chain
var rdfcChainValid = await rdfcVerificationService.VerifyCapabilityChainAsync(rdfcDelegated);
Console.WriteLine($"RDFC-1.0 Chain Valid: {rdfcChainValid}");

// --- Invoke and verify using RDFC-1.0 ---
var rdfcInvocation = new Invocation
{
    Capability = rdfcDelegated.Id,
    CapabilityAction = "read",
    InvocationTarget = "https://storage.example.com/rdfc-documents"
};
rdfcInvocation.Proof = await rdfcSigningService.SignInvocationAsync(rdfcInvocation, rdfcDelegateDid);

var rdfcInvocationValid = await rdfcVerificationService.VerifyInvocationAsync(rdfcInvocation, rdfcDelegated);
Console.WriteLine($"RDFC-1.0 Invocation Valid: {rdfcInvocationValid}");

// --- Compare: show that JCS and RDFC-1.0 produce different proofs ---
Console.WriteLine("\nComparing JCS vs RDFC-1.0 canonicalization:");

var jcsCanonicalizer = new JcsDocumentCanonicalizer();
var rdfcCanonicalizer = new RdfcDocumentCanonicalizer();

// Canonicalize the same root capability with both methods
var jcsBytes = jcsCanonicalizer.Canonicalize(rdfcRoot);
var rdfcBytes = rdfcCanonicalizer.Canonicalize(rdfcRoot);

Console.WriteLine($"  JCS output size:      {jcsBytes.Length} bytes (compact JSON)");
Console.WriteLine($"  RDFC-1.0 output size: {rdfcBytes.Length} bytes (N-Quads)");
Console.WriteLine($"  Same output:          {jcsBytes.SequenceEqual(rdfcBytes)} (expected: False)");

Console.WriteLine();
Console.WriteLine("===========================================");
Console.WriteLine("All examples completed successfully!");
Console.WriteLine("===========================================");
