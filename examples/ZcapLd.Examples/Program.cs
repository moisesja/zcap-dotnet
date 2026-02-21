using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

Console.WriteLine("===========================================");
Console.WriteLine("W3C ZCAP-LD .NET Implementation Examples");
Console.WriteLine("===========================================\n");

// Initialize services
var didProvider = new InMemoryDidProvider();
var signingService = new SigningService(didProvider);
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
    invocationTarget: "https://storage.example.com/documents/report.pdf",
    allowedActions: new[] { "read", "write", "delete" }
);

Console.WriteLine($"Root Capability ID: {rootCapability.Id}");
Console.WriteLine($"Controller: {rootCapability.Controller}");
Console.WriteLine($"Invocation Target: {rootCapability.InvocationTarget}");
Console.WriteLine($"Root Allowed Actions: {(rootCapability.AllowedAction.Length == 0 ? "(none by design)" : string.Join(", ", rootCapability.AllowedAction))}");
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
Console.WriteLine($"Expires: {bobCapability.Expires:yyyy-MM-dd HH:mm:ss} UTC");
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
Console.WriteLine($"Expires: {carolCapability.Expires:yyyy-MM-dd HH:mm:ss} UTC");

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
Console.WriteLine($"Number of Caveats: {caveatCapability.Caveat.Length}");
foreach (var caveat in caveatCapability.Caveat)
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
Console.WriteLine($"Parent Actions: {string.Join(", ", broadCapability.AllowedAction)}");
Console.WriteLine($"Child Actions: {string.Join(", ", restrictedCapability.AllowedAction)}");
Console.WriteLine($"Properly Attenuated: {restrictedCapability.AllowedAction.Length < broadCapability.AllowedAction.Length}");

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
    expires: DateTime.UtcNow.AddDays(180)
);

Console.WriteLine("Company Admin creates root capability for Q4 financials");
Console.WriteLine($"  Capability: {sensitiveDoc.Id}");
Console.WriteLine($"  Root Actions: {(sensitiveDoc.AllowedAction.Length == 0 ? "(none by design)" : string.Join(", ", sensitiveDoc.AllowedAction))}");
Console.WriteLine($"  Admin Authority Actions: {string.Join(", ", adminAuthority.AllowedAction)}");

// Admin delegates to Manager with sharing capability for 90 days
var managerAccess = await capabilityService.DelegateCapabilityAsync(
    parentCapability: adminAuthority,
    newController: managerDid,
    allowedActions: new[] { "read", "share" },
    expires: DateTime.UtcNow.AddDays(90)
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
    expires: DateTime.UtcNow.AddDays(30),
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
Console.WriteLine("===========================================");
Console.WriteLine("All examples completed successfully!");
Console.WriteLine("===========================================");
