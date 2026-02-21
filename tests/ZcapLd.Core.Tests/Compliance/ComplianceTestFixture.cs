using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Compliance;

internal sealed class ComplianceTestFixture
{
    public InMemoryDidProvider DidProvider { get; }
    public SigningService SigningService { get; }
    public CapabilityService CapabilityService { get; }
    public CaveatProcessor CaveatProcessor { get; }
    public VerificationService VerificationService { get; }

    public ComplianceTestFixture()
    {
        DidProvider = new InMemoryDidProvider();
        SigningService = new SigningService(DidProvider);
        CaveatProcessor = new CaveatProcessor();
        CapabilityService = new CapabilityService(SigningService);
        VerificationService = new VerificationService(DidProvider, CaveatProcessor);
    }

    public string RegisterControllerDid()
    {
        return DidProvider.GenerateDidKey();
    }
}

