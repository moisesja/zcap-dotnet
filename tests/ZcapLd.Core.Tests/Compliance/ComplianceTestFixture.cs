using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Compliance;

internal sealed class ComplianceTestFixture
{
    public SigningService SigningService { get; }
    public CapabilityService CapabilityService { get; }
    public CaveatProcessor CaveatProcessor { get; }
    public VerificationService VerificationService { get; }

    public ComplianceTestFixture()
    {
        SigningService = new SigningService();
        CaveatProcessor = new CaveatProcessor();
        CapabilityService = new CapabilityService(SigningService);
        VerificationService = new VerificationService(SigningService, CaveatProcessor);
    }

    public string RegisterControllerDid()
    {
        var (privateKey, publicKey) = Ed25519Signer.GenerateKeyPair();
        var did = BuildDidKey(publicKey);
        SigningService.RegisterKey(did, privateKey);
        return did;
    }

    private static string BuildDidKey(byte[] publicKey)
    {
        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes.", nameof(publicKey));
        }

        // Multicodec prefix for Ed25519 public keys: 0xed01
        var prefixed = new byte[34];
        prefixed[0] = 0xed;
        prefixed[1] = 0x01;
        Buffer.BlockCopy(publicKey, 0, prefixed, 2, 32);

        var multibaseKey = Ed25519Signer.EncodeSignature(prefixed);
        return $"did:key:{multibaseKey}";
    }
}

