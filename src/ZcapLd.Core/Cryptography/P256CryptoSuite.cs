using System.Security.Cryptography;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// NIST P-256 (secp256r1) crypto suite using .NET built-in <see cref="ECDsa"/>.
/// Zero external dependencies beyond the .NET runtime.
/// </summary>
public class P256CryptoSuite : ICryptoSuite
{
    private static readonly byte[] _multicodecPrefix = [0x80, 0x24];

    public string ProofType => "EcdsaSecp256r1Signature2019";

    public string KeyType => "EcdsaSecp256r1VerificationKey2019";

    public byte[] MulticodecPrefix => _multicodecPrefix;

    public int PublicKeyLength => 33; // compressed EC point

    public string ContextUrl => "https://w3id.org/security/suites/ecdsa-2019/v1";

    /// <summary>
    /// Signs data with a 32-byte raw P-256 private key scalar.
    /// Returns a 64-byte IEEE P1363 signature (r ∥ s).
    /// </summary>
    public byte[] Sign(byte[] data, byte[] privateKey)
    {
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("P-256 private key must be 32 bytes", nameof(privateKey));
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty", nameof(data));

        try
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKey
            });

            return ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new Exceptions.CryptographicException("Failed to sign data with P-256", ex);
        }
    }

    /// <summary>
    /// Verifies a 64-byte IEEE P1363 signature against a 33-byte compressed P-256 public key.
    /// </summary>
    public bool Verify(byte[] data, byte[] signature, byte[] publicKey)
    {
        if (publicKey == null || publicKey.Length != 33)
            throw new ArgumentException("P-256 compressed public key must be 33 bytes", nameof(publicKey));
        if (signature == null || signature.Length != 64)
            throw new ArgumentException("P-256 signature must be 64 bytes (IEEE P1363)", nameof(signature));
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty", nameof(data));

        try
        {
            var point = EcPointCompression.DecompressP256(publicKey);

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = point
            });

            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Generates a new P-256 key pair.
    /// Returns (privateKey: 32 bytes, publicKey: 33 bytes compressed).
    /// </summary>
    public static (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        var privateKey = parameters.D!;
        var publicKey = EcPointCompression.CompressP256(parameters.Q);

        return (privateKey, publicKey);
    }
}
