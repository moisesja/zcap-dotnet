using System.Collections.Concurrent;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Default implementation of <see cref="ICryptoSuiteProvider"/>.
/// Supports registration of multiple crypto suites and lookup by proof type or key type.
/// Thread-safe for concurrent reads; registration is expected at startup.
/// </summary>
public class CryptoSuiteProvider : ICryptoSuiteProvider
{
    private readonly ConcurrentDictionary<string, ICryptoSuite> _byProofType = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ICryptoSuite> _byKeyType = new(StringComparer.Ordinal);

    /// <summary>
    /// Registers a crypto suite. Replaces any existing suite with the same proof type or key type.
    /// </summary>
    public void Register(ICryptoSuite suite)
    {
        ArgumentNullException.ThrowIfNull(suite);

        _byProofType[suite.ProofType] = suite;
        _byKeyType[suite.KeyType] = suite;
    }

    public ICryptoSuite? GetByProofType(string proofType)
    {
        if (string.IsNullOrEmpty(proofType))
            return null;

        _byProofType.TryGetValue(proofType, out var suite);
        return suite;
    }

    public ICryptoSuite? GetByKeyType(string keyType)
    {
        if (string.IsNullOrEmpty(keyType))
            return null;

        _byKeyType.TryGetValue(keyType, out var suite);
        return suite;
    }
}
