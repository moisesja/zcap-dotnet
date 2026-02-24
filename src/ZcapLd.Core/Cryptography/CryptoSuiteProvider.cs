using System.Collections.Concurrent;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Default implementation of <see cref="ICryptoSuiteProvider"/>.
/// Supports registration of multiple crypto suites and lookup by proof type or multicodec prefix.
/// Thread-safe for concurrent reads; registration is expected at startup.
/// </summary>
public class CryptoSuiteProvider : ICryptoSuiteProvider
{
    private readonly ConcurrentDictionary<string, ICryptoSuite> _byProofType = new(StringComparer.Ordinal);
    private readonly List<ICryptoSuite> _suites = new();
    private readonly object _lock = new();

    /// <summary>
    /// Registers a crypto suite. Replaces any existing suite with the same proof type.
    /// </summary>
    public void Register(ICryptoSuite suite)
    {
        ArgumentNullException.ThrowIfNull(suite);

        _byProofType[suite.ProofType] = suite;

        lock (_lock)
        {
            _suites.RemoveAll(s => s.ProofType == suite.ProofType);
            _suites.Add(suite);
        }
    }

    public ICryptoSuite? GetByProofType(string proofType)
    {
        if (string.IsNullOrEmpty(proofType))
            return null;

        _byProofType.TryGetValue(proofType, out var suite);
        return suite;
    }

    public ICryptoSuite? GetByMulticodecPrefix(ReadOnlySpan<byte> prefix)
    {
        lock (_lock)
        {
            foreach (var suite in _suites)
            {
                var suitePrefix = suite.MulticodecPrefix;
                if (prefix.Length >= suitePrefix.Length &&
                    prefix[..suitePrefix.Length].SequenceEqual(suitePrefix))
                {
                    return suite;
                }
            }
        }

        return null;
    }

    public ICryptoSuite? GetByKeyType(string keyType)
    {
        if (string.IsNullOrEmpty(keyType))
            return null;

        lock (_lock)
        {
            return _suites.FirstOrDefault(s => s.KeyType == keyType);
        }
    }
}
