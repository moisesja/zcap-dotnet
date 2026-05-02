using System.Collections.Concurrent;

namespace ZcapLd.Core.Models;

/// <summary>
/// Maps `Caveat.Type` discriminator strings to concrete CLR types so the
/// <see cref="ZcapLd.Core.Cryptography.CaveatJsonConverter"/> can dispatch
/// polymorphic deserialization across packages — third-party caveat libraries
/// register their derived types here at startup, the same way custom crypto
/// suites register through <c>ICryptoSuiteProvider</c>.
///
/// The <see cref="Default"/> singleton is pre-populated with the in-library
/// caveats. The converter holds a reference to <see cref="Default"/> and
/// resolves dynamically, so registrations performed any time before the first
/// signing or verification call take effect.
/// </summary>
public sealed class CaveatTypeRegistry
{
    private readonly ConcurrentDictionary<string, Type> _byDiscriminator =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Process-wide singleton consulted by the default JSON converter.
    /// In-library types are registered in the static constructor.
    /// </summary>
    public static CaveatTypeRegistry Default { get; } = CreateDefault();

    private static CaveatTypeRegistry CreateDefault()
    {
        var registry = new CaveatTypeRegistry();
        registry.Register<ExpirationCaveat>("Expiration");
        registry.Register<UsageCountCaveat>("UsageCount");
        registry.Register<ValidWhileTrueCaveat>("ValidWhileTrue");
        return registry;
    }

    /// <summary>
    /// Registers a derived caveat type against its on-the-wire discriminator.
    /// Idempotent for the same (discriminator, type) pair; throws on conflict.
    /// </summary>
    public void Register<TCaveat>(string discriminator) where TCaveat : Caveat
    {
        if (string.IsNullOrEmpty(discriminator))
            throw new ArgumentException("Discriminator cannot be null or empty", nameof(discriminator));

        var existing = _byDiscriminator.GetOrAdd(discriminator, typeof(TCaveat));
        if (existing != typeof(TCaveat))
        {
            throw new InvalidOperationException(
                $"Discriminator '{discriminator}' is already registered to {existing.FullName}; " +
                $"cannot re-register to {typeof(TCaveat).FullName}.");
        }
    }

    /// <summary>
    /// Looks up a registered caveat type by discriminator. Returns null when
    /// no type is registered — callers throw the localized error.
    /// </summary>
    public Type? Resolve(string discriminator)
    {
        ArgumentNullException.ThrowIfNull(discriminator);
        return _byDiscriminator.TryGetValue(discriminator, out var type) ? type : null;
    }
}
