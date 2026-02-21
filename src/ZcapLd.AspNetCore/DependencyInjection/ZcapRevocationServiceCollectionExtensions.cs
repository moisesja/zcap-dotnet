using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.DependencyInjection;

/// <summary>
/// DI helpers for registering ZCAP-LD services, DID resolvers, signers, and revocation stores.
/// </summary>
public static class ZcapRevocationServiceCollectionExtensions
{
    /// <summary>
    /// Registers core ZCAP-LD services with default implementations.
    /// Uses <see cref="DidKeyResolver"/> for DID resolution and
    /// <see cref="InMemoryRevocationStore"/> for revocation storage.
    ///
    /// <b>Important:</b> No default <see cref="IDidSigner"/> is registered.
    /// You must call <see cref="AddZcapDidSigner{TSigner}"/> or
    /// <see cref="AddZcapDidSigner(IServiceCollection, Func{IServiceProvider, IDidSigner})"/>
    /// to register your signer implementation before using <see cref="ISigningService"/>.
    /// </summary>
    public static IServiceCollection AddZcapServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Register Ed25519 crypto suite by default; additional suites can be added via AddZcapCryptoSuite<T>()
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICryptoSuite, Ed25519CryptoSuite>());

        // Build ICryptoSuiteProvider from all registered ICryptoSuite instances
        services.TryAddSingleton<ICryptoSuiteProvider>(sp =>
        {
            var provider = new CryptoSuiteProvider();
            foreach (var suite in sp.GetServices<ICryptoSuite>())
            {
                provider.Register(suite);
            }
            return provider;
        });

        // DidKeyResolver depends on ICryptoSuiteProvider for multicodec prefix decoding
        services.TryAddSingleton<IDidResolver>(sp =>
            new DidKeyResolver(sp.GetRequiredService<ICryptoSuiteProvider>()));

        // No default IDidSigner — consumers must provide their own secure implementation.
        services.TryAddSingleton<ISigningService, SigningService>();
        services.TryAddSingleton<ICaveatProcessor, CaveatProcessor>();
        services.TryAddSingleton<ICapabilityService, CapabilityService>();
        services.TryAddSingleton<IRevocationStore, InMemoryRevocationStore>();
        services.TryAddSingleton<IRevocationService, RevocationService>();

        // VerificationService depends on ICryptoSuiteProvider for proof type dispatch
        services.TryAddSingleton<IVerificationService>(sp =>
            new VerificationService(
                sp.GetRequiredService<IDidResolver>(),
                sp.GetRequiredService<ICaveatProcessor>(),
                sp.GetRequiredService<ICryptoSuiteProvider>(),
                sp.GetRequiredService<IRevocationService>()));

        return services;
    }

    /// <summary>
    /// Registers an additional crypto suite (e.g. P-256, secp256k1).
    /// Call this before <see cref="AddZcapServices"/> builds the service provider,
    /// or before the <see cref="ICryptoSuiteProvider"/> singleton is first resolved.
    /// </summary>
    public static IServiceCollection AddZcapCryptoSuite<TSuite>(this IServiceCollection services)
        where TSuite : class, ICryptoSuite
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICryptoSuite, TSuite>());
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidSigner"/> implementation.
    /// This is required for any signing/delegation operations.
    /// </summary>
    public static IServiceCollection AddZcapDidSigner<TSigner>(this IServiceCollection services)
        where TSigner : class, IDidSigner
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IDidSigner, TSigner>());
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidSigner"/> using a factory.
    /// This is required for any signing/delegation operations.
    /// </summary>
    public static IServiceCollection AddZcapDidSigner(
        this IServiceCollection services,
        Func<IServiceProvider, IDidSigner> signerFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(signerFactory);

        services.Replace(ServiceDescriptor.Singleton(signerFactory));
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidResolver"/> implementation.
    /// Replaces the default <see cref="DidKeyResolver"/>.
    /// </summary>
    public static IServiceCollection AddZcapDidResolver<TResolver>(this IServiceCollection services)
        where TResolver : class, IDidResolver
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IDidResolver, TResolver>());
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidResolver"/> using a factory.
    /// Replaces the default <see cref="DidKeyResolver"/>.
    /// </summary>
    public static IServiceCollection AddZcapDidResolver(
        this IServiceCollection services,
        Func<IServiceProvider, IDidResolver> resolverFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(resolverFactory);

        services.Replace(ServiceDescriptor.Singleton(resolverFactory));
        return services;
    }

    /// <summary>
    /// Registers revocation support with the default in-memory store.
    /// </summary>
    public static IServiceCollection AddZcapRevocationSupport(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IRevocationStore, InMemoryRevocationStore>();
        services.TryAddSingleton<IRevocationService, RevocationService>();
        return services;
    }

    /// <summary>
    /// Registers revocation support using a caller-provided store type.
    /// </summary>
    public static IServiceCollection AddZcapRevocationSupport<TRevocationStore>(this IServiceCollection services)
        where TRevocationStore : class, IRevocationStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IRevocationStore, TRevocationStore>());
        services.TryAddSingleton<IRevocationService, RevocationService>();
        return services;
    }

    /// <summary>
    /// Registers revocation support using a caller-provided store factory.
    /// </summary>
    public static IServiceCollection AddZcapRevocationSupport(
        this IServiceCollection services,
        Func<IServiceProvider, IRevocationStore> revocationStoreFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(revocationStoreFactory);

        services.Replace(ServiceDescriptor.Singleton(revocationStoreFactory));
        services.TryAddSingleton<IRevocationService, RevocationService>();
        return services;
    }
}
