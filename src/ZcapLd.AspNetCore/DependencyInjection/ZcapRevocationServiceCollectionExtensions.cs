using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.DependencyInjection;

/// <summary>
/// DI helpers for registering ZCAP-LD services, DID providers, and revocation stores.
/// </summary>
public static class ZcapRevocationServiceCollectionExtensions
{
    /// <summary>
    /// Registers all core ZCAP-LD services with default implementations.
    /// Uses <see cref="InMemoryDidProvider"/> for DID/key management and
    /// <see cref="InMemoryRevocationStore"/> for revocation storage.
    /// </summary>
    public static IServiceCollection AddZcapServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IDidProvider, InMemoryDidProvider>();
        services.TryAddSingleton<ISigningService, SigningService>();
        services.TryAddSingleton<ICaveatProcessor, CaveatProcessor>();
        services.TryAddSingleton<ICapabilityService, CapabilityService>();
        services.TryAddSingleton<IRevocationStore, InMemoryRevocationStore>();
        services.TryAddSingleton<IRevocationService, RevocationService>();
        services.TryAddSingleton<IVerificationService, VerificationService>();
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidProvider"/> implementation.
    /// Call after <see cref="AddZcapServices"/> to replace the default in-memory provider.
    /// </summary>
    public static IServiceCollection AddZcapDidProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IDidProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IDidProvider, TProvider>());
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidProvider"/> using a factory.
    /// Call after <see cref="AddZcapServices"/> to replace the default in-memory provider.
    /// </summary>
    public static IServiceCollection AddZcapDidProvider(
        this IServiceCollection services,
        Func<IServiceProvider, IDidProvider> didProviderFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(didProviderFactory);

        services.Replace(ServiceDescriptor.Singleton(didProviderFactory));
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
