using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZcapLd.Core.Services;

namespace ZcapLd.AspNetCore.DependencyInjection;

/// <summary>
/// DI helpers for registering revocation services and pluggable stores.
/// </summary>
public static class ZcapRevocationServiceCollectionExtensions
{
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
