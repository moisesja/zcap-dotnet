using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Serialization;

namespace ZcapLd.Core.DependencyInjection;

/// <summary>
/// Extension methods for configuring ZCAP-LD services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds ZCAP-LD core services to the service collection.
    /// Registers all serialization and cryptographic services required for ZCAP-LD operations.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapLd(this IServiceCollection services)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        // Register serialization services
        services.TryAddSingleton<IZcapSerializationService, ZcapSerializationService>();
        services.TryAddSingleton<IMultibaseService, MultibaseService>();
        services.TryAddSingleton<IJsonLdCanonicalizationService, JsonLdCanonicalizationService>();

        // Register cryptographic services
        services.TryAddSingleton<ICryptographicService, Ed25519CryptographicService>();
        services.TryAddSingleton<IKeyProvider, InMemoryKeyProvider>();
        services.TryAddSingleton<IProofService, ProofService>();

        return services;
    }

    /// <summary>
    /// Adds ZCAP-LD serialization services to the service collection.
    /// Use this if you only need serialization without other ZCAP features.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapSerialization(this IServiceCollection services)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.TryAddSingleton<IZcapSerializationService, ZcapSerializationService>();
        services.TryAddSingleton<IMultibaseService, MultibaseService>();
        services.TryAddSingleton<IJsonLdCanonicalizationService, JsonLdCanonicalizationService>();

        return services;
    }

    /// <summary>
    /// Adds a custom multibase service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The multibase service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddMultibaseService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IMultibaseService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IMultibaseService, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom JSON-LD canonicalization service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The canonicalization service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddJsonLdCanonicalizationService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IJsonLdCanonicalizationService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IJsonLdCanonicalizationService, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom ZCAP serialization service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The serialization service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapSerializationService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IZcapSerializationService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IZcapSerializationService, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds ZCAP-LD cryptographic services to the service collection.
    /// Includes Ed25519 cryptographic service, in-memory key provider, and proof service.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapCryptography(this IServiceCollection services)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.TryAddSingleton<ICryptographicService, Ed25519CryptographicService>();
        services.TryAddSingleton<IKeyProvider, InMemoryKeyProvider>();
        services.TryAddSingleton<IProofService, ProofService>();

        return services;
    }

    /// <summary>
    /// Adds a custom cryptographic service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The cryptographic service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddCryptographicService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, ICryptographicService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<ICryptographicService, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom key provider implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The key provider implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddKeyProvider<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IKeyProvider
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IKeyProvider, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom proof service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The proof service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddProofService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IProofService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IProofService, TImplementation>();
        return services;
    }
}
