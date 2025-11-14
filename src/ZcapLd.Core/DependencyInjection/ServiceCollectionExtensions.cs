using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Delegation;
using ZcapLd.Core.Serialization;

namespace ZcapLd.Core.DependencyInjection;

/// <summary>
/// Extension methods for configuring ZCAP-LD services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds ZCAP-LD core services to the service collection.
    /// Registers all serialization, cryptographic, and delegation services required for ZCAP-LD operations.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional delegation options configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapLd(
        this IServiceCollection services,
        Action<DelegationOptions>? configureOptions = null)
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

        // Register delegation services
        services.AddZcapDelegation(configureOptions);

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

    /// <summary>
    /// Adds ZCAP-LD delegation services to the service collection.
    /// Includes attenuation validator, chain validator, and delegation service.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional delegation options configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddZcapDelegation(
        this IServiceCollection services,
        Action<DelegationOptions>? configureOptions = null)
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        // Configure options
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            // Use default options
            services.Configure<DelegationOptions>(options => { });
        }

        // Register delegation services
        services.TryAddSingleton<IAttenuationValidator, AttenuationValidator>();
        services.TryAddSingleton<ICapabilityChainValidator, CapabilityChainValidator>();
        services.TryAddSingleton<IDelegationService, DelegationService>();

        return services;
    }

    /// <summary>
    /// Adds a custom attenuation validator implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The attenuation validator implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddAttenuationValidator<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IAttenuationValidator
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IAttenuationValidator, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom capability chain validator implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The chain validator implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddCapabilityChainValidator<TImplementation>(this IServiceCollection services)
        where TImplementation : class, ICapabilityChainValidator
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<ICapabilityChainValidator, TImplementation>();
        return services;
    }

    /// <summary>
    /// Adds a custom delegation service implementation to the service collection.
    /// </summary>
    /// <typeparam name="TImplementation">The delegation service implementation type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services is null.</exception>
    public static IServiceCollection AddDelegationService<TImplementation>(this IServiceCollection services)
        where TImplementation : class, IDelegationService
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<IDelegationService, TImplementation>();
        return services;
    }
}
