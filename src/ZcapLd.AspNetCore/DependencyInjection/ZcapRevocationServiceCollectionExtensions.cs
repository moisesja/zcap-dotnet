using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NetDid.Core.Resolution;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
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

        // DidKeyResolver delegates to NetDid's DidKeyMethod for did:key resolution.
        services.TryAddSingleton<IDidResolver>(sp => new DidKeyResolver());

        // SigningService delegates proof crypto to DataProofs' legacy cryptosuites; all proofs use
        // RDFC-1.0 canonicalization (the only canonicalization ZCAP-LD supports — required for interop
        // with @digitalbazaar/zcap). No default IDidSigner — consumers must provide their own secure
        // implementation.
        services.TryAddSingleton<ISigningService>(sp =>
            new SigningService(
                sp.GetRequiredService<IDidSigner>(),
                sp.GetRequiredService<IDidResolver>(),
                sp.GetService<CaveatTypeRegistry>()));

        services.TryAddSingleton<ICapabilityService>(sp =>
            new CapabilityService(sp.GetRequiredService<ISigningService>(), sp.GetService<CaveatTypeRegistry>()));
        services.TryAddSingleton<IRevocationStore, InMemoryRevocationStore>();
        services.TryAddSingleton<IRevocationService, RevocationService>();
        services.TryAddSingleton<INonceStore, InMemoryNonceStore>();

        // VerificationService dispatches proofs to DataProofs' legacy cryptosuites and uses
        // INonceStore for replay protection. The optional IVerificationRelationshipResolver (Issue #65)
        // performs controller authorization by resolving the controller's DID document; the optional
        // IRootCapabilityResolver (Issue #50) lets it obtain a root referenced by id only in a
        // spec-exact chain (register via AddZcapRootCapabilityResolver); the optional VerificationPolicy
        // (Issue #73) enables the opt-in expiration ceiling. All proofs are verified under RDFC-1.0.
        services.TryAddSingleton<IVerificationService>(sp =>
            new VerificationService(
                sp.GetRequiredService<IDidResolver>(),
                sp.GetRequiredService<IRevocationService>(),
                sp.GetRequiredService<INonceStore>(),
                logger: sp.GetService<ILogger<VerificationService>>(),
                relationshipResolver: sp.GetService<IVerificationRelationshipResolver>(),
                rootResolver: sp.GetService<IRootCapabilityResolver>(),
                policy: sp.GetService<VerificationPolicy>(),
                caveats: sp.GetService<CaveatTypeRegistry>(),
                caveatHandlers: sp.GetServices<ICaveatHandler>()));

        return services;
    }

    /// <summary>
    /// Registers a custom caveat type (#157) in the application's <see cref="CaveatTypeRegistry"/>,
    /// which <see cref="AddZcapServices"/> passes to signing, delegation and verification. Registering
    /// any type enables the caveat extension profile; capabilities that carry caveats are not
    /// interoperable with other ZCAP implementations. Register every type before the ZCAP services are
    /// first resolved: the registry is frozen at that point.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="type">The caveat's wire type name (see <see cref="CaveatTypeRegistry.Register{TCaveat}(string)"/>).</param>
    public static IServiceCollection AddZcapCaveatType<TCaveat>(this IServiceCollection services, string type)
        where TCaveat : Caveat
    {
        ArgumentNullException.ThrowIfNull(services);

        var registry = services.LastOrDefault(d => d.ServiceType == typeof(CaveatTypeRegistry))?.ImplementationInstance
            as CaveatTypeRegistry;
        if (registry is null)
        {
            registry = new CaveatTypeRegistry();
            services.Replace(ServiceDescriptor.Singleton(registry));
        }

        registry.Register<TCaveat>(type);
        return services;
    }

    /// <summary>
    /// Registers the resource's enforcement of one caveat type (#157). Invocations whose chain carries
    /// a caveat type without a handler are denied, so every type the resource accepts needs one.
    /// </summary>
    public static IServiceCollection AddZcapCaveatHandler<THandler>(this IServiceCollection services)
        where THandler : class, ICaveatHandler
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ICaveatHandler, THandler>());
        return services;
    }

    /// <summary>Registers a caveat handler using a factory (#157).</summary>
    public static IServiceCollection AddZcapCaveatHandler(
        this IServiceCollection services,
        Func<IServiceProvider, ICaveatHandler> handlerFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(handlerFactory);

        services.AddSingleton(handlerFactory);
        return services;
    }

    /// <summary>
    /// Registers an <see cref="IRootCapabilityResolver"/> so the verifier can obtain a root
    /// capability that a spec-exact delegation chain references by id only (Issue #50). Required for
    /// verifying or revoking delegated capabilities through the DI-wired
    /// <see cref="IVerificationService"/> without supplying the root on each call. Register before
    /// <see cref="AddZcapServices"/> resolves the provider, or before the
    /// <see cref="IVerificationService"/> singleton is first resolved.
    /// </summary>
    public static IServiceCollection AddZcapRootCapabilityResolver<TResolver>(this IServiceCollection services)
        where TResolver : class, IRootCapabilityResolver
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IRootCapabilityResolver, TResolver>());
        return services;
    }

    /// <summary>
    /// Registers an <see cref="IRootCapabilityResolver"/> using a factory (Issue #50).
    /// </summary>
    public static IServiceCollection AddZcapRootCapabilityResolver(
        this IServiceCollection services,
        Func<IServiceProvider, IRootCapabilityResolver> resolverFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(resolverFactory);

        services.Replace(ServiceDescriptor.Singleton(resolverFactory));
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
    /// <remarks>
    /// A resolver that also implements <see cref="IVerificationRelationshipResolver"/> self-provides
    /// controller authorization to the verifier: <see cref="DidKeyResolver"/> does, and
    /// <see cref="ZcapLd.Core.Services.CompositeDidResolver"/> routes the check to the adapter registered for the
    /// controller's DID method, failing closed for key-only adapters (Issue #148). An
    /// <see cref="IVerificationRelationshipResolver"/> registered explicitly in the container takes
    /// precedence over what the resolver self-provides.
    /// </remarks>
    public static IServiceCollection AddZcapDidResolver<TResolver>(this IServiceCollection services)
        where TResolver : class, IDidResolver
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<IDidResolver, TResolver>());
        return services;
    }

    /// <summary>
    /// Registers a custom <see cref="IDidResolver"/> using a factory.
    /// Replaces the default <see cref="DidKeyResolver"/>. See
    /// <see cref="AddZcapDidResolver{TResolver}"/> for how a relationship-aware resolver (such as
    /// <see cref="ZcapLd.Core.Services.CompositeDidResolver"/>) self-provides controller authorization.
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
    /// Registers replay protection with the default in-memory nonce store.
    /// </summary>
    public static IServiceCollection AddZcapReplayProtection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<INonceStore, InMemoryNonceStore>();
        return services;
    }

    /// <summary>
    /// Registers replay protection using a caller-provided nonce store type.
    /// </summary>
    public static IServiceCollection AddZcapReplayProtection<TNonceStore>(this IServiceCollection services)
        where TNonceStore : class, INonceStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Replace(ServiceDescriptor.Singleton<INonceStore, TNonceStore>());
        return services;
    }

    /// <summary>
    /// Registers replay protection using a caller-provided nonce store factory.
    /// </summary>
    public static IServiceCollection AddZcapReplayProtection(
        this IServiceCollection services,
        Func<IServiceProvider, INonceStore> nonceStoreFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(nonceStoreFactory);

        services.Replace(ServiceDescriptor.Singleton(nonceStoreFactory));
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
