using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Shared test helper that creates a root capability and registers it with the in-memory provider, so
/// the verifier — which auto-detects the provider as an <see cref="IRootCapabilityResolver"/> — can
/// resolve the root that a spec-exact chain references by id only (Issue #50). Fixtures keep a thin,
/// self-documenting wrapper that forwards here, so the create+register composition lives in one place.
/// </summary>
internal static class TestRoots
{
    public static async Task<Capability> CreateAndRegisterRootAsync(
        CapabilityService capabilities,
        InMemoryDidProvider didProvider,
        ControllerSet controller,
        string invocationTarget,
        string[]? allowedActions = null,
        DateTime? expires = null,
        Caveat[]? caveats = null)
        => didProvider.RegisterRoot(
            await capabilities.CreateRootCapabilityAsync(controller, invocationTarget, allowedActions, expires, caveats));
}
