using FluentAssertions;
using Xunit;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Services;

public class CaveatProcessorTests
{
    private readonly CaveatProcessor _caveatProcessor;
    private readonly InMemoryDidProvider _didProvider;
    private readonly SigningService _signingService;
    private readonly CapabilityService _capabilityService;

    public CaveatProcessorTests()
    {
        _caveatProcessor = new CaveatProcessor();
        _didProvider = new InMemoryDidProvider();
        _signingService = new SigningService(_didProvider, _didProvider);
        _capabilityService = new CapabilityService(_signingService);
    }

    #region Caveat Evaluation Tests

    [Fact]
    public async Task EvaluateCaveats_WithNoCaveats_ShouldReturnTrue()
    {
        // Arrange
        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = Array.Empty<Caveat>()
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithSatisfiedExpirationCaveat_ShouldReturnTrue()
    {
        // Arrange
        var caveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(1) // Not expired
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { caveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithExpiredCaveat_ShouldReturnFalse()
    {
        // Arrange
        var caveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(-1) // Expired
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { caveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateCaveats_WithSatisfiedUsageCountCaveat_ShouldReturnTrue()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 5 // Still has uses left
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { caveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource",
            // UsageCountCaveat is enforceable only when the relying party supplies the current count
            // (it cannot be carried in the signed payload). 5 prior uses < MaxUses 10 -> satisfied.
            Properties = { [UsageCountCaveat.CurrentUsesContextKey] = 5 }
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithExceededUsageCount_ShouldReturnFalse()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 10 // Reached limit
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { caveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateCaveats_WithMultipleSatisfiedCaveats_ShouldReturnTrue()
    {
        // Arrange
        var expirationCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(1)
        };

        var usageCaveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 5
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { expirationCaveat, usageCaveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource",
            // 5 prior uses < MaxUses 10 -> the usage caveat is satisfied.
            Properties = { [UsageCountCaveat.CurrentUsesContextKey] = 5 }
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithOneFailedCaveat_ShouldReturnFalse()
    {
        // Arrange
        var expirationCaveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(-1) // Expired
        };

        var usageCaveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 5 // Still valid
        };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkTest",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[] { expirationCaveat, usageCaveat }
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse(); // One failed caveat fails the whole evaluation
    }

    [Fact]
    public async Task EvaluateCaveats_WithNullCapability_ShouldThrow()
    {
        // Arrange
        var context = new InvocationContext();

        // Act & Assert
        var act = async () => await _caveatProcessor.EvaluateCaveatsAsync(null!, context);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task EvaluateCaveats_WithNullContext_ShouldThrow()
    {
        // Arrange
        var capability = new Capability();

        // Act & Assert
        var act = async () => await _caveatProcessor.EvaluateCaveatsAsync(capability, null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    #endregion

    #region Caveat Merging Tests

    [Fact]
    public async Task MergeCaveats_WithSingleCapability_ShouldReturnItsCaveats()
    {
        // Arrange
        var caveat1 = new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(1) };
        var caveat2 = new UsageCountCaveat { MaxUses = 10, CurrentUses = 0 };

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[] { caveat1, caveat2 }
        };

        // Act
        var mergedCaveats = await _caveatProcessor.MergeCaveatsAsync(new[] { capability });

        // Assert
        mergedCaveats.Should().HaveCount(2);
        mergedCaveats.Should().Contain(c => c.Type == "Expiration");
        mergedCaveats.Should().Contain(c => c.Type == "UsageCount");
    }

    [Fact]
    public async Task MergeCaveats_WithMultipleCapabilities_ShouldMergeAllCaveats()
    {
        // Arrange
        var capability1 = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(1) }
            }
        };

        var capability2 = new Capability
        {
            Id = "urn:uuid:test1",
            Caveat = new Caveat[]
            {
                new UsageCountCaveat { MaxUses = 10, CurrentUses = 0 }
            }
        };

        var capability3 = new Capability
        {
            Id = "urn:uuid:test2",
            Caveat = new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(2) }
            }
        };

        // Act
        var mergedCaveats = await _caveatProcessor.MergeCaveatsAsync(
            new[] { capability1, capability2, capability3 });

        // Assert
        mergedCaveats.Should().HaveCount(3);
        mergedCaveats.Count(c => c.Type == "Expiration").Should().Be(2);
        mergedCaveats.Count(c => c.Type == "UsageCount").Should().Be(1);
    }

    [Fact]
    public async Task MergeCaveats_WithNoCaveats_ShouldReturnEmptyArray()
    {
        // Arrange
        var capability1 = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = Array.Empty<Caveat>()
        };

        var capability2 = new Capability
        {
            Id = "urn:uuid:test1",
            Caveat = Array.Empty<Caveat>()
        };

        // Act
        var mergedCaveats = await _caveatProcessor.MergeCaveatsAsync(new[] { capability1, capability2 });

        // Assert
        mergedCaveats.Should().BeEmpty();
    }

    [Fact]
    public async Task MergeCaveats_WithNullChain_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _caveatProcessor.MergeCaveatsAsync(null!);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task MergeCaveats_WithEmptyChain_ShouldThrow()
    {
        // Act & Assert
        var act = async () => await _caveatProcessor.MergeCaveatsAsync(Array.Empty<Capability>());
        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion

    #region Caveat Compatibility Validation Tests

    [Fact]
    public async Task ValidateCaveatCompatibility_WithNoCaveats_ShouldReturnTrue()
    {
        // Arrange
        var parentCaveats = Array.Empty<Caveat>();
        var childCaveats = Array.Empty<Caveat>();

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ChildAddsNewCaveat_ShouldReturnTrue()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(10) }
        };

        var childCaveats = new Caveat[]
        {
            new UsageCountCaveat { MaxUses = 5, CurrentUses = 0 } // New caveat
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeTrue(); // Child can add new restrictions
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ChildMoreRestrictiveExpiration_ShouldReturnTrue()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(10) }
        };

        var childCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(5) } // More restrictive
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ChildLessRestrictiveExpiration_ShouldReturnFalse()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(5) }
        };

        var childCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(10) } // Less restrictive
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeFalse(); // Child cannot be less restrictive
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ChildMoreRestrictiveUsageCount_ShouldReturnTrue()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new UsageCountCaveat { MaxUses = 10, CurrentUses = 0 }
        };

        var childCaveats = new Caveat[]
        {
            new UsageCountCaveat { MaxUses = 5, CurrentUses = 0 } // More restrictive
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ChildLessRestrictiveUsageCount_ShouldReturnFalse()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new UsageCountCaveat { MaxUses = 5, CurrentUses = 0 }
        };

        var childCaveats = new Caveat[]
        {
            new UsageCountCaveat { MaxUses = 10, CurrentUses = 0 } // Less restrictive
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeFalse(); // Child cannot be less restrictive
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_WithNullParentCaveats_ShouldHandleGracefully()
    {
        // Arrange
        var childCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(5) }
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(null, childCaveats);

        // Assert
        result.Should().BeTrue(); // No parent caveats means child can add any
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_WithNullChildCaveats_ShouldHandleGracefully()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(5) }
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, null);

        // Assert
        result.Should().BeTrue(); // Child inherits parent caveats implicitly
    }

    #endregion

    #region Capability Chain Caveat Evaluation Tests

    [Fact]
    public async Task EvaluateCapabilityChainCaveats_WithValidChain_ShouldReturnTrue()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read" },
            caveats: new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(10) }
            });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            "did:key:z6MkChild",
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[]
            {
                new UsageCountCaveat { MaxUses = 10, CurrentUses = 0 }
            });

        var chain = new[] { rootCapability, delegatedCapability };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource",
            // 0 prior uses < MaxUses 10 -> the usage caveat is satisfied.
            Properties = { [UsageCountCaveat.CurrentUsesContextKey] = 0 }
        };

        // Act
        var result = await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(chain, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCapabilityChainCaveats_WithExpiredCaveat_ShouldReturnFalse()
    {
        // Arrange
        var controllerDid = "did:key:z6MkController";
        _didProvider.GenerateAndRegisterKeyPair(controllerDid);

        var rootCapability = await _capabilityService.CreateRootCapabilityAsync(
            controllerDid,
            "https://example.com/resource",
            new[] { "read", "write" });

        var delegatedCapability = await _capabilityService.DelegateCapabilityAsync(
            rootCapability,
            controllerDid,
            new[] { "read" },
            DateTime.UtcNow.AddDays(5),
            new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(-1) } // Expired
            });

        var chain = new[] { rootCapability, delegatedCapability };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow,
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(chain, context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateCapabilityChainCaveats_WithNullChain_ShouldThrow()
    {
        // Arrange
        var context = new InvocationContext();

        // Act & Assert
        var act = async () => await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(null!, context);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task EvaluateCapabilityChainCaveats_WithNullContext_ShouldThrow()
    {
        // Arrange
        var capability = await _capabilityService.CreateRootCapabilityAsync(
            "did:key:z6MkTest",
            "https://example.com/resource",
            new[] { "read" });

        var chain = new[] { capability };

        // Act & Assert
        var act = async () => await _caveatProcessor.EvaluateCapabilityChainCaveatsAsync(chain, null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    #endregion

    #region ExpirationCaveat Tests

    [Fact]
    public void ExpirationCaveat_NotExpired_ShouldBeSatisfied()
    {
        // Arrange
        var caveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddHours(1)
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow
        };

        // Act
        var result = caveat.IsSatisfied(context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ExpirationCaveat_Expired_ShouldNotBeSatisfied()
    {
        // Arrange
        var caveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddHours(-1)
        };

        var context = new InvocationContext
        {
            InvocationTime = DateTime.UtcNow
        };

        // Act
        var result = caveat.IsSatisfied(context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ExpirationCaveat_Type_ShouldBeExpiration()
    {
        // Arrange
        var caveat = new ExpirationCaveat
        {
            Expires = DateTime.UtcNow.AddDays(1)
        };

        // Act & Assert
        caveat.Type.Should().Be("Expiration");
    }

    #endregion

    #region ValidWhileTrue Caveat Tests

    [Fact]
    public async Task EvaluateCaveats_WithValidWhileTrueCaveat_NoHandler_ShouldReturnFalse()
    {
        // Arrange - processor without handler (fail-closed)
        var processor = new CaveatProcessor();

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse("no handler is configured; fail-closed");
    }

    [Fact]
    public async Task EvaluateCaveats_WithValidWhileTrueCaveat_HandlerReturnsTrue_ShouldReturnTrue()
    {
        // Arrange
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(true));

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithValidWhileTrueCaveat_HandlerReturnsFalse_ShouldReturnFalse()
    {
        // Arrange - handler says capability is revoked
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(false));

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateCaveats_WithValidWhileTrueCaveat_EmptyUri_ShouldReturnFalse()
    {
        // Arrange - malformed caveat with empty URI
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(true));

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ValidWhileTrueCaveat { Uri = "" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse("empty URI is a malformed caveat");
    }

    [Fact]
    public async Task EvaluateCaveats_WithMixedCaveats_AllSatisfied_ShouldReturnTrue()
    {
        // Arrange
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(true));

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(1) },
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateCaveats_WithMixedCaveats_ValidWhileTrueFails_ShouldReturnFalse()
    {
        // Arrange
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(false));

        var capability = new Capability
        {
            Id = "urn:zcap:root:test",
            Caveat = new Caveat[]
            {
                new ExpirationCaveat { Expires = DateTime.UtcNow.AddDays(1) },
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCaveatsAsync(capability, context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ValidWhileTrue_SameUri_ShouldReturnTrue()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
        };

        var childCaveats = new Caveat[]
        {
            new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeTrue("child references the same revocation authority");
    }

    [Fact]
    public async Task ValidateCaveatCompatibility_ValidWhileTrue_DifferentUri_ShouldReturnFalse()
    {
        // Arrange
        var parentCaveats = new Caveat[]
        {
            new ValidWhileTrueCaveat { Uri = "https://example.com/status/original" }
        };

        var childCaveats = new Caveat[]
        {
            new ValidWhileTrueCaveat { Uri = "https://evil.com/status/bypass" }
        };

        // Act
        var result = await _caveatProcessor.ValidateCaveatCompatibilityAsync(parentCaveats, childCaveats);

        // Assert
        result.Should().BeFalse("child cannot change the revocation authority URI");
    }

    [Fact]
    public async Task EvaluateCapabilityChainCaveats_WithValidWhileTrue_ShouldEvaluateViaHandler()
    {
        // Arrange
        var processor = new CaveatProcessor(new StubValidWhileTrueHandler(true));

        var root = new Capability
        {
            Id = "urn:zcap:root:test",
            Controller = "did:key:z6MkRoot",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            Caveat = new Caveat[]
            {
                new ValidWhileTrueCaveat { Uri = "https://example.com/status" }
            }
        };

        var child = new Capability
        {
            Id = "urn:uuid:child",
            Controller = "did:key:z6MkChild",
            InvocationTarget = "https://example.com/resource",
            AllowedAction = new[] { "read" },
            ParentCapability = root.Id,
            Caveat = Array.Empty<Caveat>()
        };

        var context = new InvocationContext
        {
            RequestedAction = "read",
            TargetResource = "https://example.com/resource"
        };

        // Act
        var result = await processor.EvaluateCapabilityChainCaveatsAsync(new[] { root, child }, context);

        // Assert
        result.Should().BeTrue("handler confirms capability is still valid");
    }

    private class StubValidWhileTrueHandler : IValidWhileTrueHandler
    {
        private readonly bool _result;
        public StubValidWhileTrueHandler(bool result) => _result = result;
        public Task<bool> CheckAsync(string uri, CancellationToken cancellationToken = default)
            => Task.FromResult(_result);
    }

    #endregion

    #region UsageCountCaveat Tests

    [Fact]
    public void UsageCountCaveat_UnderLimit_ShouldBeSatisfied()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10
        };

        // The current count is supplied by the relying party via the invocation context (it cannot be
        // carried in the signed payload); 5 prior uses < MaxUses 10 -> satisfied.
        var context = new InvocationContext
        {
            Properties = { [UsageCountCaveat.CurrentUsesContextKey] = 5 }
        };

        // Act
        var result = caveat.IsSatisfied(context);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void UsageCountCaveat_NoContextCount_FailsClosed()
    {
        // Without a caller-supplied count, the caveat cannot be enforced (CurrentUses is 0 on any
        // wire-deserialized caveat), so it MUST deny rather than silently grant unlimited use.
        var caveat = new UsageCountCaveat { MaxUses = 10 };

        caveat.IsSatisfied(new InvocationContext()).Should().BeFalse();
    }

    [Fact]
    public void UsageCountCaveat_AtLimit_ShouldNotBeSatisfied()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 10
        };

        var context = new InvocationContext();

        // Act
        var result = caveat.IsSatisfied(context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void UsageCountCaveat_OverLimit_ShouldNotBeSatisfied()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 15
        };

        var context = new InvocationContext();

        // Act
        var result = caveat.IsSatisfied(context);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void UsageCountCaveat_Type_ShouldBeUsageCount()
    {
        // Arrange
        var caveat = new UsageCountCaveat
        {
            MaxUses = 10,
            CurrentUses = 0
        };

        // Act & Assert
        caveat.Type.Should().Be("UsageCount");
    }

    #endregion
}
