using FluentAssertions;
using Xunit;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Models;

public class ZcapTimestampsTests
{
    [Fact]
    public void Parse_OffsetlessTimestamp_IsTreatedAsUtcNotLocal()
    {
        // An offsetless ISO-8601 timestamp (legal, and emittable by cross-stack signers) must be read
        // as UTC regardless of the verifier's local timezone — otherwise two verifiers in different
        // zones disagree on expiry/freshness by up to ~26 hours.
        var parsed = ZcapTimestamps.Parse("2026-06-15T12:00:00");

        parsed.Kind.Should().Be(DateTimeKind.Utc);
        parsed.Should().Be(new DateTime(2026, 6, 15, 12, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void Parse_WithExplicitOffset_IsConvertedToUtc()
    {
        var parsed = ZcapTimestamps.Parse("2026-06-15T12:00:00-04:00");

        parsed.Should().Be(new DateTime(2026, 6, 15, 16, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void Parse_ZuluTimestamp_RoundTripsToSameInstant()
    {
        ZcapTimestamps.Parse("2026-06-15T12:00:00Z")
            .Should().Be(new DateTime(2026, 6, 15, 12, 0, 0, DateTimeKind.Utc));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-timestamp")]
    [InlineData("2026-13-99")]
    public void ParseOrNull_NullEmptyOrUnparseable_ReturnsNullWithoutThrowing(string? value)
    {
        // ParseOrNull is total: it must never throw on attacker-supplied garbage (callers that read the
        // parsed view rely on this), returning null instead.
        DateTime? result = null;
        var act = () => { result = ZcapTimestamps.ParseOrNull(value); };

        act.Should().NotThrow();
        result.Should().BeNull();
    }

    [Fact]
    public void ParseOrNull_OffsetlessTimestamp_IsTreatedAsUtc()
    {
        ZcapTimestamps.ParseOrNull("2026-06-15T12:00:00")
            .Should().Be(new DateTime(2026, 6, 15, 12, 0, 0, DateTimeKind.Utc));
    }
}
