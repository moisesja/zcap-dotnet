using FluentAssertions;
using Xunit;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class InMemoryNonceStoreTests
{
    [Fact]
    public async Task TryMarkAsUsed_FreshNonce_ReturnsFalse()
    {
        var store = new InMemoryNonceStore();

        var result = await store.TryMarkAsUsedAsync("nonce-1");

        result.Should().BeFalse("a fresh nonce should not be flagged as a replay");
    }

    [Fact]
    public async Task TryMarkAsUsed_SameNonceTwice_ReturnsTrueOnSecond()
    {
        var store = new InMemoryNonceStore();

        await store.TryMarkAsUsedAsync("nonce-1");
        var result = await store.TryMarkAsUsedAsync("nonce-1");

        result.Should().BeTrue("a previously seen nonce is a replay");
    }

    [Fact]
    public async Task TryMarkAsUsed_DifferentNonces_BothReturnFalse()
    {
        var store = new InMemoryNonceStore();

        var r1 = await store.TryMarkAsUsedAsync("nonce-1");
        var r2 = await store.TryMarkAsUsedAsync("nonce-2");

        r1.Should().BeFalse();
        r2.Should().BeFalse();
    }

    [Fact]
    public async Task TryMarkAsUsed_ExpiredNonce_ReturnsFalseAndAllowsReuse()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var store = new InMemoryNonceStore(fakeTime);

        // Record nonce with 1-minute TTL
        var expiry = fakeTime.GetUtcNow().UtcDateTime.AddMinutes(1);
        var first = await store.TryMarkAsUsedAsync("nonce-1", expiry);
        first.Should().BeFalse();

        // Advance time past expiry
        fakeTime.Advance(TimeSpan.FromMinutes(2));

        // Same nonce should be allowed again
        var second = await store.TryMarkAsUsedAsync("nonce-1", expiry);
        second.Should().BeFalse("expired nonce should be evicted and reusable");
    }

    [Fact]
    public async Task TryMarkAsUsed_NotYetExpiredNonce_ReturnsTrueAsReplay()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var store = new InMemoryNonceStore(fakeTime);

        var expiry = fakeTime.GetUtcNow().UtcDateTime.AddMinutes(5);
        await store.TryMarkAsUsedAsync("nonce-1", expiry);

        // Advance time but not past expiry
        fakeTime.Advance(TimeSpan.FromMinutes(3));

        var result = await store.TryMarkAsUsedAsync("nonce-1", expiry);
        result.Should().BeTrue("nonce has not expired yet");
    }

    [Fact]
    public async Task TryMarkAsUsed_NullNonce_ShouldThrow()
    {
        var store = new InMemoryNonceStore();

        var act = () => store.TryMarkAsUsedAsync(null!);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task TryMarkAsUsed_EmptyNonce_ShouldThrow()
    {
        var store = new InMemoryNonceStore();

        var act = () => store.TryMarkAsUsedAsync("");

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task TryMarkAsUsed_ConcurrentAccess_OnlyOneSucceeds()
    {
        var store = new InMemoryNonceStore();
        var nonce = "concurrent-nonce";
        var results = new bool[10];

        var tasks = Enumerable.Range(0, 10).Select(async i =>
        {
            results[i] = await store.TryMarkAsUsedAsync(nonce);
        });

        await Task.WhenAll(tasks);

        // Exactly one should be false (first to claim), rest should be true (replays)
        results.Count(r => r == false).Should().Be(1, "only one concurrent caller should succeed");
        results.Count(r => r == true).Should().Be(9, "all others should be flagged as replays");
    }

    /// <summary>
    /// Simple fake TimeProvider for testing time-dependent behavior.
    /// </summary>
    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now;

        public FakeTimeProvider(DateTimeOffset startTime)
        {
            _now = startTime;
        }

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan duration) => _now = _now.Add(duration);
    }
}
