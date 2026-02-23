using FluentAssertions;
using Xunit;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Services;

public class NullNonceStoreTests
{
    [Fact]
    public async Task TryMarkAsUsed_AlwaysReturnsFalse()
    {
        var store = NullNonceStore.Instance;

        var first = await store.TryMarkAsUsedAsync("nonce-1");
        var second = await store.TryMarkAsUsedAsync("nonce-1");

        first.Should().BeFalse("NullNonceStore never flags replays");
        second.Should().BeFalse("NullNonceStore never flags replays, even for the same nonce");
    }
}
