using System.Text.Json;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Issue #154 red-team F6: the union converter's own recursion over enumerables must keep the
/// serializer's depth bound, so a cyclic <c>@context</c> value fails as it did in 6.0.0 (a
/// <see cref="JsonException"/> at depth 64) rather than at the writer's 1000-level limit.
/// </summary>
public class UnionJsonValueTests
{
    [Fact(DisplayName = "A self-referencing @context array is a JsonException at the serializer's depth limit")]
    public void Serialize_CyclicContextArray_ThrowsJsonExceptionAtMaxDepth()
    {
        var cyclic = new object[1];
        cyclic[0] = cyclic;
        var capability = new Capability { Context = cyclic, Id = "urn:uuid:1", InvocationTarget = "https://example.com/r" };

        var act = () => JsonSerializer.Serialize(capability, ZcapJsonOptions.Default.GetTypeInfo(typeof(Capability)));

        act.Should().Throw<JsonException>().WithMessage("*cycle*").WithMessage("*64*");
    }

    [Fact(DisplayName = "Nesting within the limit still serializes")]
    public void Serialize_DeepButBoundedContext_Succeeds()
    {
        object nested = "https://w3id.org/zcap/v1";
        for (var i = 0; i < 60; i++)
            nested = new object[] { nested };
        var capability = new Capability { Context = nested, Id = "urn:uuid:1", InvocationTarget = "https://example.com/r" };

        var json = JsonSerializer.Serialize(capability, ZcapJsonOptions.Default.GetTypeInfo(typeof(Capability)));

        json.Should().Contain("\"@context\":" + new string('[', 60) + "\"https://w3id.org/zcap/v1\"" + new string(']', 60) + ",");
    }
}
