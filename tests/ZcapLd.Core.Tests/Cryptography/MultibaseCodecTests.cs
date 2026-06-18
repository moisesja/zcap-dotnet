using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class MultibaseCodecTests
{
    [Fact]
    public void Encode_ShouldReturnMultibaseString()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var encoded = MultibaseCodec.Encode(data);

        encoded.Should().NotBeNullOrEmpty();
        encoded.Should().StartWith("z");
    }

    [Fact]
    public void Decode_ShouldReturnOriginalBytes()
    {
        var original = new byte[] { 0xed, 0x01, 0xAA, 0xBB, 0xCC };
        var encoded = MultibaseCodec.Encode(original);

        var decoded = MultibaseCodec.Decode(encoded);

        decoded.Should().Equal(original);
    }

    [Fact]
    public void EncodeAndDecode_ShouldRoundTrip()
    {
        // Use a realistic Ed25519 signature-sized payload
        var data = new byte[64];
        Random.Shared.NextBytes(data);

        var encoded = MultibaseCodec.Encode(data);
        var decoded = MultibaseCodec.Decode(encoded);

        decoded.Should().Equal(data);
    }

    [Fact]
    public void Decode_WithInvalidPrefix_ShouldThrow()
    {
        var act = () => MultibaseCodec.Decode("a1234567890");

        act.Should().Throw<ZcapLd.Core.Exceptions.CryptographicException>();
    }

    [Fact]
    public void Encode_WithNullData_ShouldThrow()
    {
        var act = () => MultibaseCodec.Encode(null!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Encode_WithEmptyData_ShouldThrow()
    {
        var act = () => MultibaseCodec.Encode(Array.Empty<byte>());

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Decode_WithNullString_ShouldThrow()
    {
        var act = () => MultibaseCodec.Decode(null!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Decode_WithEmptyString_ShouldThrow()
    {
        var act = () => MultibaseCodec.Decode("");

        act.Should().Throw<ArgumentException>();
    }

}
