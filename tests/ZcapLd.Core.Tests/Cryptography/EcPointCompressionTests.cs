using System.Security.Cryptography;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class EcPointCompressionTests
{
    [Fact]
    public void CompressAndDecompress_ShouldRoundTrip()
    {
        // Generate a real P-256 key pair for test data
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var originalPoint = parameters.Q;

        // Compress
        var compressed = EcPointCompression.CompressP256(originalPoint);
        compressed.Should().HaveCount(33);
        compressed[0].Should().BeOneOf((byte)0x02, (byte)0x03);

        // Decompress
        var decompressed = EcPointCompression.DecompressP256(compressed);

        decompressed.X.Should().Equal(originalPoint.X);
        decompressed.Y.Should().Equal(originalPoint.Y);
    }

    [Fact]
    public void DecompressP256_WithEvenPrefix_ShouldProduceEvenY()
    {
        // Generate key pairs until we get one with an even Y coordinate
        ECPoint? evenPoint = null;
        for (int i = 0; i < 100; i++)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = ecdsa.ExportParameters(false);
            var compressed = EcPointCompression.CompressP256(parameters.Q);
            if (compressed[0] == 0x02) // even Y
            {
                evenPoint = parameters.Q;
                break;
            }
        }

        evenPoint.Should().NotBeNull("Should find an even Y key within 100 attempts");

        var compressedEven = EcPointCompression.CompressP256(evenPoint!.Value);
        compressedEven[0].Should().Be(0x02);

        var decompressed = EcPointCompression.DecompressP256(compressedEven);
        decompressed.X.Should().Equal(evenPoint.Value.X);
        decompressed.Y.Should().Equal(evenPoint.Value.Y);
    }

    [Fact]
    public void DecompressP256_WithOddPrefix_ShouldProduceOddY()
    {
        // Generate key pairs until we get one with an odd Y coordinate
        ECPoint? oddPoint = null;
        for (int i = 0; i < 100; i++)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = ecdsa.ExportParameters(false);
            var compressed = EcPointCompression.CompressP256(parameters.Q);
            if (compressed[0] == 0x03) // odd Y
            {
                oddPoint = parameters.Q;
                break;
            }
        }

        oddPoint.Should().NotBeNull("Should find an odd Y key within 100 attempts");

        var compressedOdd = EcPointCompression.CompressP256(oddPoint!.Value);
        compressedOdd[0].Should().Be(0x03);

        var decompressed = EcPointCompression.DecompressP256(compressedOdd);
        decompressed.X.Should().Equal(oddPoint.Value.X);
        decompressed.Y.Should().Equal(oddPoint.Value.Y);
    }

    [Fact]
    public void DecompressP256_WithInvalidLength_ShouldThrow()
    {
        var act = () => EcPointCompression.DecompressP256(new byte[32]);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void DecompressP256_WithInvalidPrefix_ShouldThrow()
    {
        var bad = new byte[33];
        bad[0] = 0x04; // uncompressed prefix, not valid here

        var act = () => EcPointCompression.DecompressP256(bad);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void CompressP256_WithInvalidCoordinateLength_ShouldThrow()
    {
        var point = new ECPoint { X = new byte[16], Y = new byte[32] };

        var act = () => EcPointCompression.CompressP256(point);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void MultipleKeyPairs_ShouldAllRoundTrip()
    {
        for (int i = 0; i < 10; i++)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = ecdsa.ExportParameters(false);

            var compressed = EcPointCompression.CompressP256(parameters.Q);
            var decompressed = EcPointCompression.DecompressP256(compressed);

            decompressed.X.Should().Equal(parameters.Q.X);
            decompressed.Y.Should().Equal(parameters.Q.Y);
        }
    }
}
