using System.Numerics;
using System.Security.Cryptography;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Handles compression and decompression of elliptic curve public key points.
/// Supports NIST P-256 (secp256r1). Internal utility used by <see cref="P256CryptoSuite"/>.
/// </summary>
internal static class EcPointCompression
{
    // P-256 curve constants (NIST FIPS 186-4)
    private static readonly BigInteger P256Prime = BigInteger.Parse(
        "0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber);

    private static readonly BigInteger P256B = BigInteger.Parse(
        "05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        System.Globalization.NumberStyles.HexNumber);

    // a = -3 for P-256
    private static readonly BigInteger P256A = P256Prime - 3;

    /// <summary>
    /// Decompresses a 33-byte compressed EC point to an <see cref="ECPoint"/> with X and Y coordinates.
    /// </summary>
    /// <param name="compressed">33-byte compressed public key (0x02/0x03 prefix + 32 bytes X)</param>
    /// <returns>EC point with X and Y coordinates</returns>
    public static ECPoint DecompressP256(byte[] compressed)
    {
        if (compressed == null || compressed.Length != 33)
            throw new ArgumentException("Compressed P-256 public key must be 33 bytes", nameof(compressed));

        byte prefix = compressed[0];
        if (prefix != 0x02 && prefix != 0x03)
            throw new ArgumentException("Compressed key must start with 0x02 or 0x03", nameof(compressed));

        // Extract X coordinate (big-endian)
        var xBytes = compressed.AsSpan(1, 32).ToArray();
        var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);

        // Compute y² = x³ + ax + b (mod p)
        var x3 = BigInteger.ModPow(x, 3, P256Prime);
        var ax = (P256A * x) % P256Prime;
        var ySquared = (x3 + ax + P256B) % P256Prime;
        if (ySquared < 0) ySquared += P256Prime;

        // Since P-256 prime ≡ 3 (mod 4), we can compute: y = ySquared^((p+1)/4) mod p
        var exp = (P256Prime + 1) / 4;
        var y = BigInteger.ModPow(ySquared, exp, P256Prime);

        // Verify the computed y is correct
        if (BigInteger.ModPow(y, 2, P256Prime) != ySquared)
            throw new Exceptions.CryptographicException("Failed to decompress P-256 point: no valid Y coordinate");

        // Choose the correct Y based on the prefix (0x02 = even, 0x03 = odd)
        bool needOdd = prefix == 0x03;
        if (y.IsEven != !needOdd)
        {
            y = P256Prime - y;
        }

        // Convert Y to big-endian 32-byte array
        var yBytes = y.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (yBytes.Length < 32)
        {
            var padded = new byte[32];
            Buffer.BlockCopy(yBytes, 0, padded, 32 - yBytes.Length, yBytes.Length);
            yBytes = padded;
        }

        return new ECPoint { X = xBytes, Y = yBytes };
    }

    /// <summary>
    /// Compresses an EC point to a 33-byte compressed public key.
    /// </summary>
    /// <param name="point">EC point with X and Y coordinates (each 32 bytes for P-256)</param>
    /// <returns>33-byte compressed public key (0x02/0x03 prefix + 32 bytes X)</returns>
    public static byte[] CompressP256(ECPoint point)
    {
        if (point.X == null || point.X.Length != 32 || point.Y == null || point.Y.Length != 32)
            throw new ArgumentException("P-256 EC point must have 32-byte X and Y coordinates");

        var y = new BigInteger(point.Y, isUnsigned: true, isBigEndian: true);
        byte prefix = y.IsEven ? (byte)0x02 : (byte)0x03;

        var compressed = new byte[33];
        compressed[0] = prefix;
        Buffer.BlockCopy(point.X, 0, compressed, 1, 32);
        return compressed;
    }
}
