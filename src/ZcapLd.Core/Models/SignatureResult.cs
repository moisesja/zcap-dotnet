namespace ZcapLd.Core.Models;

/// <summary>
/// Result of a signing operation, bundling the raw signature bytes with
/// the signature type string (e.g. "Ed25519Signature2020").
/// This allows different providers to declare their algorithm contextually.
/// </summary>
public record SignatureResult(byte[] Signature, string SignatureType);
