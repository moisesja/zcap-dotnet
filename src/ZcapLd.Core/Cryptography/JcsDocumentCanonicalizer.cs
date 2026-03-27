namespace ZcapLd.Core.Cryptography;

/// <summary>
/// JCS (JSON Canonicalization Scheme, RFC 8785) document canonicalizer.
/// Delegates to <see cref="JsonCanonicalizer"/>.
/// </summary>
public class JcsDocumentCanonicalizer : IDocumentCanonicalizer
{
    public string Method => "JCS";

    public byte[] Canonicalize(object document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return JsonCanonicalizer.Canonicalize(document);
    }
}
