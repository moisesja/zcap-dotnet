namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Registry for looking up document canonicalizers by method name.
/// </summary>
public interface IDocumentCanonicalizerProvider
{
    /// <summary>
    /// Returns the canonicalizer for the given method (e.g. "JCS", "RDFC-1.0").
    /// </summary>
    /// <param name="method">The canonicalization method identifier</param>
    /// <returns>The canonicalizer, or null if not registered</returns>
    IDocumentCanonicalizer? GetByMethod(string method);
}
