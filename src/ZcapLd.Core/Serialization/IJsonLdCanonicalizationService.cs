namespace ZcapLd.Core.Serialization;

/// <summary>
/// Service for JSON-LD canonicalization using RDF Dataset Canonicalization (RDFC-1.0).
/// Canonicalization is required for cryptographic signing to ensure deterministic output.
/// </summary>
public interface IJsonLdCanonicalizationService
{
    /// <summary>
    /// Canonicalizes a JSON-LD document for cryptographic signing.
    /// Uses RDF Dataset Canonicalization Algorithm (RDFC-1.0).
    /// </summary>
    /// <param name="jsonLd">The JSON-LD document as a JSON string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The canonicalized N-Quads representation.</returns>
    /// <exception cref="CanonicalizationException">Thrown when canonicalization fails.</exception>
    Task<string> CanonicalizeAsync(string jsonLd, CancellationToken cancellationToken = default);

    /// <summary>
    /// Canonicalizes a JSON-LD document and returns the bytes for signing.
    /// </summary>
    /// <param name="jsonLd">The JSON-LD document as a JSON string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The canonicalized bytes (UTF-8 encoded N-Quads).</returns>
    /// <exception cref="CanonicalizationException">Thrown when canonicalization fails.</exception>
    Task<byte[]> CanonicalizeToBytesAsync(string jsonLd, CancellationToken cancellationToken = default);

    /// <summary>
    /// Canonicalizes an object by first serializing it to JSON-LD.
    /// </summary>
    /// <typeparam name="T">The type of object to canonicalize.</typeparam>
    /// <param name="obj">The object to canonicalize.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The canonicalized N-Quads representation.</returns>
    /// <exception cref="CanonicalizationException">Thrown when canonicalization fails.</exception>
    Task<string> CanonicalizeObjectAsync<T>(T obj, CancellationToken cancellationToken = default);

    /// <summary>
    /// Canonicalizes an object and returns the bytes for signing.
    /// </summary>
    /// <typeparam name="T">The type of object to canonicalize.</typeparam>
    /// <param name="obj">The object to canonicalize.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The canonicalized bytes (UTF-8 encoded N-Quads).</returns>
    /// <exception cref="CanonicalizationException">Thrown when canonicalization fails.</exception>
    Task<byte[]> CanonicalizeObjectToBytesAsync<T>(T obj, CancellationToken cancellationToken = default);
}
