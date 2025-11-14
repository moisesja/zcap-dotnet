using System.Runtime.Serialization;

namespace ZcapLd.Core.Exceptions;

/// <summary>
/// Exception thrown when JSON-LD serialization or deserialization fails.
/// </summary>
[Serializable]
public class SerializationException : ZcapException
{
    /// <summary>
    /// Gets the type that failed to serialize or deserialize.
    /// </summary>
    public string? TypeName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SerializationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="typeName">The type that failed serialization.</param>
    public SerializationException(string message, string? typeName) : base(message)
    {
        TypeName = typeName;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public SerializationException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SerializationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="typeName">The type that failed serialization.</param>
    /// <param name="innerException">The inner exception.</param>
    public SerializationException(string message, string? typeName, Exception innerException)
        : base(message, innerException)
    {
        TypeName = typeName;
    }
}

/// <summary>
/// Exception thrown when JSON-LD canonicalization fails.
/// </summary>
[Serializable]
public class CanonicalizationException : ZcapException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CanonicalizationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public CanonicalizationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CanonicalizationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public CanonicalizationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
