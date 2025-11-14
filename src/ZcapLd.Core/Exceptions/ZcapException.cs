using System.Runtime.Serialization;

namespace ZcapLd.Core.Exceptions;

/// <summary>
/// Base exception for all ZCAP-LD related errors.
/// </summary>
[Serializable]
public class ZcapException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ZcapException"/> class.
    /// </summary>
    public ZcapException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ZcapException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public ZcapException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ZcapException"/> class with a specified error message
    /// and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.</param>
    public ZcapException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a capability validation fails.
/// </summary>
[Serializable]
public class CapabilityValidationException : ZcapException
{
    /// <summary>
    /// Gets the capability ID that failed validation.
    /// </summary>
    public string? CapabilityId { get; }

    /// <summary>
    /// Gets the validation error code.
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CapabilityValidationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The validation error code.</param>
    public CapabilityValidationException(string message, string errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CapabilityValidationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The validation error code.</param>
    /// <param name="capabilityId">The capability ID that failed validation.</param>
    public CapabilityValidationException(string message, string errorCode, string? capabilityId) : base(message)
    {
        ErrorCode = errorCode;
        CapabilityId = capabilityId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CapabilityValidationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="errorCode">The validation error code.</param>
    /// <param name="innerException">The inner exception.</param>
    public CapabilityValidationException(string message, string errorCode, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Exception thrown when a capability invocation fails.
/// </summary>
[Serializable]
public class InvocationException : ZcapException
{
    /// <summary>
    /// Gets the capability ID involved in the failed invocation.
    /// </summary>
    public string? CapabilityId { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvocationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public InvocationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvocationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="capabilityId">The capability ID involved.</param>
    public InvocationException(string message, string? capabilityId) : base(message)
    {
        CapabilityId = capabilityId;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvocationException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public InvocationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a cryptographic operation fails.
/// </summary>
[Serializable]
public class CryptographicException : ZcapException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public CryptographicException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public CryptographicException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
