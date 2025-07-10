namespace ZcapLd.Core.Exceptions;

/// <summary>
/// Base exception for ZCAP-LD related errors
/// </summary>
public class ZcapLdException : Exception
{
    public ZcapLdException() { }
    public ZcapLdException(string message) : base(message) { }
    public ZcapLdException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when capability validation fails
/// </summary>
public class CapabilityValidationException : ZcapLdException
{
    public CapabilityValidationException() { }
    public CapabilityValidationException(string message) : base(message) { }
    public CapabilityValidationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when cryptographic operations fail
/// </summary>
public class CryptographicException : ZcapLdException
{
    public CryptographicException() { }
    public CryptographicException(string message) : base(message) { }
    public CryptographicException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when capability delegation fails
/// </summary>
public class DelegationException : ZcapLdException
{
    public DelegationException() { }
    public DelegationException(string message) : base(message) { }
    public DelegationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when capability invocation fails
/// </summary>
public class InvocationException : ZcapLdException
{
    public InvocationException() { }
    public InvocationException(string message) : base(message) { }
    public InvocationException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when caveat evaluation fails
/// </summary>
public class CaveatException : ZcapLdException
{
    public CaveatException() { }
    public CaveatException(string message) : base(message) { }
    public CaveatException(string message, Exception innerException) : base(message, innerException) { }
}