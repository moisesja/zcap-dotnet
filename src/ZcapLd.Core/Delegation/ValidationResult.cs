using System;
using System.Collections.Generic;
using System.Linq;

namespace ZcapLd.Core.Delegation;

/// <summary>
/// Represents the result of a validation operation.
/// </summary>
public sealed class ValidationResult
{
    /// <summary>
    /// Gets whether the validation was successful.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the validation error code if validation failed.
    /// Null if validation succeeded.
    /// </summary>
    public string? ErrorCode { get; }

    /// <summary>
    /// Gets the validation error message if validation failed.
    /// Null if validation succeeded.
    /// </summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// Gets additional context information about the validation.
    /// </summary>
    public IReadOnlyDictionary<string, object> Context { get; }

    private ValidationResult(
        bool isValid,
        string? errorCode = null,
        string? errorMessage = null,
        Dictionary<string, object>? context = null)
    {
        IsValid = isValid;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
        Context = context ?? new Dictionary<string, object>();
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <param name="context">Optional context information.</param>
    /// <returns>A successful validation result.</returns>
    public static ValidationResult Success(Dictionary<string, object>? context = null)
    {
        return new ValidationResult(true, context: context);
    }

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    /// <param name="errorCode">The error code.</param>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="context">Optional context information.</param>
    /// <returns>A failed validation result.</returns>
    public static ValidationResult Failure(
        string errorCode,
        string errorMessage,
        Dictionary<string, object>? context = null)
    {
        if (string.IsNullOrWhiteSpace(errorCode))
        {
            throw new ArgumentNullException(nameof(errorCode));
        }

        if (string.IsNullOrWhiteSpace(errorMessage))
        {
            throw new ArgumentNullException(nameof(errorMessage));
        }

        return new ValidationResult(false, errorCode, errorMessage, context);
    }

    /// <summary>
    /// Gets a string representation of the validation result.
    /// </summary>
    public override string ToString()
    {
        if (IsValid)
        {
            return "ValidationResult: Success";
        }

        var contextStr = Context.Any()
            ? $" (Context: {string.Join(", ", Context.Select(kvp => $"{kvp.Key}={kvp.Value}"))})"
            : string.Empty;

        return $"ValidationResult: Failure - [{ErrorCode}] {ErrorMessage}{contextStr}";
    }
}
