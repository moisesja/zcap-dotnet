namespace ZcapLd.Core.Models;

/// <summary>
/// Context information for capability invocation evaluation
/// </summary>
public class InvocationContext
{
    /// <summary>
    /// Timestamp of the invocation
    /// </summary>
    public DateTime InvocationTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The action being requested
    /// </summary>
    public string RequestedAction { get; set; } = string.Empty;

    /// <summary>
    /// The target resource URI
    /// </summary>
    public string TargetResource { get; set; } = string.Empty;

    /// <summary>
    /// Additional context data
    /// </summary>
    public Dictionary<string, object> Properties { get; set; } = new();
}