using ZcapLd.Core.Models;

namespace ZcapLd.Examples;

/// <summary>
/// Example custom caveat that enforces a required HTTP Content-Type.
/// Reads "contentType" from <see cref="InvocationContext.Properties"/>,
/// which the caller injects via the 3-param VerifyInvocationAsync overload.
/// </summary>
public class ContentTypeCaveat : Caveat
{
    public override string Type => "ContentType";
    public string RequiredContentType { get; set; } = string.Empty;

    public override bool IsSatisfied(InvocationContext context)
    {
        return context.Properties.TryGetValue("contentType", out var value)
            && value is string contentType
            && string.Equals(contentType, RequiredContentType, StringComparison.OrdinalIgnoreCase);
    }
}
