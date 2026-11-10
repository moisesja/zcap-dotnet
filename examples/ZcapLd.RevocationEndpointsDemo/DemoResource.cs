namespace ZcapLd.RevocationEndpointsDemo;

/// <summary>
/// The one resource this demo protects. The invocation target is a constant identifier for the
/// resource, independent of the address the host happens to listen on: capabilities name the
/// resource, not a port, so the same capability is valid wherever this service is deployed.
/// </summary>
public static class DemoResource
{
    /// <summary>The route the protected resource is served on.</summary>
    public const string ReportPath = "/documents/report";

    /// <summary>The action a caller must hold to read the report.</summary>
    public const string ReadAction = "read";

    /// <summary>The <c>invocationTarget</c> every capability for the report must name.</summary>
    public const string ReportTarget = "https://demo.example" + ReportPath;
}
