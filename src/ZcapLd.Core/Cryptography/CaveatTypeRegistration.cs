using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Rdfc;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// A registered caveat type: its CLR class, declared parameter names and the generated, pinned
/// JSON-LD context that makes the type and every parameter part of the signed N-Quads (#157).
/// </summary>
internal sealed class CaveatTypeRegistration
{
    // Every term defined by a context a capability may carry. A parameter with one of these names
    // would redefine a protected term (expansion fails) or read as ZCAP vocabulary, so it is refused.
    private static readonly Lazy<HashSet<string>> ReservedTerms = new(LoadReservedTerms);

    private CaveatTypeRegistration(string type, Type clrType, IReadOnlyList<string> parameters)
    {
        Type = type;
        ClrType = clrType;
        Parameters = parameters;
        ContextUrl = CaveatTypeRegistry.GetContextUrl(type);
        ContextDocument = BuildContextDocument(type, parameters);
    }

    public string Type { get; }

    public Type ClrType { get; }

    /// <summary>The declared parameter (JSON) names, ordinal order.</summary>
    public IReadOnlyList<string> Parameters { get; }

    public string ContextUrl { get; }

    public string ContextDocument { get; }

    public static CaveatTypeRegistration Create(string type, Type clrType)
    {
        if (string.IsNullOrEmpty(type) || !CaveatTypeRegistry.NamePattern.IsMatch(type))
            throw new ArgumentException(
                "A caveat type is an ASCII letter followed by up to 63 ASCII letters, digits or underscores.", nameof(type));
        if (clrType.IsAbstract || !typeof(Caveat).IsAssignableFrom(clrType))
            throw new ArgumentException($"{clrType.FullName} must be a concrete Caveat subclass.", nameof(clrType));

        var typeInfo = CaveatCodec.SerializerOptions.GetTypeInfo(clrType);
        var parameters = new List<string>();
        foreach (var property in typeInfo.Properties)
        {
            if (property.IsExtensionData)
                throw new ArgumentException(
                    $"{clrType.FullName} captures extension data; every caveat parameter must be declared.", nameof(clrType));
            var name = property.Name;
            if (!CaveatTypeRegistry.NamePattern.IsMatch(name) || name is "id" or "type" || ReservedTerms.Value.Contains(name))
                throw new ArgumentException(
                    $"Caveat parameter '{name}' of {clrType.FullName} must be an ASCII identifier that is not " +
                    "'id', 'type' or a term of the ZCAP or signature-suite contexts.", nameof(clrType));
            parameters.Add(name);
        }

        parameters.Sort(StringComparer.Ordinal);
        return new CaveatTypeRegistration(type, clrType, parameters);
    }

    private static string BuildContextDocument(string type, IReadOnlyList<string> parameters)
    {
        var typeIri = CaveatTypeRegistry.TypeIriPrefix + type;
        var scoped = new JsonObject { ["@protected"] = true };
        foreach (var name in parameters)
            scoped[name] = new JsonObject { ["@id"] = $"{typeIri}#{name}", ["@type"] = "@json" };

        var context = new JsonObject
        {
            ["@context"] = new JsonObject
            {
                ["@protected"] = true,
                [type] = new JsonObject { ["@id"] = typeIri, ["@context"] = scoped },
            },
        };
        return Encoding.UTF8.GetString(NetCid.JcsCanonicalizer.Canonicalize(context));
    }

    private static HashSet<string> LoadReservedTerms()
    {
        var terms = new HashSet<string>(StringComparer.Ordinal);
        foreach (var url in new[]
                 {
                     "https://w3id.org/zcap/v1",
                     "https://w3id.org/security/suites/ed25519-2020/v1",
                     "https://w3id.org/security/suites/ecdsa-2019/v1",
                 })
        {
            string content;
            try
            {
                content = RdfcContextDocumentLoader.Instance.Load(new Uri(url)).Content;
            }
            catch (RdfCanonicalizationException)
            {
                continue; // A context the loader cannot serve cannot appear in a verified capability.
            }

            using var document = JsonDocument.Parse(content);
            Collect(document.RootElement);
        }

        return terms;

        void Collect(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    if (!property.Name.StartsWith('@'))
                        terms.Add(property.Name);
                    Collect(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                    Collect(item);
            }
        }
    }
}
