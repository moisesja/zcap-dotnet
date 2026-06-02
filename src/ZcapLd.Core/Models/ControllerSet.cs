using System.Text.Json.Serialization;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Models;

/// <summary>
/// The set of controllers authorized over a capability.
///
/// Per W3C ZCAP-LD v0.3, both root and delegated zcaps MUST have a <c>controller</c>
/// that is "a string or an array of strings that each express a URI". This immutable
/// value type models both shapes behind one API and, crucially, <b>preserves the
/// on-wire shape</b> it was created from: a single controller round-trips as a bare
/// JSON string, an array round-trips as a JSON array (even a single-element one).
///
/// Shape preservation is load-bearing for cross-language JCS interop. A single
/// controller written as a bare string produces different canonical bytes than the
/// same controller wrapped in a one-element array; if we normalized one to the other,
/// signatures produced by peer Data Integrity implementations (zcap-py, JS, Rust) over
/// the original shape would stop verifying here. See Issue #47 and the cross-stack
/// canonicalization contract pinned by #34 / #36 / #37 / #39.
///
/// The <see cref="ControllerSetJsonConverter"/> (carried by the <see cref="JsonConverterAttribute"/>
/// on this type) reads/writes both shapes; implicit conversions from <see cref="string"/>
/// and <c>string[]</c> keep single-controller call sites ergonomic.
/// </summary>
[JsonConverter(typeof(ControllerSetJsonConverter))]
public sealed class ControllerSet : IEquatable<ControllerSet>
{
    private readonly string[] _values;

    private ControllerSet(string[] values, bool isArrayForm)
    {
        _values = values;
        IsArrayForm = isArrayForm;
    }

    /// <summary>An empty controller set (no controllers). Serializes in scalar form.</summary>
    public static readonly ControllerSet Empty = new(Array.Empty<string>(), isArrayForm: false);

    /// <summary>The controller URIs, in declaration order.</summary>
    public IReadOnlyList<string> Values => _values;

    /// <summary>Number of controllers in the set.</summary>
    public int Count => _values.Length;

    /// <summary>True when the set contains no controllers.</summary>
    public bool IsEmpty => _values.Length == 0;

    /// <summary>
    /// True when this set serializes as a JSON array, false when it serializes as a
    /// bare JSON string. Tracks the original wire/construction shape so round-trips
    /// stay byte-stable for JCS canonicalization.
    /// </summary>
    public bool IsArrayForm { get; }

    /// <summary>
    /// The first controller, or empty string when the set is empty. Convenience for
    /// single-controller scenarios (display, "the" controller, default delegation signer).
    /// </summary>
    public string Primary => _values.Length > 0 ? _values[0] : string.Empty;

    /// <summary>
    /// Builds a single-controller set that serializes as a bare string. A null/whitespace
    /// value yields <see cref="Empty"/> — semantic rejection happens at the service layer,
    /// matching the prior single-string behavior.
    /// </summary>
    public static ControllerSet FromSingle(string? controller) =>
        string.IsNullOrWhiteSpace(controller)
            ? Empty
            : new ControllerSet(new[] { controller }, isArrayForm: false);

    /// <summary>
    /// Builds a controller set from many values. Defaults to array wire form. Throws when
    /// the input is null, empty, or contains a null/whitespace entry — malformed controller
    /// values per the spec must not silently produce a valid-looking capability.
    /// </summary>
    public static ControllerSet FromValues(IEnumerable<string> controllers, bool asArray = true)
    {
        ArgumentNullException.ThrowIfNull(controllers);

        var array = controllers.ToArray();
        if (array.Length == 0)
        {
            throw new ArgumentException("Controller array must contain at least one URI.", nameof(controllers));
        }

        foreach (var value in array)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException("Controller entries must be non-empty URI strings.", nameof(controllers));
            }
        }

        return new ControllerSet(array, isArrayForm: asArray);
    }

    /// <summary>True when <paramref name="controller"/> exactly matches one of the controllers.</summary>
    public bool Contains(string controller) =>
        _values.Any(v => string.Equals(v, controller, StringComparison.Ordinal));

    /// <summary>
    /// True when a proof's verification method is authorized by this set — i.e. one of the
    /// controllers equals either the verification method's bare DID (<c>vm.Split('#')[0]</c>)
    /// or the full verification method URI. This is the multi-controller authorization check
    /// used for both invocation and delegation.
    /// </summary>
    public bool ContainsVerificationMethod(string verificationMethod)
    {
        if (string.IsNullOrEmpty(verificationMethod))
        {
            return false;
        }

        var did = verificationMethod.Split('#')[0];
        return _values.Any(c =>
            string.Equals(c, did, StringComparison.Ordinal) ||
            string.Equals(c, verificationMethod, StringComparison.Ordinal));
    }

    /// <summary>Implicit conversion from a single controller string (scalar wire form).</summary>
    public static implicit operator ControllerSet(string? controller) => FromSingle(controller);

    /// <summary>Implicit conversion from a controller array (array wire form).</summary>
    public static implicit operator ControllerSet(string[]? controllers) =>
        controllers is null ? Empty : FromValues(controllers);

    /// <inheritdoc />
    public bool Equals(ControllerSet? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return IsArrayForm == other.IsArrayForm && _values.AsSpan().SequenceEqual(other._values);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as ControllerSet);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(IsArrayForm);
        foreach (var value in _values)
        {
            hash.Add(value, StringComparer.Ordinal);
        }
        return hash.ToHashCode();
    }

    /// <inheritdoc />
    public override string ToString() =>
        IsArrayForm ? $"[{string.Join(", ", _values)}]" : Primary;
}
