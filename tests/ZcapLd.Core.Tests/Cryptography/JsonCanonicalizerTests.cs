using FluentAssertions;
using System.Text;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

public class JsonCanonicalizerTests
{
    [Fact]
    public void Canonicalize_ShouldReturnDeterministicOutput()
    {
        // Arrange
        var document = new
        {
            id = "urn:uuid:test",
            controller = "did:key:example",
            invocationTarget = "https://example.com/foo"
        };

        // Act
        var canonical1 = JsonCanonicalizer.Canonicalize(document);
        var canonical2 = JsonCanonicalizer.Canonicalize(document);

        // Assert
        canonical1.Should().Equal(canonical2);
    }

    [Fact]
    public void Canonicalize_ShouldProduceUtf8Bytes()
    {
        // Arrange
        var document = new { test = "value" };

        // Act
        var result = JsonCanonicalizer.Canonicalize(document);

        // Assert
        result.Should().NotBeNull();
        var text = Encoding.UTF8.GetString(result);
        text.Should().Contain("test");
        text.Should().Contain("value");
    }

    [Fact]
    public void CanonicalizeString_ShouldParseAndCanonicalize()
    {
        // Arrange
        var json = """{"id":"urn:uuid:test","value":123}""";

        // Act
        var result = JsonCanonicalizer.CanonicalizeString(json);

        // Assert
        result.Should().NotBeNull();
        var text = Encoding.UTF8.GetString(result);
        text.Should().Contain("id");
        text.Should().Contain("value");
    }

    [Fact]
    public void CanonicalizeString_WithDifferentPropertyOrder_ShouldProduceSameOutput()
    {
        // Arrange
        var json1 = """{"id":"test","controller":"controller","target":"target"}""";
        var json2 = """{"target":"target","id":"test","controller":"controller"}""";

        // Act
        var canonical1 = JsonCanonicalizer.CanonicalizeString(json1);
        var canonical2 = JsonCanonicalizer.CanonicalizeString(json2);

        // Assert
        canonical1.Should().Equal(canonical2);
    }

    [Fact]
    public void Canonicalize_WithComplexObject_ShouldHandleAllTypes()
    {
        // Arrange
        var document = new
        {
            stringValue = "text",
            intValue = 123,
            doubleValue = 123.456,
            boolTrue = true,
            boolFalse = false,
            nullValue = (string?)null,
            arrayValue = new[] { 1, 2, 3 },
            nestedObject = new { inner = "value" }
        };

        // Act
        var result = JsonCanonicalizer.Canonicalize(document);
        var text = Encoding.UTF8.GetString(result);

        // Assert
        text.Should().Contain("text");
        text.Should().Contain("123");
        text.Should().Contain("true");
        text.Should().Contain("false");
        text.Should().Contain("[1,2,3]");
        text.Should().Contain("inner");
    }

    [Fact]
    public void Canonicalize_ShouldNotIncludeWhitespace()
    {
        // Arrange
        var document = new
        {
            id = "test",
            value = 123
        };

        // Act
        var result = JsonCanonicalizer.Canonicalize(document);
        var text = Encoding.UTF8.GetString(result);

        // Assert
        text.Should().NotContain("\n");
        text.Should().NotContain("\r");
        text.Should().NotContain("  "); // No multiple spaces
    }

    [Fact]
    public void Canonicalize_WithNullProperty_ShouldExcludeNull()
    {
        // Arrange
        var document = new
        {
            id = "test",
            nullValue = (string?)null,
            value = 123
        };

        // Act
        var result = JsonCanonicalizer.Canonicalize(document);
        var text = Encoding.UTF8.GetString(result);

        // Assert
        // Based on DefaultIgnoreCondition.WhenWritingNull
        text.Should().NotContain("nullValue");
        text.Should().Contain("id");
        text.Should().Contain("value");
    }
}
