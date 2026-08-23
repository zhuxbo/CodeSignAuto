using System.Text;
using SimplySignAuto.Core.Jobs;
using Xunit;

namespace SimplySignAuto.Core.Tests;

public sealed class SigningRequestValidatorTests
{
    [Theory]
    [InlineData("52a1b4c9", "52A1B4C9")]
    [InlineData("0052A1B4C9", "52A1B4C9")]
    [InlineData("00001", "01")]
    [InlineData("00", "00")]
    [InlineData("ABC", "0ABC")]
    [InlineData("FACE", "FACE")]
    public void Certificate_serial_is_canonicalized(string input, string expected)
    {
        Assert.True(CertificateSerialNumber.TryNormalize(input, out var actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0x52A1")]
    [InlineData("52-A1")]
    [InlineData("52:A1")]
    [InlineData("GG")]
    public void Invalid_certificate_serial_is_rejected(string input) =>
        Assert.False(CertificateSerialNumber.TryNormalize(input, out _));

    [Fact]
    public void Null_certificate_serial_is_rejected() =>
        Assert.False(CertificateSerialNumber.TryNormalize(null, out _));

    [Theory]
    [InlineData("payload.exe", "%PDF-1.7", "file_signature_mismatch")]
    [InlineData("payload.ps1", "Write-Host x", "unsupported_type")]
    public void Rejects_extension_or_magic_mismatch(string name, string prefix, string code)
    {
        var ex = Assert.Throws<ValidationException>(() =>
            SigningRequestValidator.ValidateFile(name, Encoding.ASCII.GetBytes(prefix)));

        Assert.Equal(code, ex.Code);
    }

    [Fact]
    public void Requires_certificate_serial_number()
    {
        const string json = """{"kind":"authenticode","digestAlgorithm":"sha256","appendSignature":false}""";

        AssertInvalid(json);
    }

    [Fact]
    public void Serializes_canonical_certificate_serial_number_once()
    {
        var parameters = new AuthenticodeParameters("0052a1b4c9", "sha256", false);

        var json = SigningParameters.SerializeCanonical(parameters);

        Assert.Equal("""{"appendSignature":false,"certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","kind":"authenticode"}""", json);
    }

    [Fact]
    public void Parse_stores_the_normalized_certificate_serial_number()
    {
        var parameters = Assert.IsType<AuthenticodeParameters>(SigningParameters.Parse(
            """{"kind":"authenticode","certificateSerialNumber":"0052a1b4c9","digestAlgorithm":"sha256","appendSignature":false}"""));

        Assert.Equal("52A1B4C9", parameters.CertificateSerialNumber);
    }

    [Theory]
    [InlineData("")]
    [InlineData("GG")]
    public void SerializeCanonical_rejects_directly_constructed_invalid_certificate_serial_number(string serialNumber)
    {
        var parameters = new AuthenticodeParameters(serialNumber, "sha256", false);

        Assert.Throws<ArgumentException>(() => SigningParameters.SerializeCanonical(parameters));
    }

    [Fact]
    public void SerializeCanonical_rejects_directly_constructed_null_certificate_serial_number()
    {
        var parameters = new AuthenticodeParameters(null!, "sha256", false);

        Assert.Throws<ArgumentException>(() => SigningParameters.SerializeCanonical(parameters));
    }

    [Theory]
    [InlineData("app.exe", "MZ\0\0", FileKind.Authenticode)]
    [InlineData("document.pdf", "%PDF-1.7", FileKind.Pdf)]
    public void Accepts_matching_file_signature(string name, string prefix, FileKind expected)
    {
        Assert.Equal(expected, SigningRequestValidator.ValidateFile(name, Encoding.ASCII.GetBytes(prefix)));
    }

    [Fact]
    public void Rejects_unknown_json_property()
    {
        const string json = """{"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false,"extra":true}""";

        AssertInvalid(json);
    }

    [Theory]
    [InlineData("""{"kind":"authenticode","certificateSerialNumber":"52A1","certificateSerialNumber":"52A2","digestAlgorithm":"sha256","appendSignature":false}""")]
    [InlineData("""{"kind":"authenticode","certificateSerialNumber":"52A1","digestAlgorithm":"sha256","digestAlgorithm":"sha256","appendSignature":false}""")]
    public void Rejects_duplicate_top_level_json_property(string json)
    {
        AssertInvalid(json);
    }

    [Fact]
    public void Rejects_invalid_pdf_box()
    {
        const string json = """{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,10,40],"fieldName":"Signature1"}""";

        AssertInvalid(json);
    }

    [Theory]
    [InlineData("reason")]
    [InlineData("location")]
    public void Rejects_overlong_pdf_text(string property)
    {
        var json = $$"""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1","{{property}}":"{{new string('x', 129)}}"}""";

        AssertInvalid(json);
    }

    [Fact]
    public void Rejects_parameter_kind_that_does_not_match_file()
    {
        const string json = """{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1"}""";

        var ex = Assert.Throws<ValidationException>(() =>
            SigningParameters.ParseAndValidate(json, "app.exe", "MZ"u8));

        Assert.Equal("invalid_parameters", ex.Code);
    }

    [Theory]
    [InlineData("""{"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false}""", typeof(AuthenticodeParameters))]
    [InlineData("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1"}""", typeof(PdfParameters))]
    public void Parses_valid_parameters(string json, Type expectedType)
    {
        Assert.IsType(expectedType, SigningParameters.Parse(json));
    }

    [Fact]
    public void Rejects_pdf_box_with_wrong_number_of_elements()
    {
        const string json = """{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30],"fieldName":"Signature1"}""";

        AssertInvalid(json);
    }

    [Fact]
    public void Pdf_text_rejects_control_characters()
    {
        AssertInvalid("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1","reason":"line\nbreak"}""");
        AssertInvalid("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":[10,20,30,40],"fieldName":"Signature1","location":"room\u0000x"}""");
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{")]
    [InlineData("""{"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256"}""")]
    [InlineData("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":0,"box":[10,20,30,40],"fieldName":"Signature1"}""")]
    [InlineData("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":1,"box":"10,20,30,40","fieldName":"Signature1"}""")]
    [InlineData("""{"kind":"pdf","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","page":"1","box":[10,20,30,40],"fieldName":"Signature1"}""")]
    public void Malformed_or_wrong_typed_parameter_shapes_fail_closed(string json)
    {
        AssertInvalid(json);
    }

    private static void AssertInvalid(string json)
    {
        var ex = Assert.Throws<ValidationException>(() => SigningParameters.Parse(json));

        Assert.Equal("invalid_parameters", ex.Code);
    }
}
