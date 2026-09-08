using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text;

namespace CodeSignAuto.Core.Jobs;

public abstract record SigningParameters(
    string CertificateSerialNumber,
    string DigestAlgorithm)
{
    private static readonly Regex AliasPattern = new(
        "^[A-Za-z][A-Za-z0-9_.-]{0,63}$",
        RegexOptions.CultureInvariant);

    private static readonly HashSet<string> CommonProperties = new(StringComparer.Ordinal)
    {
        "kind", "certificateSerialNumber", "digestAlgorithm",
    };

    public static SigningParameters ParseAndValidate(string json, string originalName, ReadOnlySpan<byte> prefix)
    {
        var parameters = Parse(json);
        var fileKind = SigningRequestValidator.ValidateFile(originalName, prefix);
        if ((parameters is PdfParameters && fileKind != FileKind.Pdf) ||
            (parameters is AuthenticodeParameters && fileKind != FileKind.Authenticode))
        {
            throw new ValidationException("invalid_parameters");
        }

        return parameters;
    }

    public static SigningParameters Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Invalid();
            }

            var properties = document.RootElement.EnumerateObject().ToArray();
            if (properties.Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() != properties.Length)
            {
                throw Invalid();
            }

            var values = properties.ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
            var kind = RequiredString(values, "kind");
            return kind switch
            {
                "authenticode" => ParseAuthenticode(values),
                "pdf" => ParsePdf(values),
                _ => throw Invalid(),
            };
        }
        catch (JsonException)
        {
            throw Invalid();
        }
    }

    public static string SerializeCanonical(SigningParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            switch (parameters)
            {
                case AuthenticodeParameters authenticode:
                    writer.WriteBoolean("appendSignature", authenticode.AppendSignature);
                    writer.WriteString("certificateSerialNumber", NormalizeCertificateSerialNumber(authenticode.CertificateSerialNumber));
                    writer.WriteString("digestAlgorithm", authenticode.DigestAlgorithm);
                    writer.WriteString("kind", "authenticode");
                    break;
                case PdfParameters pdf:
                    writer.WriteStartArray("box");
                    writer.WriteNumberValue(pdf.Box.Left);
                    writer.WriteNumberValue(pdf.Box.Bottom);
                    writer.WriteNumberValue(pdf.Box.Right);
                    writer.WriteNumberValue(pdf.Box.Top);
                    writer.WriteEndArray();
                    writer.WriteString("certificateSerialNumber", NormalizeCertificateSerialNumber(pdf.CertificateSerialNumber));
                    writer.WriteString("digestAlgorithm", pdf.DigestAlgorithm);
                    writer.WriteString("fieldName", pdf.FieldName);
                    writer.WriteString("kind", "pdf");
                    if (pdf.Location is not null)
                    {
                        writer.WriteString("location", pdf.Location);
                    }

                    writer.WriteNumber("page", pdf.Page);
                    if (pdf.Reason is not null)
                    {
                        writer.WriteString("reason", pdf.Reason);
                    }

                    break;
                default:
                    throw new ArgumentException("Unsupported signing parameters.", nameof(parameters));
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static AuthenticodeParameters ParseAuthenticode(IReadOnlyDictionary<string, JsonElement> values)
    {
        EnsureKnownProperties(values, "appendSignature");
        var common = ParseCommon(values);
        return new AuthenticodeParameters(
            common.CertificateSerialNumber,
            common.DigestAlgorithm,
            RequiredBoolean(values, "appendSignature"));
    }

    private static PdfParameters ParsePdf(IReadOnlyDictionary<string, JsonElement> values)
    {
        EnsureKnownProperties(values, "page", "box", "fieldName", "reason", "location");
        var common = ParseCommon(values);
        var page = RequiredInt32(values, "page");
        if (page is < 1 or > 10_000)
        {
            throw Invalid();
        }

        var box = ParseBox(values);
        var fieldName = RequiredString(values, "fieldName");
        if (!AliasPattern.IsMatch(fieldName))
        {
            throw Invalid();
        }

        return new PdfParameters(
            common.CertificateSerialNumber,
            common.DigestAlgorithm,
            page,
            box,
            fieldName,
            OptionalString(values, "reason"),
            OptionalString(values, "location"));
    }

    private static (string CertificateSerialNumber, string DigestAlgorithm) ParseCommon(
        IReadOnlyDictionary<string, JsonElement> values)
    {
        var certificateSerialNumber = RequiredString(values, "certificateSerialNumber");
        var digestAlgorithm = RequiredString(values, "digestAlgorithm");
        if (!global::CodeSignAuto.Core.Jobs.CertificateSerialNumber.TryNormalize(certificateSerialNumber, out var normalizedCertificateSerialNumber) ||
            digestAlgorithm != "sha256")
        {
            throw Invalid();
        }

        return (normalizedCertificateSerialNumber, digestAlgorithm);
    }

    private static PdfBox ParseBox(IReadOnlyDictionary<string, JsonElement> values)
    {
        if (!values.TryGetValue("box", out var element) || element.ValueKind != JsonValueKind.Array)
        {
            throw Invalid();
        }

        var boxValues = element.EnumerateArray().ToArray();
        if (boxValues.Length != 4)
        {
            throw Invalid();
        }

        var result = new PdfBox(
            RequiredDouble(boxValues[0]),
            RequiredDouble(boxValues[1]),
            RequiredDouble(boxValues[2]),
            RequiredDouble(boxValues[3]));
        if (!double.IsFinite(result.Left) || !double.IsFinite(result.Bottom) ||
            !double.IsFinite(result.Right) || !double.IsFinite(result.Top) ||
            result.Left >= result.Right || result.Bottom >= result.Top)
        {
            throw Invalid();
        }

        return result;
    }

    private static void EnsureKnownProperties(IReadOnlyDictionary<string, JsonElement> values, params string[] specificProperties)
    {
        var allowed = new HashSet<string>(CommonProperties, StringComparer.Ordinal);
        foreach (var property in specificProperties)
        {
            allowed.Add(property);
        }

        if (values.Keys.Any(key => !allowed.Contains(key)))
        {
            throw Invalid();
        }
    }

    private static string RequiredString(IReadOnlyDictionary<string, JsonElement> values, string name)
    {
        if (!values.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.String)
        {
            throw Invalid();
        }

        return element.GetString() ?? throw Invalid();
    }

    private static string? OptionalString(IReadOnlyDictionary<string, JsonElement> values, string name)
    {
        if (!values.TryGetValue(name, out var element))
        {
            return null;
        }

        if (element.ValueKind != JsonValueKind.String || element.GetString() is not { } value ||
            value.Length > 128 || value.Any(char.IsControl))
        {
            throw Invalid();
        }

        return value;
    }

    private static bool RequiredBoolean(IReadOnlyDictionary<string, JsonElement> values, string name)
    {
        if (!values.TryGetValue(name, out var element) ||
            (element.ValueKind != JsonValueKind.True && element.ValueKind != JsonValueKind.False))
        {
            throw Invalid();
        }

        return element.GetBoolean();
    }

    private static int RequiredInt32(IReadOnlyDictionary<string, JsonElement> values, string name)
    {
        if (!values.TryGetValue(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out var value))
        {
            throw Invalid();
        }

        return value;
    }

    private static double RequiredDouble(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetDouble(out var value))
        {
            throw Invalid();
        }

        return value;
    }

    private static string NormalizeCertificateSerialNumber(string value)
    {
        if (!global::CodeSignAuto.Core.Jobs.CertificateSerialNumber.TryNormalize(value, out var normalized))
        {
            throw new ArgumentException("Certificate serial number is invalid.", nameof(value));
        }

        return normalized;
    }

    private static ValidationException Invalid() => new("invalid_parameters");
}

public sealed record PdfBox(double Left, double Bottom, double Right, double Top);

public sealed record AuthenticodeParameters(
    string CertificateSerialNumber,
    string DigestAlgorithm,
    bool AppendSignature) : SigningParameters(CertificateSerialNumber, DigestAlgorithm);

public sealed record PdfParameters(
    string CertificateSerialNumber,
    string DigestAlgorithm,
    int Page,
    PdfBox Box,
    string FieldName,
    string? Reason,
    string? Location) : SigningParameters(CertificateSerialNumber, DigestAlgorithm);
