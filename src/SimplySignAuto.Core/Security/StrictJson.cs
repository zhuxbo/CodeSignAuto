using System.Text.Json;
using System.Text.RegularExpressions;

namespace SimplySignAuto.Core.Security;

public static class StrictJson
{
    public static void RejectDuplicateProperties(string json)
    {
        using var document = JsonDocument.Parse(json);
        Validate(document.RootElement, rejectSecretShapes: false);
    }

    public static void RejectDuplicatePropertiesAndSecretShapes(string json)
    {
        using var document = JsonDocument.Parse(json);
        Validate(document.RootElement, rejectSecretShapes: true);
    }

    private static void Validate(JsonElement element, bool rejectSecretShapes)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new JsonException("Duplicate JSON property.");
                }

                Validate(property.Value, rejectSecretShapes);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                Validate(item, rejectSecretShapes);
            }
        }
        else if (rejectSecretShapes &&
            element.ValueKind == JsonValueKind.String &&
            ContainsSecretShape(element.GetString()!))
        {
            throw new JsonException("Secret-shaped JSON value is not allowed.");
        }
    }

    private static bool ContainsSecretShape(string value) =>
        value.Contains("otpauth://", StringComparison.OrdinalIgnoreCase) ||
        Regex.IsMatch(
            value,
            @"\bauthorization\b\s*[:=]\s*\S+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
        Regex.IsMatch(
            value,
            @"\bbearer\s+\S+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
        Regex.IsMatch(
            value,
            @"/autologin(?:\s+|\s*=\s*)\S+",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
}
