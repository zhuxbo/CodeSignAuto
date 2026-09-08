using System.Text.RegularExpressions;
using System.Security.Cryptography;
using CodeSignAuto.Core.Otp;

namespace CodeSignAuto.Core.Security;

public static partial class SecretRedactor
{
    private const string Replacement = "[REDACTED_TOTP_SECRET]";

    public static string Redact(string value, string? actualTotpSecret = null)
    {
        ArgumentNullException.ThrowIfNull(value);

        var redacted = OtpauthSecret().Replace(
            value,
            static match => match.Groups[1].Value + Replacement);
        return !IsActualTotpSecret(actualTotpSecret)
            ? redacted
            : redacted.Replace(actualTotpSecret!, Replacement, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsActualTotpSecret(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        byte[] decoded;
        try
        {
            decoded = Base32.Decode(value);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            return decoded.Length >= 20;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    [GeneratedRegex(@"(otpauth://[^\s\""'<>]*?(?:[?&]|&amp;)secret=)[^&\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OtpauthSecret();
}
