using System.Globalization;

namespace CodeSignAuto.Core.Otp;

public sealed class OtpauthException : Exception
{
    public OtpauthException()
        : base("otpauth_invalid")
    {
    }

    public string Code => "otpauth_invalid";
}

public sealed class OtpauthProfile
{
    public OtpauthProfile(string secret, string algorithm, int digits, int period, string issuer, string account)
    {
        ValidateSecret(secret);

        if (!string.Equals(algorithm, "SHA256", StringComparison.Ordinal) || digits is not (6 or 8) || period != 30)
        {
            throw new OtpauthException();
        }

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(account))
        {
            throw new OtpauthException();
        }

        Secret = secret;
        Algorithm = algorithm;
        Digits = digits;
        Period = period;
        Issuer = issuer;
        Account = account;
    }

    public string Secret { get; }

    public string Algorithm { get; }

    public int Digits { get; }

    public int Period { get; }

    public string Issuer { get; }

    public string Account { get; }

    public static OtpauthProfile Parse(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri)
            || !HasValidPercentEncoding(uri)
            || !Uri.TryCreate(uri, UriKind.Absolute, out var parsed)
            || !string.Equals(parsed.Scheme, "otpauth", StringComparison.Ordinal)
            || !string.Equals(parsed.Host, "totp", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(parsed.UserInfo)
            || !parsed.IsDefaultPort
            || !string.IsNullOrEmpty(parsed.Fragment))
        {
            throw new OtpauthException();
        }

        var (issuer, account) = ParseLabel(parsed.AbsolutePath);
        var query = ParseQuery(parsed.Query);

        if (!query.TryGetValue("secret", out var secret)
            || !query.TryGetValue("algorithm", out var algorithm)
            || !query.TryGetValue("digits", out var digitsText)
            || !query.TryGetValue("period", out var periodText)
            || !int.TryParse(digitsText, NumberStyles.None, CultureInfo.InvariantCulture, out var digits)
            || !int.TryParse(periodText, NumberStyles.None, CultureInfo.InvariantCulture, out var period))
        {
            throw new OtpauthException();
        }

        if (query.TryGetValue("issuer", out var queryIssuer))
        {
            if (!string.Equals(queryIssuer, issuer, StringComparison.Ordinal))
            {
                throw new OtpauthException();
            }
        }

        var profile = new OtpauthProfile(secret, algorithm, digits, period, issuer, account);
        if (profile.Digits != 6)
        {
            throw new OtpauthException();
        }

        return profile;
    }

    public override string ToString() => "OtpauthProfile";

    private static bool HasValidPercentEncoding(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length
                || !Uri.IsHexDigit(value[index + 1])
                || !Uri.IsHexDigit(value[index + 2]))
            {
                return false;
            }

            index += 2;
        }

        return true;
    }

    private static (string Issuer, string Account) ParseLabel(string escapedPath)
    {
        if (escapedPath.Length <= 1)
        {
            throw new OtpauthException();
        }

        string label;
        try
        {
            label = Uri.UnescapeDataString(escapedPath[1..]);
        }
        catch (UriFormatException)
        {
            throw new OtpauthException();
        }

        var separator = label.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == label.Length - 1)
        {
            throw new OtpauthException();
        }

        var issuer = label[..separator];
        var account = label[(separator + 1)..];
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(account))
        {
            throw new OtpauthException();
        }

        return (issuer, account);
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        if (string.IsNullOrEmpty(query) || query[0] != '?')
        {
            throw new OtpauthException();
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query[1..].Split('&', StringSplitOptions.None))
        {
            var separator = pair.IndexOf('=');
            if (separator <= 0)
            {
                throw new OtpauthException();
            }

            string name;
            string value;
            try
            {
                name = Uri.UnescapeDataString(pair[..separator]);
                value = Uri.UnescapeDataString(pair[(separator + 1)..]);
            }
            catch (UriFormatException)
            {
                throw new OtpauthException();
            }

            if (name is not ("secret" or "algorithm" or "digits" or "period" or "issuer")
                || string.IsNullOrEmpty(value)
                || !values.TryAdd(name, value))
            {
                throw new OtpauthException();
            }
        }

        return values;
    }

    private static void ValidateSecret(string secret)
    {
        byte[] decoded;
        try
        {
            decoded = Base32.Decode(secret);
        }
        catch (FormatException)
        {
            throw new OtpauthException();
        }

        try
        {
            if (decoded.Length < 20)
            {
                throw new OtpauthException();
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
        }
    }
}

public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        var output = new char[(bytes.Length * 8 + 4) / 5];
        var accumulator = 0;
        var bits = 0;
        var index = 0;

        foreach (var value in bytes)
        {
            accumulator = (accumulator << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                output[index++] = Alphabet[(accumulator >> (bits - 5)) & 0x1f];
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output[index++] = Alphabet[(accumulator << (5 - bits)) & 0x1f];
        }

        return new string(output, 0, index);
    }

    public static byte[] Decode(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new FormatException();
        }

        var paddingStart = value.IndexOf('=');
        var unpaddedLength = paddingStart < 0 ? value.Length : paddingStart;
        var paddingLength = paddingStart < 0 ? 0 : value.Length - paddingStart;

        if (!HasValidPadding(value, unpaddedLength, paddingLength))
        {
            throw new FormatException();
        }

        var output = new byte[(unpaddedLength * 5) / 8];
        var accumulator = 0;
        var bits = 0;
        var index = 0;

        for (var charIndex = 0; charIndex < unpaddedLength; charIndex++)
        {
            var alphabetIndex = Alphabet.IndexOf(value[charIndex]);
            if (alphabetIndex < 0)
            {
                throw new FormatException();
            }

            accumulator = (accumulator << 5) | alphabetIndex;
            bits += 5;
            while (bits >= 8)
            {
                output[index++] = (byte)(accumulator >> (bits - 8));
                bits -= 8;
            }
        }

        if (bits > 0 && (accumulator & ((1 << bits) - 1)) != 0)
        {
            throw new FormatException();
        }

        return output;
    }

    private static bool HasValidPadding(string value, int unpaddedLength, int paddingLength)
    {
        if (paddingLength > 0 && (value.Length % 8 != 0 || value[unpaddedLength..].Any(character => character != '=')))
        {
            return false;
        }

        var expectedPadding = (unpaddedLength % 8) switch
        {
            0 => 0,
            2 => 6,
            4 => 4,
            5 => 3,
            7 => 1,
            _ => -1,
        };

        return expectedPadding >= 0 && (paddingLength == 0 || paddingLength == expectedPadding);
    }
}
