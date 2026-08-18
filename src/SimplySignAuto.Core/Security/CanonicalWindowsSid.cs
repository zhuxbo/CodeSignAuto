using System.Globalization;

namespace SimplySignAuto.Core.Security;

public static class CanonicalWindowsSid
{
    public static bool IsValid(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var parts = value.Split('-', StringSplitOptions.None);
        if (parts.Length is < 4 or > 18 || parts[0] != "S" || parts[1] != "1" ||
            !TryParseCanonical(parts[2], ulong.MaxValue, out var authority) ||
            authority > 0xFFFFFFFFFFFF)
        {
            return false;
        }

        for (var index = 3; index < parts.Length; index++)
        {
            if (!TryParseCanonical(parts[index], uint.MaxValue, out _))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryParseCanonical(string value, ulong maximum, out ulong parsed)
    {
        if (value.Length == 0 || value.Length > 1 && value[0] == '0' ||
            !value.All(character => character is >= '0' and <= '9') ||
            !ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed) ||
            parsed > maximum)
        {
            parsed = 0;
            return false;
        }

        return true;
    }
}
