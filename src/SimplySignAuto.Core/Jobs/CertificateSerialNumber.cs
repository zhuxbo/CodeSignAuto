namespace SimplySignAuto.Core.Jobs;

public static class CertificateSerialNumber
{
    public static bool TryNormalize(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is >= '0' and <= '9')
            {
                continue;
            }

            if (character is >= 'A' and <= 'F' or >= 'a' and <= 'f')
            {
                continue;
            }

            return false;
        }

        var canonical = value.Length % 2 == 0 ? value : $"0{value}";
        var firstSignificantByte = 0;
        while (firstSignificantByte < canonical.Length - 2 &&
               canonical[firstSignificantByte] == '0' &&
               canonical[firstSignificantByte + 1] == '0')
        {
            firstSignificantByte += 2;
        }

        normalized = canonical[firstSignificantByte..].ToUpperInvariant();
        return true;
    }
}
