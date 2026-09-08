namespace CodeSignAuto.Core.Versioning;

public sealed class ProductVersion : IComparable<ProductVersion>
{
    private readonly string[] _coreIdentifiers;
    private readonly string[]? _prereleaseIdentifiers;

    private ProductVersion(
        string identity,
        string display,
        string[] coreIdentifiers,
        string[]? prereleaseIdentifiers)
    {
        Identity = identity;
        Display = display;
        _coreIdentifiers = coreIdentifiers;
        _prereleaseIdentifiers = prereleaseIdentifiers;
    }

    public string Identity { get; }

    public string Display { get; }

    public static ProductVersion Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return TryParse(value, out var version)
            ? version!
            : throw new FormatException("Invalid semantic version.");
    }

    public static bool TryParse(string? value, out ProductVersion? version)
    {
        version = null;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var buildSeparator = value.IndexOf('+');
        var display = buildSeparator >= 0 ? value[..buildSeparator] : value;
        if (buildSeparator >= 0 && !TryParseIdentifiers(value[(buildSeparator + 1)..], false, out _))
        {
            return false;
        }

        var prereleaseSeparator = display.IndexOf('-');
        var core = prereleaseSeparator >= 0 ? display[..prereleaseSeparator] : display;
        var coreIdentifiers = core.Split('.');
        if (coreIdentifiers.Length != 3 || coreIdentifiers.Any(identifier => !IsCanonicalNumeric(identifier)))
        {
            return false;
        }

        string[]? prereleaseIdentifiers = null;
        if (prereleaseSeparator >= 0 &&
            !TryParseIdentifiers(display[(prereleaseSeparator + 1)..], true, out prereleaseIdentifiers))
        {
            return false;
        }

        version = new ProductVersion(value, display, coreIdentifiers, prereleaseIdentifiers);
        return true;
    }

    public int ComparePrecedenceTo(ProductVersion other)
    {
        ArgumentNullException.ThrowIfNull(other);

        for (var index = 0; index < _coreIdentifiers.Length; index++)
        {
            var comparison = CompareNumericIdentifiers(
                _coreIdentifiers[index],
                other._coreIdentifiers[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }

        if (_prereleaseIdentifiers is null)
        {
            return other._prereleaseIdentifiers is null ? 0 : 1;
        }

        if (other._prereleaseIdentifiers is null)
        {
            return -1;
        }

        var commonLength = Math.Min(_prereleaseIdentifiers.Length, other._prereleaseIdentifiers.Length);
        for (var index = 0; index < commonLength; index++)
        {
            var left = _prereleaseIdentifiers[index];
            var right = other._prereleaseIdentifiers[index];
            var leftNumeric = IsAsciiDigits(left);
            var rightNumeric = IsAsciiDigits(right);
            int comparison;
            if (leftNumeric && rightNumeric)
            {
                comparison = CompareNumericIdentifiers(left, right);
            }
            else if (leftNumeric)
            {
                comparison = -1;
            }
            else if (rightNumeric)
            {
                comparison = 1;
            }
            else
            {
                comparison = string.CompareOrdinal(left, right);
            }

            if (comparison != 0)
            {
                return comparison;
            }
        }

        return _prereleaseIdentifiers.Length.CompareTo(other._prereleaseIdentifiers.Length);
    }

    public int CompareTo(ProductVersion? other) =>
        other is null ? 1 : ComparePrecedenceTo(other);

    public override string ToString() => Identity;

    private static bool TryParseIdentifiers(
        string value,
        bool rejectNumericLeadingZero,
        out string[]? identifiers)
    {
        identifiers = value.Split('.');
        foreach (var identifier in identifiers)
        {
            if (identifier.Length == 0 || !identifier.All(IsIdentifierCharacter))
            {
                identifiers = null;
                return false;
            }

            if (rejectNumericLeadingZero &&
                identifier.Length > 1 &&
                identifier[0] == '0' &&
                IsAsciiDigits(identifier))
            {
                identifiers = null;
                return false;
            }
        }

        return true;
    }

    private static bool IsCanonicalNumeric(string value) =>
        IsAsciiDigits(value) && (value.Length == 1 || value[0] != '0');

    private static bool IsAsciiDigits(string value) =>
        value.Length > 0 && value.All(character => character is >= '0' and <= '9');

    private static bool IsIdentifierCharacter(char value) =>
        value is >= '0' and <= '9' or
            >= 'A' and <= 'Z' or
            >= 'a' and <= 'z' or
            '-';

    private static int CompareNumericIdentifiers(string left, string right)
    {
        var lengthComparison = left.Length.CompareTo(right.Length);
        return lengthComparison != 0 ? lengthComparison : string.CompareOrdinal(left, right);
    }
}
