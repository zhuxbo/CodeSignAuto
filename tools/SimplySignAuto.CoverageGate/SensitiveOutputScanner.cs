using System.Text.RegularExpressions;

namespace SimplySignAuto.Coverage;

public static partial class SensitiveOutputScanner
{
    public static IReadOnlyList<string> Find(string text, params string[] exactSecrets) =>
        FindCore(text, [], exactSecrets);

    internal static IReadOnlyList<string> FindArtifact(
        string text,
        IReadOnlyList<string> allowedAbsoluteRoots,
        params string[] exactSecrets) =>
        FindCore(text, allowedAbsoluteRoots, exactSecrets);

    private static IReadOnlyList<string> FindCore(
        string text,
        IReadOnlyList<string> allowedAbsoluteRoots,
        IReadOnlyList<string> exactSecrets)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(allowedAbsoluteRoots);
        ArgumentNullException.ThrowIfNull(exactSecrets);
        var scanned = text;
        foreach (var allowed in allowedAbsoluteRoots)
        {
            if (string.IsNullOrWhiteSpace(allowed))
            {
                continue;
            }

            var canonical = Path.GetFullPath(allowed);
            scanned = scanned.Replace(canonical, "[allowed-root]", StringComparison.Ordinal);
            scanned = scanned.Replace(canonical.Replace('\\', '/'), "[allowed-root]", StringComparison.Ordinal);
        }

        var findings = new List<string>();
        AddIfMatch(findings, "authorization", AuthorizationPattern(), scanned);
        AddIfMatch(findings, "otpauth", OtpauthPattern(), scanned);
        AddIfMatch(findings, "otp", OtpPattern(), scanned);
        AddIfMatch(findings, "sid", SidPattern(), scanned);
        AddIfMatch(findings, "absolute_path", AbsolutePathPattern(), scanned);
        AddIfMatch(findings, "private_key", PrivateKeyPattern(), scanned);
        AddIfMatch(findings, "synthetic_marker", SyntheticMarkerPattern(), scanned);
        AddIfMatch(findings, "native_exception", NativeExceptionPattern(), scanned);
        if (exactSecrets.Any(secret => !string.IsNullOrEmpty(secret) && scanned.Contains(secret, StringComparison.Ordinal)))
        {
            findings.Add("exact_secret");
        }

        return findings;
    }

    private static void AddIfMatch(List<string> findings, string label, Regex pattern, string text)
    {
        if (pattern.IsMatch(text))
        {
            findings.Add(label);
        }
    }

    [GeneratedRegex("(?i)authorization\\s*:\\s*bearer\\s+[^\\s]+|\\bbearer\\s+[A-Za-z0-9._~-]{12,}", RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationPattern();

    [GeneratedRegex("(?i)otpauth://|(?:^|[?&])secret=", RegexOptions.CultureInvariant)]
    private static partial Regex OtpauthPattern();

    [GeneratedRegex("(?<![A-Za-z0-9])\\d{6}(?![A-Za-z0-9])", RegexOptions.CultureInvariant)]
    private static partial Regex OtpPattern();

    [GeneratedRegex("(?<![A-Za-z0-9])S-1-(?:\\d+-){1,15}\\d+(?![A-Za-z0-9])", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();

    [GeneratedRegex("(?:[A-Za-z]:\\\\|/(?:Users|private|tmp|var)/)[^\\r\\n ]+", RegexOptions.CultureInvariant)]
    private static partial Regex AbsolutePathPattern();

    [GeneratedRegex("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", RegexOptions.CultureInvariant)]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex("SSA_SYNTHETIC_(?:TOKEN|FIXTURE|SECRET)_MARKER", RegexOptions.CultureInvariant)]
    private static partial Regex SyntheticMarkerPattern();

    [GeneratedRegex("(?:^|\\s)(?:System\\.)?[A-Za-z0-9_.]+Exception(?:\\s*\\([^)]*\\))?\\s*:", RegexOptions.CultureInvariant)]
    private static partial Regex NativeExceptionPattern();
}
