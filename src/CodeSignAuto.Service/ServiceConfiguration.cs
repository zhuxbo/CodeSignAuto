using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Service;

public sealed record ServiceConfiguration(
    string TokenHash,
    string SigningUserSid,
    string DataRoot,
    string SpoolRoot,
    int ListenPort,
    string OwnerMarker,
    string InstallInstanceId,
    string ExecutablePath,
    string AgentConfigurationPath,
    int RetentionHours = 24);

public sealed class ServiceConfigurationException : Exception
{
    public ServiceConfigurationException(string code)
        : base(code) => Code = code;

    public string Code { get; }
}

public interface IServiceConfigurationLoader
{
    Task<ServiceConfiguration> LoadAsync(CancellationToken cancellationToken);
}

public sealed class ServiceConfigurationLoader : IServiceConfigurationLoader
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly string _path;

    public ServiceConfigurationLoader()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CodeSignAuto",
            "service.json"))
    {
    }

    public ServiceConfigurationLoader(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<ServiceConfiguration> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
            return Deserialize(json);
        }
        catch (ServiceConfigurationException)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            throw new ServiceConfigurationException("service_configuration_missing");
        }
        catch (DirectoryNotFoundException)
        {
            throw new ServiceConfigurationException("service_configuration_missing");
        }
        catch (Exception error) when (
            error is JsonException or IOException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException)
        {
            throw new ServiceConfigurationException("service_configuration_invalid");
        }
    }

    public static ServiceConfiguration Deserialize(string json)
    {
        try
        {
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new ServiceConfigurationException("service_configuration_invalid");
            }

            return Validate(JsonSerializer.Deserialize<ServiceConfiguration>(json, SerializerOptions));
        }
        catch (ServiceConfigurationException)
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException or ArgumentException or NotSupportedException)
        {
            throw new ServiceConfigurationException("service_configuration_invalid");
        }
    }

    public static bool MatchesExpected(
        ServiceConfiguration actual,
        ServiceConfiguration expected) =>
        string.Equals(actual.TokenHash, expected.TokenHash, StringComparison.Ordinal) &&
        string.Equals(actual.SigningUserSid, expected.SigningUserSid, StringComparison.Ordinal) &&
        string.Equals(actual.DataRoot, expected.DataRoot, StringComparison.Ordinal) &&
        string.Equals(actual.SpoolRoot, expected.SpoolRoot, StringComparison.Ordinal) &&
        actual.ListenPort == expected.ListenPort &&
        actual.RetentionHours == expected.RetentionHours &&
        string.Equals(actual.OwnerMarker, expected.OwnerMarker, StringComparison.Ordinal) &&
        string.Equals(actual.InstallInstanceId, expected.InstallInstanceId, StringComparison.Ordinal) &&
        string.Equals(actual.ExecutablePath, expected.ExecutablePath, StringComparison.Ordinal) &&
        string.Equals(actual.AgentConfigurationPath, expected.AgentConfigurationPath, StringComparison.Ordinal);

    public static ServiceConfiguration Validate(ServiceConfiguration? configuration)
    {
        if (configuration is null ||
            !IsLowerSha256(configuration.TokenHash) ||
            !CanonicalWindowsSid.IsValid(configuration.SigningUserSid) ||
            !IsCanonicalAbsolutePath(configuration.DataRoot) ||
            !IsCanonicalAbsolutePath(configuration.SpoolRoot) ||
            !IsDirectChild(configuration.DataRoot, configuration.SpoolRoot, "spool") ||
            configuration.ListenPort is < 1 or > 65535 ||
            configuration.RetentionHours is < 0 or > 168 ||
            !string.Equals(configuration.OwnerMarker, "CodeSignAuto/v1", StringComparison.Ordinal) ||
            !InstallOwnershipMarker.IsInstanceId(configuration.InstallInstanceId) ||
            !IsCanonicalExecutable(configuration.ExecutablePath, "CodeSignAuto.exe") ||
            !IsCanonicalFile(configuration.AgentConfigurationPath, "agent.json") ||
            InstallControlledPath.IsSameOrDescendant(
                configuration.DataRoot,
                configuration.ExecutablePath) ||
            InstallControlledPath.IsSameOrDescendant(
                Path.GetDirectoryName(configuration.AgentConfigurationPath)!,
                configuration.ExecutablePath))
        {
            throw new ServiceConfigurationException("service_configuration_invalid");
        }

        return configuration;
    }

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalAbsolutePath(string? path)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(path) &&
                !path.Any(char.IsControl) &&
                Path.IsPathFullyQualified(path) &&
                string.Equals(Path.GetFullPath(path), path, PathComparison());
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsCanonicalExecutable(string? path, string name) =>
        IsCanonicalAbsolutePath(path) && string.Equals(Path.GetFileName(path), name, StringComparison.OrdinalIgnoreCase);

    private static bool IsCanonicalFile(string? path, string name) =>
        IsCanonicalAbsolutePath(path) && string.Equals(Path.GetFileName(path), name, StringComparison.OrdinalIgnoreCase);

    private static bool IsDirectChild(string parent, string child, string expectedName) =>
        string.Equals(Path.GetDirectoryName(child), parent, PathComparison()) &&
        string.Equals(Path.GetFileName(child), expectedName, StringComparison.OrdinalIgnoreCase);

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public static class InstallControlledPath
{
    public static bool IsSameOrDescendant(string root, string candidate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidate);
        var normalizedRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, '\\', '/');
        if (string.Equals(normalizedRoot, candidate, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return candidate.Length > normalizedRoot.Length &&
            candidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase) &&
            candidate[normalizedRoot.Length] is '\\' or '/';
    }
}

public static class InstallOwnershipMarker
{
    private const string Prefix = "CodeSignAuto/v1/";

    public static string Create(string installInstanceId)
    {
        if (!IsInstanceId(installInstanceId))
        {
            throw new ServiceConfigurationException("service_configuration_invalid");
        }

        return Prefix + installInstanceId;
    }

    public static bool IsExact(string? marker, string installInstanceId) =>
        IsInstanceId(installInstanceId) &&
        string.Equals(marker, Prefix + installInstanceId, StringComparison.Ordinal);

    public static bool IsInstanceId(string? value) =>
        value is { Length: 32 } &&
        Guid.TryParseExact(value, "N", out _) &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
