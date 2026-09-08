using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

public enum InstallationMode
{
    Manual,
    Service,
}

public sealed record InstallationReceipt(
    int SchemaVersion,
    InstallationMode Mode,
    string InstallInstanceId,
    string SigningUserSid,
    string ExecutablePath,
    string? UserDataRoot)
{
    public const int CurrentSchemaVersion = 1;

    public static InstallationReceipt ForService(ServiceConfiguration configuration)
    {
        configuration = ServiceConfigurationLoader.Validate(configuration);
        return new InstallationReceipt(
            CurrentSchemaVersion,
            InstallationMode.Service,
            configuration.InstallInstanceId,
            configuration.SigningUserSid,
            configuration.ExecutablePath,
            UserDataRoot: null);
    }

    public static InstallationReceipt ForManual(
        string installInstanceId,
        string signingUserSid,
        string executablePath,
        string userDataRoot) => InstallationReceiptValidator.Validate(new InstallationReceipt(
            CurrentSchemaVersion,
            InstallationMode.Manual,
            installInstanceId,
            signingUserSid,
            Path.GetFullPath(executablePath),
            Path.GetFullPath(userDataRoot)));
}

public static class InstallationReceiptValidator
{
    public static InstallationReceipt Validate(InstallationReceipt? receipt)
    {
        if (receipt is null ||
            receipt.SchemaVersion != InstallationReceipt.CurrentSchemaVersion ||
            !Enum.IsDefined(receipt.Mode) ||
            !InstallOwnershipMarker.IsInstanceId(receipt.InstallInstanceId) ||
            !CanonicalWindowsSid.IsValid(receipt.SigningUserSid) ||
            !IsCanonicalExecutable(receipt.ExecutablePath) ||
            receipt.Mode switch
            {
                InstallationMode.Service => receipt.UserDataRoot is not null,
                InstallationMode.Manual => !IsCanonicalDirectory(receipt.UserDataRoot) ||
                    InstallControlledPath.IsSameOrDescendant(
                        receipt.UserDataRoot!,
                        receipt.ExecutablePath),
                _ => true,
            })
        {
            throw new InstallException("installation_receipt_invalid");
        }

        return receipt;
    }

    public static void RequireServiceMatch(
        InstallationReceipt receipt,
        ServiceConfiguration configuration)
    {
        receipt = Validate(receipt);
        configuration = ServiceConfigurationLoader.Validate(configuration);
        if (receipt.Mode != InstallationMode.Service ||
            !string.Equals(
                receipt.InstallInstanceId,
                configuration.InstallInstanceId,
                StringComparison.Ordinal) ||
            !string.Equals(
                receipt.SigningUserSid,
                configuration.SigningUserSid,
                StringComparison.Ordinal) ||
            !string.Equals(
                receipt.ExecutablePath,
                configuration.ExecutablePath,
                PathComparison()))
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private static bool IsCanonicalExecutable(string? path) =>
        IsCanonicalAbsolutePath(path) &&
        string.Equals(
            Path.GetFileName(path),
            "CodeSignAuto.exe",
            StringComparison.OrdinalIgnoreCase);

    private static bool IsCanonicalDirectory(string? path) =>
        IsCanonicalAbsolutePath(path) && Path.GetPathRoot(path) != path;

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

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public static class InstallationReceiptCodec
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    public static byte[] Serialize(InstallationReceipt receipt)
    {
        receipt = InstallationReceiptValidator.Validate(receipt);
        return JsonSerializer.SerializeToUtf8Bytes(
            new InstallationReceiptDocument(
                receipt.SchemaVersion,
                receipt.Mode == InstallationMode.Manual ? "manual" : "service",
                receipt.InstallInstanceId,
                receipt.SigningUserSid,
                receipt.ExecutablePath,
                receipt.UserDataRoot),
            SerializerOptions);
    }

    public static InstallationReceipt Deserialize(string json)
    {
        try
        {
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            var document = JsonSerializer.Deserialize<InstallationReceiptDocument>(
                json,
                SerializerOptions) ?? throw Invalid();
            var mode = document.Mode switch
            {
                "manual" => InstallationMode.Manual,
                "service" => InstallationMode.Service,
                _ => throw Invalid(),
            };
            return InstallationReceiptValidator.Validate(new InstallationReceipt(
                document.SchemaVersion,
                mode,
                document.InstallInstanceId,
                document.SigningUserSid,
                document.ExecutablePath,
                document.UserDataRoot));
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException or ArgumentException or NotSupportedException)
        {
            throw Invalid(error);
        }
    }

    private static InstallException Invalid(Exception? inner = null) =>
        new("installation_receipt_invalid");

    private sealed record InstallationReceiptDocument(
        [property: JsonRequired] int SchemaVersion,
        [property: JsonRequired] string Mode,
        [property: JsonRequired] string InstallInstanceId,
        [property: JsonRequired] string SigningUserSid,
        [property: JsonRequired] string ExecutablePath,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? UserDataRoot);

}

internal interface IInstallationReceiptStore
{
    Task<InstallationReceipt?> LoadOptionalAsync(CancellationToken cancellationToken);

    Task CreateAsync(
        InstallationReceipt receipt,
        CancellationToken cancellationToken);

    Task DeleteExactAsync(
        InstallationReceipt receipt,
        CancellationToken cancellationToken);
}

internal sealed class WindowsInstallationReceiptStore : IInstallationReceiptStore
{
    private const int MaximumReceiptBytes = 32 * 1024;
    private readonly string _path;

    public WindowsInstallationReceiptStore()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CodeSignAuto",
            "install.json"))
    {
    }

    internal WindowsInstallationReceiptStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    internal static string ReceiptPath => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CodeSignAuto",
        "install.json"));

    public async Task<InstallationReceipt?> LoadOptionalAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var kind = NoFollowFile.InspectPathEntry(_path);
            if (kind == NoFollowPathEntryKind.Missing)
            {
                return null;
            }

            if (kind != NoFollowPathEntryKind.RegularFile)
            {
                throw new InstallException("installation_receipt_invalid");
            }

            await using var stream = NoFollowFile.OpenRead(_path, FileShare.Read, 4096);
            if (stream.Length is <= 0 or > MaximumReceiptBytes)
            {
                throw new InstallException("installation_receipt_invalid");
            }

            using var reader = new StreamReader(
                stream,
                new UTF8Encoding(false, true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 4096,
                leaveOpen: false);
            var receipt = InstallationReceiptCodec.Deserialize(
                await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false));
            if (OperatingSystem.IsWindows())
            {
                WindowsInstallAcl.VerifyFile(
                    _path,
                    InstallAclProfile.AdministratorsOnly,
                    new SecurityIdentifier(receipt.SigningUserSid));
            }

            return receipt;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or
                NotSupportedException or DecoderFallbackException)
        {
            throw new InstallException("installation_receipt_invalid");
        }
    }

    public async Task CreateAsync(
        InstallationReceipt receipt,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        var content = InstallationReceiptCodec.Serialize(receipt);
        var parent = Path.GetDirectoryName(_path)
            ?? throw new InstallException("installation_receipt_write_failed");
        var signingUser = new SecurityIdentifier(receipt.SigningUserSid);
        if (NoFollowFile.InspectPathEntry(parent) != NoFollowPathEntryKind.Directory ||
            NoFollowFile.InspectPathEntry(_path) != NoFollowPathEntryKind.Missing)
        {
            throw new InstallException("installation_receipt_write_failed");
        }

        WindowsInstallAcl.VerifyDirectory(
            parent,
            InstallAclProfile.AdministratorsOnly,
            signingUser);
        var temporary = Path.Combine(
            parent,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        var published = false;
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            WindowsInstallAcl.ApplyFile(
                temporary,
                InstallAclProfile.AdministratorsOnly,
                signingUser);
            File.Move(temporary, _path, overwrite: false);
            published = true;
            WindowsInstallAcl.VerifyFile(
                _path,
                InstallAclProfile.AdministratorsOnly,
                signingUser);
        }
        catch (Exception original)
        {
            if (published)
            {
                try
                {
                    if (NoFollowFile.InspectPathEntry(_path) == NoFollowPathEntryKind.RegularFile)
                    {
                        File.Delete(_path);
                    }

                    if (NoFollowFile.InspectPathEntry(_path) != NoFollowPathEntryKind.Missing)
                    {
                        throw new InstallException("installation_receipt_state_uncertain");
                    }
                }
                catch
                {
                    throw new InstallException("installation_receipt_state_uncertain");
                }
            }

            if (original is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            }

            if (original is InstallException)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            }

            throw new InstallException("installation_receipt_write_failed");
        }
        finally
        {
            if (!published && NoFollowFile.InspectPathEntry(temporary) == NoFollowPathEntryKind.RegularFile)
            {
                File.Delete(temporary);
            }
        }
    }

    public async Task DeleteExactAsync(
        InstallationReceipt receipt,
        CancellationToken cancellationToken)
    {
        var current = await LoadOptionalAsync(cancellationToken).ConfigureAwait(false);
        if (current != receipt)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        try
        {
            File.Delete(_path);
            if (NoFollowFile.InspectPathEntry(_path) != NoFollowPathEntryKind.Missing)
            {
                throw new InstallException("installation_receipt_state_uncertain");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or
                NotSupportedException)
        {
            throw new InstallException("installation_receipt_state_uncertain");
        }
    }
}
