using System.Security.Cryptography;
using System.Text.Json;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Jobs;

namespace SimplySignAuto.Agent.Signing;

public interface IPdfSigner
{
    Task<SigningResult> SignAsync(
        SigningContext context,
        PdfParameters parameters,
        SigningCertificate certificate,
        CancellationToken cancellationToken);
}

public sealed class PdfSigningProfile
{
    private PdfSigningProfile(
        string? helperPath,
        string? helperSha256,
        string timestampUrl)
    {
        HelperPath = helperPath;
        HelperSha256 = helperSha256;
        TimestampUrl = timestampUrl;
    }

    internal string? HelperPath { get; }

    internal string? HelperSha256 { get; }

    internal string TimestampUrl { get; }

    public static PdfSigningProfile Create(
        string helperPath,
        string helperSha256,
        string timestampUrl)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(helperPath) ||
                !Path.IsPathFullyQualified(helperPath) ||
                helperPath.Any(char.IsControl) ||
                !string.Equals(Path.GetFileName(helperPath), "SimplySignPdfSigner.exe", StringComparison.OrdinalIgnoreCase) ||
                !IsLowerSha256(helperSha256))
            {
                throw new ArgumentException("invalid_profile");
            }

            return new PdfSigningProfile(
                Path.GetFullPath(helperPath),
                helperSha256,
                ValidateTimestampUrl(timestampUrl));
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw new ArgumentException("invalid_profile");
        }
    }

    public static PdfSigningProfile Create(string timestampUrl)
    {
        try
        {
            return new PdfSigningProfile(null, null, ValidateTimestampUrl(timestampUrl));
        }
        catch (Exception error) when (
            error is ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw new ArgumentException("invalid_profile");
        }
    }

    public override string ToString() => string.Empty;

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string ValidateTimestampUrl(string? timestampUrl)
    {
        if (string.IsNullOrWhiteSpace(timestampUrl) ||
            timestampUrl.Any(char.IsControl) ||
            !Uri.TryCreate(timestampUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsoluteUri.Length > 2048 ||
            uri.AbsoluteUri.Any(char.IsControl))
        {
            throw new ArgumentException("invalid_profile");
        }

        return uri.AbsoluteUri;
    }

}

public sealed class PdfSigner : IPdfSigner
{
    private const int BufferSize = 81_920;
    private readonly IProcessRunner _runner;
    private readonly PdfSigningProfile _profile;
    private readonly IInstalledPdfToolResolver? _resolver;
    private readonly string _spoolRoot;
    private readonly TimeSpan _processTimeout;

    public PdfSigner(
        IProcessRunner runner,
        PdfSigningProfile profile,
        string spoolRoot,
        TimeSpan processTimeout)
        : this(runner, profile, spoolRoot, processTimeout, resolver: null)
    {
    }

    public PdfSigner(
        IProcessRunner runner,
        PdfSigningProfile profile,
        string spoolRoot,
        TimeSpan processTimeout,
        IInstalledPdfToolResolver? resolver)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _resolver = resolver;
        if (_resolver is null &&
            (string.IsNullOrWhiteSpace(_profile.HelperPath) ||
             string.IsNullOrWhiteSpace(_profile.HelperSha256)))
        {
            throw new ArgumentException("invalid_profile", nameof(profile));
        }

        try
        {
            if (string.IsNullOrWhiteSpace(spoolRoot) || !Path.IsPathFullyQualified(spoolRoot))
            {
                throw new ArgumentException("invalid_spool_root");
            }

            _spoolRoot = Path.GetFullPath(spoolRoot);
            if (!Directory.Exists(_spoolRoot) || IsReparseOrLink(_spoolRoot, directory: true))
            {
                throw new ArgumentException("invalid_spool_root");
            }
        }
        catch (Exception error) when (
            error is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new ArgumentException("invalid_spool_root");
        }

        if (processTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(processTimeout));
        }

        _processTimeout = processTimeout;
    }

    public async Task<SigningResult> SignAsync(
        SigningContext context,
        PdfParameters parameters,
        SigningCertificate certificate,
        CancellationToken cancellationToken)
    {
        var paths = ValidateContext(context, parameters, certificate);
        var helper = await ResolveHelperAsync(cancellationToken).ConfigureAwait(false);
        var failureCode = "internal_error";
        var succeeded = false;
        try
        {
            DeleteControlledFile(paths.RequestPath, rejectReparse: true);
            DeleteControlledFile(paths.PartPath, rejectReparse: true);
            await using var helperLock = await OpenVerifiedHelperAsync(
                    helper.ExecutablePath,
                    helper.Sha256,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteRequestAsync(paths, parameters, certificate, cancellationToken).ConfigureAwait(false);

            ProcessResult process;
            try
            {
                process = await _runner.RunAsync(
                    helper.ExecutablePath,
                    ["sign", "--request", paths.RequestPath],
                    _processTimeout,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                throw new SigningException("internal_error");
            }

            if (process.Termination == ProcessTermination.Cancelled && cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if (process.Termination != ProcessTermination.Exited)
            {
                throw new SigningException(process.Termination switch
                {
                    ProcessTermination.LaunchFailed => "pdf_helper_missing",
                    ProcessTermination.TimedOut or ProcessTermination.IoFailed => "pdf_sign_failed",
                    _ => "internal_error",
                });
            }

            var response = ParseResponse(process);
            if (!response.Ok)
            {
                failureCode = MapFailure(response.FailureCode);
                if (!ExitMatches(process.ExitCode, response.FailureCode))
                {
                    failureCode = "internal_error";
                }

                throw new SigningException(failureCode);
            }

            if (!process.Succeeded || !File.Exists(paths.PartPath) || IsReparseOrLink(paths.PartPath, directory: false))
            {
                throw new SigningException(process.Succeeded ? "pdf_invalid" : "internal_error");
            }

            var result = await HashFileAsync(paths.PartPath, cancellationToken).ConfigureAwait(false);
            if (!DeleteControlledFileBestEffort(paths.RequestPath))
            {
                DeleteControlledFileBestEffort(paths.PartPath);
                throw new SigningException("internal_error");
            }

            succeeded = true;
            return result;
        }
        catch (OperationCanceledException)
        {
            DeleteControlledFileBestEffort(paths.PartPath);
            throw;
        }
        catch (SigningException)
        {
            DeleteControlledFileBestEffort(paths.PartPath);
            throw;
        }
        catch (Exception)
        {
            DeleteControlledFileBestEffort(paths.PartPath);
            throw new SigningException(failureCode);
        }
        finally
        {
            var requestDeleted = DeleteControlledFileBestEffort(paths.RequestPath);
            if (!requestDeleted && succeeded)
            {
                DeleteControlledFileBestEffort(paths.PartPath);
            }
        }
    }

    private ValidatedPaths ValidateContext(
        SigningContext context,
        PdfParameters parameters,
        SigningCertificate certificate)
    {
        if (context is null || parameters is null || context.JobId == Guid.Empty || context.Extension != ".pdf" ||
            certificate is null ||
            parameters.CertificateSerialNumber != certificate.SerialNumber ||
            parameters.DigestAlgorithm != "sha256" ||
            !certificate.SupportsPdf)
        {
            throw new SigningException("invalid_parameters");
        }

        try
        {
            var directory = Path.GetFullPath(Path.Combine(_spoolRoot, context.JobId.ToString("N")));
            var rootPrefix = _spoolRoot.EndsWith(Path.DirectorySeparatorChar)
                ? _spoolRoot
                : _spoolRoot + Path.DirectorySeparatorChar;
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!directory.StartsWith(rootPrefix, comparison) || !Directory.Exists(directory) ||
                IsReparseOrLink(directory, directory: true))
            {
                throw new SigningException("input_corrupt");
            }

            var input = Path.Combine(directory, "input.pdf");
            var part = Path.Combine(directory, "result.part.pdf");
            var request = Path.Combine(directory, "pdf-request.json");
            if (!File.Exists(input) || IsReparseOrLink(input, directory: false))
            {
                throw new SigningException("input_corrupt");
            }

            return new ValidatedPaths(input, part, request);
        }
        catch (SigningException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new SigningException("input_corrupt");
        }
    }

    private async Task<InstalledPdfTool> ResolveHelperAsync(CancellationToken cancellationToken)
    {
        if (_resolver is null)
        {
            return new InstalledPdfTool(_profile.HelperPath!, _profile.HelperSha256!);
        }

        var resolution = await _resolver.ResolveAsync(cancellationToken).ConfigureAwait(false);
        if (resolution.Status != InstalledPdfToolStatus.Ready ||
            resolution.Tool is null ||
            string.IsNullOrWhiteSpace(resolution.Tool.ExecutablePath) ||
            !Path.IsPathFullyQualified(resolution.Tool.ExecutablePath) ||
            !IsLowerSha256(resolution.Tool.Sha256))
        {
            throw new SigningException(resolution.FailureCode is
                "pdf_support_not_installed" or "pdf_helper_tampered"
                    ? resolution.FailureCode
                    : "pdf_helper_tampered");
        }

        return resolution.Tool;
    }

    private async Task<FileStream> OpenVerifiedHelperAsync(
        string helperPath,
        string helperSha256,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(helperPath))
        {
            throw new SigningException("pdf_helper_missing");
        }

        try
        {
            if (IsReparseOrLink(helperPath, directory: false))
            {
                throw new SigningException("pdf_helper_tampered");
            }

            var stream = new FileStream(
                helperPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var actual = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(
                    Convert.ToHexString(actual).ToLowerInvariant(),
                    helperSha256,
                    StringComparison.Ordinal))
            {
                await stream.DisposeAsync().ConfigureAwait(false);
                throw new SigningException("pdf_helper_tampered");
            }

            return stream;
        }
        catch (SigningException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            throw new SigningException("pdf_helper_missing");
        }
        catch (Exception)
        {
            throw new SigningException("pdf_helper_tampered");
        }
    }

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private async Task WriteRequestAsync(
        ValidatedPaths paths,
        PdfParameters parameters,
        SigningCertificate certificate,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            paths.RequestPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            BufferSize,
            FileOptions.Asynchronous);
        await using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        writer.WriteString("modulePath", certificate.ModulePath);
        writer.WriteNumber("slotId", certificate.SlotId);
        writer.WriteString("tokenSerial", certificate.TokenSerial);
        writer.WriteString("certificateIdHex", certificate.CertificateIdHex);
        writer.WriteString("privateKeyIdHex", certificate.PrivateKeyIdHex);
        writer.WriteString("inputPath", paths.InputPath);
        writer.WriteString("outputPath", paths.PartPath);
        writer.WriteNumber("page", parameters.Page);
        writer.WriteStartArray("box");
        writer.WriteNumberValue(parameters.Box.Left);
        writer.WriteNumberValue(parameters.Box.Bottom);
        writer.WriteNumberValue(parameters.Box.Right);
        writer.WriteNumberValue(parameters.Box.Top);
        writer.WriteEndArray();
        writer.WriteString("fieldName", parameters.FieldName);
        if (parameters.Reason is not null)
        {
            writer.WriteString("reason", parameters.Reason);
        }

        if (parameters.Location is not null)
        {
            writer.WriteString("location", parameters.Location);
        }

        writer.WriteString("tsaUrl", _profile.TimestampUrl);
        writer.WriteEndObject();
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }

    private static HelperResponse ParseResponse(ProcessResult process)
    {
        if (process.Termination != ProcessTermination.Exited ||
            process.StandardOutputTruncated ||
            process.StandardErrorTruncated ||
            !string.IsNullOrEmpty(process.StandardError) ||
            !process.StandardOutput.EndsWith('\n'))
        {
            throw new SigningException("internal_error");
        }

        var responseJson = process.StandardOutput.EndsWith("\r\n", StringComparison.Ordinal)
            ? process.StandardOutput[..^2]
            : process.StandardOutput[..^1];
        if (responseJson.Contains('\r') || responseJson.Contains('\n'))
        {
            throw new SigningException("internal_error");
        }

        try
        {
            using var document = JsonDocument.Parse(responseJson);
            var root = document.RootElement;
            var names = root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
            if (root.ValueKind != JsonValueKind.Object ||
                !names.SequenceEqual(["failureCode", "ok"], StringComparer.Ordinal) ||
                root.GetProperty("ok").ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw new JsonException();
            }

            var ok = root.GetProperty("ok").GetBoolean();
            var failure = root.GetProperty("failureCode");
            if (ok && failure.ValueKind == JsonValueKind.Null)
            {
                return new HelperResponse(true, null);
            }

            if (!ok && failure.ValueKind == JsonValueKind.String && failure.GetString() is { Length: > 0 and <= 64 } code)
            {
                return new HelperResponse(false, code);
            }

            throw new JsonException();
        }
        catch (JsonException)
        {
            throw new SigningException("internal_error");
        }
    }

    private static bool ExitMatches(int? exitCode, string? failureCode) => failureCode switch
    {
        "token_missing" or "token_identifier_mismatch" or "certificate_missing" or
            "private_key_missing" or "certificate_invalid" or "pkcs11_unavailable" or
            "pkcs11_session_lost" => exitCode == 10,
        "pdf_validation_failed" => exitCode == 30,
        "input_modified" or "pdf_sign_failed" => exitCode == 20,
        _ => exitCode is not null and not 0,
    };

    private static string MapFailure(string? failureCode) => failureCode switch
    {
        "token_missing" or "token_identifier_mismatch" => "token_missing",
        "private_key_missing" => "private_key_missing",
        "pkcs11_session_lost" => "pkcs11_session_lost",
        "certificate_missing" or "certificate_invalid" => "certificate_missing",
        "input_modified" => "input_corrupt",
        "pdf_validation_failed" => "pdf_verify_failed",
        "pdf_sign_failed" => "pdf_sign_failed",
        _ => "internal_error",
    };

    private static async Task<SigningResult> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return new SigningResult(stream.Length, Convert.ToHexString(hash).ToLowerInvariant());
    }

    private static void DeleteControlledFile(string path, bool rejectReparse)
    {
        if (!File.Exists(path) && new FileInfo(path).LinkTarget is null)
        {
            return;
        }

        if (rejectReparse && IsReparseOrLink(path, directory: false))
        {
            File.Delete(path);
            throw new SigningException("internal_error");
        }

        File.Delete(path);
    }

    private static bool DeleteControlledFileBestEffort(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                return false;
            }

            if (File.Exists(path) || new FileInfo(path).LinkTarget is not null)
            {
                File.Delete(path);
            }

            return !File.Exists(path) && new FileInfo(path).LinkTarget is null;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsReparseOrLink(string path, bool directory)
    {
        FileSystemInfo info = directory ? new DirectoryInfo(path) : new FileInfo(path);
        try
        {
            info.Refresh();
            return info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private sealed record ValidatedPaths(string InputPath, string PartPath, string RequestPath);

    private sealed record HelperResponse(bool Ok, string? FailureCode);
}
