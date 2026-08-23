using System.Security.Cryptography;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Agent.Signing;

public sealed class SigningWorker
{
    private const int BufferSize = 81_920;
    private static readonly HashSet<string> AuthenticodeExtensions = new(StringComparer.Ordinal)
    {
        ".exe", ".dll", ".msi", ".sys", ".cat",
    };
    private readonly IAuthenticodeSigner? _authenticodeSigner;
    private readonly IPdfSigner? _pdfSigner;
    private readonly ISimplySignSessionManager _sessionManager;
    private readonly string _spoolRoot;

    public SigningWorker(
        IAuthenticodeSigner? authenticodeSigner,
        IPdfSigner? pdfSigner,
        ISimplySignSessionManager sessionManager,
        string spoolRoot)
    {
        _authenticodeSigner = authenticodeSigner;
        _pdfSigner = pdfSigner;
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        if (authenticodeSigner is null && pdfSigner is null)
        {
            throw new ArgumentException("Signing capability configuration is invalid.");
        }

        Capabilities = new[]
        {
            authenticodeSigner is null ? null : "authenticode",
            pdfSigner is null ? null : "pdf",
        }.Where(capability => capability is not null).Cast<string>().ToArray();

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
    }

    public IReadOnlyList<string> Capabilities { get; }

    public async Task<JobTerminalMessage> ExecuteAsync(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken)
    {
        await using var publication = await PreparePublicationAsync(command, progress, cancellationToken)
            .ConfigureAwait(false);
        return publication.Terminal;
    }

    public async Task<JobTerminalPublication> PreparePublicationAsync(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(progress);
        return await PrepareControlledPublicationAsync(command, progress, cancellationToken).ConfigureAwait(false);
    }

    private async Task<JobTerminalPublication> PrepareControlledPublicationAsync(
        SignJobCommand command,
        JobProgressReporter progress,
        CancellationToken cancellationToken)
    {
        try
        {
            ValidateCommandIdentity(command);
            var parameters = ParseAndMatch(command);
            var capabilityError = parameters switch
            {
                AuthenticodeParameters when _authenticodeSigner is null => "unsupported_type",
                PdfParameters when _pdfSigner is null => "unsupported_type",
                _ => null,
            };
            if (capabilityError is not null)
            {
                return new JobTerminalPublication(Failed(command, capabilityError));
            }

            await using var input = OpenAndValidateInput(command);
            var actual = await HashInputAsync(input, cancellationToken).ConfigureAwait(false);
            if (actual.Size != command.InputSize ||
                !string.Equals(actual.Sha256, command.InputSha256, StringComparison.Ordinal))
            {
                return new JobTerminalPublication(Failed(command, "input_corrupt"));
            }

            var context = new SigningContext(command.JobId, command.Extension);
            var lease = await _sessionManager
                .AcquireReadySignLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var leaseTransferred = false;
            try
            {
                try
                {
                    var terminal = await lease.RunAsync<JobTerminalMessage>(async leaseCancellation =>
                    {
                        var kind = parameters is PdfParameters ? SigningKind.Pdf : SigningKind.Authenticode;
                        var certificate = lease.CatalogSnapshot.Resolve(
                            parameters.CertificateSerialNumber,
                            kind,
                            DateTimeOffset.UtcNow);
                        await progress(10, "signing", leaseCancellation).ConfigureAwait(false);
                        SigningResult result = parameters switch
                        {
                            PdfParameters pdf => await _pdfSigner!
                                .SignAsync(context, pdf, certificate, leaseCancellation).ConfigureAwait(false),
                            AuthenticodeParameters authenticode => await _authenticodeSigner!
                                .SignAsync(context, authenticode, certificate, leaseCancellation).ConfigureAwait(false),
                            _ => throw new SigningException("invalid_parameters"),
                        };
                        if (result.Size < 0 || !IsLowerSha256(result.Sha256))
                        {
                            throw new SigningException("internal_error");
                        }

                        await progress(90, "verifying", leaseCancellation).ConfigureAwait(false);
                        return new JobCompleted(command.JobId, command.DispatchId, result.Size, result.Sha256);
                    }).ConfigureAwait(false);
                    var publication = new JobTerminalPublication(terminal, lease);
                    leaseTransferred = true;
                    return publication;
                }
                catch (SigningException error)
                {
                    if (error.Code is "token_missing" or "pkcs11_session_lost" or
                        "certificate_missing" or "private_key_missing")
                    {
                        _sessionManager.Invalidate();
                    }

                    var publication = new JobTerminalPublication(Failed(command, MapError(error.Code)), lease);
                    leaseTransferred = true;
                    return publication;
                }
            }
            finally
            {
                if (!leaseTransferred)
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ValidationException)
        {
            return new JobTerminalPublication(Failed(command, "invalid_parameters"));
        }
        catch (SigningException error)
        {
            return new JobTerminalPublication(Failed(command, MapError(error.Code)));
        }
        catch (SimplySignException error)
        {
            return new JobTerminalPublication(Failed(command, MapError(error.Code)));
        }
        catch (Exception)
        {
            return new JobTerminalPublication(Failed(command, "internal_error"));
        }
    }

    private static void ValidateCommandIdentity(SignJobCommand command)
    {
        if (command.JobId == Guid.Empty || command.DispatchId == Guid.Empty ||
            command.AttemptNumber is < 1 or > 2 || command.InputSize < 0 ||
            !IsLowerSha256(command.InputSha256))
        {
            throw new SigningException("invalid_parameters");
        }
    }

    private static SigningParameters ParseAndMatch(SignJobCommand command)
    {
        var parameters = SigningParameters.Parse(command.CanonicalParametersJson);
        var matches = parameters switch
        {
            PdfParameters => command.Extension == ".pdf",
            AuthenticodeParameters => AuthenticodeExtensions.Contains(command.Extension),
            _ => false,
        };
        if (!matches)
        {
            throw new ValidationException("invalid_parameters");
        }

        return parameters;
    }

    private FileStream OpenAndValidateInput(SignJobCommand command)
    {
        try
        {
            var directory = Path.GetFullPath(Path.Combine(_spoolRoot, command.JobId.ToString("N")));
            var rootPrefix = _spoolRoot.EndsWith(Path.DirectorySeparatorChar)
                ? _spoolRoot
                : _spoolRoot + Path.DirectorySeparatorChar;
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var inputPath = Path.GetFullPath(Path.Combine(directory, "input" + command.Extension));
            if (!directory.StartsWith(rootPrefix, comparison) ||
                !string.Equals(Path.GetDirectoryName(inputPath), directory, comparison) ||
                !Directory.Exists(directory) ||
                !File.Exists(inputPath) ||
                IsReparseOrLink(directory, directory: true) ||
                IsReparseOrLink(inputPath, directory: false))
            {
                throw new SigningException("input_corrupt");
            }

            return new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                BufferSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
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

    private static async Task<InputMetadata> HashInputAsync(FileStream input, CancellationToken cancellationToken)
    {
        var hash = await SHA256.HashDataAsync(input, cancellationToken).ConfigureAwait(false);
        return new InputMetadata(input.Length, Convert.ToHexString(hash).ToLowerInvariant());
    }

    private static JobFailed Failed(SignJobCommand command, string code) =>
        new(command.JobId, command.DispatchId, code, SafeMessage(code));

    private static string SafeMessage(string code) => code switch
    {
        "input_corrupt" => "The signing input is unavailable or changed.",
        "invalid_parameters" => "The signing parameters are invalid.",
        "unsupported_type" => "The requested signing type is not configured.",
        "token_missing" => "The signing token is unavailable.",
        "private_key_missing" => "The private key is unavailable.",
        "certificate_missing" => "The signing certificate is unavailable.",
        "certificate_catalog_unavailable" => "The certificate catalog is unavailable.",
        "certificate_not_found" => "The requested certificate was not found.",
        "certificate_serial_ambiguous" => "The certificate serial number is ambiguous.",
        "certificate_not_usable" => "The requested certificate is not usable.",
        "pkcs11_session_lost" => "The signing token session was lost.",
        "pdf_helper_missing" => "The PDF signing helper is unavailable.",
        "pdf_helper_tampered" => "The PDF signing helper failed integrity verification.",
        "pdf_invalid" => "The PDF signing result is invalid.",
        "pdf_sign_failed" => "PDF signing failed.",
        "pdf_appearance_font_missing" => "The configured PDF appearance font is unavailable.",
        "pdf_verify_failed" => "PDF signature verification failed.",
        "signtool_missing" => "The signing tool is unavailable.",
        "invalid_signable_file" => "The file cannot be Authenticode signed.",
        "already_signed" => "The file is already signed.",
        "authenticode_sign_failed" => "Authenticode signing failed.",
        "authenticode_verify_failed" => "Authenticode verification failed.",
        "simplysign_exe_missing" => "SimplySign Desktop is unavailable.",
        "simplysign_close_timeout" => "SimplySign Desktop did not close in time.",
        "simplysign_login_failed" => "SimplySign login failed.",
        _ => "The signing operation failed.",
    };

    private static string MapError(string? code) => code switch
    {
        "input_corrupt" => code,
        "invalid_parameters" => code,
        "unsupported_type" => code,
        "token_missing" => code,
        "private_key_missing" => code,
        "certificate_missing" => code,
        "certificate_catalog_unavailable" => code,
        "certificate_not_found" => code,
        "certificate_serial_ambiguous" => code,
        "certificate_not_usable" => code,
        "pkcs11_session_lost" => code,
        "pdf_helper_missing" => code,
        "pdf_helper_tampered" => code,
        "pdf_invalid" => code,
        "pdf_sign_failed" => code,
        "pdf_appearance_font_missing" => code,
        "pdf_verify_failed" => code,
        "signtool_missing" => code,
        "invalid_signable_file" => code,
        "already_signed" => code,
        "authenticode_sign_failed" => code,
        "authenticode_verify_failed" => code,
        "authenticode_signature_enumeration_failed" => "authenticode_verify_failed",
        "authenticode_signature_reader_unavailable" => "authenticode_verify_failed",
        "simplysign_exe_missing" => code,
        "simplysign_close_timeout" => code,
        "simplysign_login_failed" => code,
        _ => "internal_error",
    };

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

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

    private void DeleteControlledPart(SignJobCommand command)
    {
        try
        {
            var directory = Path.GetFullPath(Path.Combine(_spoolRoot, command.JobId.ToString("N")));
            var partPath = Path.GetFullPath(Path.Combine(
                directory,
                "result" + command.Extension.ToLowerInvariant() + ".part"));
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(Path.GetDirectoryName(partPath), directory, comparison))
            {
                throw new SigningException("internal_error");
            }

            if (File.Exists(partPath) || new FileInfo(partPath).LinkTarget is not null)
            {
                File.Delete(partPath);
            }
        }
        catch (SigningException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            throw new SigningException("internal_error");
        }
    }

    private sealed record InputMetadata(long Size, string Sha256);
}
