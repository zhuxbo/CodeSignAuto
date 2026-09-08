using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Agent.Signing;

public sealed class SigningContext
{
    public SigningContext(Guid jobId, string extension)
    {
        JobId = jobId;
        Extension = extension;
    }

    public Guid JobId { get; }

    public string Extension { get; }

    public override string ToString() => string.Empty;
}

public sealed class SigningResult
{
    public SigningResult(long size, string sha256)
    {
        Size = size;
        Sha256 = sha256;
    }

    public long Size { get; }

    public string Sha256 { get; }

    public override string ToString() => string.Empty;
}

public sealed class SigningException : Exception
{
    public SigningException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }

    public override string ToString() => string.Empty;
}

public sealed class AuthenticodeSigningProfile
{
    private AuthenticodeSigningProfile(
        string signToolPath,
        string timestampUrl)
    {
        SignToolPath = signToolPath;
        TimestampUrl = timestampUrl;
    }

    internal string SignToolPath { get; }

    internal string TimestampUrl { get; }

    public static AuthenticodeSigningProfile Create(
        string signToolPath,
        string timestampUrl)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(signToolPath) ||
                string.IsNullOrWhiteSpace(timestampUrl) ||
                signToolPath.Any(char.IsControl) ||
                timestampUrl.Length > 2048 ||
                timestampUrl.Any(char.IsControl) ||
                !Path.IsPathFullyQualified(signToolPath))
            {
                throw InvalidProfile();
            }

            var fullSignToolPath = Path.GetFullPath(signToolPath);
            if (!string.Equals(Path.GetFileName(fullSignToolPath), "signtool.exe", StringComparison.OrdinalIgnoreCase))
            {
                throw InvalidProfile();
            }

            if (!Uri.TryCreate(timestampUrl, UriKind.Absolute, out var timestampUri) ||
                (timestampUri.Scheme != Uri.UriSchemeHttp && timestampUri.Scheme != Uri.UriSchemeHttps) ||
                string.IsNullOrWhiteSpace(timestampUri.Host) ||
                !string.IsNullOrEmpty(timestampUri.UserInfo) ||
                !string.IsNullOrEmpty(timestampUri.Fragment) ||
                timestampUri.AbsoluteUri.Length > 2048 ||
                timestampUri.AbsoluteUri.Any(char.IsControl))
            {
                throw InvalidProfile();
            }

            return new AuthenticodeSigningProfile(
                fullSignToolPath,
                timestampUri.AbsoluteUri);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or SecurityException)
        {
            throw InvalidProfile();
        }
    }

    public override string ToString() => string.Empty;

    internal static string NormalizeThumbprint(string value) =>
        value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

    private static ArgumentException InvalidProfile() => new("invalid_profile");

}

public interface IAuthenticodeSigner
{
    Task<SigningResult> SignAsync(
        SigningContext context,
        AuthenticodeParameters parameters,
        SigningCertificate certificate,
        CancellationToken cancellationToken);
}

public interface IControlledFileCopier
{
    Task CopyAsync(string inputPath, string resultPartPath, CancellationToken cancellationToken);
}

public sealed class ControlledFileCopier : IControlledFileCopier
{
    private const int BufferSize = 81_920;

    public async Task CopyAsync(
        string inputPath,
        string resultPartPath,
        CancellationToken cancellationToken)
    {
        await using var input = new FileStream(
            inputPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = new FileStream(
            resultPartPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await input.CopyToAsync(output, BufferSize, cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        output.Flush(flushToDisk: true);
    }
}

public interface IAuthenticodeSignatureReader
{
    IReadOnlyList<string> ReadSignerThumbprints(string signedFilePath);
}

internal readonly record struct WinTrustSignatureRequest(
    string SignedFilePath,
    uint SignatureIndex,
    uint SignatureFlags);

internal readonly record struct WinTrustSignatureProbe(
    int Status,
    uint SecondarySignatureCount,
    string? Thumbprint);

internal interface IWinTrustSignatureApi
{
    WinTrustSignatureProbe Probe(WinTrustSignatureRequest request);
}

public sealed partial class WindowsAuthenticodeSignatureReader : IAuthenticodeSignatureReader
{
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const uint GetSecondarySignatureCount = 0x00000002;
    private const uint VerifySpecificSignature = 0x00000001;
    private const uint MaximumSecondarySignatures = 63;
    private readonly IWinTrustSignatureApi _signatureApi;
    private readonly bool _enforceWindowsPlatform;

    public WindowsAuthenticodeSignatureReader()
        : this(new NativeWinTrustSignatureApi(), enforceWindowsPlatform: true)
    {
    }

    internal WindowsAuthenticodeSignatureReader(IWinTrustSignatureApi signatureApi)
        : this(signatureApi, enforceWindowsPlatform: false)
    {
    }

    private WindowsAuthenticodeSignatureReader(
        IWinTrustSignatureApi signatureApi,
        bool enforceWindowsPlatform)
    {
        _signatureApi = signatureApi ?? throw new ArgumentNullException(nameof(signatureApi));
        _enforceWindowsPlatform = enforceWindowsPlatform;
    }

    public IReadOnlyList<string> ReadSignerThumbprints(string signedFilePath)
    {
        if (_enforceWindowsPlatform && !OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("authenticode_signature_reader_unavailable");
        }

        var primary = _signatureApi.Probe(new WinTrustSignatureRequest(
            signedFilePath,
            SignatureIndex: 0,
            GetSecondarySignatureCount));
        if (primary.Status == TrustENoSignature)
        {
            return [];
        }

        EnsureSuccessfulProbe(primary);
        var signers = new List<string>();
        signers.Add(primary.Thumbprint!);
        if (primary.SecondarySignatureCount > MaximumSecondarySignatures)
        {
            throw new CryptographicException("authenticode_signature_enumeration_failed");
        }

        for (uint index = 1; index <= primary.SecondarySignatureCount; index++)
        {
            var secondary = _signatureApi.Probe(new WinTrustSignatureRequest(
                signedFilePath,
                index,
                VerifySpecificSignature));
            EnsureSuccessfulProbe(secondary);
            signers.Add(secondary.Thumbprint!);
        }

        return signers;
    }

    private static void EnsureSuccessfulProbe(WinTrustSignatureProbe probe)
    {
        if (probe.Status != 0 || string.IsNullOrWhiteSpace(probe.Thumbprint))
        {
            throw new CryptographicException("authenticode_signature_enumeration_failed");
        }
    }

    private sealed class NativeWinTrustSignatureApi : IWinTrustSignatureApi
    {
        public WinTrustSignatureProbe Probe(WinTrustSignatureRequest request)
        {
            var fileInfo = new WinTrustFileInfo(request.SignedFilePath);
            var signatureSettings = new WinTrustSignatureSettings(request.SignatureIndex, request.SignatureFlags);
            var fileInfoPointer = IntPtr.Zero;
            var signatureSettingsPointer = IntPtr.Zero;
            var fileInfoMarshaled = false;
            var signatureSettingsMarshaled = false;
            var trustData = new WinTrustData();
            var action = NativeMethods.GenericVerifyV2;
            try
            {
                fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
                fileInfoMarshaled = true;
                signatureSettingsPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustSignatureSettings>());
                Marshal.StructureToPtr(signatureSettings, signatureSettingsPointer, fDeleteOld: false);
                signatureSettingsMarshaled = true;
                trustData = new WinTrustData(fileInfoPointer, signatureSettingsPointer);

                var status = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
                if (status != 0)
                {
                    return new WinTrustSignatureProbe(status, 0, null);
                }

                if (trustData.StateData == IntPtr.Zero)
                {
                    throw new CryptographicException("authenticode_signature_enumeration_failed");
                }

                var updatedSettings = Marshal.PtrToStructure<WinTrustSignatureSettings>(signatureSettingsPointer);
                var providerData = NativeMethods.WTHelperProvDataFromStateData(trustData.StateData);
                if (providerData == IntPtr.Zero)
                {
                    throw new CryptographicException("authenticode_signature_enumeration_failed");
                }

                var providerSigner = NativeMethods.WTHelperGetProvSignerFromChain(
                    providerData,
                    signerIndex: 0,
                    counterSigner: false,
                    counterSignerIndex: 0);
                if (providerSigner == IntPtr.Zero)
                {
                    throw new CryptographicException("authenticode_signature_enumeration_failed");
                }

                var providerCertificatePointer = NativeMethods.WTHelperGetProvCertFromChain(providerSigner, certificateIndex: 0);
                if (providerCertificatePointer == IntPtr.Zero)
                {
                    throw new CryptographicException("authenticode_signature_enumeration_failed");
                }

                var providerCertificate = Marshal.PtrToStructure<CryptProviderCertificate>(providerCertificatePointer);
                if (providerCertificate.CertificateContext == IntPtr.Zero)
                {
                    throw new CryptographicException("authenticode_signature_enumeration_failed");
                }

#pragma warning disable SYSLIB0057
                using var certificate = new X509Certificate2(providerCertificate.CertificateContext);
#pragma warning restore SYSLIB0057
                var thumbprint = certificate.Thumbprint ?? throw new CryptographicException("authenticode_certificate_missing");
                return new WinTrustSignatureProbe(status, updatedSettings.SecondarySignatureCount, thumbprint);
            }
            finally
            {
                if (trustData.StateData != IntPtr.Zero)
                {
                    TryCloseState(ref action, ref trustData);
                }

                if (signatureSettingsPointer != IntPtr.Zero)
                {
                    FreeMarshaled<WinTrustSignatureSettings>(signatureSettingsPointer, signatureSettingsMarshaled);
                }

                if (fileInfoPointer != IntPtr.Zero)
                {
                    FreeMarshaled<WinTrustFileInfo>(fileInfoPointer, fileInfoMarshaled);
                }
            }
        }
    }

    private static void TryCloseState(ref Guid action, ref WinTrustData trustData)
    {
        try
        {
            trustData.StateAction = WinTrustData.StateActionClose;
            _ = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
        }
        catch (Exception error) when (
            error is DllNotFoundException
                or EntryPointNotFoundException
                or MarshalDirectiveException)
        {
        }
    }

    private static void FreeMarshaled<T>(IntPtr pointer, bool initialized)
    {
        if (initialized)
        {
            try
            {
                Marshal.DestroyStructure<T>(pointer);
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException)
            {
            }
        }

        Marshal.FreeHGlobal(pointer);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public WinTrustFileInfo(string path)
        {
            Size = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = path;
            FileHandle = IntPtr.Zero;
            KnownSubject = IntPtr.Zero;
        }

        public uint Size;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string FilePath;

        public IntPtr FileHandle;

        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustSignatureSettings
    {
        public WinTrustSignatureSettings(uint signatureIndex, uint flags)
        {
            Size = (uint)Marshal.SizeOf<WinTrustSignatureSettings>();
            SignatureIndex = signatureIndex;
            Flags = flags;
            SecondarySignatureCount = 0;
            VerifiedSignatureIndex = 0;
            CryptoPolicy = IntPtr.Zero;
        }

        public uint Size;
        public uint SignatureIndex;
        public uint Flags;
        public uint SecondarySignatureCount;
        public uint VerifiedSignatureIndex;
        public IntPtr CryptoPolicy;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public const uint StateActionVerify = 0x00000001;
        public const uint StateActionClose = 0x00000002;
        private const uint ProviderFlagRevocationCheckNone = 0x00000010;

        public WinTrustData(IntPtr fileInfo, IntPtr signatureSettings)
        {
            Size = (uint)Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = 2;
            RevocationChecks = 0;
            UnionChoice = 1;
            FileInfo = fileInfo;
            StateAction = StateActionVerify;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = ProviderFlagRevocationCheckNone;
            UiContext = 0;
            SignatureSettings = signatureSettings;
        }

        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCertificate
    {
        public uint Size;
        public IntPtr CertificateContext;
    }

    private static partial class NativeMethods
    {
        internal static Guid GenericVerifyV2 => new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

        [LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
        internal static partial int WinVerifyTrust(
            IntPtr windowHandle,
            ref Guid actionId,
            ref WinTrustData trustData);

        [LibraryImport("wintrust.dll", EntryPoint = "WTHelperProvDataFromStateData")]
        internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

        [LibraryImport("wintrust.dll", EntryPoint = "WTHelperGetProvSignerFromChain")]
        internal static partial IntPtr WTHelperGetProvSignerFromChain(
            IntPtr providerData,
            uint signerIndex,
            [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
            uint counterSignerIndex);

        [LibraryImport("wintrust.dll", EntryPoint = "WTHelperGetProvCertFromChain")]
        internal static partial IntPtr WTHelperGetProvCertFromChain(
            IntPtr providerSigner,
            uint certificateIndex);
    }
}

public sealed class AuthenticodeSigner : IAuthenticodeSigner
{
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".sys", ".cat",
    };

    private readonly IProcessRunner _runner;
    private readonly IAuthenticodeSignatureReader _signatureReader;
    private readonly AuthenticodeSigningProfile _profile;
    private readonly string _spoolRoot;
    private readonly IControlledFileCopier _copier;
    private readonly IAuthenticodeFileValidator _fileValidator;
    private readonly TimeSpan _processTimeout;

    public AuthenticodeSigner(
        IProcessRunner runner,
        IAuthenticodeSignatureReader signatureReader,
        AuthenticodeSigningProfile profile,
        string spoolRoot,
        IControlledFileCopier copier,
        IAuthenticodeFileValidator fileValidator,
        TimeSpan processTimeout)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _signatureReader = signatureReader ?? throw new ArgumentNullException(nameof(signatureReader));
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _copier = copier ?? throw new ArgumentNullException(nameof(copier));
        _fileValidator = fileValidator ?? throw new ArgumentNullException(nameof(fileValidator));
        try
        {
            if (!Path.IsPathFullyQualified(spoolRoot))
            {
                throw new ArgumentException("invalid_spool_root");
            }

            _spoolRoot = Path.GetFullPath(spoolRoot);
            if (!Directory.Exists(_spoolRoot) || IsReparseOrSymbolicLink(_spoolRoot, directory: true))
            {
                throw new ArgumentException("invalid_spool_root");
            }
        }
        catch (ArgumentException)
        {
            throw new ArgumentException("invalid_spool_root");
        }
        catch (Exception error) when (IsFileOrSecurityFailure(error) || error is NotSupportedException)
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
        AuthenticodeParameters parameters,
        SigningCertificate certificate,
        CancellationToken cancellationToken)
    {
        string? controlledPartPath = null;
        try
        {
            var validated = ValidateContext(context);
            controlledPartPath = validated.ResultPartPath;
            DeleteStalePartAndRejectReparse(controlledPartPath);
            var certificateThumbprint = ValidateParameters(parameters, certificate);
            cancellationToken.ThrowIfCancellationRequested();

            await _copier.CopyAsync(validated.InputPath, controlledPartPath, cancellationToken).ConfigureAwait(false);
            if (!_fileValidator.IsValid(controlledPartPath, context.Extension))
            {
                throw new SigningException("invalid_signable_file");
            }

            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyList<string>? existingSigners = null;
            if (parameters.AppendSignature)
            {
                existingSigners = ReadSigners(controlledPartPath);
            }

            if (!parameters.AppendSignature)
            {
                var precheck = await RunAsync(
                    ["verify", "/pa", "/all", controlledPartPath],
                    "authenticode_verify_failed",
                    cancellationToken).ConfigureAwait(false);
                if (precheck.Termination == ProcessTermination.LaunchFailed)
                {
                    throw new SigningException("signtool_missing");
                }

                ThrowIfCancelled(precheck, cancellationToken);
                if (precheck.Termination != ProcessTermination.Exited)
                {
                    throw new SigningException("authenticode_verify_failed");
                }

                if (precheck.ExitCode == 0)
                {
                    throw new SigningException("already_signed");
                }
            }

            var signArguments = new List<string> { "sign" };
            if (parameters.AppendSignature)
            {
                signArguments.Add("/as");
            }

            signArguments.AddRange(
            [
                "/fd", "SHA256",
                "/sha1", certificateThumbprint,
                "/tr", _profile.TimestampUrl,
                "/td", "SHA256",
                "/v", controlledPartPath,
            ]);

            var sign = await RunAsync(signArguments, "authenticode_sign_failed", cancellationToken).ConfigureAwait(false);
            ThrowIfCancelled(sign, cancellationToken);
            if (sign.Termination == ProcessTermination.LaunchFailed)
            {
                throw new SigningException("signtool_missing");
            }

            if (!sign.Succeeded)
            {
                throw new SigningException("authenticode_sign_failed");
            }

            var verify = await RunAsync(
                ["verify", "/pa", "/all", "/v", controlledPartPath],
                "authenticode_verify_failed",
                cancellationToken).ConfigureAwait(false);
            ThrowIfCancelled(verify, cancellationToken);
            if (!verify.Succeeded)
            {
                throw new SigningException("authenticode_verify_failed");
            }

            VerifySigners(controlledPartPath, existingSigners, parameters.AppendSignature, certificateThumbprint);
            return await HashAsync(controlledPartPath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            DeleteControlledPart(controlledPartPath);
            throw;
        }
        catch (SigningException)
        {
            DeleteControlledPart(controlledPartPath);
            throw;
        }
        catch (Exception error) when (IsFileOrSecurityFailure(error))
        {
            DeleteControlledPart(controlledPartPath);
            throw new SigningException("internal_error");
        }
        catch (Exception)
        {
            DeleteControlledPart(controlledPartPath);
            throw new SigningException("internal_error");
        }
    }

    private async Task<ProcessResult> RunAsync(
        IReadOnlyList<string> arguments,
        string failureCode,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _runner.RunAsync(
                _profile.SignToolPath,
                arguments,
                _processTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new SigningException(failureCode);
        }
    }

    private ValidatedContext ValidateContext(SigningContext context)
    {
        if (context is null)
        {
            throw new SigningException("invalid_signable_file");
        }

        try
        {
            if (context.JobId == Guid.Empty ||
                !AllowedExtensions.Contains(context.Extension) ||
                !string.Equals(
                    Path.GetExtension("input" + context.Extension),
                    context.Extension,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new SigningException("invalid_signable_file");
            }

            if (!Directory.Exists(_spoolRoot) || IsReparseOrSymbolicLink(_spoolRoot, directory: true))
            {
                throw new SigningException("invalid_signable_file");
            }

            var extension = context.Extension.ToLowerInvariant();
            var jobDirectory = Path.GetFullPath(Path.Combine(_spoolRoot, context.JobId.ToString("N")));
            var inputPath = Path.GetFullPath(Path.Combine(jobDirectory, "input" + extension));
            var resultPartPath = Path.GetFullPath(Path.Combine(jobDirectory, "result.part" + extension));
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var rootWithSeparator = _spoolRoot.EndsWith(Path.DirectorySeparatorChar)
                ? _spoolRoot
                : _spoolRoot + Path.DirectorySeparatorChar;
            if (!jobDirectory.StartsWith(rootWithSeparator, comparison) ||
                string.Equals(inputPath, resultPartPath, comparison) ||
                !string.Equals(Path.GetDirectoryName(inputPath), jobDirectory, comparison) ||
                !string.Equals(Path.GetDirectoryName(resultPartPath), jobDirectory, comparison))
            {
                throw new SigningException("invalid_signable_file");
            }

            if (!Directory.Exists(jobDirectory) ||
                !File.Exists(inputPath) ||
                IsReparseOrSymbolicLink(jobDirectory, directory: true) ||
                IsReparseOrSymbolicLink(inputPath, directory: false))
            {
                throw new SigningException("invalid_signable_file");
            }

            return new ValidatedContext(inputPath, resultPartPath);
        }
        catch (SigningException)
        {
            throw;
        }
        catch (Exception error) when (IsFileOrSecurityFailure(error) || error is ArgumentException or NotSupportedException)
        {
            throw new SigningException("invalid_signable_file");
        }
    }

    private static string ValidateParameters(
        AuthenticodeParameters parameters,
        SigningCertificate certificate)
    {
        if (parameters is null ||
            certificate is null ||
            !string.Equals(parameters.CertificateSerialNumber, certificate.SerialNumber, StringComparison.Ordinal) ||
            !string.Equals(parameters.DigestAlgorithm, "sha256", StringComparison.Ordinal) ||
            !certificate.SupportsAuthenticode)
        {
            throw new SigningException("invalid_parameters");
        }

        var thumbprint = AuthenticodeSigningProfile.NormalizeThumbprint(certificate.Sha1Thumbprint);
        if (thumbprint.Length != 40 || thumbprint.Any(static character => !Uri.IsHexDigit(character)))
        {
            throw new SigningException("invalid_parameters");
        }

        return thumbprint;
    }

    private IReadOnlyList<string> ReadSigners(string resultPartPath)
    {
        try
        {
            return _signatureReader.ReadSignerThumbprints(resultPartPath)
                .Select(AuthenticodeSigningProfile.NormalizeThumbprint)
                .ToArray();
        }
        catch (Exception)
        {
            throw new SigningException("authenticode_verify_failed");
        }
    }

    private void VerifySigners(
        string resultPartPath,
        IReadOnlyList<string>? existingSigners,
        bool appendSignature,
        string certificateThumbprint)
    {
        var actualSigners = ReadSigners(resultPartPath);
        if (!appendSignature)
        {
            if (actualSigners.Count != 1 ||
                !string.Equals(actualSigners[0], certificateThumbprint, StringComparison.Ordinal))
            {
                throw new SigningException("authenticode_verify_failed");
            }

            return;
        }

        if (existingSigners is null || actualSigners.Count != existingSigners.Count + 1)
        {
            throw new SigningException("authenticode_verify_failed");
        }

        for (var index = 0; index < existingSigners.Count; index++)
        {
            if (!string.Equals(existingSigners[index], actualSigners[index], StringComparison.Ordinal))
            {
                throw new SigningException("authenticode_verify_failed");
            }
        }

        if (!string.Equals(actualSigners[^1], certificateThumbprint, StringComparison.Ordinal))
        {
            throw new SigningException("authenticode_verify_failed");
        }
    }

    private static async Task<SigningResult> HashAsync(string path, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81_920];
        long size = 0;
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            buffer.Length,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            hash.AppendData(buffer, 0, read);
            size += read;
        }

        return new SigningResult(size, Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant());
    }

    private static void ThrowIfCancelled(ProcessResult result, CancellationToken cancellationToken)
    {
        if (result.Termination == ProcessTermination.Cancelled)
        {
            throw new OperationCanceledException("authenticode_cancelled", innerException: null, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private static void DeleteStalePartAndRejectReparse(string path)
    {
        if (IsReparseOrSymbolicLink(path, directory: false))
        {
            DeleteControlledPart(path);
            throw new SigningException("invalid_signable_file");
        }

        if (!File.Exists(path))
        {
            if (Directory.Exists(path))
            {
                throw new SigningException("invalid_signable_file");
            }

            return;
        }

        DeleteControlledPart(path);
        if (File.Exists(path))
        {
            throw new SigningException("internal_error");
        }
    }

    private static bool IsReparseOrSymbolicLink(string path, bool directory)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }

        try
        {
            FileSystemInfo info = directory ? new DirectoryInfo(path) : new FileInfo(path);
            return info.LinkTarget is not null;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void DeleteControlledPart(string? path)
    {
        if (path is null)
        {
            return;
        }

        try
        {
            File.Delete(path);
        }
        catch (Exception error) when (IsFileOrSecurityFailure(error))
        {
        }
    }

    private static bool IsFileOrSecurityFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or SecurityException;

    private sealed record ValidatedContext(string InputPath, string ResultPartPath);
}

public interface ISignToolMetadataReader
{
    SignToolMetadata Read(string signToolPath);
}

public sealed class SignToolMetadata
{
    public SignToolMetadata(string? fileVersion, bool isX64)
    {
        FileVersion = fileVersion;
        IsX64 = isX64;
    }

    public string? FileVersion { get; }

    public bool IsX64 { get; }

    public override string ToString() => string.Empty;
}

public sealed class SignToolMetadataReader : ISignToolMetadataReader
{
    private const ushort Amd64Machine = 0x8664;

    public SignToolMetadata Read(string signToolPath)
    {
        var version = FileVersionInfo.GetVersionInfo(signToolPath).FileVersion;
        using var stream = new FileStream(signToolPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Span<byte> dosHeader = stackalloc byte[64];
        stream.ReadExactly(dosHeader);
        if (!dosHeader[..2].SequenceEqual("MZ"u8))
        {
            return new SignToolMetadata(version, isX64: false);
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[0x3c..]);
        if (peOffset < dosHeader.Length || peOffset > stream.Length - 6)
        {
            return new SignToolMetadata(version, isX64: false);
        }

        stream.Position = peOffset;
        Span<byte> peHeader = stackalloc byte[6];
        stream.ReadExactly(peHeader);
        var isX64 = peHeader[..4].SequenceEqual("PE\0\0"u8) &&
            BinaryPrimitives.ReadUInt16LittleEndian(peHeader[4..]) == Amd64Machine;
        return new SignToolMetadata(version, isX64);
    }
}

public sealed class SignToolPreflightResult
{
    public SignToolPreflightResult(bool available, string executableName, string? fileVersion, string? errorCode)
    {
        Available = available;
        ExecutableName = executableName;
        FileVersion = fileVersion;
        ErrorCode = errorCode;
    }

    public bool Available { get; }

    public string ExecutableName { get; }

    public string? FileVersion { get; }

    public string? ErrorCode { get; }

    public override string ToString() => string.Empty;
}

public sealed class SignToolPreflight
{
    private static readonly TimeSpan PreflightTimeout = TimeSpan.FromSeconds(15);
    private readonly IProcessRunner _runner;
    private readonly AuthenticodeSigningProfile _profile;
    private readonly ISignToolMetadataReader _metadataReader;

    public SignToolPreflight(
        IProcessRunner runner,
        AuthenticodeSigningProfile profile,
        ISignToolMetadataReader metadataReader)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _metadataReader = metadataReader ?? throw new ArgumentNullException(nameof(metadataReader));
    }

    public async Task<SignToolPreflightResult> CheckAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var executableName = Path.GetFileName(_profile.SignToolPath);
        try
        {
            if (!File.Exists(_profile.SignToolPath) || IsReparseOrSymbolicLink(_profile.SignToolPath))
            {
                return Missing(executableName);
            }

            var process = await _runner.RunAsync(
                _profile.SignToolPath,
                ["/?"],
                PreflightTimeout,
                cancellationToken).ConfigureAwait(false);
            if (process.Termination == ProcessTermination.Cancelled)
            {
                throw new OperationCanceledException("signtool_preflight_cancelled", innerException: null, cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Succeeded)
            {
                return Missing(executableName);
            }

            var metadata = _metadataReader.Read(_profile.SignToolPath);
            return !IsSafeFileVersion(metadata.FileVersion) || !metadata.IsX64
                ? Missing(executableName)
                : new SignToolPreflightResult(true, executableName, metadata.FileVersion, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return Missing(executableName);
        }
    }

    private static bool IsReparseOrSymbolicLink(string path)
    {
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }

        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static SignToolPreflightResult Missing(string executableName) =>
        new(false, executableName, null, "signtool_missing");

    private static bool IsSafeFileVersion(string? version) =>
        version is { Length: > 0 and <= 128 } &&
        version.All(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '.' or '-' or '_' or '+' or '(' or ')' or ' ');
}
