using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.Tools;

internal interface IInstalledPdfToolSecurity
{
    Task<string?> ReadManifestAsync(
        PdfExtensionPaths paths,
        CancellationToken cancellationToken);

    Task<string?> ReadManifestAsync(
        PdfExtensionPaths paths,
        string signingUserSid,
        CancellationToken cancellationToken);

    Task VerifyHelperAsync(
        string path,
        PdfExtensionManifest manifest,
        CancellationToken cancellationToken);

    Task VerifyHelperAsync(
        string path,
        PdfExtensionManifest manifest,
        string signingUserSid,
        CancellationToken cancellationToken);
}

internal sealed class WindowsInstalledPdfToolResolver : IInstalledPdfToolResolver
{
    private readonly PdfExtensionPaths _paths;
    private readonly IInstalledPdfToolSecurity _security;

    public WindowsInstalledPdfToolResolver(
        string programFilesRoot,
        IInstalledPdfToolSecurity? security = null)
    {
        _paths = PdfExtensionPaths.FromProgramFiles(programFilesRoot);
        _security = security ?? new WindowsInstalledPdfToolSecurity();
    }

    public async Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken)
    {
        try
        {
            var manifestJson = await _security.ReadManifestAsync(_paths, cancellationToken)
                .ConfigureAwait(false);
            if (manifestJson is null)
            {
                return InstalledPdfToolResolution.NotInstalled();
            }

            var manifest = PdfExtensionManifestCodec.Decode(manifestJson);
            await _security.VerifyHelperAsync(_paths.Helper, manifest, cancellationToken)
                .ConfigureAwait(false);
            return InstalledPdfToolResolution.Ready(new InstalledPdfTool(
                _paths.Helper,
                manifest.HelperSha256));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return InstalledPdfToolResolution.Tampered();
        }
    }
}

internal sealed class WindowsInstalledPdfToolSecurity : IInstalledPdfToolSecurity
{
    private const int BufferSize = 64 * 1024;
    private readonly IAuthenticodeSignatureReader _signatureReader;
    private readonly ILocalFileIdentityProvider _fileIdentities;
    private readonly Func<string, byte[]> _readSignerCertificate;

    public WindowsInstalledPdfToolSecurity()
        : this(
            new WindowsAuthenticodeSignatureReader(),
            PlatformLocalFileIdentityProvider.Instance,
            ReadSignerCertificate)
    {
    }

    internal WindowsInstalledPdfToolSecurity(
        IAuthenticodeSignatureReader signatureReader,
        ILocalFileIdentityProvider fileIdentities,
        Func<string, byte[]> readSignerCertificate)
    {
        _signatureReader = signatureReader ?? throw new ArgumentNullException(nameof(signatureReader));
        _fileIdentities = fileIdentities ?? throw new ArgumentNullException(nameof(fileIdentities));
        _readSignerCertificate = readSignerCertificate ??
            throw new ArgumentNullException(nameof(readSignerCertificate));
    }

    public async Task<string?> ReadManifestAsync(
        PdfExtensionPaths paths,
        CancellationToken cancellationToken) =>
        await ReadManifestAsync(paths, GetCurrentSid(), cancellationToken).ConfigureAwait(false);

    public async Task<string?> ReadManifestAsync(
        PdfExtensionPaths paths,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);
        cancellationToken.ThrowIfCancellationRequested();
        var rootKind = NoFollowFile.InspectPathEntry(paths.Root);
        if (rootKind == NoFollowPathEntryKind.Missing)
        {
            VerifyNoReparseAncestors(paths.Root);
            return null;
        }

        if (rootKind != NoFollowPathEntryKind.Directory ||
            NoFollowFile.InspectPathEntry(paths.Manifest) != NoFollowPathEntryKind.RegularFile)
        {
            throw new IOException("pdf_extension_manifest_invalid");
        }

        VerifyExtensionRoot(paths.Root, signingUserSid);
        return await ReadProtectedTextAsync(paths.Manifest, signingUserSid, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task VerifyHelperAsync(
        string path,
        PdfExtensionManifest manifest,
        CancellationToken cancellationToken) =>
        await VerifyHelperAsync(path, manifest, GetCurrentSid(), cancellationToken)
            .ConfigureAwait(false);

    public async Task VerifyHelperAsync(
        string path,
        PdfExtensionManifest manifest,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var root = Path.GetDirectoryName(path) ?? throw new IOException("pdf_extension_path_invalid");
        VerifyExtensionRoot(root, signingUserSid);
        await using var stream = OpenProtectedFile(path, signingUserSid);
        if (stream.Length != manifest.HelperLength)
        {
            throw new IOException("pdf_helper_length_mismatch");
        }

        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferSize];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            sha256.AppendData(buffer, 0, read);
        }

        if (!FixedHashEquals(sha256.GetHashAndReset(), manifest.HelperSha256))
        {
            throw new CryptographicException("pdf_helper_hash_mismatch");
        }

        var signers = _signatureReader.ReadSignerThumbprints(path);
        if (signers.Count != 1)
        {
            throw new CryptographicException("pdf_helper_signature_invalid");
        }

        var rawCertificate = _readSignerCertificate(path);
        try
        {
            if (!FixedHashEquals(
                    SHA256.HashData(rawCertificate),
                    manifest.PublisherCertificateSha256))
            {
                throw new CryptographicException("pdf_helper_publisher_mismatch");
            }

            using var certificate = X509CertificateLoader.LoadCertificate(rawCertificate);
            if (!string.Equals(
                    certificate.Thumbprint,
                    signers[0],
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("pdf_helper_publisher_mismatch");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawCertificate);
        }
    }

    private async Task<string> ReadProtectedTextAsync(
        string path,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenProtectedFile(path, signingUserSid);
        using var reader = new StreamReader(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            BufferSize,
            leaveOpen: true);
        var text = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        if (text.Length == 0 || text[0] == '\ufeff')
        {
            throw new IOException("pdf_extension_manifest_invalid");
        }

        return text;
    }

    private FileStream OpenProtectedFile(string path, string signingUserSid)
    {
        var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path);
        try
        {
            WindowsExecutableSecurity.VerifyEntry(
                WindowsNoFollowSecurity.Read(handle),
                signingUserSid,
                requireReadExecute: true);
            if (!_fileIdentities.TryGetIdentity(handle, out var identity) || identity.LinkCount != 1)
            {
                throw new IOException("pdf_extension_link_invalid");
            }

            return new FileStream(handle, FileAccess.Read, BufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void VerifyExtensionRoot(string root, string signingUserSid)
    {
        WindowsExecutableSecurity.VerifyEntry(
            WindowsNoFollowSecurity.ReadDirectory(root),
            signingUserSid,
            requireReadExecute: true);
        VerifyNoReparseAncestors(root);
    }

    private static void VerifyNoReparseAncestors(string path)
    {
        for (var current = Directory.GetParent(path); current is not null; current = current.Parent)
        {
            if ((WindowsNoFollowSecurity.ReadDirectory(current.FullName).Attributes &
                    FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("pdf_extension_path_invalid");
            }
        }
    }

    private static string GetCurrentSid() =>
        WindowsIdentity.GetCurrent().User?.Value ??
        throw new IOException("pdf_extension_identity_invalid");

    private static bool FixedHashEquals(byte[] actual, string expected) =>
        CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(expected));

#pragma warning disable SYSLIB0057 // WinVerifyTrust succeeds before this leaf-certificate extraction; the framework has no replacement API.
    private static byte[] ReadSignerCertificate(string path) =>
        X509Certificate.CreateFromSignedFile(path).GetRawCertData();
#pragma warning restore SYSLIB0057
}
