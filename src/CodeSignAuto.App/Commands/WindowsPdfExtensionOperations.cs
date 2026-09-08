using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.App;
using CodeSignAuto.App.Tools;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

internal sealed record PdfExtensionRuntimeContext(
    string ProgramFilesRoot,
    string ProgramDataRoot,
    string ProcessPath,
    string ProductVersion);

internal sealed record PdfExtensionUninstallRegistration(
    string MainExecutable,
    string DisplayVersion,
    string InstallLocation,
    string DisplayIcon,
    string UninstallString,
    string OwnerMarker)
{
    internal static PdfExtensionUninstallRegistration Create(
        string mainExecutable,
        string displayVersion,
        string installLocation) => new(
            mainExecutable,
            displayVersion,
            installLocation,
            $"\"{mainExecutable}\",0",
            $"\"{mainExecutable}\" pdf-extension uninstall",
            $"CodeSignAutoPdfSupport/v1/{displayVersion}");
}

internal interface IPdfExtensionArtifactVerifier
{
    Task<PdfExtensionManifest> VerifySourceAsync(
        PdfExtensionPaths paths,
        string mainExecutable,
        CancellationToken cancellationToken);

    Task VerifyInstalledAsync(
        PdfExtensionPaths paths,
        PdfExtensionManifest expected,
        string signingUserSid,
        CancellationToken cancellationToken);

    Task<PdfExtensionManifest> ReadAndVerifyInstalledAsync(
        PdfExtensionPaths paths,
        string mainExecutable,
        string signingUserSid,
        CancellationToken cancellationToken);
}

internal interface IPdfExtensionRegistrationStore
{
    bool IsExact(PdfExtensionUninstallRegistration registration);

    void Create(PdfExtensionUninstallRegistration registration);

    void Remove(PdfExtensionUninstallRegistration registration);
}

internal interface IPdfExtensionMainIdentitySource
{
    Task<InstalledProductIdentity> LoadAsync(CancellationToken cancellationToken);
}

internal static class PdfExtensionMainIdentityResolver
{
    public static InstalledProductIdentity Resolve(
        InstallationReceipt? receipt,
        ServiceConfiguration? configuration)
    {
        try
        {
            receipt = InstallationReceiptValidator.Validate(receipt);
            if (receipt.Mode == InstallationMode.Service)
            {
                if (configuration is null)
                {
                    throw new InstallException("pdf_extension_main_invalid");
                }

                InstallationReceiptValidator.RequireServiceMatch(receipt, configuration);
            }
            else if (configuration is not null)
            {
                throw new InstallException("pdf_extension_main_invalid");
            }

            return new InstalledProductIdentity(
                receipt.ExecutablePath,
                receipt.SigningUserSid);
        }
        catch (InstallException error) when (error.Code == "pdf_extension_main_invalid")
        {
            throw;
        }
        catch
        {
            throw new InstallException("pdf_extension_main_invalid");
        }
    }
}

internal sealed class WindowsPdfExtensionMainIdentitySource : IPdfExtensionMainIdentitySource
{
    private readonly IInstallationReceiptStore _receiptStore;
    private readonly IServiceConfigurationLoader _configurationLoader;

    public WindowsPdfExtensionMainIdentitySource()
        : this(new WindowsInstallationReceiptStore(), new ServiceConfigurationLoader())
    {
    }

    internal WindowsPdfExtensionMainIdentitySource(
        IInstallationReceiptStore receiptStore,
        IServiceConfigurationLoader configurationLoader)
    {
        _receiptStore = receiptStore ?? throw new ArgumentNullException(nameof(receiptStore));
        _configurationLoader = configurationLoader ??
            throw new ArgumentNullException(nameof(configurationLoader));
    }

    public async Task<InstalledProductIdentity> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var receipt = await _receiptStore.LoadOptionalAsync(cancellationToken)
                .ConfigureAwait(false);
            if (receipt is null)
            {
                throw new InstallException("pdf_extension_main_invalid");
            }

            ServiceConfiguration? configuration = null;
            var configurationExists = WindowsPathSafety.EntryExists(
                WindowsUninstallEnvironment.ConfigurationPath);
            if (receipt.Mode == InstallationMode.Service)
            {
                if (!configurationExists)
                {
                    throw new InstallException("pdf_extension_main_invalid");
                }

                configuration = await _configurationLoader.LoadAsync(cancellationToken)
                    .ConfigureAwait(false);
            }
            else if (configurationExists)
            {
                throw new InstallException("pdf_extension_main_invalid");
            }

            return PdfExtensionMainIdentityResolver.Resolve(receipt, configuration);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException error) when (error.Code == "pdf_extension_main_invalid")
        {
            throw;
        }
        catch
        {
            throw new InstallException("pdf_extension_main_invalid");
        }
    }
}

internal sealed class WindowsPdfExtensionOperations : IPdfExtensionOperations
{
    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);
    private readonly PdfExtensionRuntimeContext _context;
    private readonly IPdfExtensionMainIdentitySource _mainIdentitySource;
    private readonly IPdfExtensionArtifactVerifier _verifier;
    private readonly IPdfExtensionRegistrationStore _registrationStore;
    private readonly Func<string> _nonceFactory;
    private PdfExtensionInstallPlan? _activePlan;
    private PdfExtensionSourceLease? _sourceLease;
    private LocalFileIdentity? _publishedRootIdentity;
    private LocalFileIdentity? _manifestIdentity;
    private LocalFileIdentity? _helperIdentity;
    private LocalFileIdentity? _licenseIdentity;
    private LocalFileIdentity? _thirdPartyNoticesIdentity;
    private bool _stagingCreated;
    private bool _promoted;
    private bool _alreadyInstalled;

    internal WindowsPdfExtensionOperations()
        : this(
            new PdfExtensionRuntimeContext(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.ProcessPath ?? string.Empty,
                ApplicationVersion.ReadIdentity(typeof(WindowsPdfExtensionOperations).Assembly)),
            new WindowsPdfExtensionMainIdentitySource(),
            new WindowsPdfExtensionArtifactVerifier(),
            new WindowsPdfExtensionRegistrationStore(),
            () => Guid.NewGuid().ToString("N"))
    {
    }

    internal WindowsPdfExtensionOperations(
        PdfExtensionRuntimeContext context,
        IPdfExtensionMainIdentitySource mainIdentitySource,
        IPdfExtensionArtifactVerifier verifier,
        IPdfExtensionRegistrationStore registrationStore,
        Func<string> nonceFactory)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _mainIdentitySource = mainIdentitySource ??
            throw new ArgumentNullException(nameof(mainIdentitySource));
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _registrationStore = registrationStore ??
            throw new ArgumentNullException(nameof(registrationStore));
        _nonceFactory = nonceFactory ?? throw new ArgumentNullException(nameof(nonceFactory));
    }

    public void RequireAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new InstallException("administrator_required");
        }
    }

    public async Task<PdfExtensionInstallPlan> PlanInstallAsync(
        string mediaRoot,
        CancellationToken cancellationToken)
    {
        RequireAdministrator();
        if (_activePlan is not null)
        {
            throw new InstallException("pdf_extension_install_active");
        }

        PdfExtensionSourceLease? lease = null;
        try
        {
            var programFilesRoot = RequireCanonicalPath(_context.ProgramFilesRoot);
            _ = RequireCanonicalPath(_context.ProgramDataRoot);
            var mainExecutable = Path.Combine(
                programFilesRoot,
                "CodeSignAuto",
                "CodeSignAuto.exe");
            if (!string.Equals(
                    RequireCanonicalPath(_context.ProcessPath),
                    mainExecutable,
                    StringComparison.OrdinalIgnoreCase) ||
                NoFollowFile.InspectPathEntry(mainExecutable) != NoFollowPathEntryKind.RegularFile)
            {
                throw new InstallException("pdf_extension_main_invalid");
            }

            var identity = await _mainIdentitySource.LoadAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    identity.ExecutablePath,
                    mainExecutable,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("pdf_extension_main_invalid");
            }

            _ = new SecurityIdentifier(identity.SigningUserSid);
            var target = PdfExtensionPaths.FromProgramFiles(programFilesRoot);
            var targetKind = NoFollowFile.InspectPathEntry(target.Root);

            var instanceId = _nonceFactory();
            if (!IsInstanceId(instanceId))
            {
                throw new InstallException("pdf_extension_install_invalid");
            }

            var stagingRoot = Path.Combine(
                programFilesRoot,
                $"CodeSignAuto PDF Support.part-{instanceId}");
            if (NoFollowFile.InspectPathEntry(stagingRoot) != NoFollowPathEntryKind.Missing)
            {
                throw new InstallException("pdf_extension_target_exists");
            }

            var canonicalMediaRoot = RequireCanonicalPath(mediaRoot);
            lease = PdfExtensionSourceLease.Capture(canonicalMediaRoot);
            var source = new PdfExtensionPaths(
                canonicalMediaRoot,
                Path.Combine(canonicalMediaRoot, "extension.json"),
                Path.Combine(canonicalMediaRoot, "CodeSignAutoPdfSigner.exe"),
                Path.Combine(canonicalMediaRoot, "LICENSE.txt"),
                Path.Combine(canonicalMediaRoot, "THIRD-PARTY-NOTICES.txt"));
            var manifest = await _verifier.VerifySourceAsync(
                    source,
                    mainExecutable,
                    cancellationToken)
                .ConfigureAwait(false);
            lease.VerifyUnchanged();
            var plan = new PdfExtensionInstallPlan(
                target,
                manifest,
                identity.SigningUserSid,
                instanceId);
            if (targetKind != NoFollowPathEntryKind.Missing)
            {
                if (targetKind != NoFollowPathEntryKind.Directory)
                {
                    throw new InstallException("pdf_extension_target_exists");
                }

                var installed = await _verifier.ReadAndVerifyInstalledAsync(
                        target,
                        mainExecutable,
                        identity.SigningUserSid,
                        cancellationToken)
                    .ConfigureAwait(false);
                var registration = PdfExtensionUninstallRegistration.Create(
                    mainExecutable,
                    installed.ProductVersion,
                    target.Root);
                if (installed != manifest || !_registrationStore.IsExact(registration))
                {
                    throw new InstallException("pdf_extension_target_exists");
                }

                _alreadyInstalled = true;
            }

            _sourceLease = lease;
            lease = null;
            _activePlan = plan;
            return plan;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("pdf_extension_media_invalid");
        }
        finally
        {
            lease?.Dispose();
        }
    }

    public async Task PublishInstallAsync(
        PdfExtensionInstallPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!ReferenceEquals(plan, _activePlan) || _sourceLease is null)
        {
            throw new InstallException("pdf_extension_install_invalid");
        }

        var signingUser = new SecurityIdentifier(plan.SigningUserSid);
        var stagingRoot = Path.Combine(
            _context.ProgramFilesRoot,
            $"CodeSignAuto PDF Support.part-{plan.InstanceId}");
        var staging = new PdfExtensionPaths(
            stagingRoot,
            Path.Combine(stagingRoot, "extension.json"),
            Path.Combine(stagingRoot, "CodeSignAutoPdfSigner.exe"),
            Path.Combine(stagingRoot, "LICENSE.txt"),
            Path.Combine(stagingRoot, "THIRD-PARTY-NOTICES.txt"));
        try
        {
            _sourceLease.VerifyUnchanged();
            if (_alreadyInstalled)
            {
                CompleteInstall();
                return;
            }

            var directorySecurity = WindowsInstallAcl
                .CreateDirectorySecurity(InstallAclProfile.SigningUserRead, signingUser)
                .GetSecurityDescriptorBinaryForm();
            WindowsNativeProtectedObject.CreateDirectory(staging.Root, directorySecurity);
            _stagingCreated = true;
            using (var rootHandle = WindowsNoFollowSecurity.OpenDirectoryHandle(staging.Root))
            {
                _publishedRootIdentity = RequireSingleLinkIdentity(rootHandle);
            }

            await CopySourceAsync(
                    _sourceLease.Manifest,
                    staging.Manifest,
                    signingUser,
                    identity => _manifestIdentity = identity,
                    cancellationToken)
                .ConfigureAwait(false);
            await CopySourceAsync(
                    _sourceLease.Helper,
                    staging.Helper,
                    signingUser,
                    identity => _helperIdentity = identity,
                    cancellationToken)
                .ConfigureAwait(false);
            await CopySourceAsync(
                    _sourceLease.License,
                    staging.License,
                    signingUser,
                    identity => _licenseIdentity = identity,
                    cancellationToken)
                .ConfigureAwait(false);
            await CopySourceAsync(
                    _sourceLease.ThirdPartyNotices,
                    staging.ThirdPartyNotices,
                    signingUser,
                    identity => _thirdPartyNoticesIdentity = identity,
                    cancellationToken)
                .ConfigureAwait(false);
            _sourceLease.VerifyUnchanged();
            await _verifier.VerifyInstalledAsync(
                    staging,
                    plan.Manifest,
                    plan.SigningUserSid,
                    cancellationToken)
                .ConfigureAwait(false);

            Directory.Move(staging.Root, plan.Target.Root);
            _promoted = true;
            VerifyRootIdentity(plan.Target.Root, _publishedRootIdentity);
            await _verifier.VerifyInstalledAsync(
                    plan.Target,
                    plan.Manifest,
                    plan.SigningUserSid,
                    cancellationToken)
                .ConfigureAwait(false);
            _registrationStore.Create(PdfExtensionUninstallRegistration.Create(
                _context.ProcessPath,
                plan.Manifest.ProductVersion,
                plan.Target.Root));
            CompleteInstall();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            RollbackInstall(plan, staging, signingUser);
            throw;
        }
        catch (InstallException)
        {
            RollbackInstall(plan, staging, signingUser);
            throw;
        }
        catch
        {
            RollbackInstall(plan, staging, signingUser);
            throw new InstallException("pdf_extension_install_failed");
        }
    }

    public async Task UninstallAsync(CancellationToken cancellationToken)
    {
        RequireAdministrator();
        var identity = await _mainIdentitySource.LoadAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(
                identity.ExecutablePath,
                _context.ProcessPath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("pdf_extension_main_invalid");
        }

        var target = PdfExtensionPaths.FromProgramFiles(_context.ProgramFilesRoot);
        if (NoFollowFile.InspectPathEntry(target.Root) == NoFollowPathEntryKind.Missing)
        {
            var missingRegistration = PdfExtensionUninstallRegistration.Create(
                _context.ProcessPath,
                _context.ProductVersion,
                target.Root);
            _registrationStore.Remove(missingRegistration);
            return;
        }

        var manifest = await _verifier.ReadAndVerifyInstalledAsync(
                target,
                _context.ProcessPath,
                identity.SigningUserSid,
                cancellationToken)
            .ConfigureAwait(false);
        var registration = PdfExtensionUninstallRegistration.Create(
            _context.ProcessPath,
            manifest.ProductVersion,
            target.Root);
        LocalFileIdentity rootIdentity;
        using (var rootHandle = WindowsNoFollowSecurity.OpenDirectoryHandle(target.Root))
        {
            rootIdentity = RequireSingleLinkIdentity(rootHandle);
        }

        var signingUser = new SecurityIdentifier(identity.SigningUserSid);
        _registrationStore.Remove(registration);
        try
        {
            DeleteOwnedRoot(target, rootIdentity, signingUser);
        }
        catch
        {
            try
            {
                _registrationStore.Create(registration);
            }
            catch
            {
            }

            throw new InstallException("pdf_extension_uninstall_state_uncertain");
        }
    }

    private static async Task CopySourceAsync(
        FileStream source,
        string destination,
        SecurityIdentifier signingUser,
        Action<LocalFileIdentity> recordIdentity,
        CancellationToken cancellationToken)
    {
        var fileSecurity = WindowsInstallAcl
            .CreateFileSecurity(InstallAclProfile.SigningUserRead, signingUser)
            .GetSecurityDescriptorBinaryForm();
        var handle = WindowsNativeProtectedObject.CreateFile(destination, fileSecurity);
        var createdIdentity = RequireSingleLinkIdentity(handle);
        recordIdentity(createdIdentity);
        await using (var output = new FileStream(handle, FileAccess.Write, 64 * 1024, isAsync: true))
        {
            source.Position = 0;
            await source.CopyToAsync(output, 64 * 1024, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }

        WindowsInstallAcl.VerifyFile(destination, InstallAclProfile.SigningUserRead, signingUser);
        using var readback = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(destination);
        if (!createdIdentity.RefersToSameFile(RequireSingleLinkIdentity(readback)))
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }
    }

    private void RollbackInstall(
        PdfExtensionInstallPlan plan,
        PdfExtensionPaths staging,
        SecurityIdentifier signingUser)
    {
        try
        {
            if (_promoted)
            {
                DeleteOwnedRoot(plan.Target, _publishedRootIdentity, signingUser);
            }
            else if (_stagingCreated)
            {
                DeleteOwnedStaging(staging, _publishedRootIdentity, signingUser);
            }

            CompleteInstall();
        }
        catch
        {
            _sourceLease?.Dispose();
            _sourceLease = null;
            _activePlan = null;
            throw new InstallException("pdf_extension_install_state_uncertain");
        }
    }

    private void CompleteInstall()
    {
        _sourceLease?.Dispose();
        _sourceLease = null;
        _activePlan = null;
        _publishedRootIdentity = null;
        _manifestIdentity = null;
        _helperIdentity = null;
        _licenseIdentity = null;
        _thirdPartyNoticesIdentity = null;
        _stagingCreated = false;
        _promoted = false;
        _alreadyInstalled = false;
    }

    private static void DeleteOwnedRoot(
        PdfExtensionPaths paths,
        LocalFileIdentity? expectedRootIdentity,
        SecurityIdentifier signingUser)
    {
        if (expectedRootIdentity is null || !HasExactFiles(paths.Root))
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        WindowsInstallAcl.VerifyDirectory(paths.Root, InstallAclProfile.SigningUserRead, signingUser);
        foreach (var file in new[]
                 {
                     paths.Manifest, paths.Helper, paths.License, paths.ThirdPartyNotices,
                 })
        {
            WindowsInstallAcl.VerifyFile(file, InstallAclProfile.SigningUserRead, signingUser);
            using var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(file);
            _ = RequireSingleLinkIdentity(handle);
        }

        VerifyRootIdentity(paths.Root, expectedRootIdentity);
        File.Delete(paths.Manifest);
        File.Delete(paths.Helper);
        File.Delete(paths.License);
        File.Delete(paths.ThirdPartyNotices);
        VerifyRootIdentity(paths.Root, expectedRootIdentity);
        Directory.Delete(paths.Root);
    }

    private void DeleteOwnedStaging(
        PdfExtensionPaths paths,
        LocalFileIdentity? expectedRootIdentity,
        SecurityIdentifier signingUser)
    {
        if (expectedRootIdentity is null)
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        var entries = Directory.EnumerateFileSystemEntries(paths.Root).ToArray();
        if (entries.Any(path =>
                !string.Equals(path, paths.Manifest, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(path, paths.Helper, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(path, paths.License, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(path, paths.ThirdPartyNotices, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        WindowsInstallAcl.VerifyDirectory(paths.Root, InstallAclProfile.SigningUserRead, signingUser);
        DeleteOwnedPartialFile(paths.Manifest, _manifestIdentity, signingUser);
        DeleteOwnedPartialFile(paths.Helper, _helperIdentity, signingUser);
        DeleteOwnedPartialFile(paths.License, _licenseIdentity, signingUser);
        DeleteOwnedPartialFile(
            paths.ThirdPartyNotices,
            _thirdPartyNoticesIdentity,
            signingUser);
        VerifyRootIdentity(paths.Root, expectedRootIdentity);
        Directory.Delete(paths.Root);
    }

    private static void DeleteOwnedPartialFile(
        string path,
        LocalFileIdentity? expectedIdentity,
        SecurityIdentifier signingUser)
    {
        var kind = NoFollowFile.InspectPathEntry(path);
        if (kind == NoFollowPathEntryKind.Missing)
        {
            if (expectedIdentity is not null)
            {
                throw new InstallException("pdf_extension_install_state_uncertain");
            }

            return;
        }

        if (kind != NoFollowPathEntryKind.RegularFile || expectedIdentity is null)
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        WindowsInstallAcl.VerifyFile(path, InstallAclProfile.SigningUserRead, signingUser);
        using (var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path))
        {
            if (!expectedIdentity.Value.RefersToSameFile(RequireSingleLinkIdentity(handle)))
            {
                throw new InstallException("pdf_extension_install_state_uncertain");
            }
        }

        File.Delete(path);
    }

    private static void VerifyRootIdentity(string root, LocalFileIdentity? expected)
    {
        if (expected is null)
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        using var handle = WindowsNoFollowSecurity.OpenDirectoryHandle(root);
        if (!expected.Value.RefersToSameFile(RequireSingleLinkIdentity(handle)))
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }
    }

    private static LocalFileIdentity RequireSingleLinkIdentity(SafeFileHandle handle)
    {
        if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(handle, out var identity) ||
            identity.LinkCount != 1)
        {
            throw new InstallException("pdf_extension_media_invalid");
        }

        return identity;
    }

    private static string RequireCanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            path.Any(char.IsControl) ||
            !Path.IsPathFullyQualified(path))
        {
            throw new InstallException("pdf_extension_path_invalid");
        }

        var canonical = Path.GetFullPath(path);
        if (!string.Equals(canonical, path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("pdf_extension_path_invalid");
        }

        return canonical;
    }

    private static bool IsInstanceId(string value) =>
        value.Length == 32 &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool HasExactFiles(string root) =>
        Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .SequenceEqual(
                new[]
                    {
                        "LICENSE.txt", "CodeSignAutoPdfSigner.exe", "THIRD-PARTY-NOTICES.txt",
                        "extension.json",
                    }
                    .Order(StringComparer.Ordinal),
                StringComparer.Ordinal);

    private sealed class PdfExtensionSourceLease : IDisposable
    {
        private readonly SafeFileHandle _rootHandle;
        private readonly LocalFileIdentity _rootIdentity;
        private readonly LocalFileIdentity _manifestIdentity;
        private readonly LocalFileIdentity _helperIdentity;
        private readonly LocalFileIdentity _licenseIdentity;
        private readonly LocalFileIdentity _thirdPartyNoticesIdentity;

        private PdfExtensionSourceLease(
            string root,
            SafeFileHandle rootHandle,
            LocalFileIdentity rootIdentity,
            FileStream manifest,
            LocalFileIdentity manifestIdentity,
            FileStream helper,
            LocalFileIdentity helperIdentity,
            FileStream license,
            LocalFileIdentity licenseIdentity,
            FileStream thirdPartyNotices,
            LocalFileIdentity thirdPartyNoticesIdentity)
        {
            Root = root;
            _rootHandle = rootHandle;
            _rootIdentity = rootIdentity;
            Manifest = manifest;
            _manifestIdentity = manifestIdentity;
            Helper = helper;
            _helperIdentity = helperIdentity;
            License = license;
            _licenseIdentity = licenseIdentity;
            ThirdPartyNotices = thirdPartyNotices;
            _thirdPartyNoticesIdentity = thirdPartyNoticesIdentity;
        }

        internal string Root { get; }

        internal FileStream Manifest { get; }

        internal FileStream Helper { get; }

        internal FileStream License { get; }

        internal FileStream ThirdPartyNotices { get; }

        internal static PdfExtensionSourceLease Capture(string root)
        {
            SafeFileHandle? rootHandle = null;
            FileStream? manifest = null;
            FileStream? helper = null;
            FileStream? license = null;
            FileStream? thirdPartyNotices = null;
            try
            {
                if (NoFollowFile.InspectPathEntry(root) != NoFollowPathEntryKind.Directory ||
                    !HasExactFiles(root))
                {
                    throw new InstallException("pdf_extension_media_invalid");
                }

                rootHandle = WindowsNoFollowSecurity.OpenDirectoryHandle(root);
                WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                    WindowsNoFollowSecurity.Read(rootHandle),
                    directory: true);
                var rootIdentity = RequireSingleLinkIdentity(rootHandle);
                (manifest, var manifestIdentity) = OpenSourceFile(
                    Path.Combine(root, "extension.json"));
                (helper, var helperIdentity) = OpenSourceFile(
                    Path.Combine(root, "CodeSignAutoPdfSigner.exe"));
                (license, var licenseIdentity) = OpenSourceFile(
                    Path.Combine(root, "LICENSE.txt"));
                (thirdPartyNotices, var thirdPartyNoticesIdentity) = OpenSourceFile(
                    Path.Combine(root, "THIRD-PARTY-NOTICES.txt"));
                var lease = new PdfExtensionSourceLease(
                    root,
                    rootHandle,
                    rootIdentity,
                    manifest,
                    manifestIdentity,
                    helper,
                    helperIdentity,
                    license,
                    licenseIdentity,
                    thirdPartyNotices,
                    thirdPartyNoticesIdentity);
                rootHandle = null;
                manifest = null;
                helper = null;
                license = null;
                thirdPartyNotices = null;
                lease.VerifyUnchanged();
                return lease;
            }
            catch
            {
                throw new InstallException("pdf_extension_media_invalid");
            }
            finally
            {
                thirdPartyNotices?.Dispose();
                license?.Dispose();
                helper?.Dispose();
                manifest?.Dispose();
                rootHandle?.Dispose();
            }
        }

        internal void VerifyUnchanged()
        {
            if (!HasExactFiles(Root) ||
                !_rootIdentity.RefersToSameFile(RequireSingleLinkIdentity(_rootHandle)) ||
                !_manifestIdentity.RefersToSameFile(
                    RequireSingleLinkIdentity(Manifest.SafeFileHandle)) ||
                !_helperIdentity.RefersToSameFile(RequireSingleLinkIdentity(Helper.SafeFileHandle)) ||
                !_licenseIdentity.RefersToSameFile(RequireSingleLinkIdentity(License.SafeFileHandle)) ||
                !_thirdPartyNoticesIdentity.RefersToSameFile(
                    RequireSingleLinkIdentity(ThirdPartyNotices.SafeFileHandle)))
            {
                throw new InstallException("pdf_extension_media_changed");
            }
        }

        public void Dispose()
        {
            ThirdPartyNotices.Dispose();
            License.Dispose();
            Helper.Dispose();
            Manifest.Dispose();
            _rootHandle.Dispose();
        }

        private static (FileStream Stream, LocalFileIdentity Identity) OpenSourceFile(string path)
        {
            if (NoFollowFile.InspectPathEntry(path) != NoFollowPathEntryKind.RegularFile)
            {
                throw new InstallException("pdf_extension_media_invalid");
            }

            var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path);
            try
            {
                WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                    WindowsNoFollowSecurity.Read(handle),
                    directory: false);
                var identity = RequireSingleLinkIdentity(handle);
                return (new FileStream(handle, FileAccess.Read, 64 * 1024, isAsync: false), identity);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
    }
}

internal sealed class WindowsPdfExtensionArtifactVerifier : IPdfExtensionArtifactVerifier
{
    private const int BufferSize = 64 * 1024;
    private readonly IAuthenticodeSignatureReader _signatureReader;
    private readonly Func<string, byte[]> _readSignerCertificate;

    internal WindowsPdfExtensionArtifactVerifier()
        : this(new WindowsAuthenticodeSignatureReader(), ReadSignerCertificate)
    {
    }

    internal WindowsPdfExtensionArtifactVerifier(
        IAuthenticodeSignatureReader signatureReader,
        Func<string, byte[]> readSignerCertificate)
    {
        _signatureReader = signatureReader ?? throw new ArgumentNullException(nameof(signatureReader));
        _readSignerCertificate = readSignerCertificate ??
            throw new ArgumentNullException(nameof(readSignerCertificate));
    }

    public async Task<PdfExtensionManifest> VerifySourceAsync(
        PdfExtensionPaths paths,
        string mainExecutable,
        CancellationToken cancellationToken)
    {
        var manifest = PdfExtensionManifestCodec.Decode(
            await ReadUtf8Async(paths.Manifest, cancellationToken).ConfigureAwait(false));
        await VerifyHelperCryptographyAsync(paths.Helper, manifest, cancellationToken)
            .ConfigureAwait(false);
        VerifyPublisher(mainExecutable, manifest.PublisherCertificateSha256);
        return manifest;
    }

    public async Task VerifyInstalledAsync(
        PdfExtensionPaths paths,
        PdfExtensionManifest expected,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        var signingUser = new SecurityIdentifier(signingUserSid);
        if (!HasExactInstalledFiles(paths.Root))
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        WindowsInstallAcl.VerifyDirectory(
            paths.Root,
            InstallAclProfile.SigningUserRead,
            signingUser);
        WindowsInstallAcl.VerifyFile(
            paths.Manifest,
            InstallAclProfile.SigningUserRead,
            signingUser);
        WindowsInstallAcl.VerifyFile(
            paths.Helper,
            InstallAclProfile.SigningUserRead,
            signingUser);
        var actual = PdfExtensionManifestCodec.Decode(
            await ReadUtf8Async(paths.Manifest, cancellationToken).ConfigureAwait(false));
        if (actual != expected)
        {
            throw new InstallException("pdf_extension_install_state_uncertain");
        }

        await VerifyHelperCryptographyAsync(paths.Helper, expected, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PdfExtensionManifest> ReadAndVerifyInstalledAsync(
        PdfExtensionPaths paths,
        string mainExecutable,
        string signingUserSid,
        CancellationToken cancellationToken)
    {
        var manifest = PdfExtensionManifestCodec.Decode(
            await ReadUtf8Async(paths.Manifest, cancellationToken).ConfigureAwait(false));
        await VerifyInstalledAsync(paths, manifest, signingUserSid, cancellationToken)
            .ConfigureAwait(false);
        VerifyPublisher(mainExecutable, manifest.PublisherCertificateSha256);
        return manifest;
    }

    private async Task VerifyHelperCryptographyAsync(
        string path,
        PdfExtensionManifest manifest,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path),
            FileAccess.Read,
            BufferSize,
            isAsync: false);
        if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(
                stream.SafeFileHandle,
                out var identity) ||
            identity.LinkCount != 1 ||
            stream.Length != manifest.HelperLength)
        {
            throw new InstallException("pdf_extension_artifact_invalid");
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[BufferSize];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        if (!CryptographicOperations.FixedTimeEquals(
                hash.GetHashAndReset(),
                Convert.FromHexString(manifest.HelperSha256)))
        {
            throw new InstallException("pdf_extension_artifact_invalid");
        }

        VerifyPublisher(path, manifest.PublisherCertificateSha256);
    }

    private void VerifyPublisher(string path, string expectedPublisher)
    {
        var signers = _signatureReader.ReadSignerThumbprints(path);
        if (signers.Count != 1)
        {
            throw new InstallException("pdf_extension_publisher_invalid");
        }

        var raw = _readSignerCertificate(path);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(raw),
                    Convert.FromHexString(expectedPublisher)))
            {
                throw new InstallException("pdf_extension_publisher_invalid");
            }

            using var certificate = X509CertificateLoader.LoadCertificate(raw);
            if (!string.Equals(
                    certificate.Thumbprint,
                    signers[0],
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("pdf_extension_publisher_invalid");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static async Task<string> ReadUtf8Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path),
            FileAccess.Read,
            BufferSize,
            isAsync: false);
        using var reader = new StreamReader(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            BufferSize,
            leaveOpen: true);
        var text = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        if (text.Length == 0 || text[0] == '\ufeff')
        {
            throw new InstallException("pdf_extension_manifest_invalid");
        }

        return text;
    }

    private static bool HasExactInstalledFiles(string root) =>
        Directory.EnumerateFileSystemEntries(root)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .SequenceEqual(
                new[]
                    {
                        "LICENSE.txt", "CodeSignAutoPdfSigner.exe", "THIRD-PARTY-NOTICES.txt",
                        "extension.json",
                    }
                    .Order(StringComparer.Ordinal),
                StringComparer.Ordinal);

#pragma warning disable SYSLIB0057 // WinVerifyTrust succeeds before extracting the PE leaf certificate; the framework exposes no replacement.
    private static byte[] ReadSignerCertificate(string path) =>
        X509Certificate.CreateFromSignedFile(path).GetRawCertData();
#pragma warning restore SYSLIB0057
}

internal sealed class WindowsPdfExtensionRegistrationStore : IPdfExtensionRegistrationStore
{
    private const string KeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CodeSignAutoPdfSupport";

    public bool IsExact(PdfExtensionUninstallRegistration registration)
    {
        Validate(registration);
        using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
        if (key is null)
        {
            return false;
        }

        try
        {
            Verify(key, registration);
            return true;
        }
        catch (InstallException)
        {
            return false;
        }
    }

    public void Create(PdfExtensionUninstallRegistration registration)
    {
        Validate(registration);
        using (var existing = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false))
        {
            if (existing is not null)
            {
                throw new InstallException("pdf_extension_registration_exists");
            }
        }

        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(KeyPath, writable: true)
                ?? throw new InstallException("pdf_extension_registration_failed");
            foreach (var pair in Expected(registration))
            {
                key.SetValue(pair.Key, pair.Value, RegistryValueKind.String);
            }

            Verify(key, registration);
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            Registry.LocalMachine.DeleteSubKey(KeyPath, throwOnMissingSubKey: false);
            throw new InstallException("pdf_extension_registration_failed");
        }
    }

    public void Remove(PdfExtensionUninstallRegistration registration)
    {
        Validate(registration);
        using (var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false))
        {
            if (key is null)
            {
                return;
            }

            Verify(key, registration);
        }

        Registry.LocalMachine.DeleteSubKey(KeyPath, throwOnMissingSubKey: true);
        using var remaining = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
        if (remaining is not null)
        {
            throw new InstallException("pdf_extension_uninstall_state_uncertain");
        }
    }

    private static void Verify(
        RegistryKey key,
        PdfExtensionUninstallRegistration registration)
    {
        var expected = Expected(registration);
        if (key.GetSubKeyNames().Length != 0 ||
            !key.GetValueNames().Order(StringComparer.Ordinal).SequenceEqual(
                expected.Keys.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InstallException("pdf_extension_registration_invalid");
        }

        foreach (var pair in expected)
        {
            if (key.GetValueKind(pair.Key) != RegistryValueKind.String ||
                !string.Equals(
                    key.GetValue(
                        pair.Key,
                        null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames) as string,
                    pair.Value,
                    StringComparison.Ordinal))
            {
                throw new InstallException("pdf_extension_registration_invalid");
            }
        }
    }

    private static IReadOnlyDictionary<string, string> Expected(
        PdfExtensionUninstallRegistration registration) =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DisplayName"] = "CodeSignAuto PDF Support",
            ["DisplayVersion"] = registration.DisplayVersion,
            ["Publisher"] = "CodeSignAuto",
            ["InstallLocation"] = registration.InstallLocation,
            ["DisplayIcon"] = registration.DisplayIcon,
            ["UninstallString"] = registration.UninstallString,
            ["CodeSignAutoOwner"] = registration.OwnerMarker,
        };

    private static void Validate(PdfExtensionUninstallRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (!Path.IsPathFullyQualified(registration.MainExecutable) ||
            !Path.IsPathFullyQualified(registration.InstallLocation) ||
            string.IsNullOrWhiteSpace(registration.DisplayVersion) ||
            !string.Equals(
                registration.DisplayIcon,
                $"\"{registration.MainExecutable}\",0",
                StringComparison.Ordinal) ||
            !string.Equals(
                registration.UninstallString,
                $"\"{registration.MainExecutable}\" pdf-extension uninstall",
                StringComparison.Ordinal) ||
            !string.Equals(
                registration.OwnerMarker,
                $"CodeSignAutoPdfSupport/v1/{registration.DisplayVersion}",
                StringComparison.Ordinal))
        {
            throw new InstallException("pdf_extension_registration_invalid");
        }
    }
}
