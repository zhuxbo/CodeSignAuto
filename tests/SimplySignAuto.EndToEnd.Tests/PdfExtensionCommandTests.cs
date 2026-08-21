using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using SimplySignAuto.App;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.Tools;
using SimplySignAuto.Service;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class PdfExtensionCommandTests
{
    [Fact]
    public void Pdf_extension_identity_uses_manual_receipt_without_service_configuration()
    {
        var receipt = InstallationReceipt.ForManual(
            "0123456789abcdef0123456789abcdef",
            "S-1-5-21-1000-2000-3000-4000",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            @"C:\Users\Administrator\AppData\Local\SimplySignAuto\manual");

        var identity = PdfExtensionMainIdentityResolver.Resolve(receipt, configuration: null);

        Assert.Equal(receipt.ExecutablePath, identity.ExecutablePath);
        Assert.Equal(receipt.SigningUserSid, identity.SigningUserSid);
    }

    [Fact]
    public void Pdf_extension_identity_cross_checks_service_receipt_and_configuration()
    {
        var configuration = ServiceConfigurationLoader.Validate(new ServiceConfiguration(
            new string('a', 64),
            "S-1-5-21-1000-2000-3000-4000",
            @"C:\ProgramData\SimplySignAuto",
            @"C:\ProgramData\SimplySignAuto\spool",
            7080,
            "SimplySignAuto/v1",
            "0123456789abcdef0123456789abcdef",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            @"C:\Users\SimplySignAgent\AppData\Local\SimplySignAuto\agent.json"));
        var receipt = InstallationReceipt.ForService(configuration);

        var exact = PdfExtensionMainIdentityResolver.Resolve(receipt, configuration);
        var error = Assert.Throws<InstallException>(() =>
            PdfExtensionMainIdentityResolver.Resolve(
                receipt,
                configuration with { SigningUserSid = "S-1-5-21-1000-2000-3000-4001" }));

        Assert.Equal(configuration.ExecutablePath, exact.ExecutablePath);
        Assert.Equal("pdf_extension_main_invalid", error.Code);
    }

    [Fact]
    public void Pdf_extension_identity_rejects_missing_receipt_and_manual_service_conflicts()
    {
        var manual = InstallationReceipt.ForManual(
            "0123456789abcdef0123456789abcdef",
            "S-1-5-21-1000-2000-3000-4000",
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            @"C:\Users\Administrator\AppData\Local\SimplySignAuto\manual");
        var configuration = new ServiceConfiguration(
            new string('a', 64),
            manual.SigningUserSid,
            @"C:\ProgramData\SimplySignAuto",
            @"C:\ProgramData\SimplySignAuto\spool",
            7080,
            "SimplySignAuto/v1",
            manual.InstallInstanceId,
            manual.ExecutablePath,
            @"C:\Users\Administrator\AppData\Local\SimplySignAuto\agent.json");

        Assert.Equal(
            "pdf_extension_main_invalid",
            Assert.Throws<InstallException>(() =>
                PdfExtensionMainIdentityResolver.Resolve(receipt: null, configuration: null)).Code);
        Assert.Equal(
            "pdf_extension_main_invalid",
            Assert.Throws<InstallException>(() =>
                PdfExtensionMainIdentityResolver.Resolve(manual, configuration)).Code);
    }

    [WindowsFact]
    public async Task Install_requires_elevated_administrator_before_planning_or_mutation()
    {
        var operations = new RecordingPdfExtensionOperations { IsAdministrator = false };
        using var error = new StringWriter();

        var exitCode = await PdfExtensionCommand.ExecuteAsync(
            ["install", "--media-root", @"C:\ProgramData\SimplySignAuto\setup\pdf"],
            TextWriter.Null,
            error,
            CancellationToken.None,
            operations);

        Assert.Equal(1, exitCode);
        Assert.Equal("administrator_required", error.ToString().Trim());
        Assert.Equal(["administrator"], operations.Events);
    }

    [WindowsFact]
    public async Task Install_plans_the_complete_source_before_the_single_publication_mutation()
    {
        var operations = new RecordingPdfExtensionOperations();
        using var output = new StringWriter();

        var exitCode = await PdfExtensionCommand.ExecuteAsync(
            ["install", "--media-root", @"C:\ProgramData\SimplySignAuto\setup\pdf"],
            output,
            TextWriter.Null,
            CancellationToken.None,
            operations);

        Assert.Equal(0, exitCode);
        Assert.Equal(
            ["phase=pdf_extension_media code=ready", "pdf_extension_installed"],
            output.ToString().Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries));
        Assert.Equal(["administrator", "plan", "publish"], operations.Events);
    }

    [WindowsFact]
    public async Task Planning_failure_returns_the_stable_code_without_publication()
    {
        var operations = new RecordingPdfExtensionOperations
        {
            PlanFailure = new InstallException("pdf_extension_media_invalid"),
        };
        using var error = new StringWriter();

        var exitCode = await PdfExtensionCommand.ExecuteAsync(
            ["install", "--media-root", @"C:\ProgramData\SimplySignAuto\setup\pdf"],
            TextWriter.Null,
            error,
            CancellationToken.None,
            operations);

        Assert.Equal(1, exitCode);
        Assert.Equal("pdf_extension_media_invalid", error.ToString().Trim());
        Assert.Equal(["administrator", "plan"], operations.Events);
    }

    [WindowsFact]
    public async Task Uninstall_uses_the_same_administrator_gate_and_cleanup_implementation()
    {
        var operations = new RecordingPdfExtensionOperations();
        using var output = new StringWriter();

        var exitCode = await PdfExtensionCommand.ExecuteAsync(
            ["uninstall"],
            output,
            TextWriter.Null,
            CancellationToken.None,
            operations);

        Assert.Equal(0, exitCode);
        Assert.Equal("pdf_extension_uninstalled", output.ToString().Trim());
        Assert.Equal(["administrator", "uninstall"], operations.Events);
    }

    [WindowsFact]
    public void Elevation_relaunches_only_the_exact_internal_route_and_waits_for_its_exit()
    {
        var launcher = new RecordingElevationLauncher(exitCode: 17);
        var exitCode = PdfExtensionElevation.RelaunchElevatedAndWait(
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            ["install", "--media-root", @"C:\ProgramData\SimplySignAuto\setup\pdf"],
            TextWriter.Null,
            launcher);

        Assert.Equal(17, exitCode);
        Assert.Equal(
            [
                "pdf-extension",
                "install",
                "--media-root",
                @"C:\ProgramData\SimplySignAuto\setup\pdf",
            ],
            launcher.Arguments);
        Assert.Equal("runas", launcher.Verb);

        using var error = new StringWriter();
        Assert.Equal(1, PdfExtensionElevation.RelaunchElevatedAndWait(
            @"C:\Program Files\SimplySignAuto\SimplySignAuto.exe",
            ["install", "--media-root", "relative"],
            error,
            launcher));
        Assert.Equal("pdf_extension_elevation_failed", error.ToString().Trim());
    }

    [WindowsAdministratorFact]
    public async Task Windows_installer_publishes_the_exact_tree_before_registration()
    {
        using var fixture = new WindowsInstallFixture();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration);

        var plan = await operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);

        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Empty(registration.Events);

        await operations.PublishInstallAsync(plan, CancellationToken.None);

        Assert.Equal(
            [
                "extension.json",
                "LICENSE.txt",
                "SimplySignPdfSigner.exe",
                "THIRD-PARTY-NOTICES.txt",
            ],
            Directory.EnumerateFiles(fixture.TargetRoot)
                .Select(path => Path.GetFileName(path)!)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray());
        Assert.Equal(
            ["verify-source", "verify-staging", "verify-final"],
            verifier.Events);
        Assert.Equal(["register"], registration.Events);
        Assert.True(registration.TargetExistedWhenCreated);
        Assert.Empty(Directory.EnumerateFileSystemEntries(
            fixture.ProgramFilesRoot,
            "SimplySignAuto PDF Support.part-*"));
    }

    [WindowsAdministratorFact]
    public async Task Manual_receipt_installs_and_uninstalls_the_pdf_extension()
    {
        using var fixture = new WindowsInstallFixture();
        var receipt = InstallationReceipt.ForManual(
            fixture.Configuration.InstallInstanceId,
            fixture.Configuration.SigningUserSid,
            fixture.MainExecutable,
            Path.Combine(fixture.Root, "manual"));
        var identity = PdfExtensionMainIdentityResolver.Resolve(receipt, configuration: null);
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration, identity: identity);

        var plan = await operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);
        await operations.PublishInstallAsync(plan, CancellationToken.None);
        await operations.UninstallAsync(CancellationToken.None);

        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Equal(["register", "remove"], registration.Events);
    }

    [WindowsAdministratorFact]
    public async Task Windows_installer_rejects_an_unknown_media_member_before_target_mutation()
    {
        using var fixture = new WindowsInstallFixture();
        fixture.AddUnknownMediaFile();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None));

        Assert.Equal("pdf_extension_media_invalid", failure.Code);
        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Empty(verifier.Events);
        Assert.Empty(registration.Events);
    }

    [WindowsAdministratorTheory]
    [InlineData("hardlink")]
    [InlineData("reparse")]
    [InlineData("acl")]
    public async Task Windows_installer_rejects_unsafe_media_before_target_mutation(string mismatch)
    {
        using var fixture = new WindowsInstallFixture();
        fixture.IntroduceUnsafeMedia(mismatch);
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration);

        var failure = await Assert.ThrowsAsync<InstallException>(() =>
            operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None));

        Assert.Equal("pdf_extension_media_invalid", failure.Code);
        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Empty(verifier.Events);
        Assert.Empty(registration.Events);
    }

    [WindowsAdministratorFact]
    public async Task Windows_installer_is_idempotent_only_for_the_exact_verified_installation()
    {
        using var fixture = new WindowsInstallFixture();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var first = fixture.CreateOperations(verifier, registration);
        var firstPlan = await first.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);
        await first.PublishInstallAsync(firstPlan, CancellationToken.None);
        var helperBefore = await File.ReadAllBytesAsync(
            Path.Combine(fixture.TargetRoot, "SimplySignPdfSigner.exe"));

        var second = fixture.CreateOperations(verifier, registration);
        var secondPlan = await second.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);
        await second.PublishInstallAsync(secondPlan, CancellationToken.None);

        Assert.Equal(helperBefore, await File.ReadAllBytesAsync(
            Path.Combine(fixture.TargetRoot, "SimplySignPdfSigner.exe")));
        Assert.Equal(1, registration.Events.Count(item => item == "register"));
        Assert.Equal(1, verifier.Events.Count(item => item == "verify-existing"));
        Assert.Empty(Directory.EnumerateFileSystemEntries(
            fixture.ProgramFilesRoot,
            "SimplySignAuto PDF Support.part-*"));
    }

    [WindowsAdministratorFact]
    public async Task Windows_installer_cancellation_after_staging_creation_removes_only_its_partial_tree()
    {
        using var fixture = new WindowsInstallFixture();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration);
        var plan = await operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            operations.PublishInstallAsync(plan, cancellation.Token));

        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Empty(Directory.EnumerateFileSystemEntries(
            fixture.ProgramFilesRoot,
            "SimplySignAuto PDF Support.part-*"));
        Assert.Empty(registration.Events);
        Assert.True(File.Exists(Path.Combine(fixture.MediaRoot, "extension.json")));
        Assert.True(File.Exists(Path.Combine(fixture.MediaRoot, "SimplySignPdfSigner.exe")));
    }

    [WindowsAdministratorFact]
    public async Task Windows_extension_uninstall_removes_the_exact_verified_tree_and_registration()
    {
        using var fixture = new WindowsInstallFixture();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var operations = fixture.CreateOperations(verifier, registration);
        var plan = await operations.PlanInstallAsync(fixture.MediaRoot, CancellationToken.None);
        await operations.PublishInstallAsync(plan, CancellationToken.None);

        await operations.UninstallAsync(CancellationToken.None);

        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Equal(["register", "remove"], registration.Events);
        Assert.Equal(1, verifier.Events.Count(item => item == "verify-existing"));
        Assert.True(File.Exists(Path.Combine(fixture.MediaRoot, "extension.json")));
        Assert.True(File.Exists(Path.Combine(fixture.MediaRoot, "SimplySignPdfSigner.exe")));
    }

    [WindowsAdministratorFact]
    public async Task Newer_main_uninstalls_an_older_verified_pdf_extension_using_its_manifest_version()
    {
        using var fixture = new WindowsInstallFixture();
        var verifier = new RecordingArtifactVerifier(fixture.Manifest);
        var registration = new RecordingRegistrationStore();
        var originalMain = fixture.CreateOperations(
            verifier,
            registration,
            productVersion: "0.16.0");
        var plan = await originalMain.PlanInstallAsync(
            fixture.MediaRoot,
            CancellationToken.None);
        await originalMain.PublishInstallAsync(plan, CancellationToken.None);

        var upgradedMain = fixture.CreateOperations(
            verifier,
            registration,
            productVersion: "0.17.0");
        await upgradedMain.UninstallAsync(CancellationToken.None);

        Assert.False(Directory.Exists(fixture.TargetRoot));
        Assert.Equal("0.16.0", registration.RemovedRegistration?.DisplayVersion);
        Assert.Equal(
            "SimplySignAutoPdfSupport/v1/0.16.0",
            registration.RemovedRegistration?.OwnerMarker);
    }

    private sealed class RecordingPdfExtensionOperations : IPdfExtensionOperations
    {
        public bool IsAdministrator { get; init; } = true;

        public Exception? PlanFailure { get; init; }

        public List<string> Events { get; } = [];

        public void RequireAdministrator()
        {
            Events.Add("administrator");
            if (!IsAdministrator)
            {
                throw new InstallException("administrator_required");
            }
        }

        public Task<PdfExtensionInstallPlan> PlanInstallAsync(
            string mediaRoot,
            CancellationToken cancellationToken)
        {
            Events.Add("plan");
            if (PlanFailure is not null)
            {
                return Task.FromException<PdfExtensionInstallPlan>(PlanFailure);
            }

            return Task.FromResult(new PdfExtensionInstallPlan(
                PdfExtensionPaths.FromProgramFiles(@"C:\Program Files"),
                new PdfExtensionManifest(
                    1,
                    "0.16.0",
                    "0.1.0",
                    42,
                    new string('a', 64),
                    new string('b', 64)),
                "S-1-5-21-1000-2000-3000-4000",
                "0123456789abcdef0123456789abcdef"));
        }

        public Task PublishInstallAsync(
            PdfExtensionInstallPlan plan,
            CancellationToken cancellationToken)
        {
            Events.Add("publish");
            return Task.CompletedTask;
        }

        public Task UninstallAsync(CancellationToken cancellationToken)
        {
            Events.Add("uninstall");
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingElevationLauncher(int exitCode) : IUninstallElevationLauncher
    {
        public IReadOnlyList<string>? Arguments { get; private set; }

        public string? Verb { get; private set; }

        public int LaunchAndWait(
            string executablePath,
            IReadOnlyList<string> arguments,
            string verb)
        {
            Arguments = arguments;
            Verb = verb;
            return exitCode;
        }
    }

    private sealed class RecordingArtifactVerifier(PdfExtensionManifest manifest)
        : IPdfExtensionArtifactVerifier
    {
        public List<string> Events { get; } = [];

        public Task<PdfExtensionManifest> VerifySourceAsync(
            PdfExtensionPaths paths,
            string mainExecutable,
            CancellationToken cancellationToken)
        {
            Events.Add("verify-source");
            Assert.EndsWith(
                Path.Combine("SimplySignAuto", "SimplySignAuto.exe"),
                mainExecutable,
                StringComparison.OrdinalIgnoreCase);
            return Task.FromResult(manifest);
        }

        public Task VerifyInstalledAsync(
            PdfExtensionPaths paths,
            PdfExtensionManifest expected,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            Assert.True(File.Exists(paths.Manifest));
            Assert.True(File.Exists(paths.Helper));
            Events.Add(paths.Root.Contains(".part-", StringComparison.Ordinal)
                ? "verify-staging"
                : "verify-final");
            return Task.CompletedTask;
        }

        public Task<PdfExtensionManifest> ReadAndVerifyInstalledAsync(
            PdfExtensionPaths paths,
            string mainExecutable,
            string signingUserSid,
            CancellationToken cancellationToken)
        {
            Events.Add("verify-existing");
            return Task.FromResult(manifest);
        }
    }

    private sealed class RecordingRegistrationStore : IPdfExtensionRegistrationStore
    {
        private PdfExtensionUninstallRegistration? _registration;

        public List<string> Events { get; } = [];

        public bool TargetExistedWhenCreated { get; private set; }

        public PdfExtensionUninstallRegistration? RemovedRegistration { get; private set; }

        public void Create(PdfExtensionUninstallRegistration registration)
        {
            Assert.Null(_registration);
            _registration = registration;
            Events.Add("register");
            TargetExistedWhenCreated = Directory.Exists(registration.InstallLocation);
        }

        public bool IsExact(PdfExtensionUninstallRegistration registration) =>
            _registration == registration;

        public void Remove(PdfExtensionUninstallRegistration registration)
        {
            if (_registration is not null)
            {
                Assert.Equal(_registration, registration);
                RemovedRegistration = registration;
                _registration = null;
                Events.Add("remove");
            }
        }
    }

    private sealed class StaticPdfExtensionMainIdentitySource(InstalledProductIdentity identity)
        : IPdfExtensionMainIdentitySource
    {
        public Task<InstalledProductIdentity> LoadAsync(CancellationToken cancellationToken) =>
            Task.FromResult(identity);
    }

    private sealed class WindowsInstallFixture : IDisposable
    {
        private readonly SecurityIdentifier _signingUser = new(
            WellKnownSidType.BuiltinUsersSid,
            domainSid: null);

        public WindowsInstallFixture()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "SimplySignAuto.PdfExtension",
                Guid.NewGuid().ToString("N"));
            ProgramFilesRoot = Path.Combine(Root, "Program Files");
            var productRoot = Path.Combine(ProgramFilesRoot, "SimplySignAuto");
            ProgramDataRoot = Path.Combine(Root, "ProgramData");
            MediaRoot = Path.Combine(Root, "media");
            TargetRoot = Path.Combine(ProgramFilesRoot, "SimplySignAuto PDF Support");
            MainExecutable = Path.Combine(productRoot, "SimplySignAuto.exe");
            Directory.CreateDirectory(productRoot);
            Directory.CreateDirectory(ProgramDataRoot);
            Directory.CreateDirectory(MediaRoot);
            File.WriteAllText(MainExecutable, "main-fixture");
            WindowsInstallAcl.ApplyDirectory(
                MediaRoot,
                InstallAclProfile.AdministratorsOnly,
                _signingUser);

            var helper = Path.Combine(MediaRoot, "SimplySignPdfSigner.exe");
            File.WriteAllText(helper, "signed-helper-fixture");
            Manifest = new PdfExtensionManifest(
                1,
                "0.16.0",
                "0.1.0",
                new FileInfo(helper).Length,
                new string('a', 64),
                new string('b', 64));
            File.WriteAllText(
                Path.Combine(MediaRoot, "extension.json"),
                JsonSerializer.Serialize(new
                {
                    schemaVersion = Manifest.SchemaVersion,
                    productVersion = Manifest.ProductVersion,
                    helperVersion = Manifest.HelperVersion,
                    helperLength = Manifest.HelperLength,
                    helperSha256 = Manifest.HelperSha256,
                    publisherCertificateSha256 = Manifest.PublisherCertificateSha256,
                }));
            File.WriteAllText(Path.Combine(MediaRoot, "LICENSE.txt"), "MIT fixture");
            File.WriteAllText(
                Path.Combine(MediaRoot, "THIRD-PARTY-NOTICES.txt"),
                "Third-party notice fixture");
            foreach (var file in Directory.EnumerateFiles(MediaRoot))
            {
                WindowsInstallAcl.ApplyFile(
                    file,
                    InstallAclProfile.AdministratorsOnly,
                    _signingUser);
            }

            Configuration = new ServiceConfiguration(
                new string('c', 64),
                _signingUser.Value,
                Path.Combine(ProgramDataRoot, "SimplySignAuto"),
                Path.Combine(ProgramDataRoot, "SimplySignAuto", "spool"),
                7080,
                "SimplySignAuto/v1",
                "0123456789abcdef0123456789abcdef",
                MainExecutable,
                Path.Combine(Root, "agent.json"));
        }

        public string Root { get; }

        public string ProgramFilesRoot { get; }

        public string ProgramDataRoot { get; }

        public string MediaRoot { get; }

        public string TargetRoot { get; }

        public string MainExecutable { get; }

        public PdfExtensionManifest Manifest { get; }

        public ServiceConfiguration Configuration { get; }

        public WindowsPdfExtensionOperations CreateOperations(
            IPdfExtensionArtifactVerifier verifier,
            IPdfExtensionRegistrationStore registration,
            string productVersion = "0.16.0",
            InstalledProductIdentity? identity = null) => new(
                new PdfExtensionRuntimeContext(
                    ProgramFilesRoot,
                    ProgramDataRoot,
                    MainExecutable,
                    productVersion),
                new StaticPdfExtensionMainIdentitySource(identity ?? new InstalledProductIdentity(
                    Configuration.ExecutablePath,
                    Configuration.SigningUserSid)),
                verifier,
                registration,
                () => "0123456789abcdef0123456789abcdef");

        public void AddUnknownMediaFile()
        {
            var path = Path.Combine(MediaRoot, "unknown.bin");
            File.WriteAllText(path, "unknown");
            WindowsInstallAcl.ApplyFile(
                path,
                InstallAclProfile.AdministratorsOnly,
                _signingUser);
        }

        public void IntroduceUnsafeMedia(string mismatch)
        {
            var helper = Path.Combine(MediaRoot, "SimplySignPdfSigner.exe");
            switch (mismatch)
            {
                case "hardlink":
                    var hardlink = Path.Combine(Root, "helper-hardlink.exe");
                    if (!CreateHardLinkW(hardlink, helper, nint.Zero))
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    }

                    break;
                case "reparse":
                    var external = Path.Combine(Root, "external-helper.exe");
                    File.WriteAllText(external, "signed-helper-fixture");
                    File.Delete(helper);
                    File.CreateSymbolicLink(helper, external);
                    break;
                case "acl":
                    WindowsInstallAcl.ApplyFile(
                        helper,
                        InstallAclProfile.SigningUserRead,
                        _signingUser);
                    break;
                default:
                    throw new InvalidOperationException("unknown_fixture_mismatch");
            }
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows path semantics.";
            }
        }
    }

    private sealed class WindowsAdministratorTheoryAttribute : TheoryAttribute
    {
        public WindowsAdministratorTheoryAttribute()
        {
            if (!OperatingSystem.IsWindows() ||
                !string.Equals(
                    Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_ADMIN_INTEGRATION"),
                    "1",
                    StringComparison.Ordinal))
            {
                Skip = "Requires an explicitly enabled elevated Windows integration run.";
            }
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string fileName,
        string existingFileName,
        nint securityAttributes);
}
