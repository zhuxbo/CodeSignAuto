using SimplySignAuto.Core.Versioning;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

internal sealed class ManualUpgradeTransaction : IUpgradeTransaction
{
    private readonly InstallationReceipt _receipt;
    private readonly IInstallationReceiptStore _receiptStore;
    private readonly ProductUninstallRegistration _oldRegistration;
    private readonly ProductUninstallRegistration _newRegistration;
    private readonly IUpgradeMediaTransaction _media;
    private readonly IUpgradeRegistrationStore _registrations;
    private InstallMediaPlan? _mediaPlan;
    private bool _registrationUpdated;
    private bool _committed;

    internal ManualUpgradeTransaction(
        InstallationReceipt receipt,
        IInstallationReceiptStore receiptStore,
        ProductUninstallRegistration oldRegistration,
        ProductUninstallRegistration newRegistration,
        IUpgradeMediaTransaction media,
        IUpgradeRegistrationStore registrations)
    {
        _receipt = InstallationReceiptValidator.Validate(receipt);
        if (_receipt.Mode != InstallationMode.Manual)
        {
            throw new ArgumentException("Manual receipt is required.", nameof(receipt));
        }

        _receiptStore = receiptStore ?? throw new ArgumentNullException(nameof(receiptStore));
        _oldRegistration = oldRegistration ?? throw new ArgumentNullException(nameof(oldRegistration));
        _newRegistration = newRegistration ?? throw new ArgumentNullException(nameof(newRegistration));
        _media = media ?? throw new ArgumentNullException(nameof(media));
        _registrations = registrations ?? throw new ArgumentNullException(nameof(registrations));
    }

    public InstallationMode Mode => InstallationMode.Manual;

    internal static async Task<ManualUpgradeTransaction?> TryCreateAsync(
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var receiptStore = new WindowsInstallationReceiptStore();
        var receipt = await receiptStore.LoadOptionalAsync(cancellationToken).ConfigureAwait(false);
        if (receipt is null || receipt.Mode != InstallationMode.Manual)
        {
            return null;
        }

        if (WindowsPathSafety.EntryExists(WindowsUninstallEnvironment.ConfigurationPath))
        {
            throw new SetupException("owned_resource_mismatch");
        }

        var expectedExecutable = InstallMediaPaths.GetTargetExecutablePath(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        if (!string.Equals(
                receipt.ExecutablePath,
                expectedExecutable,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SetupException("owned_resource_mismatch");
        }

        var plan = await new ManualUninstallPlanner(new WindowsManualUninstallEnvironment(receipt))
            .PlanAsync(new UninstallOptions(PurgeData: false, Confirmation: null), cancellationToken)
            .ConfigureAwait(false);
        await new WindowsManualInstalledMediaUninstallPreflight()
            .VerifyAsync(receipt, cancellationToken)
            .ConfigureAwait(false);
        WindowsManualUninstallOwnership.Verify(plan, expectedExecutable);
        await new WindowsOptionalToolUninstallPreflight()
            .VerifyAsync(
                new InstalledProductIdentity(
                    receipt.ExecutablePath,
                    receipt.SigningUserSid),
                cancellationToken)
            .ConfigureAwait(false);
        var native = new WindowsUninstallNative();
        foreach (var action in plan.Actions)
        {
            switch (action)
            {
                case RemoveOwnedPdfExtension:
                    break;
                case RemoveOwnedDesktopShortcut shortcut:
                    native.VerifyDesktopShortcutOwnership(shortcut);
                    break;
                case RemoveOwnedProductUninstall:
                    break;
                case PurgeControlledData:
                    break;
                default:
                    throw new SetupException("owned_resource_mismatch");
            }
        }

        var ownerMarker = InstallOwnershipMarker.Create(receipt.InstallInstanceId);
        var oldRegistration = WindowsProductUninstallRegistry.ReadExact(
            receipt.ExecutablePath,
            ownerMarker,
            "owned_resource_mismatch");
        var oldVersion = ProductVersion.Parse(oldRegistration.DisplayVersion);
        var newVersion = ProductVersion.Parse(
            SimplySignAuto.App.ApplicationVersion.ReadIdentity(typeof(ManualUpgradeTransaction).Assembly));
        if (newVersion.ComparePrecedenceTo(oldVersion) <= 0)
        {
            throw new SetupException("upgrade_version_not_newer");
        }

        var sourceRoot = Environment.ProcessPath is { } processPath
            ? Path.GetDirectoryName(Path.GetFullPath(processPath))
            : null;
        if (sourceRoot is null)
        {
            throw new SetupException("install_media_source_invalid");
        }

        return new ManualUpgradeTransaction(
            receipt,
            receiptStore,
            oldRegistration,
            ProductUninstallRegistration.Create(
                receipt.ExecutablePath,
                newVersion.Identity,
                ownerMarker),
            new WindowsInstallMediaStager(
                sourceRoot,
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                new WindowsInstallMediaVerifier(),
                () => Guid.NewGuid().ToString("N"),
                new WindowsAtomicProtectedDirectoryOperations(),
                upgrade: true),
            new UpgradeRegistrationStore());
    }

    public async Task StageAsync(CancellationToken cancellationToken)
    {
        await VerifyReceiptAsync(cancellationToken).ConfigureAwait(false);
        _mediaPlan = await _media.PlanAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(
                _mediaPlan.TargetExecutablePath,
                _receipt.ExecutablePath,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new SetupException("owned_resource_mismatch");
        }

        await _media.StageAsync(_mediaPlan, cancellationToken).ConfigureAwait(false);
        await _media.AuthorizeAsync(_mediaPlan, _receipt.SigningUserSid, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task VerifyReplaceableAsync(CancellationToken cancellationToken) =>
        _media.VerifyUpgradeTargetReplaceableAsync(
            _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
            cancellationToken);

    public Task ActivateAsync(CancellationToken cancellationToken) =>
        _media.ActivateUpgradeAsync(
            _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
            cancellationToken);

    public Task VerifyAsync(CancellationToken cancellationToken) =>
        VerifyReceiptAsync(cancellationToken);

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        await VerifyReceiptAsync(cancellationToken).ConfigureAwait(false);
        _registrations.ReplaceExact(
            _oldRegistration,
            _newRegistration,
            "product_registration_failed");
        _registrationUpdated = true;
        await _media.CommitUpgradeAsync(
                _mediaPlan ?? throw new SetupException("upgrade_state_uncertain"),
                cancellationToken)
            .ConfigureAwait(false);
        _committed = true;
    }

    public async Task RollbackAsync()
    {
        if (_committed)
        {
            return;
        }

        var uncertain = false;
        if (_registrationUpdated)
        {
            try
            {
                _registrations.ReplaceExact(
                    _newRegistration,
                    _oldRegistration,
                    "upgrade_state_uncertain");
                _registrationUpdated = false;
            }
            catch
            {
                uncertain = true;
            }
        }

        if (_mediaPlan is not null)
        {
            uncertain |= !await TryAsync(() => _media.RollbackAsync(_mediaPlan))
                .ConfigureAwait(false);
        }

        uncertain |= !await TryAsync(() => VerifyReceiptAsync(CancellationToken.None))
            .ConfigureAwait(false);
        if (uncertain)
        {
            throw new SetupException("upgrade_state_uncertain");
        }
    }

    private async Task VerifyReceiptAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (await _receiptStore.LoadOptionalAsync(cancellationToken).ConfigureAwait(false) != _receipt)
            {
                throw new SetupException("owned_resource_mismatch");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SetupException)
        {
            throw;
        }
        catch
        {
            throw new SetupException("owned_resource_mismatch");
        }
    }

    private static async Task<bool> TryAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
