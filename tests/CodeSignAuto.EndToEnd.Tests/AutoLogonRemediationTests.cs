using CodeSignAuto.App.Commands;
using CodeSignAuto.App;
using Microsoft.Win32;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class AutoLogonRemediationTests
{
    [Fact]
    public async Task Setup_cleanup_command_accepts_only_the_exact_internal_route()
    {
        Assert.Equal(
            ApplicationEntryKind.AutoLogonRemediation,
            ApplicationEntryRoute.Parse(["setup-disable-autologon"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["setup-disable-autologon", "extra"]).Kind);

        var platform = RecordingPlatform.Conflicted();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await DisableAutoLogonCommand.ExecuteAsync(
            [],
            platform,
            output,
            error,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal("autologon_disabled" + Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());

        platform = RecordingPlatform.Conflicted();
        exitCode = await DisableAutoLogonCommand.ExecuteAsync(
            ["extra"],
            platform,
            TextWriter.Null,
            error,
            CancellationToken.None);
        Assert.Equal(2, exitCode);
        Assert.Empty(platform.Events);
        Assert.Equal(
            "autologon_cleanup_arguments_invalid" + Environment.NewLine,
            error.ToString());
    }

    [Fact]
    public async Task Confirmed_cleanup_disables_AutoLogon_before_removing_saved_credentials()
    {
        var platform = RecordingPlatform.Conflicted();
        using var output = new StringWriter();

        await new AutoLogonRemediationOrchestrator(platform).ExecuteAsync(
            output,
            CancellationToken.None);

        Assert.Equal(
            ["inspect", "disable-registry", "inspect", "remove-lsa", "inspect"],
            platform.Events);
        Assert.False(platform.State.AutoAdminLogonEnabled);
        Assert.False(platform.State.RegistryDefaultPasswordPresent);
        Assert.False(platform.State.LsaDefaultPasswordPresent);
        Assert.Equal("autologon_disabled" + Environment.NewLine, output.ToString());
    }

    [Fact]
    public async Task Product_owned_state_is_rejected_before_any_cleanup_mutation()
    {
        var platform = RecordingPlatform.Conflicted() with
        {
            State = RecordingPlatform.Conflicted().State with { ProductStatePresent = true },
        };

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationOrchestrator(platform).ExecuteAsync(
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("autologon_cleanup_owned_state", failure.Code);
        Assert.Equal(["inspect"], platform.Events);
    }

    [Fact]
    public async Task Registry_readback_failure_stops_before_LSA_cleanup()
    {
        var platform = RecordingPlatform.Conflicted() with { KeepRegistryConflict = true };

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationOrchestrator(platform).ExecuteAsync(
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("autologon_cleanup_failed", failure.Code);
        Assert.Equal(["inspect", "disable-registry", "inspect"], platform.Events);
        Assert.DoesNotContain("remove-lsa", platform.Events);
    }

    [Fact]
    public async Task State_drift_after_mutation_reports_partial_cleanup_failure()
    {
        var platform = RecordingPlatform.Conflicted() with
        {
            ProductAppearsAfterRegistryMutation = true,
        };

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationOrchestrator(platform).ExecuteAsync(
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("autologon_cleanup_failed", failure.Code);
        Assert.Equal(["inspect", "disable-registry", "inspect"], platform.Events);
    }

    [Fact]
    public async Task LSA_removal_must_be_confirmed_absent_before_reporting_success()
    {
        var platform = RecordingPlatform.Conflicted() with { KeepLsaSecret = true };

        var failure = await Assert.ThrowsAsync<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationOrchestrator(platform).ExecuteAsync(
                TextWriter.Null,
                CancellationToken.None));

        Assert.Equal("autologon_cleanup_failed", failure.Code);
        Assert.Equal(
            ["inspect", "disable-registry", "inspect", "remove-lsa", "inspect"],
            platform.Events);
    }

    [Fact]
    public void Registry_cleanup_changes_only_AutoAdminLogon_and_DefaultPassword()
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
            ["DefaultPassword"] = WinlogonStoredValue.String("legacy-password-not-read"),
            ["DefaultUserName"] = WinlogonStoredValue.String("Administrator"),
            ["DefaultDomainName"] = WinlogonStoredValue.String("SIGNING-SERVER"),
            ["UnrelatedValue"] = WinlogonStoredValue.DWord(7),
        });

        new AutoLogonRemediationRegistry(store).DisableAndVerify();

        Assert.Equal(WinlogonStoredValue.String("0"), store.Read("AutoAdminLogon"));
        Assert.False(store.HasValue("DefaultPassword"));
        Assert.Equal(WinlogonStoredValue.String("Administrator"), store.Read("DefaultUserName"));
        Assert.Equal(WinlogonStoredValue.String("SIGNING-SERVER"), store.Read("DefaultDomainName"));
        Assert.Equal(WinlogonStoredValue.DWord(7), store.Read("UnrelatedValue"));
        Assert.Equal(
            ["write:AutoAdminLogon", "flush", "delete:DefaultPassword", "flush"],
            store.Mutations);
    }

    [Fact]
    public void AutoAdminLogon_readback_failure_preserves_saved_credentials()
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
            ["DefaultPassword"] = WinlogonStoredValue.String("legacy-password-not-read"),
        })
        {
            IgnoreAutoAdminLogonWrite = true,
        };

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationRegistry(store).DisableAndVerify());

        Assert.Equal("autologon_cleanup_failed", failure.Code);
        Assert.True(store.HasValue("DefaultPassword"));
        Assert.Equal(["write:AutoAdminLogon", "flush"], store.Mutations);
    }

    [Fact]
    public void Registry_cleanup_never_reads_saved_password_contents()
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
            ["DefaultPassword"] = WinlogonStoredValue.String("content-must-not-be-read"),
        })
        {
            ThrowOnDefaultPasswordRead = true,
        };

        new AutoLogonRemediationRegistry(store).DisableAndVerify();

        Assert.False(store.HasValue("DefaultPassword"));
    }

    [Fact]
    public void Non_string_DefaultPassword_is_rejected_without_mutation()
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
            ["DefaultPassword"] = WinlogonStoredValue.DWord(7),
        })
        {
            ThrowOnDefaultPasswordRead = true,
        };

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationRegistry(store).DisableAndVerify());

        Assert.Equal("autologon_cleanup_state_uncertain", failure.Code);
        Assert.Empty(store.Mutations);
        Assert.True(store.HasValue("DefaultPassword"));
    }

    [Fact]
    public void External_product_resources_are_folded_into_the_registry_inspection()
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
        });

        var inspection = new AutoLogonRemediationRegistry(store).Inspect(
            isAdministrator: true,
            managedAgentUserExists: false,
            lsaDefaultPasswordPresent: true,
            externalProductStatePresent: true);

        Assert.True(inspection.ProductStatePresent);
    }

    [Theory]
    [InlineData("CodeSignAutoAgentUserOwner")]
    [InlineData("CodeSignAutoUninstallState")]
    [InlineData("CodeSignAutoLsaDefaultPasswordOwner")]
    public void Product_owned_registry_state_blocks_cleanup(string markerName)
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = WinlogonStoredValue.String("1"),
            [markerName] = WinlogonStoredValue.String("owned"),
        });

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationRegistry(store).DisableAndVerify());

        Assert.Equal("autologon_cleanup_owned_state", failure.Code);
        Assert.Empty(store.Mutations);
    }

    [Theory]
    [InlineData(RegistryValueKind.DWord, 1)]
    [InlineData(RegistryValueKind.String, "yes")]
    public void Invalid_AutoAdminLogon_value_blocks_cleanup(
        RegistryValueKind kind,
        object value)
    {
        var store = new RecordingWinlogonStore(new Dictionary<string, WinlogonStoredValue>
        {
            ["AutoAdminLogon"] = new WinlogonStoredValue(true, value, kind),
        });

        var failure = Assert.Throws<ProvisionAgentUserException>(() =>
            new AutoLogonRemediationRegistry(store).DisableAndVerify());

        Assert.Equal("autologon_cleanup_state_uncertain", failure.Code);
        Assert.Empty(store.Mutations);
    }

    private sealed record RecordingPlatform : IAutoLogonRemediationPlatform
    {
        public AutoLogonRemediationInspection State { get; set; } = ConflictedState();

        public bool KeepRegistryConflict { get; init; }

        public bool KeepLsaSecret { get; init; }

        public bool ProductAppearsAfterRegistryMutation { get; init; }

        public List<string> Events { get; } = [];

        public static RecordingPlatform Conflicted() => new();

        public Task<AutoLogonRemediationInspection> InspectAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("inspect");
            return Task.FromResult(State);
        }

        public Task DisableRegistryAutoLogonAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("disable-registry");
            if (!KeepRegistryConflict)
            {
                State = State with
                {
                    AutoAdminLogonEnabled = false,
                    RegistryDefaultPasswordPresent = false,
                    ProductStatePresent = ProductAppearsAfterRegistryMutation,
                };
            }

            return Task.CompletedTask;
        }

        public Task RemoveLsaDefaultPasswordAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("remove-lsa");
            if (!KeepLsaSecret)
            {
                State = State with { LsaDefaultPasswordPresent = false };
            }

            return Task.CompletedTask;
        }

        private static AutoLogonRemediationInspection ConflictedState() => new(
            IsAdministrator: true,
            AutoAdminLogonValueValid: true,
            DefaultPasswordValueValid: true,
            ProductStatePresent: false,
            ManagedAgentUserExists: false,
            AutoAdminLogonEnabled: true,
            RegistryDefaultPasswordPresent: true,
            LsaDefaultPasswordPresent: true);
    }

    private sealed class RecordingWinlogonStore(
        IReadOnlyDictionary<string, WinlogonStoredValue> initial) : IWinlogonValueStore
    {
        private readonly Dictionary<string, WinlogonStoredValue> _values =
            new(initial, StringComparer.OrdinalIgnoreCase);

        public List<string> Mutations { get; } = [];

        public bool IgnoreAutoAdminLogonWrite { get; init; }

        public bool ThrowOnDefaultPasswordRead { get; init; }

        public bool HasValue(string name) => _values.ContainsKey(name);

        public IReadOnlyCollection<string> GetValueNames() => _values.Keys.ToArray();

        public RegistryValueKind? ReadKind(string name) =>
            _values.TryGetValue(name, out var value) ? value.Kind : null;

        public WinlogonStoredValue Read(string name)
        {
            if (ThrowOnDefaultPasswordRead &&
                string.Equals(name, "DefaultPassword", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("DefaultPassword contents must not be read.");
            }

            return _values.TryGetValue(name, out var value) ? value : WinlogonStoredValue.Missing;
        }

        public void Write(string name, WinlogonStoredValue value)
        {
            Mutations.Add("write:" + name);
            if (!IgnoreAutoAdminLogonWrite ||
                !string.Equals(name, "AutoAdminLogon", StringComparison.OrdinalIgnoreCase))
            {
                _values[name] = value;
            }
        }

        public void Delete(string name)
        {
            Mutations.Add("delete:" + name);
            _values.Remove(name);
        }

        public void Flush() => Mutations.Add("flush");
    }
}
