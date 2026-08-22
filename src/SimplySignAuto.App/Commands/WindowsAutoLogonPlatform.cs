using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

internal interface IWindowsLsaSecretStore
{
    bool Exists();

    bool MatchesFingerprint(ReadOnlySpan<byte> expectedFingerprint);

    void Store(SensitiveAgentUserPassword password);

    void Remove();
}

internal interface IWindowsLsaOwnerReceiptStore
{
    string? ReadReceipt();

    void WriteReceipt(string receipt);

    void RemoveReceipt();
}

internal sealed class SensitiveLsaSecretFingerprint : IDisposable
{
    private byte[]? _value;

    private SensitiveLsaSecretFingerprint(byte[] value) => _value = value;

    public static SensitiveLsaSecretFingerprint Compute(ReadOnlySpan<char> secret)
    {
        var value = new byte[System.Security.Cryptography.SHA256.HashSizeInBytes];
        try
        {
            System.Security.Cryptography.SHA256.HashData(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(secret),
                value);
            return new SensitiveLsaSecretFingerprint(value);
        }
        catch
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);
            throw;
        }
    }

    public ReadOnlySpan<byte> AsSpan() =>
        _value ?? throw new ObjectDisposedException(nameof(SensitiveLsaSecretFingerprint));

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _value, null);
        if (value is not null)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);
        }
    }
}

internal static class LsaSecretReceipt
{
    private const string Separator = "/sha256/";
    private const int FingerprintBytes = System.Security.Cryptography.SHA256.HashSizeInBytes;

    public static string Create(string ownerMarker, ReadOnlySpan<byte> fingerprint)
    {
        if (fingerprint.Length != FingerprintBytes)
        {
            throw new ProvisionAgentUserException("lsa_secret_receipt_failed");
        }

        return ownerMarker + Separator + Convert.ToHexString(fingerprint);
    }

    public static bool IsForOwner(string? receipt, string ownerMarker)
    {
        Span<byte> fingerprint = stackalloc byte[FingerprintBytes];
        try
        {
            return TryReadFingerprint(receipt, ownerMarker, fingerprint);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(fingerprint);
        }
    }

    public static bool Matches(
        string? receipt,
        string ownerMarker,
        ReadOnlySpan<byte> expectedFingerprint)
    {
        if (expectedFingerprint.Length != FingerprintBytes)
        {
            return false;
        }

        Span<byte> actualFingerprint = stackalloc byte[FingerprintBytes];
        try
        {
            return TryReadFingerprint(receipt, ownerMarker, actualFingerprint) &&
                System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    actualFingerprint,
                    expectedFingerprint);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(actualFingerprint);
        }
    }

    public static bool TryReadFingerprint(
        string? receipt,
        string ownerMarker,
        Span<byte> fingerprint)
    {
        fingerprint.Clear();
        if (fingerprint.Length != FingerprintBytes || receipt is null)
        {
            return false;
        }

        var prefix = ownerMarker + Separator;
        return receipt.Length == prefix.Length + (FingerprintBytes * 2) &&
            receipt.StartsWith(prefix, StringComparison.Ordinal) &&
            TryDecodeHex(receipt.AsSpan(prefix.Length), fingerprint);
    }

    private static bool TryDecodeHex(ReadOnlySpan<char> value, Span<byte> destination)
    {
        if (value.Length != destination.Length * 2)
        {
            return false;
        }

        for (var index = 0; index < destination.Length; index++)
        {
            var high = HexNibble(value[index * 2]);
            var low = HexNibble(value[(index * 2) + 1]);
            if (high < 0 || low < 0)
            {
                destination.Clear();
                return false;
            }

            destination[index] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int HexNibble(char value) => value switch
    {
        >= '0' and <= '9' => value - '0',
        >= 'A' and <= 'F' => value - 'A' + 10,
        _ => -1,
    };
}

internal sealed class OwnedLsaSecretTransaction
{
    private readonly IWindowsLsaSecretStore _secret;
    private readonly IWindowsLsaOwnerReceiptStore _receipt;

    public OwnedLsaSecretTransaction(
        IWindowsLsaSecretStore secret,
        IWindowsLsaOwnerReceiptStore receipt)
    {
        _secret = secret ?? throw new ArgumentNullException(nameof(secret));
        _receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
    }

    public void Store(SensitiveAgentUserPassword password, string ownerMarker)
    {
        ArgumentNullException.ThrowIfNull(password);
        ValidateOwner(ownerMarker);
        if (_secret.Exists() || _receipt.ReadReceipt() is not null)
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }

        using var fingerprint = SensitiveLsaSecretFingerprint.Compute(password.AsSpan());
        var receiptValue = LsaSecretReceipt.Create(ownerMarker, fingerprint.AsSpan());
        var receiptWritten = false;
        var secretWritten = false;
        try
        {
            _receipt.WriteReceipt(receiptValue);
            receiptWritten = true;
            if (!LsaSecretReceipt.Matches(
                    _receipt.ReadReceipt(),
                    ownerMarker,
                    fingerprint.AsSpan()))
            {
                throw new ProvisionAgentUserException("lsa_secret_receipt_failed");
            }

            _secret.Store(password);
            secretWritten = true;
            if (!_secret.MatchesFingerprint(fingerprint.AsSpan()) ||
                !LsaSecretReceipt.Matches(
                    _receipt.ReadReceipt(),
                    ownerMarker,
                    fingerprint.AsSpan()))
            {
                throw new ProvisionAgentUserException("lsa_secret_readback_failed");
            }
        }
        catch (Exception original)
        {
            var uncertain = false;
            if (!receiptWritten)
            {
                try
                {
                    var observedReceipt = _receipt.ReadReceipt();
                    if (LsaSecretReceipt.Matches(
                            observedReceipt,
                            ownerMarker,
                            fingerprint.AsSpan()))
                    {
                        receiptWritten = true;
                    }
                    else if (observedReceipt is not null)
                    {
                        uncertain = true;
                    }
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (receiptWritten)
            {
                try
                {
                    if (!LsaSecretReceipt.Matches(
                            _receipt.ReadReceipt(),
                            ownerMarker,
                            fingerprint.AsSpan()))
                    {
                        uncertain = true;
                    }
                    else
                    {
                        if (!secretWritten)
                        {
                            if (_secret.MatchesFingerprint(fingerprint.AsSpan()))
                            {
                                secretWritten = true;
                            }
                            else if (_secret.Exists())
                            {
                                uncertain = true;
                            }
                        }

                        if (secretWritten)
                        {
                            if (!_secret.MatchesFingerprint(fingerprint.AsSpan()))
                            {
                                uncertain = true;
                            }
                            else
                            {
                                _secret.Remove();
                                if (_secret.Exists())
                                {
                                    uncertain = true;
                                }
                            }
                        }

                        if (!uncertain)
                        {
                            _receipt.RemoveReceipt();
                            if (_receipt.ReadReceipt() is not null)
                            {
                                uncertain = true;
                            }
                        }
                    }
                }
                catch
                {
                    uncertain = true;
                }
            }

            ThrowPreserving(original, uncertain);
        }
    }

    public bool IsOwned(string ownerMarker)
    {
        ValidateOwner(ownerMarker);
        Span<byte> fingerprint = stackalloc byte[System.Security.Cryptography.SHA256.HashSizeInBytes];
        try
        {
            return LsaSecretReceipt.TryReadFingerprint(
                    _receipt.ReadReceipt(),
                    ownerMarker,
                    fingerprint) &&
                _secret.MatchesFingerprint(fingerprint);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(fingerprint);
        }
    }

    public void Remove(string ownerMarker)
    {
        ValidateOwner(ownerMarker);
        Span<byte> fingerprint = stackalloc byte[System.Security.Cryptography.SHA256.HashSizeInBytes];
        try
        {
            if (!LsaSecretReceipt.TryReadFingerprint(
                    _receipt.ReadReceipt(),
                    ownerMarker,
                    fingerprint) ||
                !_secret.MatchesFingerprint(fingerprint))
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }

            _secret.Remove();
            if (_secret.Exists() ||
                !LsaSecretReceipt.Matches(_receipt.ReadReceipt(), ownerMarker, fingerprint))
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }

            _receipt.RemoveReceipt();
            if (_receipt.ReadReceipt() is not null)
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }
        }
        catch (ProvisionAgentUserException error) when (error.RollbackStateUncertain)
        {
            throw;
        }
        catch
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(fingerprint);
        }
    }

    public void FinalizeRemoval(string ownerMarker)
    {
        ValidateOwner(ownerMarker);
        Span<byte> fingerprint = stackalloc byte[System.Security.Cryptography.SHA256.HashSizeInBytes];
        try
        {
            var receipt = _receipt.ReadReceipt();
            var receiptOwned = LsaSecretReceipt.TryReadFingerprint(
                receipt,
                ownerMarker,
                fingerprint);
            if (_secret.Exists())
            {
                if (!receiptOwned || !_secret.MatchesFingerprint(fingerprint))
                {
                    throw new ProvisionAgentUserException(
                        "provision_state_uncertain",
                        rollbackStateUncertain: true);
                }

                Remove(ownerMarker);
                return;
            }

            if (receipt is null)
            {
                return;
            }

            if (!receiptOwned)
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }

            _receipt.RemoveReceipt();
            if (_receipt.ReadReceipt() is not null)
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(fingerprint);
        }
    }

    private static void ValidateOwner(string ownerMarker)
    {
        const string prefix = "SimplySignAuto/v1/";
        if (!ownerMarker.StartsWith(prefix, StringComparison.Ordinal) ||
            !InstallOwnershipMarker.IsInstanceId(ownerMarker[prefix.Length..]))
        {
            throw new ProvisionAgentUserException("provision_owner_invalid");
        }
    }

    private static void ThrowPreserving(Exception original, bool uncertain)
    {
        if (original is ProvisionAgentUserException known)
        {
            throw new ProvisionAgentUserException(
                known.Code,
                known.RollbackStateUncertain || uncertain);
        }

        throw new ProvisionAgentUserException("lsa_secret_write_failed", uncertain);
    }
}

internal sealed record WinlogonStoredValue(bool Present, object? Value, RegistryValueKind Kind)
{
    public static WinlogonStoredValue Missing { get; } = new(false, null, RegistryValueKind.None);

    public static WinlogonStoredValue String(string value) =>
        new(true, value, RegistryValueKind.String);

    public static WinlogonStoredValue DWord(int value) =>
        new(true, value, RegistryValueKind.DWord);
}

internal interface IWinlogonValueStore
{
    IReadOnlyCollection<string> GetValueNames();

    RegistryValueKind? ReadKind(string name);

    WinlogonStoredValue Read(string name);

    void Write(string name, WinlogonStoredValue value);

    void Delete(string name);

    void Flush();
}

internal sealed class WinlogonMutationTransaction
{
    internal const string LsaOwnerReceiptValueName = "SimplySignAutoLsaDefaultPasswordOwner";
    private const string OwnerValueName = "SimplySignAutoAgentUserOwner";
    private const string PriorUserValueName = "SimplySignAutoPriorDefaultUserName";
    private const string PriorDomainValueName = "SimplySignAutoPriorDefaultDomainName";
    private const string PriorAutoValueName = "SimplySignAutoPriorAutoAdminLogon";
    private const string PriorUserPresentValueName = "SimplySignAutoPriorDefaultUserNamePresent";
    private const string PriorDomainPresentValueName = "SimplySignAutoPriorDefaultDomainNamePresent";
    private const string PriorAutoPresentValueName = "SimplySignAutoPriorAutoAdminLogonPresent";
    private static readonly string[] ProductWinlogonValues =
    [
        OwnerValueName,
        PriorUserValueName,
        PriorDomainValueName,
        PriorAutoValueName,
        PriorUserPresentValueName,
        PriorDomainPresentValueName,
        PriorAutoPresentValueName,
    ];

    private readonly IWinlogonValueStore _store;

    public WinlogonMutationTransaction(IWinlogonValueStore store) =>
        _store = store ?? throw new ArgumentNullException(nameof(store));

    public void Apply(string userName, string domainName, string ownerMarker)
    {
        var snapshot = new WinlogonSnapshot(
            _store.Read("DefaultUserName"),
            _store.Read("DefaultDomainName"),
            _store.Read("AutoAdminLogon"));
        ValidatePreflight(ownerMarker);
        try
        {
            SavePrior(snapshot.User, PriorUserPresentValueName, PriorUserValueName);
            SavePrior(snapshot.Domain, PriorDomainPresentValueName, PriorDomainValueName);
            SavePrior(snapshot.AutoAdminLogon, PriorAutoPresentValueName, PriorAutoValueName);
            _store.Write("DefaultUserName", WinlogonStoredValue.String(userName));
            _store.Write("DefaultDomainName", WinlogonStoredValue.String(domainName));
            _store.Write("AutoAdminLogon", WinlogonStoredValue.String("1"));
            _store.Write(OwnerValueName, WinlogonStoredValue.String(ownerMarker));
            _store.Flush();
            AssertApplied(userName, domainName, ownerMarker, snapshot);
        }
        catch (Exception original)
        {
            var uncertain = false;
            try
            {
                Restore("DefaultUserName", snapshot.User);
                Restore("DefaultDomainName", snapshot.Domain);
                Restore("AutoAdminLogon", snapshot.AutoAdminLogon);
                foreach (var name in ProductWinlogonValues)
                {
                    _store.Delete(name);
                }

                _store.Flush();
                AssertRestored(snapshot);
            }
            catch
            {
                uncertain = true;
            }

            var code = original is ProvisionAgentUserException known
                ? known.Code
                : "autologon_registry_failed";
            throw new ProvisionAgentUserException(code, uncertain);
        }
    }

    private void ValidatePreflight(string ownerMarker)
    {
        if (!LsaSecretReceipt.IsForOwner(
                _store.Read(LsaOwnerReceiptValueName).Value as string,
                ownerMarker) ||
            ProductWinlogonValues.Any(name => _store.Read(name).Present) ||
            _store.GetValueNames().Contains("DefaultPassword", StringComparer.OrdinalIgnoreCase) ||
            string.Equals(_store.Read("AutoAdminLogon").Value as string, "1", StringComparison.Ordinal))
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }
    }

    private void SavePrior(WinlogonStoredValue prior, string presentName, string valueName)
    {
        _store.Write(presentName, WinlogonStoredValue.DWord(prior.Present ? 1 : 0));
        if (prior.Present)
        {
            _store.Write(valueName, prior);
        }
    }

    private void Restore(string name, WinlogonStoredValue prior)
    {
        if (prior.Present)
        {
            _store.Write(name, prior);
        }
        else
        {
            _store.Delete(name);
        }
    }

    private void AssertApplied(
        string userName,
        string domainName,
        string ownerMarker,
        WinlogonSnapshot snapshot)
    {
        if (_store.Read("DefaultUserName") != WinlogonStoredValue.String(userName) ||
            _store.Read("DefaultDomainName") != WinlogonStoredValue.String(domainName) ||
            _store.Read("AutoAdminLogon") != WinlogonStoredValue.String("1") ||
            _store.Read(OwnerValueName) != WinlogonStoredValue.String(ownerMarker) ||
            _store.GetValueNames().Contains("DefaultPassword", StringComparer.OrdinalIgnoreCase) ||
            !LsaSecretReceipt.IsForOwner(
                _store.Read(LsaOwnerReceiptValueName).Value as string,
                ownerMarker))
        {
            throw new ProvisionAgentUserException("autologon_readback_failed");
        }

        AssertPrior(snapshot.User, PriorUserPresentValueName, PriorUserValueName);
        AssertPrior(snapshot.Domain, PriorDomainPresentValueName, PriorDomainValueName);
        AssertPrior(snapshot.AutoAdminLogon, PriorAutoPresentValueName, PriorAutoValueName);
    }

    private void AssertPrior(WinlogonStoredValue prior, string presentName, string valueName)
    {
        if (_store.Read(presentName) != WinlogonStoredValue.DWord(prior.Present ? 1 : 0) ||
            (prior.Present && _store.Read(valueName) != prior) ||
            (!prior.Present && _store.Read(valueName).Present))
        {
            throw new ProvisionAgentUserException("autologon_readback_failed");
        }
    }

    private void AssertRestored(WinlogonSnapshot snapshot)
    {
        if (_store.Read("DefaultUserName") != snapshot.User ||
            _store.Read("DefaultDomainName") != snapshot.Domain ||
            _store.Read("AutoAdminLogon") != snapshot.AutoAdminLogon ||
            ProductWinlogonValues.Any(name => _store.Read(name).Present))
        {
            throw new ProvisionAgentUserException("provision_state_uncertain", rollbackStateUncertain: true);
        }
    }

    private sealed record WinlogonSnapshot(
        WinlogonStoredValue User,
        WinlogonStoredValue Domain,
        WinlogonStoredValue AutoAdminLogon);
}

internal sealed class RegistryWinlogonValueStore : IWinlogonValueStore
{
    private static readonly object Missing = new();
    private readonly RegistryKey _key;

    public RegistryWinlogonValueStore(RegistryKey key) =>
        _key = key ?? throw new ArgumentNullException(nameof(key));

    public IReadOnlyCollection<string> GetValueNames() => _key.GetValueNames();

    public RegistryValueKind? ReadKind(string name) =>
        _key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase)
            ? _key.GetValueKind(name)
            : null;

    public WinlogonStoredValue Read(string name)
    {
        var value = _key.GetValue(name, Missing, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return ReferenceEquals(value, Missing)
            ? WinlogonStoredValue.Missing
            : new WinlogonStoredValue(true, value, _key.GetValueKind(name));
    }

    public void Write(string name, WinlogonStoredValue value)
    {
        if (!value.Present || value.Value is null)
        {
            throw new ProvisionAgentUserException("autologon_registry_failed");
        }

        _key.SetValue(name, value.Value, value.Kind);
    }

    public void Delete(string name) => _key.DeleteValue(name, throwOnMissingValue: false);

    public void Flush() => _key.Flush();
}

internal sealed class WindowsLsaSecretStore : IWindowsLsaSecretStore
{
    private const string SecretName = "DefaultPassword";

    public bool Exists() => WindowsLsaPrivateData.Exists(SecretName);

    public bool MatchesFingerprint(ReadOnlySpan<byte> expectedFingerprint) =>
        WindowsLsaPrivateData.MatchesFingerprint(SecretName, expectedFingerprint);

    public void Store(SensitiveAgentUserPassword password) =>
        WindowsLsaPrivateData.Store(SecretName, password.AsSpan());

    public void Remove() => WindowsLsaPrivateData.Remove(SecretName);
}

internal sealed class WindowsLsaOwnerReceiptStore : IWindowsLsaOwnerReceiptStore
{
    private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    public string? ReadReceipt()
    {
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false);
        return key?.GetValue(WinlogonMutationTransaction.LsaOwnerReceiptValueName) as string;
    }

    public void WriteReceipt(string receipt)
    {
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new ProvisionAgentUserException("lsa_secret_receipt_failed");
        if (key.GetValue(WinlogonMutationTransaction.LsaOwnerReceiptValueName) is not null)
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }

        key.SetValue(
            WinlogonMutationTransaction.LsaOwnerReceiptValueName,
            receipt,
            RegistryValueKind.String);
        key.Flush();
    }

    public void RemoveReceipt()
    {
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new ProvisionAgentUserException("lsa_secret_receipt_failed");
        key.DeleteValue(WinlogonMutationTransaction.LsaOwnerReceiptValueName, throwOnMissingValue: false);
        key.Flush();
    }
}

internal sealed record DisabledOwnedAutoLogon(
    string SigningUserSid,
    string AccountName,
    string ProfilePath,
    string OwnerMarker);

internal sealed record DisabledAutoLogonFinalizationEvidence(
    string? OwnerMarker,
    string? UninstallState,
    string? SigningUserSid,
    string? AccountName,
    string? ProfilePath,
    bool HasPriorState,
    bool DefaultPasswordPresent,
    bool LsaReceiptPresent,
    bool LsaSecretPresent);

public sealed class WindowsAutoLogonPlatform : IWindowsAutoLogonPlatform
{
    private const string AgentTaskName = "SimplySignAuto.Agent";
    private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string OwnerValueName = "SimplySignAutoAgentUserOwner";
    private const string PriorUserValueName = "SimplySignAutoPriorDefaultUserName";
    private const string PriorDomainValueName = "SimplySignAutoPriorDefaultDomainName";
    private const string PriorAutoValueName = "SimplySignAutoPriorAutoAdminLogon";
    private const string PriorUserPresentValueName = "SimplySignAutoPriorDefaultUserNamePresent";
    private const string PriorDomainPresentValueName = "SimplySignAutoPriorDefaultDomainNamePresent";
    private const string PriorAutoPresentValueName = "SimplySignAutoPriorAutoAdminLogonPresent";
    private const string UninstallStateValueName = "SimplySignAutoUninstallState";
    private const string UninstallSidValueName = "SimplySignAutoUninstallSid";
    private const string UninstallAccountValueName = "SimplySignAutoUninstallAccount";
    private const string UninstallProfileValueName = "SimplySignAutoUninstallProfile";
    private const string UninstallDisabledState = "disabled";
    private const string DefaultPasswordSecret = "DefaultPassword";
    private static readonly string[] RequiredRights =
    [
        "SeInteractiveLogonRight",
        "SeDenyNetworkLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
    ];

    public Task<AgentUserProvisionInspection> InspectAsync(
        string userName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false);
        var autoEnabled = string.Equals(
            key?.GetValue("AutoAdminLogon") as string,
            "1",
            StringComparison.Ordinal);
        var autoUser = key?.GetValue("DefaultUserName") as string;
        var autoDomain = key?.GetValue("DefaultDomainName") as string;
        var account = string.IsNullOrWhiteSpace(autoUser)
            ? null
            : string.IsNullOrWhiteSpace(autoDomain)
                ? autoUser
                : $"{autoDomain}\\{autoUser}";
        var userExists = WindowsLocalAccount.Exists(userName);
        var dangerousRights = userExists && WindowsLsaAccountRights.Read(ResolveSid(userName))
            .Except(RequiredRights, StringComparer.Ordinal)
            .Any();
        return Task.FromResult(new AgentUserProvisionInspection(
            WindowsSupportPolicy.IsCurrentWindowsSupported(),
            IsAdministrator(),
            WindowsDomainRole.IsDomainController(),
            userExists,
            autoEnabled,
            autoEnabled ? account : null,
            RegistryValueExists(key, "DefaultPassword"),
            key?.GetValue(OwnerValueName) is not null ||
                key?.GetValue(WinlogonMutationTransaction.LsaOwnerReceiptValueName) is not null ||
                HasPriorState(key),
            dangerousRights,
            WindowsLsaPrivateData.Exists(DefaultPasswordSecret),
            userExists && WindowsLocalAccount.IsManaged(userName)));
    }

    public Task<ProvisionedAgentUser> ResolveExistingUserAsync(
        string userName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        if (!WindowsLocalAccount.Exists(userName))
        {
            throw new ProvisionAgentUserException("agent_user_missing");
        }

        return Task.FromResult(ResolveUser(userName));
    }

    public Task<ProvisionedAgentUser> CreateLocalUserAsync(
        string userName,
        SensitiveAgentUserPassword password,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        if (WindowsLocalAccount.Exists(userName))
        {
            throw new ProvisionAgentUserException("agent_user_exists");
        }

        WindowsLocalAccount.Create(userName, password);
        try
        {
            return Task.FromResult(ResolveUser(userName));
        }
        catch
        {
            WindowsLocalAccount.Delete(userName);
            throw;
        }
    }

    public Task<ProvisionedAgentUser> CreateUserProfileAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        return Task.FromResult(WindowsUserProfile.CreateOwned(user, ownerMarker));
    }

    public Task ResetLocalUserPasswordAsync(
        ProvisionedAgentUser user,
        SensitiveAgentUserPassword password,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        var userName = user.AccountName[(user.AccountName.IndexOf('\\') + 1)..];
        WindowsLocalAccount.ResetPassword(userName, password);
        return Task.CompletedTask;
    }

    public Task ConfigureRightsAsync(
        ProvisionedAgentUser user,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        WindowsLocalAccount.EnsureUsersGroupOnly(user);
        WindowsLsaAccountRights.Add(user.Sid, RequiredRights);
        return Task.CompletedTask;
    }

    public Task StoreLsaSecretAsync(
        ProvisionedAgentUser user,
        SensitiveAgentUserPassword password,
        string ownerMarker,
        CancellationToken cancellationToken)
    {
        _ = user;
        _ = ownerMarker;
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        CreateLsaTransaction().Store(password, ownerMarker);

        return Task.CompletedTask;
    }

    public Task WriteWinlogonAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new ProvisionAgentUserException("autologon_registry_failed");
        var userName = user.AccountName[(user.AccountName.IndexOf('\\') + 1)..];
        new WinlogonMutationTransaction(new RegistryWinlogonValueStore(key))
            .Apply(userName, user.LocalDomainName, ownerMarker);

        return Task.CompletedTask;
    }

    public async Task CreateAgentTaskAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        var action = CreateAgentTask(
            user,
            ownerMarker,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        _ = await new WindowsInstallActionExecutor(user.Sid)
            .CreateTaskRegistrationAsync(action, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AgentUserProvisionReadback> ReadbackAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        var rights = WindowsLsaAccountRights.Read(user.Sid);
        var groups = WindowsLocalAccount.ReadLocalGroupSids(user.AccountName);
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false);
        var configuredOwner = key?.GetValue(OwnerValueName) as string;
        var configuredUser = key?.GetValue("DefaultUserName") as string;
        var configuredDomain = key?.GetValue("DefaultDomainName") as string;
        var configuredAccount = string.IsNullOrWhiteSpace(configuredUser)
            ? null
            : $"{configuredDomain}\\{configuredUser}";
        var taskOwner = string.IsNullOrEmpty(ownerMarker) ? configuredOwner : ownerMarker;
        var taskExact = taskOwner is not null &&
            await IsAgentTaskExactAsync(
                    CreateAgentTask(
                        user,
                        taskOwner,
                        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)),
                    cancellationToken)
                .ConfigureAwait(false);
        var lsaOwner = string.IsNullOrEmpty(ownerMarker) ? configuredOwner : ownerMarker;
        var lsaSecretOwned = lsaOwner is not null && CreateLsaTransaction().IsOwned(lsaOwner);
        var profile = string.IsNullOrEmpty(ownerMarker)
            ? new OwnedUserProfileReadback(false, null)
            : WindowsUserProfile.ReadOwned(user, ownerMarker);
        return new AgentUserProvisionReadback(
            WindowsLocalAccount.Exists(configuredUser ?? user.AccountName[(user.AccountName.IndexOf('\\') + 1)..]),
            groups.SetEquals([WindowsLocalAccount.UsersGroupSid]),
            rights.Contains("SeInteractiveLogonRight"),
            rights.Contains("SeDenyNetworkLogonRight"),
            rights.Contains("SeDenyRemoteInteractiveLogonRight"),
            configuredAccount,
            string.Equals(key?.GetValue("AutoAdminLogon") as string, "1", StringComparison.Ordinal),
            lsaSecretOwned,
            RegistryValueExists(key, "DefaultPassword"),
            taskExact,
            configuredOwner,
            profile.Exact,
            profile.Path);
    }

    public async Task RollbackAgentTaskAsync(ProvisionedAgentUser user, string ownerMarker)
    {
        EnsureWindows();
        var action = CreateAgentTask(
            user,
            ownerMarker,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var lookup = new WindowsInstallResourceLookup();
        if (!lookup.TaskExists(action.Name))
        {
            return;
        }

        if (!lookup.TaskMatchesOwner(action))
        {
            throw new ProvisionAgentUserException("provision_state_uncertain");
        }

        await new WindowsOwnedTaskRollback(
                new DefaultWindowsCommandRunner(),
                lookup,
                new WindowsInstallStartupRuntime())
            .ExecuteAsync(action.Name, CancellationToken.None)
            .ConfigureAwait(false);
    }

    public Task RollbackWinlogonAsync(ProvisionedAgentUser user, string ownerMarker)
    {
        EnsureWindows();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new ProvisionAgentUserException("provision_state_uncertain");
        var userName = user.AccountName[(user.AccountName.IndexOf('\\') + 1)..];
        if (!string.Equals(key.GetValue(OwnerValueName) as string, ownerMarker, StringComparison.Ordinal) ||
            !string.Equals(key.GetValue("DefaultUserName") as string, userName, StringComparison.Ordinal) ||
            !string.Equals(key.GetValue("DefaultDomainName") as string, user.LocalDomainName, StringComparison.Ordinal))
        {
            throw new ProvisionAgentUserException("provision_state_uncertain");
        }

        RestoreWinlogonValues(key);
        return Task.CompletedTask;
    }

    public Task RollbackLsaSecretAsync(ProvisionedAgentUser user, string ownerMarker)
    {
        _ = user;
        EnsureWindows();
        CreateLsaTransaction().Remove(ownerMarker);
        return Task.CompletedTask;
    }

    public Task RollbackRightsAsync(ProvisionedAgentUser user)
    {
        EnsureWindows();
        WindowsLsaAccountRights.Remove(user.Sid, RequiredRights);
        return Task.CompletedTask;
    }

    public Task RollbackUserProfileAsync(ProvisionedAgentUser user, string ownerMarker)
    {
        EnsureWindows();
        WindowsUserProfile.DeleteOwned(user, ownerMarker);
        return Task.CompletedTask;
    }

    public Task RollbackLocalUserAsync(ProvisionedAgentUser user)
    {
        EnsureWindows();
        var current = ResolveUser(user.AccountName[(user.AccountName.IndexOf('\\') + 1)..]);
        if (!string.Equals(current.Sid, user.Sid, StringComparison.Ordinal))
        {
            throw new ProvisionAgentUserException("provision_state_uncertain");
        }

        WindowsLocalAccount.Delete(user.AccountName[(user.AccountName.IndexOf('\\') + 1)..]);
        return Task.CompletedTask;
    }

    internal static CreateInteractiveLogonTask CreateAgentTask(
        ProvisionedAgentUser user,
        string ownerMarker,
        string programFilesRoot) => new(
        AgentTaskName,
        user.AccountName,
        user.Sid,
        InstallMediaPaths.GetTargetExecutablePath(programFilesRoot),
        ["agent", "--background"],
        "InteractiveToken",
        Highest: true,
        RunOnlyIfNetworkAvailable: true,
        ownerMarker);

    private static async Task<string?> ReadAgentTaskOwnerAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await new DefaultWindowsCommandRunner().RunCheckedAsync(
                "schtasks.exe",
                ["/Query", "/TN", AgentTaskName, "/XML"],
                "task_registration_failed",
                cancellationToken).ConfigureAwait(false);
            var document = System.Xml.Linq.XDocument.Parse(result.StandardOutput);
            System.Xml.Linq.XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            var sources = document.Descendants(task + "Source").ToArray();
            const string prefix = "SimplySignAuto/v1/";
            if (sources.Length != 1 ||
                !sources[0].Value.StartsWith(prefix, StringComparison.Ordinal) ||
                !InstallOwnershipMarker.IsInstanceId(sources[0].Value[prefix.Length..]))
            {
                return null;
            }

            return sources[0].Value;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> IsAgentTaskExactAsync(
        CreateInteractiveLogonTask action,
        CancellationToken cancellationToken)
    {
        try
        {
            await WindowsTaskXml.VerifyRegisteredAsync(
                action,
                new DefaultWindowsCommandRunner(),
                cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static ProvisionedAgentUser ResolveUser(string userName)
    {
        try
        {
            var account = new NTAccount(Environment.MachineName, userName);
            var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            return new ProvisionedAgentUser(account.Value, sid.Value, Environment.MachineName);
        }
        catch (Exception error) when (error is IdentityNotMappedException or SystemException)
        {
            throw new ProvisionAgentUserException("agent_user_invalid");
        }
    }

    private static string ResolveSid(string userName) => ResolveUser(userName).Sid;

    private static OwnedLsaSecretTransaction CreateLsaTransaction() => new(
        new WindowsLsaSecretStore(),
        new WindowsLsaOwnerReceiptStore());

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool HasPriorState(RegistryKey? key) => key is not null &&
        new[]
        {
            PriorUserValueName,
            PriorDomainValueName,
            PriorAutoValueName,
            PriorUserPresentValueName,
            PriorDomainPresentValueName,
            PriorAutoPresentValueName,
        }.Any(name => key.GetValue(name) is not null);

    private static void SavePriorValue(
        RegistryKey key,
        string sourceName,
        string presentName,
        string valueName)
    {
        var prior = key.GetValue(sourceName) as string;
        key.SetValue(presentName, prior is null ? 0 : 1, RegistryValueKind.DWord);
        if (prior is not null)
        {
            key.SetValue(valueName, prior, RegistryValueKind.String);
        }
    }

    private static void RestoreWinlogonValues(RegistryKey key)
    {
        RestorePriorValue(key, "DefaultUserName", PriorUserPresentValueName, PriorUserValueName);
        RestorePriorValue(key, "DefaultDomainName", PriorDomainPresentValueName, PriorDomainValueName);
        RestorePriorValue(key, "AutoAdminLogon", PriorAutoPresentValueName, PriorAutoValueName);
        key.DeleteValue(OwnerValueName, throwOnMissingValue: false);
        key.DeleteValue(UninstallStateValueName, throwOnMissingValue: false);
        key.DeleteValue(UninstallSidValueName, throwOnMissingValue: false);
        key.DeleteValue(UninstallAccountValueName, throwOnMissingValue: false);
        key.DeleteValue(UninstallProfileValueName, throwOnMissingValue: false);
        key.Flush();
    }

    private static void AssertRestoredAutoLogonFields(RegistryKey key)
    {
        if (key.GetValue(OwnerValueName) is not null ||
            key.GetValue(UninstallStateValueName) is not null ||
            key.GetValue(UninstallSidValueName) is not null ||
            key.GetValue(UninstallAccountValueName) is not null ||
            key.GetValue(UninstallProfileValueName) is not null ||
            HasPriorState(key) ||
            RegistryValueExists(key, "DefaultPassword") ||
            new WindowsLsaOwnerReceiptStore().ReadReceipt() is not null ||
            WindowsLsaPrivateData.Exists(DefaultPasswordSecret))
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static void RestorePriorValue(
        RegistryKey key,
        string targetName,
        string presentName,
        string valueName)
    {
        if (key.GetValue(presentName) is int present)
        {
            if (present == 1 && key.GetValue(valueName) is string prior)
            {
                key.SetValue(targetName, prior, RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(targetName, throwOnMissingValue: false);
            }
        }

        key.DeleteValue(presentName, throwOnMissingValue: false);
        key.DeleteValue(valueName, throwOnMissingValue: false);
    }

    internal static void VerifyOwnedAutoLogon(string signingUserSid, string ownerMarker)
    {
        EnsureWindows();
        try
        {
            if (ReadDisabledAutoLogon(ownerMarker) is { } disabled)
            {
                if (!string.Equals(disabled.SigningUserSid, signingUserSid, StringComparison.Ordinal))
                {
                    throw new InstallException("owned_resource_mismatch");
                }

                return;
            }

            _ = ReadOwnedAutoLogon(signingUserSid, ownerMarker);
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("resource_preflight_failed");
        }
    }

    internal static void RemoveOwnedAutoLogon(
        string signingUserSid,
        string ownerMarker,
        string? expectedAccountName = null,
        string? expectedProfilePath = null)
    {
        EnsureWindows();
        if (ReadDisabledAutoLogon(ownerMarker) is { } disabled)
        {
            if (!string.Equals(disabled.SigningUserSid, signingUserSid, StringComparison.Ordinal))
            {
                throw new InstallException("owned_resource_mismatch");
            }

            return;
        }

        try
        {
            _ = ReadOwnedAutoLogon(signingUserSid, ownerMarker);
            expectedAccountName ??= ((NTAccount)new SecurityIdentifier(signingUserSid)
                .Translate(typeof(NTAccount))).Value;
            expectedProfilePath ??= WindowsUserProfile.ReadReceipt(signingUserSid).RegisteredPath;
            if (string.IsNullOrWhiteSpace(expectedAccountName) ||
                string.IsNullOrWhiteSpace(expectedProfilePath) ||
                !Path.IsPathFullyQualified(expectedProfilePath) ||
                !string.Equals(
                    Path.GetFullPath(expectedProfilePath),
                    expectedProfilePath,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InstallException("owned_resource_mismatch");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("resource_preflight_failed");
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
                throw new InstallException("uninstall_state_uncertain");
            AssertOwnedAutoLogon(key, signingUserSid, ownerMarker);
            key.SetValue(UninstallSidValueName, signingUserSid, RegistryValueKind.String);
            key.SetValue(UninstallAccountValueName, expectedAccountName, RegistryValueKind.String);
            key.SetValue(UninstallProfileValueName, expectedProfilePath, RegistryValueKind.String);
            key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
            key.SetValue(UninstallStateValueName, UninstallDisabledState, RegistryValueKind.String);
            key.Flush();
            _ = ReadDisabledAutoLogon(ownerMarker) ??
                throw new InstallException("uninstall_state_uncertain");
        }
        catch
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
                    throw new InstallException("uninstall_state_uncertain");
                if (!string.Equals(key.GetValue(OwnerValueName) as string, ownerMarker, StringComparison.Ordinal) ||
                    !CreateLsaTransaction().IsOwned(ownerMarker))
                {
                    throw new InstallException("uninstall_state_uncertain");
                }

                key.SetValue("AutoAdminLogon", "1", RegistryValueKind.String);
                key.DeleteValue(UninstallStateValueName, throwOnMissingValue: false);
                key.DeleteValue(UninstallSidValueName, throwOnMissingValue: false);
                key.DeleteValue(UninstallAccountValueName, throwOnMissingValue: false);
                key.DeleteValue(UninstallProfileValueName, throwOnMissingValue: false);
                key.Flush();
                _ = ReadOwnedAutoLogon(signingUserSid, ownerMarker);
            }
            catch
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            throw new InstallException("uninstall_state_uncertain");
        }
    }

    internal static DisabledOwnedAutoLogon? ReadDisabledAutoLogon(
        string ownerMarker,
        bool requireLsaOwnership = true)
    {
        EnsureWindows();
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false) ??
            throw new InstallException("owned_resource_mismatch");
        var state = key.GetValue(UninstallStateValueName) as string;
        var sid = key.GetValue(UninstallSidValueName) as string;
        var account = key.GetValue(UninstallAccountValueName) as string;
        var profile = key.GetValue(UninstallProfileValueName) as string;
        if (state is null && sid is null && account is null && profile is null)
        {
            return null;
        }

        if (!string.Equals(state, UninstallDisabledState, StringComparison.Ordinal) ||
            !string.Equals(key.GetValue(OwnerValueName) as string, ownerMarker, StringComparison.Ordinal) ||
            sid is null || !CanonicalWindowsSid.IsValid(sid) ||
            string.IsNullOrWhiteSpace(account) ||
            string.IsNullOrWhiteSpace(profile) ||
            !Path.IsPathFullyQualified(profile!) ||
            !string.Equals(Path.GetFullPath(profile!), profile, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(key.GetValue("AutoAdminLogon") as string, "0", StringComparison.Ordinal) ||
            RegistryValueExists(key, "DefaultPassword") ||
            (requireLsaOwnership && !CreateLsaTransaction().IsOwned(ownerMarker)))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var exactSid = sid!;
        var exactAccount = account!;
        var exactProfile = profile!;
        var separator = exactAccount.IndexOf('\\');
        if (separator <= 0 || separator == exactAccount.Length - 1 ||
            !string.Equals(key.GetValue("DefaultDomainName") as string, exactAccount[..separator], StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(key.GetValue("DefaultUserName") as string, exactAccount[(separator + 1)..], StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        _ = ReadPriorValue(key, PriorUserPresentValueName, PriorUserValueName);
        _ = ReadPriorValue(key, PriorDomainPresentValueName, PriorDomainValueName);
        _ = ReadPriorValue(key, PriorAutoPresentValueName, PriorAutoValueName);
        return new DisabledOwnedAutoLogon(exactSid, exactAccount, exactProfile, ownerMarker);
    }

    internal static void FinalizeDisabledAutoLogon(
        string signingUserSid,
        string ownerMarker)
    {
        var disabled = ReadDisabledAutoLogon(ownerMarker, requireLsaOwnership: false) ??
            throw new InstallException("uninstall_state_uncertain");
        if (!string.Equals(disabled.SigningUserSid, signingUserSid, StringComparison.Ordinal))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        CreateLsaTransaction().FinalizeRemoval(ownerMarker);
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: true) ??
            throw new InstallException("uninstall_state_uncertain");
        RestoreWinlogonValues(key);
        AssertRestoredAutoLogonFields(key);
    }

    internal static void FinalizeDisabledAutoLogon(
        string signingUserSid,
        string ownerMarker,
        string installInstanceId)
    {
        EnsureWindows();
        bool requiresFinalization;
        using (var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false) ??
            throw new InstallException("uninstall_state_uncertain"))
        {
            requiresFinalization = RequiresExactDisabledAutoLogonFinalization(
                ownerMarker,
                signingUserSid,
                installInstanceId,
                new DisabledAutoLogonFinalizationEvidence(
                    key.GetValue(OwnerValueName) as string,
                    key.GetValue(UninstallStateValueName) as string,
                    key.GetValue(UninstallSidValueName) as string,
                    key.GetValue(UninstallAccountValueName) as string,
                    key.GetValue(UninstallProfileValueName) as string,
                    HasPriorState(key),
                    RegistryValueExists(key, "DefaultPassword"),
                    new WindowsLsaOwnerReceiptStore().ReadReceipt() is not null,
                    WindowsLsaPrivateData.Exists(DefaultPasswordSecret)));
        }

        if (!requiresFinalization)
        {
            return;
        }

        FinalizeDisabledAutoLogon(signingUserSid, ownerMarker);
    }

    internal static bool RequiresExactDisabledAutoLogonFinalization(
        string ownerMarker,
        string signingUserSid,
        string installInstanceId,
        DisabledAutoLogonFinalizationEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!InstallOwnershipMarker.IsExact(ownerMarker, installInstanceId) ||
            !CanonicalWindowsSid.IsValid(signingUserSid))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        if (IsFullyFinalizedEvidence(
                evidence.OwnerMarker,
                evidence.UninstallState,
                evidence.SigningUserSid,
                evidence.AccountName,
                evidence.ProfilePath,
                evidence.HasPriorState,
                evidence.DefaultPasswordPresent,
                evidence.LsaReceiptPresent,
                evidence.LsaSecretPresent))
        {
            return false;
        }

        if (!string.Equals(evidence.OwnerMarker, ownerMarker, StringComparison.Ordinal) ||
            !string.Equals(evidence.UninstallState, UninstallDisabledState, StringComparison.Ordinal) ||
            !string.Equals(evidence.SigningUserSid, signingUserSid, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(evidence.AccountName) ||
            string.IsNullOrWhiteSpace(evidence.ProfilePath) ||
            !Path.IsPathFullyQualified(evidence.ProfilePath) ||
            !string.Equals(
                Path.GetFullPath(evidence.ProfilePath),
                evidence.ProfilePath,
                StringComparison.OrdinalIgnoreCase) ||
            !evidence.HasPriorState ||
            evidence.DefaultPasswordPresent)
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        return true;
    }

    internal static bool IsFullyFinalizedEvidence(
        string? ownerMarker,
        string? uninstallState,
        string? uninstallSid,
        string? uninstallAccount,
        string? uninstallProfile,
        bool hasPriorState,
        bool defaultPasswordPresent,
        bool lsaReceiptPresent,
        bool lsaSecretPresent) =>
        ownerMarker is null &&
        uninstallState is null &&
        uninstallSid is null &&
        uninstallAccount is null &&
        uninstallProfile is null &&
        !hasPriorState &&
        !defaultPasswordPresent &&
        !lsaReceiptPresent &&
        !lsaSecretPresent;

    private static OwnedAutoLogonSnapshot ReadOwnedAutoLogon(
        string signingUserSid,
        string ownerMarker)
    {
        using var key = Registry.LocalMachine.OpenSubKey(WinlogonPath, writable: false) ??
            throw new InstallException("owned_resource_mismatch");
        AssertOwnedAutoLogon(key, signingUserSid, ownerMarker);
        return new OwnedAutoLogonSnapshot(
            ReadPriorValue(key, PriorUserPresentValueName, PriorUserValueName),
            ReadPriorValue(key, PriorDomainPresentValueName, PriorDomainValueName),
            ReadPriorValue(key, PriorAutoPresentValueName, PriorAutoValueName));
    }

    private static void AssertOwnedAutoLogon(
        RegistryKey key,
        string signingUserSid,
        string ownerMarker,
        bool requireLsaSecret = true)
    {
        var user = key.GetValue("DefaultUserName") as string;
        var domain = key.GetValue("DefaultDomainName") as string;
        if (!string.Equals(key.GetValue(OwnerValueName) as string, ownerMarker, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(user) ||
            string.IsNullOrWhiteSpace(domain) ||
            !string.Equals(key.GetValue("AutoAdminLogon") as string, "1", StringComparison.Ordinal) ||
            RegistryValueExists(key, "DefaultPassword"))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        try
        {
            var lsa = CreateLsaTransaction();
            if (requireLsaSecret && !lsa.IsOwned(ownerMarker))
            {
                throw new InstallException("uninstall_state_uncertain");
            }

            if (!requireLsaSecret &&
                (new WindowsLsaOwnerReceiptStore().ReadReceipt() is not null ||
                    WindowsLsaPrivateData.Exists(DefaultPasswordSecret)))
            {
                throw new InstallException("owned_resource_mismatch");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("owned_resource_mismatch");
        }

        try
        {
            var actualSid = ((SecurityIdentifier)new NTAccount(domain, user)
                .Translate(typeof(SecurityIdentifier))).Value;
            if (!string.Equals(actualSid, signingUserSid, StringComparison.Ordinal))
            {
                throw new InstallException("owned_resource_mismatch");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch (Exception error) when (error is IdentityNotMappedException or SystemException)
        {
            throw new InstallException("owned_resource_mismatch");
        }

        _ = ReadPriorValue(key, PriorUserPresentValueName, PriorUserValueName);
        _ = ReadPriorValue(key, PriorDomainPresentValueName, PriorDomainValueName);
        _ = ReadPriorValue(key, PriorAutoPresentValueName, PriorAutoValueName);
    }

    private static PriorWinlogonValue ReadPriorValue(
        RegistryKey key,
        string presentName,
        string valueName)
    {
        if (key.GetValue(presentName) is not int present || present is not (0 or 1))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        var value = key.GetValue(valueName);
        if ((present == 1 && value is not string) || (present == 0 && value is not null))
        {
            throw new InstallException("owned_resource_mismatch");
        }

        return new PriorWinlogonValue(present == 1, value as string);
    }

    private static void AssertRestoredAutoLogon(
        RegistryKey key,
        OwnedAutoLogonSnapshot prior)
    {
        AssertRestoredValue(key, "DefaultUserName", prior.User);
        AssertRestoredValue(key, "DefaultDomainName", prior.Domain);
        AssertRestoredValue(key, "AutoAdminLogon", prior.AutoAdminLogon);
        AssertRestoredAutoLogonFields(key);
    }

    private static void AssertRestoredValue(
        RegistryKey key,
        string valueName,
        PriorWinlogonValue prior)
    {
        var actual = key.GetValue(valueName);
        if ((prior.Present && !string.Equals(actual as string, prior.Value, StringComparison.Ordinal)) ||
            (!prior.Present && actual is not null))
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private sealed record PriorWinlogonValue(bool Present, string? Value);

    private sealed record OwnedAutoLogonSnapshot(
        PriorWinlogonValue User,
        PriorWinlogonValue Domain,
        PriorWinlogonValue AutoAdminLogon);

    private static bool RegistryValueExists(RegistryKey? key, string name) =>
        key?.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase) == true;

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new ProvisionAgentUserException("windows_required");
        }
    }
}

internal sealed record OwnedUserProfileReadback(bool Exact, string? Path);

internal sealed record OwnedUserProfileReceipt(
    bool ProfileExists,
    bool HasOwnershipValues,
    string? RegisteredPath,
    string? OwnerMarker,
    string? InstallInstanceId,
    string? Sid,
    string? AccountName,
    string? RecordedPath);

internal static class WindowsProfilesDirectory
{
    private const int MaxPath = 260;

    internal static string Resolve()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new ProvisionAgentUserException("windows_required");
        }

        var capacity = MaxPath;
        var buffer = new StringBuilder(capacity);
        if (!GetProfilesDirectory(buffer, ref capacity))
        {
            if (Marshal.GetLastWin32Error() != 122 || capacity <= MaxPath)
            {
                throw new ProvisionAgentUserException("profile_readback_failed");
            }

            buffer = new StringBuilder(capacity);
            if (!GetProfilesDirectory(buffer, ref capacity))
            {
                throw new ProvisionAgentUserException("profile_readback_failed");
            }
        }

        var path = Path.GetFullPath(buffer.ToString());
        if (!Directory.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            throw new ProvisionAgentUserException("profile_readback_failed");
        }

        return path;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProfilesDirectory(
        StringBuilder profileDirectory,
        ref int size);
}

internal static class WindowsUserProfile
{
    private const string ProfileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string OwnerValue = "SimplySignAutoProfileOwner";
    private const string InstallInstanceValue = "SimplySignAutoProfileInstallInstanceId";
    private const string SidValue = "SimplySignAutoProfileSid";
    private const string AccountValue = "SimplySignAutoProfileAccount";
    private const string PathValue = "SimplySignAutoProfilePath";
    private const int MaxPath = 260;

    internal static ProvisionedAgentUser CreateOwned(ProvisionedAgentUser user, string ownerMarker)
    {
        ValidateIdentity(user, ownerMarker);
        using (var existing = Registry.LocalMachine.OpenSubKey(
            $@"{ProfileListPath}\{user.Sid}",
            writable: false))
        {
            if (existing is not null)
            {
                throw new ProvisionAgentUserException("profile_conflict");
            }
        }

        var userName = LocalUserName(user.AccountName);
        var pathBuffer = new StringBuilder(MaxPath);
        var profileCreated = false;
        string? profilePath = null;
        try
        {
            var result = CreateProfile(user.Sid, userName, pathBuffer, checked((uint)pathBuffer.Capacity));
            if (result != 0)
            {
                throw new ProvisionAgentUserException("profile_create_failed");
            }

            profileCreated = true;
            profilePath = Path.GetFullPath(pathBuffer.ToString());
            var expectedProfilePath = Path.GetFullPath(Path.Combine(
                WindowsProfilesDirectory.Resolve(),
                userName));
            if (!PathEquals(profilePath, expectedProfilePath))
            {
                throw new ProvisionAgentUserException("profile_conflict");
            }

            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ProfileListPath}\{user.Sid}",
                writable: true) ?? throw new ProvisionAgentUserException("profile_readback_failed");
            var registeredPath = ReadRegisteredPath(key);
            if (!PathEquals(profilePath, registeredPath) ||
                new[] { OwnerValue, InstallInstanceValue, SidValue, AccountValue, PathValue }
                    .Any(name => key.GetValue(name) is not null))
            {
                throw new ProvisionAgentUserException("profile_conflict");
            }

            var instanceId = ownerMarker["SimplySignAuto/v1/".Length..];
            key.SetValue(OwnerValue, ownerMarker, RegistryValueKind.String);
            key.SetValue(InstallInstanceValue, instanceId, RegistryValueKind.String);
            key.SetValue(SidValue, user.Sid, RegistryValueKind.String);
            key.SetValue(AccountValue, user.AccountName, RegistryValueKind.String);
            key.SetValue(PathValue, profilePath, RegistryValueKind.String);
            key.Flush();

            var provisioned = user with { ProfilePath = profilePath, OwnerMarker = ownerMarker };
            var readback = ReadOwned(provisioned, ownerMarker);
            if (!readback.Exact || !PathEquals(readback.Path, profilePath))
            {
                throw new ProvisionAgentUserException("profile_readback_failed");
            }

            return provisioned;
        }
        catch (Exception original)
        {
            var uncertain = false;
            if (profileCreated)
            {
                try
                {
                    if (!DeleteProfile(user.Sid, null, null) ||
                        ProfileEntryExists(user.Sid) ||
                        (profilePath is not null && Directory.Exists(profilePath)))
                    {
                        uncertain = true;
                    }
                }
                catch
                {
                    uncertain = true;
                }
            }

            if (original is ProvisionAgentUserException known)
            {
                throw new ProvisionAgentUserException(
                    known.Code,
                    known.RollbackStateUncertain || uncertain);
            }

            throw new ProvisionAgentUserException("profile_create_failed", uncertain);
        }
    }

    internal static OwnedUserProfileReadback ReadOwned(
        ProvisionedAgentUser user,
        string ownerMarker)
    {
        ValidateIdentity(user, ownerMarker);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ProfileListPath}\{user.Sid}",
                writable: false);
            if (key is null)
            {
                return new OwnedUserProfileReadback(false, null);
            }

            var registeredPath = ReadRegisteredPath(key);
            var recordedPath = key.GetValue(PathValue) as string;
            var instanceId = ownerMarker["SimplySignAuto/v1/".Length..];
            var exact = string.Equals(key.GetValue(OwnerValue) as string, ownerMarker, StringComparison.Ordinal) &&
                string.Equals(key.GetValue(InstallInstanceValue) as string, instanceId, StringComparison.Ordinal) &&
                string.Equals(key.GetValue(SidValue) as string, user.Sid, StringComparison.Ordinal) &&
                string.Equals(key.GetValue(AccountValue) as string, user.AccountName, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(recordedPath) &&
                Path.IsPathFullyQualified(recordedPath) &&
                PathEquals(Path.GetFullPath(recordedPath), recordedPath) &&
                PathEquals(recordedPath, registeredPath) &&
                (user.ProfilePath is null || PathEquals(user.ProfilePath, recordedPath)) &&
                Directory.Exists(recordedPath) &&
                !IsReparsePoint(recordedPath);
            return new OwnedUserProfileReadback(exact, exact ? recordedPath : null);
        }
        catch (ProvisionAgentUserException)
        {
            throw;
        }
        catch
        {
            return new OwnedUserProfileReadback(false, null);
        }
    }

    internal static OwnedUserProfileReceipt ReadReceipt(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ProfileListPath}\{sid}",
                writable: false);
            if (key is null)
            {
                return new OwnedUserProfileReceipt(
                    false,
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null);
            }

            var owner = key.GetValue(OwnerValue) as string;
            var instance = key.GetValue(InstallInstanceValue) as string;
            var recordedSid = key.GetValue(SidValue) as string;
            var account = key.GetValue(AccountValue) as string;
            var recordedPath = key.GetValue(PathValue) as string;
            return new OwnedUserProfileReceipt(
                true,
                owner is not null || instance is not null || recordedSid is not null ||
                    account is not null || recordedPath is not null,
                ReadRegisteredPath(key),
                owner,
                instance,
                recordedSid,
                account,
                recordedPath);
        }
        catch (ProvisionAgentUserException)
        {
            throw;
        }
        catch
        {
            throw new ProvisionAgentUserException("profile_readback_failed");
        }
    }

    internal static void DeleteOwned(ProvisionedAgentUser user, string ownerMarker)
    {
        var readback = ReadOwned(user, ownerMarker);
        if (!readback.Exact || readback.Path is null || !PathEquals(user.ProfilePath, readback.Path))
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }

        try
        {
            if (!DeleteProfile(user.Sid, null, null) ||
                ProfileEntryExists(user.Sid) ||
                Directory.Exists(readback.Path))
            {
                throw new ProvisionAgentUserException(
                    "provision_state_uncertain",
                    rollbackStateUncertain: true);
            }
        }
        catch (ProvisionAgentUserException)
        {
            throw;
        }
        catch
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }
    }

    internal static Task DeleteOwnedForUninstallAsync(
        UninstallSigningIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var state = WindowsUninstallIdentity.GetManagedProfileRemovalState(identity);
        switch (state)
        {
            case ManagedProfileRemovalState.RegisteredAndPresent:
                DeleteOwned(WindowsUninstallIdentity.AsProvisionedUser(identity), identity.OwnerMarker);
                break;
            case ManagedProfileRemovalState.RegistryOnly:
                using (var profileList = Registry.LocalMachine.OpenSubKey(
                    ProfileListPath,
                    writable: true) ?? throw new ProvisionAgentUserException("profile_readback_failed"))
                {
                    profileList.DeleteSubKeyTree(identity.Sid, throwOnMissingSubKey: false);
                    profileList.Flush();
                }

                break;
            case ManagedProfileRemovalState.DirectoryOnly:
                return Task.CompletedTask;
            case ManagedProfileRemovalState.Complete:
                return Task.CompletedTask;
            default:
                throw new ProvisionAgentUserException("profile_readback_failed");
        }

        if (ProfileEntryExists(identity.Sid) || Directory.Exists(identity.ProfilePath))
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }

        return Task.CompletedTask;
    }

    internal static bool IsSafeOwnedProfilePath(UninstallSigningIdentity identity)
    {
        try
        {
            var profilesRoot = WindowsProfilesDirectory.Resolve();
            if (!string.Equals(
                    identity.ProfilePath,
                    Path.GetFullPath(Path.Combine(profilesRoot, identity.UserName)),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            WindowsNoFollowSecurity.VerifyTrustedAnchor(
                WindowsNoFollowSecurity.ReadDirectory(profilesRoot));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ValidateIdentity(ProvisionedAgentUser user, string ownerMarker)
    {
        ArgumentNullException.ThrowIfNull(user);
        const string ownerPrefix = "SimplySignAuto/v1/";
        if (!ownerMarker.StartsWith(ownerPrefix, StringComparison.Ordinal) ||
            !InstallOwnershipMarker.IsInstanceId(ownerMarker[ownerPrefix.Length..]) ||
            string.IsNullOrWhiteSpace(user.AccountName) ||
            string.IsNullOrWhiteSpace(user.Sid))
        {
            throw new ProvisionAgentUserException("profile_identity_invalid");
        }
    }

    private static string ReadRegisteredPath(RegistryKey key)
    {
        var value = key.GetValue(
            "ProfileImagePath",
            null,
            RegistryValueOptions.None) as string;
        return !string.IsNullOrWhiteSpace(value) && Path.IsPathFullyQualified(value)
            ? Path.GetFullPath(value)
            : throw new ProvisionAgentUserException("profile_readback_failed");
    }

    internal static bool ProfileEntryExists(string sid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{ProfileListPath}\{sid}", writable: false);
        return key is not null;
    }

    private static string LocalUserName(string accountName)
    {
        var separator = accountName.IndexOf('\\');
        return separator >= 0 && separator + 1 < accountName.Length
            ? accountName[(separator + 1)..]
            : throw new ProvisionAgentUserException("profile_identity_invalid");
    }

    private static bool PathEquals(string? left, string? right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool IsReparsePoint(string path)
    {
        var directory = new DirectoryInfo(path);
        directory.Refresh();
        return directory.LinkTarget is not null ||
            (directory.Attributes & FileAttributes.ReparsePoint) != 0;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CreateProfile(
        string pszUserSid,
        string pszUserName,
        StringBuilder pszProfilePath,
        uint cchProfilePath);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteProfile(
        string lpSidString,
        string? lpProfilePath,
        string? lpComputerName);
}

internal static class WindowsLocalAccount
{
    private const string ManagedComment = "SimplySign Auto signing agent";
    internal const string UsersGroupSid = "S-1-5-32-545";
    private const int NerrSuccess = 0;
    private const int NerrUserNotFound = 2221;
    private const int ErrorMoreData = 234;
    private const uint UserPrivUser = 1;
    private const uint UfScript = 0x0001;
    private const uint UfDontExpirePasswd = 0x10000;
    private const uint LgIncludeIndirect = 1;

    internal static bool Exists(string userName)
    {
        var status = NetUserGetInfo(null, userName, 0, out var buffer);
        if (buffer != IntPtr.Zero)
        {
            _ = NetApiBufferFree(buffer);
        }

        return status switch
        {
            NerrSuccess => true,
            NerrUserNotFound => false,
            _ => throw new ProvisionAgentUserException("agent_user_lookup_failed"),
        };
    }

    internal static void Create(string userName, SensitiveAgentUserPassword password)
    {
        var passwordBuffer = Marshal.AllocHGlobal(checked((password.Length + 1) * sizeof(char)));
        try
        {
            var span = password.AsSpan();
            for (var index = 0; index < span.Length; index++)
            {
                Marshal.WriteInt16(passwordBuffer, index * sizeof(char), span[index]);
            }

            Marshal.WriteInt16(passwordBuffer, span.Length * sizeof(char), 0);
            var user = new UserInfo1
            {
                Name = userName,
                Password = passwordBuffer,
                Privilege = UserPrivUser,
                HomeDirectory = null,
                Comment = ManagedComment,
                Flags = UfScript | UfDontExpirePasswd,
                ScriptPath = null,
            };
            var status = NetUserAdd(null, 1, ref user, out _);
            if (status != NerrSuccess)
            {
                throw new ProvisionAgentUserException("agent_user_create_failed");
            }
        }
        finally
        {
            var zeros = new byte[checked((password.Length + 1) * sizeof(char))];
            Marshal.Copy(zeros, 0, passwordBuffer, zeros.Length);
            Marshal.FreeHGlobal(passwordBuffer);
        }
    }

    internal static void Delete(string userName)
    {
        var status = NetUserDel(null, userName);
        if (status is not (NerrSuccess or NerrUserNotFound))
        {
            throw new ProvisionAgentUserException("agent_user_delete_failed");
        }
    }

    internal static bool IsManaged(string userName)
    {
        var status = NetUserGetInfo(null, userName, 1, out var buffer);
        if (status != NerrSuccess)
        {
            if (buffer != IntPtr.Zero)
            {
                _ = NetApiBufferFree(buffer);
            }

            return status == NerrUserNotFound
                ? false
                : throw new ProvisionAgentUserException("agent_user_lookup_failed");
        }

        try
        {
            var user = Marshal.PtrToStructure<UserInfo1>(buffer);
            return string.Equals(user.Name, userName, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(user.Comment, ManagedComment, StringComparison.Ordinal) &&
                user.Privilege == UserPrivUser &&
                (user.Flags & (UfScript | UfDontExpirePasswd)) == (UfScript | UfDontExpirePasswd);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                _ = NetApiBufferFree(buffer);
            }
        }
    }

    internal static void ResetPassword(string userName, SensitiveAgentUserPassword password)
    {
        var passwordBuffer = Marshal.AllocHGlobal(checked((password.Length + 1) * sizeof(char)));
        try
        {
            var span = password.AsSpan();
            for (var index = 0; index < span.Length; index++)
            {
                Marshal.WriteInt16(passwordBuffer, index * sizeof(char), span[index]);
            }

            Marshal.WriteInt16(passwordBuffer, span.Length * sizeof(char), 0);
            var user = new UserInfo1003 { Password = passwordBuffer };
            if (NetUserSetInfo(null, userName, 1003, ref user, out _) != NerrSuccess)
            {
                throw new ProvisionAgentUserException("agent_user_password_reset_failed");
            }
        }
        finally
        {
            var zeros = new byte[checked((password.Length + 1) * sizeof(char))];
            Marshal.Copy(zeros, 0, passwordBuffer, zeros.Length);
            Marshal.FreeHGlobal(passwordBuffer);
        }
    }

    internal static void EnsureUsersGroupOnly(ProvisionedAgentUser user)
    {
        var current = ReadLocalGroupSids(user.AccountName);
        var prohibited = new[] { "S-1-5-32-544", "S-1-5-32-555" };
        if (current.Overlaps(prohibited))
        {
            throw new ProvisionAgentUserException("agent_user_rights_invalid");
        }

        if (!current.Contains(UsersGroupSid))
        {
            var usersAccount = (NTAccount)new SecurityIdentifier(UsersGroupSid)
                .Translate(typeof(NTAccount));
            var name = usersAccount.Value[(usersAccount.Value.IndexOf('\\') + 1)..];
            var sid = new SecurityIdentifier(user.Sid);
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var member = new LocalGroupMembersInfo0 { Sid = handle.AddrOfPinnedObject() };
                var status = NetLocalGroupAddMembers(null, name, 0, ref member, 1);
                if (status != NerrSuccess)
                {
                    throw new ProvisionAgentUserException("agent_user_rights_failed");
                }
            }
            finally
            {
                handle.Free();
            }

            current = ReadLocalGroupSids(user.AccountName);
        }

        if (!current.SetEquals([UsersGroupSid]))
        {
            throw new ProvisionAgentUserException("agent_user_rights_invalid");
        }
    }

    internal static HashSet<string> ReadLocalGroupSids(string accountName)
    {
        var userName = accountName[(accountName.IndexOf('\\') + 1)..];
        var status = NetUserGetLocalGroups(
            null,
            userName,
            0,
            LgIncludeIndirect,
            out var buffer,
            -1,
            out var entries,
            out _);
        if (status is not (NerrSuccess or ErrorMoreData))
        {
            throw new ProvisionAgentUserException("agent_user_rights_readback_failed");
        }

        try
        {
            var groups = new HashSet<string>(StringComparer.Ordinal);
            var size = Marshal.SizeOf<LocalGroupUsersInfo0>();
            for (var index = 0; index < entries; index++)
            {
                var item = Marshal.PtrToStructure<LocalGroupUsersInfo0>(buffer + (index * size));
                var name = Marshal.PtrToStringUni(item.Name);
                if (!string.IsNullOrWhiteSpace(name))
                {
                    try
                    {
                        var sid = (SecurityIdentifier)new NTAccount(name)
                            .Translate(typeof(SecurityIdentifier));
                        groups.Add(sid.Value);
                    }
                    catch (IdentityNotMappedException)
                    {
                        throw new ProvisionAgentUserException("agent_user_rights_readback_failed");
                    }
                }
            }

            return groups;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                _ = NetApiBufferFree(buffer);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public IntPtr Password;
        public uint PasswordAge;
        public uint Privilege;
        [MarshalAs(UnmanagedType.LPWStr)] public string? HomeDirectory;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string? ScriptPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo1003 { public IntPtr Password; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo0 { public IntPtr Sid; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupUsersInfo0 { public IntPtr Name; }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserAdd(
        string? serverName,
        int level,
        ref UserInfo1 buffer,
        out int parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserDel(string? serverName, string userName);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(
        string? serverName,
        string userName,
        int level,
        ref UserInfo1003 buffer,
        out int parameterError);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(
        string? serverName,
        string userName,
        int level,
        out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAddMembers(
        string? serverName,
        string groupName,
        int level,
        ref LocalGroupMembersInfo0 buffer,
        int totalEntries);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetLocalGroups(
        string? serverName,
        string userName,
        int level,
        uint flags,
        out IntPtr buffer,
        int preferredMaximumLength,
        out int entriesRead,
        out int totalEntries);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}

internal static class WindowsDomainRole
{
    internal static bool IsDomainController()
    {
        var status = DsRoleGetPrimaryDomainInformation(
            null,
            1,
            out var buffer);
        if (status != 0)
        {
            throw new ProvisionAgentUserException("domain_role_lookup_failed");
        }

        try
        {
            var role = Marshal.PtrToStructure<DsRolePrimaryDomainInfoBasic>(buffer).MachineRole;
            return role is 4 or 5;
        }
        finally
        {
            DsRoleFreeMemory(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DsRolePrimaryDomainInfoBasic
    {
        public int MachineRole;
        public uint Flags;
        public IntPtr DomainNameFlat;
        public IntPtr DomainNameDns;
        public IntPtr DomainForestName;
        public Guid DomainGuid;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int DsRoleGetPrimaryDomainInformation(
        string? server,
        int level,
        out IntPtr buffer);

    [DllImport("netapi32.dll")]
    private static extern void DsRoleFreeMemory(IntPtr buffer);
}

internal static class WindowsLsaAccountRights
{
    private const uint PolicyCreateAccount = 0x00000010;
    private const uint PolicyLookupNames = 0x00000800;
    internal const uint AddPolicyAccess = PolicyLookupNames | PolicyCreateAccount;

    internal static HashSet<string> Read(string sid)
    {
        using var policy = OpenPolicy(PolicyLookupNames);
        using var pinnedSid = new PinnedSid(sid);
        var status = LsaEnumerateAccountRights(
            policy.DangerousGetHandle(),
            pinnedSid.Pointer,
            out var buffer,
            out var count);
        if (status == unchecked((int)0xC0000034))
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        ThrowIfLsaError(status, "agent_user_rights_readback_failed");
        try
        {
            var rights = new HashSet<string>(StringComparer.Ordinal);
            var size = Marshal.SizeOf<LsaUnicodeString>();
            for (var index = 0; index < count; index++)
            {
                var value = Marshal.PtrToStructure<LsaUnicodeString>(buffer + (index * size));
                if (value.Buffer != IntPtr.Zero && value.Length > 0)
                {
                    rights.Add(Marshal.PtrToStringUni(value.Buffer, value.Length / 2));
                }
            }

            return rights;
        }
        finally
        {
            _ = LsaFreeMemory(buffer);
        }
    }

    internal static void Add(string sid, IReadOnlyList<string> rights)
    {
        using var policy = OpenPolicy(AddPolicyAccess);
        using var pinnedSid = new PinnedSid(sid);
        using var nativeRights = new NativeLsaStrings(rights);
        ThrowIfLsaError(
            LsaAddAccountRights(
                policy.DangerousGetHandle(),
                pinnedSid.Pointer,
                nativeRights.Values,
                nativeRights.Values.Length),
            "agent_user_rights_failed");
        if (!Read(sid).SetEquals(rights))
        {
            throw new ProvisionAgentUserException("agent_user_rights_readback_failed");
        }
    }

    internal static void Remove(string sid, IReadOnlyList<string> rights)
    {
        using var policy = OpenPolicy(PolicyLookupNames);
        using var pinnedSid = new PinnedSid(sid);
        using var nativeRights = new NativeLsaStrings(rights);
        ThrowIfLsaError(
            LsaRemoveAccountRights(
                policy.DangerousGetHandle(),
                pinnedSid.Pointer,
                false,
                nativeRights.Values,
                nativeRights.Values.Length),
            "agent_user_rights_failed");
    }

    private static SafeLsaPolicyHandle OpenPolicy(uint access)
    {
        var attributes = new LsaObjectAttributes
        {
            Length = Marshal.SizeOf<LsaObjectAttributes>(),
        };
        ThrowIfLsaError(
            LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out var handle),
            "agent_user_rights_failed");
        return handle;
    }

    internal static void ThrowIfLsaError(int status, string code)
    {
        if (status != 0)
        {
            _ = LsaNtStatusToWinError(status);
            throw new ProvisionAgentUserException(code);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LsaUnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    internal sealed class SafeLsaPolicyHandle : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeLsaPolicyHandle() : base(ownsHandle: true) { }

        protected override bool ReleaseHandle() => LsaClose(handle) == 0;
    }

    private sealed class PinnedSid : IDisposable
    {
        private readonly GCHandle _handle;

        public PinnedSid(string sid)
        {
            var securityIdentifier = new SecurityIdentifier(sid);
            var bytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(bytes, 0);
            _handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            Pointer = _handle.AddrOfPinnedObject();
        }

        public IntPtr Pointer { get; }

        public void Dispose() => _handle.Free();
    }

    private sealed class NativeLsaStrings : IDisposable
    {
        private readonly IntPtr[] _buffers;

        public NativeLsaStrings(IReadOnlyList<string> values)
        {
            _buffers = values.Select(Marshal.StringToHGlobalUni).ToArray();
            Values = values.Select((value, index) => new LsaUnicodeString
            {
                Length = checked((ushort)(value.Length * 2)),
                MaximumLength = checked((ushort)((value.Length + 1) * 2)),
                Buffer = _buffers[index],
            }).ToArray();
        }

        public LsaUnicodeString[] Values { get; }

        public void Dispose()
        {
            foreach (var buffer in _buffers)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [DllImport("advapi32.dll")]
    private static extern int LsaOpenPolicy(
        IntPtr systemName,
        ref LsaObjectAttributes objectAttributes,
        uint desiredAccess,
        out SafeLsaPolicyHandle policyHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaEnumerateAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        out IntPtr userRights,
        out int countOfRights);

    [DllImport("advapi32.dll")]
    private static extern int LsaAddAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        [In] LsaUnicodeString[] userRights,
        int countOfRights);

    [DllImport("advapi32.dll")]
    private static extern int LsaRemoveAccountRights(
        IntPtr policyHandle,
        IntPtr accountSid,
        [MarshalAs(UnmanagedType.Bool)] bool allRights,
        [In] LsaUnicodeString[] userRights,
        int countOfRights);

    [DllImport("advapi32.dll")]
    private static extern int LsaClose(IntPtr objectHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);
}

internal static class WindowsLsaPrivateData
{
    private const uint PolicyCreateSecret = 0x00000020;
    private const uint PolicyGetPrivateInformation = 0x00000004;

    internal static void Store(string keyName, ReadOnlySpan<char> secret)
    {
        using var policy = OpenPolicy(PolicyCreateSecret | PolicyGetPrivateInformation);
        using var key = new NativeUnicodeString(keyName);
        var chars = secret.ToArray();
        var handle = GCHandle.Alloc(chars, GCHandleType.Pinned);
        try
        {
            var value = new WindowsLsaAccountRights.LsaUnicodeString
            {
                Length = checked((ushort)(chars.Length * 2)),
                MaximumLength = checked((ushort)(chars.Length * 2)),
                Buffer = handle.AddrOfPinnedObject(),
            };
            WindowsLsaAccountRights.ThrowIfLsaError(
                LsaStorePrivateData(
                    policy.DangerousGetHandle(),
                    ref key.Value,
                    ref value),
                "lsa_secret_write_failed");
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(chars.AsSpan()));
            handle.Free();
        }
    }

    internal static bool Exists(string keyName)
    {
        using var policy = OpenPolicy(PolicyGetPrivateInformation);
        using var key = new NativeUnicodeString(keyName);
        var status = LsaRetrievePrivateData(
            policy.DangerousGetHandle(),
            ref key.Value,
            out var buffer);
        if (status == unchecked((int)0xC0000034))
        {
            return false;
        }

        WindowsLsaAccountRights.ThrowIfLsaError(status, "lsa_secret_readback_failed");
        var plaintextBuffer = IntPtr.Zero;
        var plaintextLength = 0;
        try
        {
            var value = Marshal.PtrToStructure<WindowsLsaAccountRights.LsaUnicodeString>(buffer);
            if (!IsValidRetrievedSecretBuffer(value.Buffer, value.Length, value.MaximumLength))
            {
                throw new ProvisionAgentUserException("lsa_secret_readback_failed");
            }

            plaintextBuffer = value.Buffer;
            plaintextLength = value.Length;
            return true;
        }
        finally
        {
            if (plaintextBuffer != IntPtr.Zero && plaintextLength > 0)
            {
                Marshal.Copy(new byte[plaintextLength], 0, plaintextBuffer, plaintextLength);
            }

            _ = LsaFreeMemory(buffer);
        }
    }

    internal static bool MatchesFingerprint(
        string keyName,
        ReadOnlySpan<byte> expectedFingerprint)
    {
        if (expectedFingerprint.Length != System.Security.Cryptography.SHA256.HashSizeInBytes)
        {
            return false;
        }

        using var policy = OpenPolicy(PolicyGetPrivateInformation);
        using var key = new NativeUnicodeString(keyName);
        var status = LsaRetrievePrivateData(
            policy.DangerousGetHandle(),
            ref key.Value,
            out var buffer);
        if (status == unchecked((int)0xC0000034))
        {
            return false;
        }

        WindowsLsaAccountRights.ThrowIfLsaError(status, "lsa_secret_readback_failed");
        try
        {
            var value = Marshal.PtrToStructure<WindowsLsaAccountRights.LsaUnicodeString>(buffer);
            return MatchesAndZeroRetrievedSecretBuffer(
                value.Buffer,
                value.Length,
                value.MaximumLength,
                expectedFingerprint);
        }
        finally
        {
            _ = LsaFreeMemory(buffer);
        }
    }

    internal static bool MatchesAndZeroRetrievedSecretBuffer(
        IntPtr buffer,
        ushort length,
        ushort maximumLength,
        ReadOnlySpan<byte> expectedFingerprint)
    {
        if (!IsValidRetrievedSecretBuffer(buffer, length, maximumLength) ||
            expectedFingerprint.Length != System.Security.Cryptography.SHA256.HashSizeInBytes)
        {
            throw new ProvisionAgentUserException("lsa_secret_readback_failed");
        }

        var plaintext = GC.AllocateUninitializedArray<byte>(length);
        Span<byte> actualFingerprint = stackalloc byte[System.Security.Cryptography.SHA256.HashSizeInBytes];
        try
        {
            Marshal.Copy(buffer, plaintext, 0, plaintext.Length);
            System.Security.Cryptography.SHA256.HashData(plaintext, actualFingerprint);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                actualFingerprint,
                expectedFingerprint);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(actualFingerprint);
            for (var index = 0; index < length; index++)
            {
                Marshal.WriteByte(buffer, index, 0);
            }
        }
    }

    internal static bool IsValidRetrievedSecretBuffer(
        IntPtr buffer,
        ushort length,
        ushort maximumLength) =>
        buffer != IntPtr.Zero &&
        length is >= 2 and <= 1024 &&
        length % sizeof(char) == 0 &&
        maximumLength >= length &&
        maximumLength <= 1024 &&
        maximumLength % sizeof(char) == 0;

    internal static void Remove(string keyName)
    {
        using var policy = OpenPolicy(PolicyCreateSecret);
        using var key = new NativeUnicodeString(keyName);
        WindowsLsaAccountRights.ThrowIfLsaError(
            LsaStorePrivateData(
                policy.DangerousGetHandle(),
                ref key.Value,
                IntPtr.Zero),
            "lsa_secret_delete_failed");
    }

    private static WindowsLsaAccountRights.SafeLsaPolicyHandle OpenPolicy(uint access)
    {
        var attributes = new LsaObjectAttributes { Length = Marshal.SizeOf<LsaObjectAttributes>() };
        WindowsLsaAccountRights.ThrowIfLsaError(
            LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out var handle),
            "lsa_secret_open_failed");
        return handle;
    }

    private sealed class NativeUnicodeString : IDisposable
    {
        public NativeUnicodeString(string value)
        {
            var buffer = Marshal.StringToHGlobalUni(value);
            Value = new WindowsLsaAccountRights.LsaUnicodeString
            {
                Length = checked((ushort)(value.Length * 2)),
                MaximumLength = checked((ushort)((value.Length + 1) * 2)),
                Buffer = buffer,
            };
        }

        public WindowsLsaAccountRights.LsaUnicodeString Value;

        public void Dispose() => Marshal.FreeHGlobal(Value.Buffer);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll")]
    private static extern int LsaOpenPolicy(
        IntPtr systemName,
        ref LsaObjectAttributes objectAttributes,
        uint desiredAccess,
        out WindowsLsaAccountRights.SafeLsaPolicyHandle policyHandle);

    [DllImport("advapi32.dll")]
    private static extern int LsaStorePrivateData(
        IntPtr policyHandle,
        ref WindowsLsaAccountRights.LsaUnicodeString keyName,
        ref WindowsLsaAccountRights.LsaUnicodeString privateData);

    [DllImport("advapi32.dll", EntryPoint = "LsaStorePrivateData")]
    private static extern int LsaStorePrivateData(
        IntPtr policyHandle,
        ref WindowsLsaAccountRights.LsaUnicodeString keyName,
        IntPtr privateData);

    [DllImport("advapi32.dll")]
    private static extern int LsaRetrievePrivateData(
        IntPtr policyHandle,
        ref WindowsLsaAccountRights.LsaUnicodeString keyName,
        out IntPtr privateData);

    [DllImport("advapi32.dll")]
    private static extern int LsaFreeMemory(IntPtr buffer);
}
