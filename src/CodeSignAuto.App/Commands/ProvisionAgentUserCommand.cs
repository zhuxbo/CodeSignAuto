using System.Security.Cryptography;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

public enum AgentUserProvisionMode
{
    ExistingUser,
    ProvisionUser,
    RepairUser,
}

public enum AgentUserPasswordCategory
{
    Uppercase,
    Lowercase,
    Digit,
    Symbol,
}

public sealed record ProvisionAgentUserOptions(
    AgentUserProvisionMode Mode,
    string UserName);

public sealed record AgentUserProvisionInspection(
    bool IsSupportedWindows,
    bool IsAdministrator,
    bool IsDomainController,
    bool UserExists,
    bool AutoLogonConfigured,
    string? AutoLogonAccountName,
    bool RegistryDefaultPasswordPresent,
    bool ProvisionOwnerPresent,
    bool DangerousRightsPresent,
    bool LsaDefaultPasswordPresent = false,
    bool ManagedLocalUser = false);

public sealed record ProvisionedAgentUser(
    string AccountName,
    string Sid,
    string LocalDomainName,
    string? ProfilePath = null,
    string? OwnerMarker = null);

public sealed record AgentUserProvisionReadback(
    bool UserExists,
    bool OnlyUsersGroup,
    bool InteractiveLogonAllowed,
    bool NetworkLogonDenied,
    bool RemoteInteractiveLogonDenied,
    string? AutoLogonAccountName,
    bool AutoAdminLogonEnabled,
    bool LsaSecretPresent,
    bool RegistryDefaultPasswordPresent,
    bool AgentTaskExact,
    string? OwnerMarker,
    bool ProfileExact = false,
    string? ProfilePath = null);

public sealed class ProvisionAgentUserException : Exception
{
    public ProvisionAgentUserException(string code, bool rollbackStateUncertain = false)
        : base(code)
    {
        Code = code;
        RollbackStateUncertain = rollbackStateUncertain;
    }

    public string Code { get; }

    public bool RollbackStateUncertain { get; }
}

public sealed class SensitiveAgentUserPassword : IDisposable
{
    private char[]? _value;

    internal SensitiveAgentUserPassword(char[] value) =>
        _value = value ?? throw new ArgumentNullException(nameof(value));

    public int Length => _value?.Length ?? 0;

    internal ReadOnlySpan<char> AsSpan() =>
        _value ?? throw new ObjectDisposedException(nameof(SensitiveAgentUserPassword));

    public bool ContainsCategory(AgentUserPasswordCategory category)
    {
        var value = AsSpan();
        return category switch
        {
            AgentUserPasswordCategory.Uppercase => value.ContainsAnyInRange('A', 'Z'),
            AgentUserPasswordCategory.Lowercase => value.ContainsAnyInRange('a', 'z'),
            AgentUserPasswordCategory.Digit => value.ContainsAnyInRange('0', '9'),
            AgentUserPasswordCategory.Symbol => value.IndexOfAny("!#$%&()*+,-.:;<=>?@[]^_{|}~") >= 0,
            _ => false,
        };
    }

    internal bool IsStrong() =>
        Length >= 32 && Length <= 64 &&
        ContainsCategory(AgentUserPasswordCategory.Uppercase) &&
        ContainsCategory(AgentUserPasswordCategory.Lowercase) &&
        ContainsCategory(AgentUserPasswordCategory.Digit) &&
        ContainsCategory(AgentUserPasswordCategory.Symbol);

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _value, null);
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(value.AsSpan()));
        }
    }

    public override string ToString() => string.Empty;
}

public interface IAgentUserPasswordGenerator
{
    SensitiveAgentUserPassword Generate();
}

public sealed class CryptographicAgentUserPasswordGenerator : IAgentUserPasswordGenerator
{
    private const string Uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lowercase = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!#$%&()*+,-.:;<=>?@[]^_{|}~";
    private const string All = Uppercase + Lowercase + Digits + Symbols;
    private const int PasswordLength = 32;

    public SensitiveAgentUserPassword Generate()
    {
        var value = new char[PasswordLength];
        value[0] = Pick(Uppercase);
        value[1] = Pick(Lowercase);
        value[2] = Pick(Digits);
        value[3] = Pick(Symbols);
        for (var index = 4; index < value.Length; index++)
        {
            value[index] = Pick(All);
        }

        for (var index = value.Length - 1; index > 0; index--)
        {
            var other = RandomNumberGenerator.GetInt32(index + 1);
            (value[index], value[other]) = (value[other], value[index]);
        }

        return new SensitiveAgentUserPassword(value);
    }

    private static char Pick(string alphabet) =>
        alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
}

public interface IProvisionOwnerGenerator
{
    string Generate();
}

public sealed class RandomProvisionOwnerGenerator : IProvisionOwnerGenerator
{
    public string Generate() => InstallOwnershipMarker.Create(Guid.NewGuid().ToString("N"));
}

public interface IWindowsAutoLogonPlatform
{
    Task<AgentUserProvisionInspection> InspectAsync(
        string userName,
        CancellationToken cancellationToken);

    Task<ProvisionedAgentUser> ResolveExistingUserAsync(
        string userName,
        CancellationToken cancellationToken);

    Task<ProvisionedAgentUser> CreateLocalUserAsync(
        string userName,
        SensitiveAgentUserPassword password,
        CancellationToken cancellationToken);

    Task<ProvisionedAgentUser> CreateUserProfileAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken);

    Task ResetLocalUserPasswordAsync(
        ProvisionedAgentUser user,
        SensitiveAgentUserPassword password,
        CancellationToken cancellationToken);

    Task ConfigureRightsAsync(
        ProvisionedAgentUser user,
        CancellationToken cancellationToken);

    Task StoreLsaSecretAsync(
        ProvisionedAgentUser user,
        SensitiveAgentUserPassword password,
        string ownerMarker,
        CancellationToken cancellationToken);

    Task WriteWinlogonAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken);

    Task CreateAgentTaskAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken);

    Task<AgentUserProvisionReadback> ReadbackAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        CancellationToken cancellationToken);

    Task RollbackAgentTaskAsync(ProvisionedAgentUser user, string ownerMarker);

    Task RollbackWinlogonAsync(ProvisionedAgentUser user, string ownerMarker);

    Task RollbackLsaSecretAsync(ProvisionedAgentUser user, string ownerMarker);

    Task RollbackRightsAsync(ProvisionedAgentUser user);

    Task RollbackUserProfileAsync(ProvisionedAgentUser user, string ownerMarker);

    Task RollbackLocalUserAsync(ProvisionedAgentUser user);
}

public sealed class ProvisionAgentUserOrchestrator
{
    private readonly IWindowsAutoLogonPlatform _platform;
    private readonly IAgentUserPasswordGenerator _passwordGenerator;
    private readonly IProvisionOwnerGenerator _ownerGenerator;

    public ProvisionAgentUserOrchestrator(
        IWindowsAutoLogonPlatform platform,
        IAgentUserPasswordGenerator passwordGenerator,
        IProvisionOwnerGenerator ownerGenerator)
    {
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
        _passwordGenerator = passwordGenerator ?? throw new ArgumentNullException(nameof(passwordGenerator));
        _ownerGenerator = ownerGenerator ?? throw new ArgumentNullException(nameof(ownerGenerator));
    }

    public Task<ProvisionedAgentUser> ExecuteAsync(
        ProvisionAgentUserOptions options,
        CancellationToken cancellationToken) =>
        ExecuteCoreAsync(options, output: null, afterUserCreated: null, cancellationToken);

    internal Task<ProvisionedAgentUser> ExecuteAsync(
        ProvisionAgentUserOptions options,
        Func<ProvisionedAgentUser, CancellationToken, Task> afterUserCreated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(afterUserCreated);
        return ExecuteCoreAsync(options, output: null, afterUserCreated, cancellationToken);
    }

    public Task<ProvisionedAgentUser> ExecuteAsync(
        ProvisionAgentUserOptions options,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        return ExecuteCoreAsync(options, output, afterUserCreated: null, cancellationToken);
    }

    private async Task<ProvisionedAgentUser> ExecuteCoreAsync(
        ProvisionAgentUserOptions options,
        TextWriter? output,
        Func<ProvisionedAgentUser, CancellationToken, Task>? afterUserCreated,
        CancellationToken cancellationToken)
    {
        ValidateOptions(options);
        var inspection = await _platform.InspectAsync(options.UserName, cancellationToken)
            .ConfigureAwait(false);
        ValidateEnvironment(inspection);

        if (options.Mode == AgentUserProvisionMode.ExistingUser)
        {
            var existing = await _platform.ResolveExistingUserAsync(options.UserName, cancellationToken)
                .ConfigureAwait(false);
            var readback = await _platform.ReadbackAsync(existing, string.Empty, cancellationToken)
                .ConfigureAwait(false);
            ValidateExistingReadback(existing, inspection, readback);
            if (output is not null)
            {
                await output.WriteLineAsync("agent_user_ready").ConfigureAwait(false);
            }

            return existing;
        }

        if (options.Mode == AgentUserProvisionMode.RepairUser)
        {
            ValidateRepairProvision(inspection);
            var existing = await _platform.ResolveExistingUserAsync(options.UserName, cancellationToken)
                .ConfigureAwait(false);
            return await RepairExistingUserAsync(existing, output, cancellationToken)
                .ConfigureAwait(false);
        }

        ValidateFreshProvision(inspection);
        using var password = _passwordGenerator.Generate();
        if (!password.IsStrong())
        {
            throw new ProvisionAgentUserException("password_generation_failed");
        }

        var ownerMarker = _ownerGenerator.Generate();
        if (!IsOwnerMarker(ownerMarker))
        {
            throw new ProvisionAgentUserException("provision_owner_invalid");
        }

        ProvisionedAgentUser? user = null;
        var userCreated = false;
        var profileCreated = false;
        var rightsConfigured = false;
        var secretStored = false;
        var winlogonWritten = false;
        var taskCreated = false;
        try
        {
            user = await _platform.CreateLocalUserAsync(options.UserName, password, cancellationToken)
                .ConfigureAwait(false);
            userCreated = true;
            if (afterUserCreated is not null)
            {
                await afterUserCreated(user, cancellationToken).ConfigureAwait(false);
            }

            user = await _platform.CreateUserProfileAsync(user, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            profileCreated = true;
            await _platform.ConfigureRightsAsync(user, cancellationToken).ConfigureAwait(false);
            rightsConfigured = true;
            await _platform.StoreLsaSecretAsync(user, password, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            secretStored = true;
            await _platform.WriteWinlogonAsync(user, ownerMarker, cancellationToken).ConfigureAwait(false);
            winlogonWritten = true;
            await _platform.CreateAgentTaskAsync(user, ownerMarker, cancellationToken).ConfigureAwait(false);
            taskCreated = true;
            var readback = await _platform.ReadbackAsync(user, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            ValidateProvisionReadback(user, ownerMarker, readback, requireProfile: true);
        }
        catch (Exception original)
        {
            var rollbackUncertain = await RollbackAsync(
                user,
                ownerMarker,
                taskCreated,
                winlogonWritten,
                secretStored,
                rightsConfigured,
                profileCreated,
                userCreated).ConfigureAwait(false);
            if (original is ProvisionAgentUserException known)
            {
                throw new ProvisionAgentUserException(
                    known.Code,
                    known.RollbackStateUncertain || rollbackUncertain);
            }

            if (original is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            }

            throw new ProvisionAgentUserException("provision_agent_user_failed", rollbackUncertain);
        }

        if (output is not null)
        {
            await output.WriteLineAsync("agent_user_ready").ConfigureAwait(false);
        }

        return user!;
    }

    internal async Task RollbackOwnedProvisionAsync(ProvisionedAgentUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.OwnerMarker is not { } ownerMarker ||
            !IsOwnerMarker(ownerMarker) ||
            string.IsNullOrWhiteSpace(user.ProfilePath))
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }

        var uncertain = await RollbackAsync(
            user,
            ownerMarker,
            taskCreated: true,
            winlogonWritten: true,
            secretStored: true,
            rightsConfigured: true,
            profileCreated: true,
            userCreated: true).ConfigureAwait(false);
        if (uncertain)
        {
            throw new ProvisionAgentUserException(
                "provision_state_uncertain",
                rollbackStateUncertain: true);
        }
    }

    private async Task<ProvisionedAgentUser> RepairExistingUserAsync(
        ProvisionedAgentUser user,
        TextWriter? output,
        CancellationToken cancellationToken)
    {
        using var password = _passwordGenerator.Generate();
        if (!password.IsStrong())
        {
            throw new ProvisionAgentUserException("password_generation_failed");
        }

        var ownerMarker = _ownerGenerator.Generate();
        if (!IsOwnerMarker(ownerMarker))
        {
            throw new ProvisionAgentUserException("provision_owner_invalid");
        }

        var secretStored = false;
        var winlogonWritten = false;
        var taskCreated = false;
        try
        {
            await _platform.ConfigureRightsAsync(user, cancellationToken).ConfigureAwait(false);
            await _platform.StoreLsaSecretAsync(user, password, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            secretStored = true;
            await _platform.WriteWinlogonAsync(user, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            winlogonWritten = true;
            await _platform.CreateAgentTaskAsync(user, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            taskCreated = true;
            var readback = await _platform.ReadbackAsync(user, ownerMarker, cancellationToken)
                .ConfigureAwait(false);
            ValidateProvisionReadback(user, ownerMarker, readback, requireProfile: false);
            await _platform.ResetLocalUserPasswordAsync(user, password, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception original)
        {
            var rollbackUncertain = await RollbackRepairAsync(
                user,
                ownerMarker,
                taskCreated,
                winlogonWritten,
                secretStored).ConfigureAwait(false);
            if (original is ProvisionAgentUserException known)
            {
                throw new ProvisionAgentUserException(
                    known.Code,
                    known.RollbackStateUncertain || rollbackUncertain);
            }

            if (original is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(original).Throw();
            }

            throw new ProvisionAgentUserException("provision_agent_user_failed", rollbackUncertain);
        }

        if (output is not null)
        {
            await output.WriteLineAsync("agent_user_ready").ConfigureAwait(false);
        }

        return user;
    }

    private async Task<bool> RollbackRepairAsync(
        ProvisionedAgentUser user,
        string ownerMarker,
        bool taskCreated,
        bool winlogonWritten,
        bool secretStored)
    {
        var uncertain = false;
        async Task TryAsync(Func<Task> rollback)
        {
            try
            {
                await rollback().ConfigureAwait(false);
            }
            catch
            {
                uncertain = true;
            }
        }

        if (taskCreated)
        {
            await TryAsync(() => _platform.RollbackAgentTaskAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (winlogonWritten)
        {
            await TryAsync(() => _platform.RollbackWinlogonAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (secretStored)
        {
            await TryAsync(() => _platform.RollbackLsaSecretAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        return uncertain;
    }

    private async Task<bool> RollbackAsync(
        ProvisionedAgentUser? user,
        string ownerMarker,
        bool taskCreated,
        bool winlogonWritten,
        bool secretStored,
        bool rightsConfigured,
        bool profileCreated,
        bool userCreated)
    {
        if (user is null)
        {
            return false;
        }

        var uncertain = false;
        async Task TryAsync(Func<Task> rollback)
        {
            try
            {
                await rollback().ConfigureAwait(false);
            }
            catch
            {
                uncertain = true;
            }
        }

        if (taskCreated)
        {
            await TryAsync(() => _platform.RollbackAgentTaskAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (winlogonWritten)
        {
            await TryAsync(() => _platform.RollbackWinlogonAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (secretStored)
        {
            await TryAsync(() => _platform.RollbackLsaSecretAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (rightsConfigured)
        {
            await TryAsync(() => _platform.RollbackRightsAsync(user)).ConfigureAwait(false);
        }

        if (profileCreated)
        {
            await TryAsync(() => _platform.RollbackUserProfileAsync(user, ownerMarker)).ConfigureAwait(false);
        }

        if (userCreated)
        {
            await TryAsync(() => _platform.RollbackLocalUserAsync(user)).ConfigureAwait(false);
        }

        return uncertain;
    }

    private static void ValidateOptions(ProvisionAgentUserOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(options.Mode) ||
            options.UserName.Length is < 1 or > 20 ||
            options.UserName is "." or ".." ||
            options.UserName.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '_' and not '-' and not '.'))
        {
            throw new ProvisionAgentUserException("provision_arguments_invalid");
        }
    }

    internal static void ValidateEnvironment(AgentUserProvisionInspection inspection)
    {
        if (!inspection.IsSupportedWindows)
        {
            throw new ProvisionAgentUserException("os_unsupported");
        }

        if (!inspection.IsAdministrator)
        {
            throw new ProvisionAgentUserException("administrator_required");
        }

        if (inspection.IsDomainController)
        {
            throw new ProvisionAgentUserException("domain_controller_unsupported");
        }

        if (inspection.RegistryDefaultPasswordPresent)
        {
            throw new ProvisionAgentUserException("autologon_plaintext_password_present");
        }

        if (inspection.DangerousRightsPresent)
        {
            throw new ProvisionAgentUserException("agent_user_rights_invalid");
        }
    }

    internal static void ValidateFreshProvision(AgentUserProvisionInspection inspection)
    {
        if (inspection.UserExists)
        {
            throw new ProvisionAgentUserException("agent_user_exists");
        }

        if (inspection.AutoLogonConfigured || inspection.ProvisionOwnerPresent)
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }

        if (inspection.LsaDefaultPasswordPresent)
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }
    }

    private static void ValidateRepairProvision(AgentUserProvisionInspection inspection)
    {
        if (!inspection.UserExists)
        {
            throw new ProvisionAgentUserException("agent_user_missing");
        }

        if (!inspection.ManagedLocalUser)
        {
            throw new ProvisionAgentUserException("agent_user_not_managed");
        }

        if (inspection.AutoLogonConfigured || inspection.ProvisionOwnerPresent ||
            inspection.LsaDefaultPasswordPresent)
        {
            throw new ProvisionAgentUserException("autologon_conflict");
        }
    }

    internal static string ValidateExistingReadback(
        ProvisionedAgentUser user,
        AgentUserProvisionInspection inspection,
        AgentUserProvisionReadback readback)
    {
        if (!inspection.UserExists ||
            !inspection.AutoLogonConfigured ||
            !string.Equals(inspection.AutoLogonAccountName, user.AccountName, StringComparison.OrdinalIgnoreCase))
        {
            throw new ProvisionAgentUserException("autologon_not_ready");
        }

        ValidateReadbackCore(user, readback);
        if (readback.OwnerMarker is not { } ownerMarker || !IsOwnerMarker(ownerMarker))
        {
            throw new ProvisionAgentUserException("autologon_readback_failed");
        }

        return ownerMarker["CodeSignAuto/v1/".Length..];
    }

    private static void ValidateProvisionReadback(
        ProvisionedAgentUser user,
        string ownerMarker,
        AgentUserProvisionReadback readback,
        bool requireProfile)
    {
        ValidateReadbackCore(user, readback);
        if (!string.Equals(readback.OwnerMarker, ownerMarker, StringComparison.Ordinal) ||
            (requireProfile &&
                (!readback.ProfileExact ||
                    string.IsNullOrWhiteSpace(user.ProfilePath) ||
                    !string.Equals(readback.ProfilePath, user.ProfilePath, PathComparison()))))
        {
            throw new ProvisionAgentUserException("autologon_readback_failed");
        }
    }

    private static void ValidateReadbackCore(
        ProvisionedAgentUser user,
        AgentUserProvisionReadback readback)
    {
        if (!readback.UserExists ||
            !readback.OnlyUsersGroup ||
            !readback.InteractiveLogonAllowed ||
            !readback.NetworkLogonDenied ||
            !readback.RemoteInteractiveLogonDenied ||
            !string.Equals(readback.AutoLogonAccountName, user.AccountName, StringComparison.OrdinalIgnoreCase) ||
            !readback.AutoAdminLogonEnabled ||
            !readback.LsaSecretPresent ||
            readback.RegistryDefaultPasswordPresent ||
            !readback.AgentTaskExact)
        {
            throw new ProvisionAgentUserException("autologon_readback_failed");
        }
    }

    private static bool IsOwnerMarker(string value) =>
        value.StartsWith("CodeSignAuto/v1/", StringComparison.Ordinal) &&
        InstallOwnershipMarker.IsInstanceId(value["CodeSignAuto/v1/".Length..]);

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

public static class ProvisionAgentUserCommand
{
    public static async Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        using var lease = new ServiceConfigurationWriterLeaseFactory().TryAcquire();
        if (lease is null)
        {
            await error.WriteLineAsync("provision_busy").ConfigureAwait(false);
            return 1;
        }

        if (!TryParse(args, out var options))
        {
            await error.WriteLineAsync("provision_arguments_invalid").ConfigureAwait(false);
            return 2;
        }

        try
        {
            _ = await new ProvisionAgentUserOrchestrator(
                    new WindowsAutoLogonPlatform(),
                    new CryptographicAgentUserPasswordGenerator(),
                    new RandomProvisionOwnerGenerator())
                .ExecuteAsync(options!, output, cancellationToken)
                .ConfigureAwait(false);
            return 0;
        }
        catch (ProvisionAgentUserException provisionError)
        {
            await error.WriteLineAsync(FormatFailure(provisionError)).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 1;
        }
        catch
        {
            await error.WriteLineAsync("provision_agent_user_failed").ConfigureAwait(false);
            return 1;
        }
    }

    internal static bool TryParse(string[] args, out ProvisionAgentUserOptions? options)
    {
        options = null;
        if (args is not ["--mode", var mode, "--user", var user])
        {
            return false;
        }

        var parsedMode = mode switch
        {
            "existing-user" => AgentUserProvisionMode.ExistingUser,
            "provision-user" => AgentUserProvisionMode.ProvisionUser,
            "repair-user" => AgentUserProvisionMode.RepairUser,
            _ => (AgentUserProvisionMode?)null,
        };
        if (parsedMode is null)
        {
            return false;
        }

        options = new ProvisionAgentUserOptions(parsedMode.Value, user);
        return true;
    }

    internal static string FormatFailure(ProvisionAgentUserException error) =>
        error.RollbackStateUncertain
            ? $"{error.Code} rollback_state_uncertain"
            : error.Code;
}
