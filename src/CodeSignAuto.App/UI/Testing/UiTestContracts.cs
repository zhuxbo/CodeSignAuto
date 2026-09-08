using System.Globalization;

namespace CodeSignAuto.App.UI.Testing;

public sealed record UiTestState
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        "ready",
        "partial",
        "session0",
        "token-missing",
        "active-job",
        "job-failed",
        "unknown",
    };

    private UiTestState(string code) => Code = code;

    public string Code { get; }

    public static bool TryParse(string? value, out UiTestState? state)
    {
        state = value is not null && Allowed.Contains(value) ? new UiTestState(value) : null;
        return state is not null;
    }
}

public sealed record UiTestLaunchOptions(
    UiTestState State,
    string PipeName,
    string Nonce,
    int ProcessId,
    string CultureName = "zh-CN")
{
    public const string ModeEnvironmentVariable = "SIMPLYSIGN_UI_TEST_MODE";
    public const string PipeEnvironmentVariable = "SIMPLYSIGN_UI_TEST_PIPE";
    public const string NonceEnvironmentVariable = "SIMPLYSIGN_UI_TEST_NONCE";
    public const string CultureEnvironmentVariable = "SIMPLYSIGN_UI_TEST_CULTURE";
    private const string PipePrefix = "SSA.UI.";

    public static UiTestLaunchResult Parse(
        string[] arguments,
        IReadOnlyDictionary<string, string?> environment,
        int processId)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(environment);
        if (arguments is not ["--ui-test-state", var stateCode] ||
            !UiTestState.TryParse(stateCode, out var state) ||
            processId <= 0 ||
            !TryGetExact(environment, ModeEnvironmentVariable, out var mode) || mode != "1" ||
            !TryGetExact(environment, PipeEnvironmentVariable, out var pipeName) || !IsPrivatePipeName(pipeName) ||
            !TryGetExact(environment, NonceEnvironmentVariable, out var nonce) || !IsHex(nonce, 64) ||
            !TryGetExact(environment, CultureEnvironmentVariable, out var cultureName) ||
            cultureName is not "zh-CN" and not "en-US")
        {
            return UiTestLaunchResult.Rejected;
        }

        return new UiTestLaunchResult(
            new UiTestLaunchOptions(state!, pipeName!, nonce!, processId, cultureName!),
            null);
    }

    private static bool TryGetExact(
        IReadOnlyDictionary<string, string?> environment,
        string key,
        out string? value)
    {
        if (!environment.TryGetValue(key, out value))
        {
            return false;
        }

        return value is not null && !value.Any(char.IsControl);
    }

    private static bool IsPrivatePipeName(string? value) =>
        value is { Length: 39 } &&
        value.StartsWith(PipePrefix, StringComparison.Ordinal) &&
        IsHex(value[PipePrefix.Length..], 32);

    internal static bool IsHex(string? value, int length) =>
        value is not null && value.Length == length &&
        value.All(static character =>
            character is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f');
}

public static class UiTestTrayIdentity
{
    private const string Prefix = "SSA-UI-TEST:";
    private const string PipePrefix = "SSA.UI.";

    public static string Create(int processId, string pipeName)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        if (pipeName is not { Length: 39 } ||
            !pipeName.StartsWith(PipePrefix, StringComparison.Ordinal) ||
            !UiTestLaunchOptions.IsHex(pipeName[PipePrefix.Length..], 32))
        {
            throw new ArgumentException("ui_test_tray_identity_invalid", nameof(pipeName));
        }

        return $"{Prefix}{processId}:{pipeName[PipePrefix.Length..].ToLowerInvariant()}";
    }

    internal static bool IsValid(string? value)
    {
        if (value is null || !value.StartsWith(Prefix, StringComparison.Ordinal) || value.Length > 63)
        {
            return false;
        }

        var separator = value.IndexOf(':', Prefix.Length);
        return separator > Prefix.Length &&
            int.TryParse(
                value.AsSpan(Prefix.Length, separator - Prefix.Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var processId) &&
            processId > 0 &&
            UiTestLaunchOptions.IsHex(value[(separator + 1)..], 32) &&
            value[(separator + 1)..].All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}

public sealed record UiTestLaunchResult(UiTestLaunchOptions? Options, string? ErrorCode)
{
    public static UiTestLaunchResult Rejected { get; } = new(null, "invalid_arguments");

    public bool IsAccepted => Options is not null && ErrorCode is null;
}

public sealed record UiTestHandshake(
    int SchemaVersion,
    string State,
    int ProcessId,
    string Nonce)
{
    public static UiTestHandshake Create(UiTestLaunchOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new UiTestHandshake(1, options.State.Code, options.ProcessId, options.Nonce);
    }

    public bool IsValidFor(UiTestLaunchOptions options) =>
        options is not null && SchemaVersion == 1 && ProcessId > 0 &&
        ProcessId == options.ProcessId &&
        string.Equals(State, options.State.Code, StringComparison.Ordinal) &&
        string.Equals(Nonce, options.Nonce, StringComparison.Ordinal) &&
        UiTestLaunchOptions.IsHex(Nonce, 64);
}

public readonly record struct UiClientSize(double Width, double Height);

public static class UiWindowGeometry
{
    public const int BaseDpi = 96;

    public static UiClientSize Default { get; } = new(1024, 768);

    public static UiClientSize Minimum { get; } = new(960, 720);

    public static bool IsLandscapeFourByThree(UiClientSize size, double tolerance)
    {
        if (!double.IsFinite(size.Width) || !double.IsFinite(size.Height) ||
            size.Width <= size.Height || size.Height <= 0 ||
            !double.IsFinite(tolerance) || tolerance < 0)
        {
            return false;
        }

        return Math.Abs((size.Width / size.Height) - (4d / 3d)) <= tolerance;
    }

    public static UiClientSize ToPhysical(UiClientSize logical, int dpi)
    {
        if (dpi is < 96 or > 768)
        {
            throw new ArgumentOutOfRangeException(nameof(dpi));
        }

        var scale = dpi / (double)BaseDpi;
        return new UiClientSize(
            Math.Round(logical.Width * scale, MidpointRounding.AwayFromZero),
            Math.Round(logical.Height * scale, MidpointRounding.AwayFromZero));
    }

    public static UiClientSize ToLogical(UiClientSize physical, int dpi)
    {
        if (dpi is < 96 or > 768)
        {
            throw new ArgumentOutOfRangeException(nameof(dpi));
        }

        var scale = dpi / (double)BaseDpi;
        return new UiClientSize(physical.Width / scale, physical.Height / scale);
    }

    public static string Describe(UiClientSize logical, int dpi)
    {
        var physical = ToPhysical(logical, dpi);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"dpi={dpi};logical={logical.Width}x{logical.Height};physical={physical.Width}x{physical.Height}");
    }
}

public static class UiTestProgramGate
{
    public static async Task<int> DispatchAsync(
        string[] routeArguments,
        IReadOnlyDictionary<string, string?> environment,
        int processId,
        Func<UiTestLaunchOptions, CancellationToken, Task<int>> execute,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(routeArguments);
        ArgumentNullException.ThrowIfNull(execute);
        ArgumentNullException.ThrowIfNull(error);
        var launch = routeArguments is [var state]
            ? UiTestLaunchOptions.Parse(["--ui-test-state", state], environment, processId)
            : UiTestLaunchResult.Rejected;
        if (!launch.IsAccepted)
        {
            await error.WriteLineAsync("invalid_arguments").ConfigureAwait(false);
            return 2;
        }

        return await execute(launch.Options!, cancellationToken).ConfigureAwait(false);
    }
}
