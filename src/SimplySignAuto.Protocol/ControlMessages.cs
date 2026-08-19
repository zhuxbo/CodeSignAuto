namespace SimplySignAuto.Protocol;

public static class AdminControlContract
{
    public const int ProtocolVersion = 1;

    public const string Refresh = "refresh";
    public const string Relogin = "relogin";
    public const string Logout = "logout";
    public const string ImportOtp = "import_otp";
    public const string ClearOtp = "clear_otp";
    public const string GenerateTotp = "generate_totp";

    private static readonly HashSet<string> Operations = new(StringComparer.Ordinal)
    {
        Refresh,
        Relogin,
        Logout,
        ImportOtp,
        ClearOtp,
        GenerateTotp,
    };

    private static readonly HashSet<string> ErrorCodes = new(StringComparer.Ordinal)
    {
        "management_unavailable",
        "agent_busy",
        "otp_missing",
        "otp_wrong_user",
        "otp_corrupt",
        "otp_profile_invalid",
        "otp_delete_failed",
        "clock_not_synchronized",
        "simplysign_login_failed",
        "certificate_catalog_unavailable",
        "internal_error",
    };

    internal static bool IsOperation(string? value) =>
        value is not null && Operations.Contains(value);

    public static bool IsErrorCode(string? value) =>
        value is not null && ErrorCodes.Contains(value);
}

public sealed record AdminControlHello(
    int ProtocolVersion,
    int ProcessId,
    int SessionId,
    string UserSid) : AgentMessage;

public sealed record AdminControlAccepted(int ProtocolVersion) : AgentMessage;

public sealed record AgentControlRequest(
    Guid RequestId,
    string Operation,
    string? OtpUri = null) : AgentMessage;

public sealed record AgentControlResponse(
    Guid RequestId,
    string Operation,
    AgentHeartbeat? Heartbeat,
    string? TotpCode,
    int? RemainingSeconds,
    DateTimeOffset? ExpiresAtUtc,
    string? ErrorCode,
    Guid? CorrelationId) : AgentMessage;

public sealed record UpgradeDrainRequest(
    Guid RequestId,
    int TimeoutSeconds) : AgentMessage;

public sealed record UpgradeDrainResponse(
    Guid RequestId,
    bool Drained,
    string? ErrorCode) : AgentMessage;

public sealed record UpgradeResumeRequest(Guid RequestId) : AgentMessage;

public sealed record UpgradeResumeResponse(
    Guid RequestId,
    bool Resumed,
    string? ErrorCode) : AgentMessage;
