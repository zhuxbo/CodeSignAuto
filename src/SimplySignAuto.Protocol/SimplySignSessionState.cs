using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimplySignAuto.Protocol;

[JsonConverter(typeof(SimplySignSessionStateJsonConverter))]
public enum SimplySignSessionState
{
    Unknown = 1,
    Checking,
    Ready,
    LoginRequired,
    Loginning,
    WaitToken,
    Failed,
}

public enum TransitionCause
{
    Normal,
    Invalidated,
}

public static class SimplySignSessionStatePolicy
{
    public static SimplySignSessionState ParseExact(string? value) => value switch
    {
        "UNKNOWN" => SimplySignSessionState.Unknown,
        "CHECKING" => SimplySignSessionState.Checking,
        "READY" => SimplySignSessionState.Ready,
        "LOGIN_REQUIRED" => SimplySignSessionState.LoginRequired,
        "LOGINNING" => SimplySignSessionState.Loginning,
        "WAIT_TOKEN" => SimplySignSessionState.WaitToken,
        "FAILED" => SimplySignSessionState.Failed,
        _ => throw InvalidState(),
    };

    public static string Format(SimplySignSessionState state) => state switch
    {
        SimplySignSessionState.Unknown => "UNKNOWN",
        SimplySignSessionState.Checking => "CHECKING",
        SimplySignSessionState.Ready => "READY",
        SimplySignSessionState.LoginRequired => "LOGIN_REQUIRED",
        SimplySignSessionState.Loginning => "LOGINNING",
        SimplySignSessionState.WaitToken => "WAIT_TOKEN",
        SimplySignSessionState.Failed => "FAILED",
        _ => throw InvalidState(),
    };

    private static ProtocolException InvalidState() =>
        new("invalid_message", "The SimplySign session state is invalid.");
}

public static class SimplySignSessionTransitionPolicy
{
    public static bool IsAllowed(
        SimplySignSessionState from,
        SimplySignSessionState to,
        TransitionCause cause)
    {
        if (!Enum.IsDefined(from) || !Enum.IsDefined(to) || !Enum.IsDefined(cause))
        {
            return false;
        }

        if (cause == TransitionCause.Invalidated)
        {
            return to == SimplySignSessionState.Unknown;
        }

        return from == to || (from, to) switch
        {
            (SimplySignSessionState.Unknown, SimplySignSessionState.Checking) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.Ready) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.LoginRequired) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.Ready, SimplySignSessionState.Checking) => true,
            (SimplySignSessionState.LoginRequired, SimplySignSessionState.Loginning) => true,
            (SimplySignSessionState.Loginning, SimplySignSessionState.WaitToken) => true,
            (SimplySignSessionState.Loginning, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.Ready) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.LoginRequired) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.Failed, SimplySignSessionState.Checking) => true,
            _ => false,
        };
    }

    public static bool IsAllowed(
        SimplySignSessionSnapshot previous,
        SimplySignSessionSnapshot candidate,
        TransitionCause cause)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(candidate);
        if (!IsAllowed(previous.State, candidate.State, cause) ||
            candidate.ProbedAtUtc < previous.ProbedAtUtc)
        {
            return false;
        }

        if (cause == TransitionCause.Invalidated)
        {
            return candidate.SessionGeneration > previous.SessionGeneration &&
                candidate.TransitionedAtUtc >= previous.TransitionedAtUtc;
        }

        return candidate.SessionGeneration == previous.SessionGeneration &&
            (candidate.State == previous.State
                ? candidate.TransitionedAtUtc == previous.TransitionedAtUtc
                : candidate.TransitionedAtUtc > previous.TransitionedAtUtc);
    }

}

public static class SimplySignSessionReasonCodes
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        "unknown",
        "checking",
        "ready",
        "login_required",
        "loginning",
        "wait_token",
        "failed",
        "invalidated",
        "session_missing",
        "session_mismatch",
        "token_missing",
        "token_mismatch",
        "certificate_missing",
        "certificate_mismatch",
        "private_key_missing",
        "private_key_mismatch",
        "probe_failed",
        "login_failed",
        "retry_scheduled",
    };

    public static bool IsAllowed(string? value) => value is not null && Allowed.Contains(value);

    public static bool IsValidForState(SimplySignSessionState state, string? reasonCode) =>
        (state, reasonCode) switch
        {
            (SimplySignSessionState.Unknown, "unknown" or "invalidated") => true,
            (SimplySignSessionState.Checking, "checking") => true,
            (SimplySignSessionState.Ready, "ready") => true,
            (SimplySignSessionState.LoginRequired, "login_required") => true,
            (SimplySignSessionState.Loginning, "loginning") => true,
            (SimplySignSessionState.WaitToken, "wait_token" or "token_missing") => true,
            (SimplySignSessionState.Failed,
                "failed" or
                "session_missing" or
                "session_mismatch" or
                "token_mismatch" or
                "certificate_missing" or
                "certificate_mismatch" or
                "private_key_missing" or
                "private_key_mismatch" or
                "probe_failed" or
                "login_failed" or
                "retry_scheduled") => true,
            _ => false,
        };

    internal static bool IsCompatibleOuterReason(string? outerReasonCode, string? sessionReasonCode) =>
        string.Equals(outerReasonCode, sessionReasonCode, StringComparison.Ordinal) ||
        (outerReasonCode, sessionReasonCode) switch
        {
            ("token_identifier_mismatch", "token_mismatch") => true,
            ("certificate_identifier_mismatch", "certificate_mismatch") => true,
            ("private_key_identifier_mismatch", "private_key_mismatch") => true,
            ("heartbeat_missing", "unknown") => true,
            ("pdf_support_not_installed" or "pdf_helper_tampered", _) => true,
            _ => false,
        };
}

public sealed record SimplySignSessionSnapshot
{
    public SimplySignSessionSnapshot(
        SimplySignSessionState state,
        long sessionGeneration,
        DateTimeOffset probedAtUtc,
        DateTimeOffset transitionedAtUtc,
        int? sessionId,
        bool tokenPresent,
        bool tokenMatches,
        bool certificatePresent,
        bool certificateMatches,
        bool privateKeyPresent,
        bool privateKeyMatches,
        bool ready,
        string reasonCode,
        int attempt,
        DateTimeOffset? nextRetryAtUtc,
        bool? simplySignProcessRunning = null,
        int? simplySignProcessSessionId = null)
    {
        if (!Enum.IsDefined(state) ||
            sessionGeneration <= 0 ||
            !IsUtc(probedAtUtc) ||
            !IsUtc(transitionedAtUtc) ||
            transitionedAtUtc > probedAtUtc ||
            sessionId is <= 0 ||
            tokenMatches && !tokenPresent ||
            certificateMatches && !certificatePresent ||
            privateKeyMatches && !privateKeyPresent ||
            !SimplySignSessionReasonCodes.IsValidForState(state, reasonCode) ||
            attempt is < 0 or > 1_000_000 ||
            nextRetryAtUtc is { } retry && (!IsUtc(retry) || retry < probedAtUtc || attempt == 0) ||
            simplySignProcessSessionId is <= 0 ||
            simplySignProcessRunning is null && simplySignProcessSessionId is not null ||
            simplySignProcessRunning == true && simplySignProcessSessionId is null ||
            simplySignProcessRunning == false && simplySignProcessSessionId is not null ||
            ready != (state == SimplySignSessionState.Ready) ||
            reasonCode == "ready" && state != SimplySignSessionState.Ready ||
            state == SimplySignSessionState.Ready &&
                (sessionId is null || !tokenPresent || !tokenMatches ||
                    !certificatePresent || !certificateMatches ||
                    !privateKeyPresent || !privateKeyMatches || reasonCode != "ready"))
        {
            throw new ArgumentException("The SimplySign session snapshot is invalid.");
        }

        State = state;
        SessionGeneration = sessionGeneration;
        ProbedAtUtc = probedAtUtc;
        TransitionedAtUtc = transitionedAtUtc;
        SessionId = sessionId;
        TokenPresent = tokenPresent;
        TokenMatches = tokenMatches;
        CertificatePresent = certificatePresent;
        CertificateMatches = certificateMatches;
        PrivateKeyPresent = privateKeyPresent;
        PrivateKeyMatches = privateKeyMatches;
        Ready = ready;
        ReasonCode = reasonCode;
        Attempt = attempt;
        NextRetryAtUtc = nextRetryAtUtc;
        SimplySignProcessRunning = simplySignProcessRunning;
        SimplySignProcessSessionId = simplySignProcessSessionId;
    }

    public SimplySignSessionState State { get; }
    public long SessionGeneration { get; }
    public DateTimeOffset ProbedAtUtc { get; }
    public DateTimeOffset TransitionedAtUtc { get; }
    public int? SessionId { get; }
    public bool TokenPresent { get; }
    public bool TokenMatches { get; }
    public bool CertificatePresent { get; }
    public bool CertificateMatches { get; }
    public bool PrivateKeyPresent { get; }
    public bool PrivateKeyMatches { get; }
    public bool Ready { get; }
    public string ReasonCode { get; }
    public int Attempt { get; }
    public DateTimeOffset? NextRetryAtUtc { get; }
    public bool? SimplySignProcessRunning { get; }
    public int? SimplySignProcessSessionId { get; }

    private static bool IsUtc(DateTimeOffset value) =>
        value != default && value.Offset == TimeSpan.Zero;
}

internal static class SimplySignSessionContractPolicy
{
    public static bool IsValid(
        long sessionGeneration,
        params CapabilitySnapshot?[] capabilities)
    {
        return sessionGeneration > 0 && capabilities.All(capability =>
            capability is null ||
            capability.Configured == (capability.Session is not null) &&
            (capability.Session is null ||
                capability.Session.SessionGeneration == sessionGeneration &&
                (capability.Ready == capability.Session.Ready ||
                    !capability.Ready && capability.Session.Ready &&
                    ManagementSnapshotReasonCodes.IsPdfToolFailure(capability.ReasonCode)) &&
                capability.TokenPresent == capability.Session.TokenPresent &&
                capability.TokenMatches == capability.Session.TokenMatches &&
                capability.CertificatePresent == capability.Session.CertificatePresent &&
                capability.CertificateMatches == capability.Session.CertificateMatches &&
                capability.PrivateKeyPresent == capability.Session.PrivateKeyPresent &&
                capability.PrivateKeyMatches == capability.Session.PrivateKeyMatches &&
                SimplySignSessionReasonCodes.IsCompatibleOuterReason(
                    capability.ReasonCode,
                    capability.Session.ReasonCode)));
    }
}

internal sealed class SimplySignSessionStateJsonConverter : JsonConverter<SimplySignSessionState>
{
    public override SimplySignSessionState Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new ProtocolException("invalid_message", "The SimplySign session state is invalid.");
        }

        return SimplySignSessionStatePolicy.ParseExact(reader.GetString());
    }

    public override void Write(
        Utf8JsonWriter writer,
        SimplySignSessionState value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(SimplySignSessionStatePolicy.Format(value));
}
