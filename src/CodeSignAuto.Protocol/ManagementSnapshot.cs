using System.Collections.ObjectModel;
using System.Text.RegularExpressions;

namespace CodeSignAuto.Protocol;

public static partial class IdentifierSuffixPolicy
{
    public static string? Create(string? identifier)
    {
        if (string.IsNullOrEmpty(identifier) || !SafeIdentifierPattern().IsMatch(identifier))
        {
            return null;
        }

        return identifier[^Math.Min(8, identifier.Length)..];
    }

    internal static bool IsValid(string? suffix) =>
        suffix is null || suffix.Length is >= 1 and <= 8 && SafeIdentifierPattern().IsMatch(suffix);

    [GeneratedRegex("^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifierPattern();
}

public static class CertificateThumbprintSuffixPolicy
{
    public static bool IsValid(string? suffix) =>
        suffix is { Length: 8 } &&
        suffix.All(static character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
}

public static class ManagementSnapshotReasonCodes
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
        "not_configured",
        "process_missing",
        "process_session_mismatch",
        "process_probe_failed",
        "token_missing",
        "token_mismatch",
        "token_identifier_mismatch",
        "certificate_missing",
        "certificate_mismatch",
        "certificate_identifier_mismatch",
        "private_key_missing",
        "private_key_mismatch",
        "private_key_identifier_mismatch",
        "probe_output_invalid",
        "probe_request_invalid",
        "probe_request_cleanup_failed",
        "probe_token_unavailable",
        "probe_process_failed",
        "probe_failed",
        "login_failed",
        "retry_scheduled",
        "management_unavailable",
        "service_unavailable",
        "agent_unavailable",
        "agent_session_invalid",
        "heartbeat_missing",
        "heartbeat_invalid",
        "heartbeat_stale",
        "not_yet_valid",
        "expired",
        "private_key_ambiguous",
        "certificate_serial_ambiguous",
        "unsupported_purpose",
        "catalog_stale",
        "pdf_support_not_installed",
        "pdf_helper_tampered",
    };

    public static bool IsAllowed(string? code) => code is not null && Allowed.Contains(code);

    internal static bool IsPdfToolFailure(string? code) =>
        code is "pdf_support_not_installed" or "pdf_helper_tampered";
}

public static class ManagementJobCodes
{
    private static readonly HashSet<string> Kinds = new(StringComparer.Ordinal)
    {
        "authenticode", "pdf",
    };

    private static readonly HashSet<string> CurrentStates = new(StringComparer.Ordinal)
    {
        "waiting_for_agent", "signing", "verifying",
    };

    private static readonly HashSet<string> CurrentStages = new(StringComparer.Ordinal)
    {
        "waiting_for_agent", "signing", "verifying",
    };

    private static readonly HashSet<string> TerminalStates = new(StringComparer.Ordinal)
    {
        "succeeded", "failed", "expired",
    };

    private static readonly HashSet<string> ErrorCodes = new(StringComparer.Ordinal)
    {
        "invalid_parameters", "unsupported_type", "file_signature_mismatch", "file_too_large",
        "idempotency_conflict", "agent_unavailable", "agent_session_zero", "agent_wrong_user",
        "agent_already_running", "agent_protocol_mismatch", "otp_missing", "otp_wrong_user",
        "otp_corrupt", "otp_profile_invalid", "clock_not_synchronized", "simplysign_exe_missing",
        "simplysign_close_timeout", "simplysign_login_failed", "token_missing", "certificate_missing",
        "private_key_missing", "pkcs11_session_lost", "signtool_missing", "invalid_signable_file",
        "already_signed", "authenticode_sign_failed", "authenticode_verify_failed", "pdf_helper_missing",
        "pdf_helper_tampered", "pdf_invalid", "pdf_sign_failed", "pdf_appearance_font_missing",
        "pdf_verify_failed", "tsa_failed",
        "spool_write_failed", "input_corrupt", "result_corrupt", "recovery_exhausted",
        "manual_job_interrupted", "job_expired",
        "certificate_catalog_unavailable", "certificate_not_found",
        "certificate_serial_ambiguous", "certificate_not_usable", "internal_error",
    };

    internal static bool IsKind(string? value) => value is not null && Kinds.Contains(value);

    internal static bool IsCurrentState(string? value) => value is not null && CurrentStates.Contains(value);

    internal static bool IsCurrentStage(string? value) => value is not null && CurrentStages.Contains(value);

    internal static bool IsTerminalState(string? value) => value is not null && TerminalStates.Contains(value);

    public static bool IsErrorCode(string? value) => value is not null && ErrorCodes.Contains(value);
}

public sealed record CertificateSummary
{
    private static readonly HashSet<string> CurrentUnavailableReasons = new(StringComparer.Ordinal)
    {
        "not_yet_valid",
        "expired",
        "private_key_missing",
        "private_key_ambiguous",
        "certificate_serial_ambiguous",
        "unsupported_purpose",
    };

    public CertificateSummary(
        string commonName,
        string serialNumber,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset notAfterUtc,
        bool authenticodeUsable,
        bool pdfUsable,
        bool catalogCurrent,
        string? unavailableReason)
    {
        if (!IsSafeText(commonName, 256) ||
            !IsCanonicalSerial(serialNumber) ||
            !IsUtcDate(notBeforeUtc) ||
            !IsUtcDate(notAfterUtc) ||
            notBeforeUtc > notAfterUtc ||
            !catalogCurrent &&
                (authenticodeUsable || pdfUsable || unavailableReason != "catalog_stale") ||
            catalogCurrent && (authenticodeUsable || pdfUsable) && unavailableReason is not null ||
            catalogCurrent && !authenticodeUsable && !pdfUsable &&
                (unavailableReason is null || !CurrentUnavailableReasons.Contains(unavailableReason)))
        {
            throw new ArgumentException("The certificate summary is invalid.");
        }

        CommonName = commonName;
        SerialNumber = serialNumber;
        NotBeforeUtc = notBeforeUtc;
        NotAfterUtc = notAfterUtc;
        AuthenticodeUsable = authenticodeUsable;
        PdfUsable = pdfUsable;
        CatalogCurrent = catalogCurrent;
        UnavailableReason = unavailableReason;
    }

    public string CommonName { get; }
    public string SerialNumber { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset NotAfterUtc { get; }
    public bool AuthenticodeUsable { get; }
    public bool PdfUsable { get; }
    public bool CatalogCurrent { get; }
    public string? UnavailableReason { get; }

    private static bool IsSafeText(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value.All(static character => !char.IsControl(character));

    private static bool IsCanonicalSerial(string? value) =>
        value is { Length: >= 2 and <= 128 } &&
        value.Length % 2 == 0 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'A' and <= 'F') &&
        (value.Length == 2 || !value.StartsWith("00", StringComparison.Ordinal));

    private static bool IsUtcDate(DateTimeOffset value) =>
        value != default && value.Offset == TimeSpan.Zero && value.Year is >= 1900 and <= 2200;
}

internal sealed class CertificateSummaryCollection : IReadOnlyList<CertificateSummary>
{
    public const int MaximumCount = 256;
    private readonly CertificateSummary[] _items;

    public CertificateSummaryCollection(IReadOnlyList<CertificateSummary>? items)
    {
        if (items is null || items.Count > MaximumCount || items.Any(static item => item is null))
        {
            throw new ArgumentException("The certificate summary collection is invalid.");
        }

        _items = items.ToArray();
    }

    public int Count => _items.Length;
    public CertificateSummary this[int index] => _items[index];
    public IEnumerator<CertificateSummary> GetEnumerator() =>
        ((IEnumerable<CertificateSummary>)_items).GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
        _items.GetEnumerator();

    public override bool Equals(object? obj) =>
        obj is IReadOnlyList<CertificateSummary> other && _items.SequenceEqual(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var item in _items)
        {
            hash.Add(item);
        }

        return hash.ToHashCode();
    }
}

public sealed record CapabilitySnapshot
{
    public CapabilitySnapshot(
        bool configured,
        bool tokenPresent,
        bool tokenMatches,
        string? tokenSuffix,
        bool certificatePresent,
        bool certificateMatches,
        string? certificateSuffix,
        bool privateKeyPresent,
        bool privateKeyMatches,
        string? privateKeySuffix,
        bool ready,
        string reasonCode,
        DateTimeOffset? certificateNotAfterUtc = null,
        string? certificateThumbprintSuffix = null,
        SimplySignSessionSnapshot? session = null)
    {
        if (!ManagementSnapshotReasonCodes.IsAllowed(reasonCode) ||
            !IdentifierSuffixPolicy.IsValid(tokenSuffix) ||
            !IdentifierSuffixPolicy.IsValid(certificateSuffix) ||
            !IdentifierSuffixPolicy.IsValid(privateKeySuffix) ||
            tokenSuffix is not null && !tokenPresent ||
            certificateSuffix is not null && !certificatePresent ||
            privateKeySuffix is not null && !privateKeyPresent ||
            tokenMatches && !tokenPresent ||
            certificateMatches && !certificatePresent ||
            privateKeyMatches && !privateKeyPresent ||
            !configured && (tokenPresent || tokenMatches || tokenSuffix is not null ||
                certificatePresent || certificateMatches || certificateSuffix is not null ||
                privateKeyPresent || privateKeyMatches || privateKeySuffix is not null || ready ||
                reasonCode != "not_configured") ||
            ready && (!configured || !tokenPresent || !tokenMatches ||
                !certificatePresent || !certificateMatches ||
                !privateKeyPresent || !privateKeyMatches || reasonCode != "ready") ||
            reasonCode == "ready" && !ready ||
            configured && reasonCode == "not_configured")
        {
            throw new ArgumentException("The capability snapshot is invalid.");
        }

        Configured = configured;
        TokenPresent = tokenPresent;
        TokenMatches = tokenMatches;
        TokenSuffix = tokenSuffix;
        CertificatePresent = certificatePresent;
        CertificateMatches = certificateMatches;
        CertificateSuffix = certificateSuffix;
        PrivateKeyPresent = privateKeyPresent;
        PrivateKeyMatches = privateKeyMatches;
        PrivateKeySuffix = privateKeySuffix;
        Ready = ready;
        ReasonCode = reasonCode;
        if (certificateNotAfterUtc is { } notAfter &&
            (notAfter == default || notAfter.Offset != TimeSpan.Zero || notAfter.Year is < 2000 or > 2100) ||
            certificateThumbprintSuffix is not null &&
                !CertificateThumbprintSuffixPolicy.IsValid(certificateThumbprintSuffix) ||
            certificatePresent &&
                (certificateNotAfterUtc is null) != (certificateThumbprintSuffix is null) ||
            certificatePresent && session is null && certificateNotAfterUtc is null ||
            !certificatePresent && (certificateNotAfterUtc is not null || certificateThumbprintSuffix is not null))
        {
            throw new ArgumentException("The certificate metadata is invalid.");
        }

        CertificateNotAfterUtc = certificateNotAfterUtc;
        CertificateThumbprintSuffix = certificateThumbprintSuffix;
        Session = session;
    }

    public bool Configured { get; }
    public bool TokenPresent { get; }
    public bool TokenMatches { get; }
    public string? TokenSuffix { get; }
    public bool CertificatePresent { get; }
    public bool CertificateMatches { get; }
    public string? CertificateSuffix { get; }
    public bool PrivateKeyPresent { get; }
    public bool PrivateKeyMatches { get; }
    public string? PrivateKeySuffix { get; }
    public bool Ready { get; }
    public string ReasonCode { get; }
    public DateTimeOffset? CertificateNotAfterUtc { get; }
    public string? CertificateThumbprintSuffix { get; }
    public SimplySignSessionSnapshot? Session { get; }

    public static CapabilitySnapshot NotConfigured() =>
        new(false, false, false, null, false, false, null, false, false, null, false, "not_configured");
}

public sealed record CurrentJobSnapshot
{
    public CurrentJobSnapshot(
        Guid jobId,
        string kind,
        string state,
        string stage,
        DateTimeOffset startedAtUtc,
        long elapsedSeconds)
    {
        if (jobId == Guid.Empty ||
            !ManagementJobCodes.IsKind(kind) ||
            !ManagementJobCodes.IsCurrentState(state) ||
            !ManagementJobCodes.IsCurrentStage(stage) ||
            startedAtUtc == default || startedAtUtc.Offset != TimeSpan.Zero ||
            elapsedSeconds is < 0 or > 31_536_000)
        {
            throw new ArgumentException("The current job snapshot is invalid.");
        }

        JobId = jobId;
        Kind = kind;
        State = state;
        Stage = stage;
        StartedAtUtc = startedAtUtc;
        ElapsedSeconds = elapsedSeconds;
    }

    public Guid JobId { get; }
    public string Kind { get; }
    public string State { get; }
    public string Stage { get; }
    public DateTimeOffset StartedAtUtc { get; }
    public long ElapsedSeconds { get; }
}

public sealed record RecentJobSnapshot
{
    public RecentJobSnapshot(
        Guid jobId,
        string kind,
        string terminalState,
        DateTimeOffset completedAtUtc,
        string? errorCode)
    {
        if (jobId == Guid.Empty ||
            !ManagementJobCodes.IsKind(kind) ||
            !ManagementJobCodes.IsTerminalState(terminalState) ||
            completedAtUtc == default || completedAtUtc.Offset != TimeSpan.Zero ||
            terminalState == "succeeded" && errorCode is not null ||
            terminalState != "succeeded" && !ManagementJobCodes.IsErrorCode(errorCode))
        {
            throw new ArgumentException("The recent job snapshot is invalid.");
        }

        JobId = jobId;
        Kind = kind;
        TerminalState = terminalState;
        CompletedAtUtc = completedAtUtc;
        ErrorCode = errorCode;
    }

    public Guid JobId { get; }
    public string Kind { get; }
    public string TerminalState { get; }
    public DateTimeOffset CompletedAtUtc { get; }
    public string? ErrorCode { get; }
}

public sealed record ManagementSnapshot
{
    public const int CurrentVersion = 1;

    public ManagementSnapshot(
        int snapshotVersion,
        DateTimeOffset generatedAtUtc,
        Guid connectionId,
        bool serviceAvailable,
        bool agentConnected,
        int agentSessionId,
        int heartbeatSessionId,
        long? heartbeatAgeMilliseconds,
        bool simplySignProcessRunning,
        int? simplySignProcessSessionId,
        CapabilitySnapshot authenticode,
        CapabilitySnapshot pdf,
        int queuedJobCount,
        int activeJobCount,
        CurrentJobSnapshot? currentJob,
        IReadOnlyList<RecentJobSnapshot> recentJobs,
        long sessionGeneration,
        IReadOnlyList<CertificateSummary>? certificates = null)
    {
        ArgumentNullException.ThrowIfNull(authenticode);
        ArgumentNullException.ThrowIfNull(pdf);
        ArgumentNullException.ThrowIfNull(recentJobs);
        if (!SimplySignSessionContractPolicy.IsValid(sessionGeneration, authenticode, pdf))
        {
            throw new ProtocolException(
                "invalid_message",
                "The management SimplySign session contract is invalid.");
        }

        if (ManagementSnapshotReasonCodes.IsPdfToolFailure(authenticode.ReasonCode))
        {
            throw new ArgumentException("The management snapshot capability is invalid.");
        }

        if (snapshotVersion != CurrentVersion ||
            generatedAtUtc == default || generatedAtUtc.Offset != TimeSpan.Zero ||
            connectionId == Guid.Empty || !serviceAvailable || !agentConnected ||
            agentSessionId < 0 || heartbeatSessionId < 0 ||
            heartbeatAgeMilliseconds is < -86_400_000 or > 86_400_000 ||
            simplySignProcessSessionId < 0 ||
            simplySignProcessRunning && simplySignProcessSessionId is null ||
            !simplySignProcessRunning && simplySignProcessSessionId is not null ||
            queuedJobCount is < 0 or > 1_000_000 ||
            activeJobCount is < 0 or > 1_000_000 ||
            currentJob is not null && activeJobCount == 0 ||
            recentJobs.Count > 5 ||
            recentJobs.Any(job => job is null) ||
            recentJobs.Select(job => job.JobId).Distinct().Count() != recentJobs.Count)
        {
            throw new ArgumentException("The management snapshot is invalid.");
        }

        SnapshotVersion = snapshotVersion;
        GeneratedAtUtc = generatedAtUtc;
        ConnectionId = connectionId;
        ServiceAvailable = serviceAvailable;
        AgentConnected = agentConnected;
        AgentSessionId = agentSessionId;
        HeartbeatSessionId = heartbeatSessionId;
        HeartbeatAgeMilliseconds = heartbeatAgeMilliseconds;
        SimplySignProcessRunning = simplySignProcessRunning;
        SimplySignProcessSessionId = simplySignProcessSessionId;
        Authenticode = authenticode;
        Pdf = pdf;
        QueuedJobCount = queuedJobCount;
        ActiveJobCount = activeJobCount;
        CurrentJob = currentJob;
        RecentJobs = new ReadOnlyCollection<RecentJobSnapshot>(recentJobs.ToArray());
        SessionGeneration = sessionGeneration;
        Certificates = new CertificateSummaryCollection(certificates ?? []);
    }

    public int SnapshotVersion { get; }
    public DateTimeOffset GeneratedAtUtc { get; }
    public Guid ConnectionId { get; }
    public bool ServiceAvailable { get; }
    public bool AgentConnected { get; }
    public int AgentSessionId { get; }
    public int HeartbeatSessionId { get; }
    public long? HeartbeatAgeMilliseconds { get; }
    public bool SimplySignProcessRunning { get; }
    public int? SimplySignProcessSessionId { get; }
    public CapabilitySnapshot Authenticode { get; }
    public CapabilitySnapshot Pdf { get; }
    public int QueuedJobCount { get; }
    public int ActiveJobCount { get; }
    public CurrentJobSnapshot? CurrentJob { get; }
    public IReadOnlyList<RecentJobSnapshot> RecentJobs { get; }
    [System.Text.Json.Serialization.JsonIgnore(
        Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public long SessionGeneration { get; }
    public IReadOnlyList<CertificateSummary> Certificates { get; }

    public bool Equals(ManagementSnapshot? other) =>
        other is not null &&
        SnapshotVersion == other.SnapshotVersion &&
        GeneratedAtUtc == other.GeneratedAtUtc &&
        ConnectionId == other.ConnectionId &&
        ServiceAvailable == other.ServiceAvailable &&
        AgentConnected == other.AgentConnected &&
        AgentSessionId == other.AgentSessionId &&
        HeartbeatSessionId == other.HeartbeatSessionId &&
        HeartbeatAgeMilliseconds == other.HeartbeatAgeMilliseconds &&
        SimplySignProcessRunning == other.SimplySignProcessRunning &&
        SimplySignProcessSessionId == other.SimplySignProcessSessionId &&
        Equals(Authenticode, other.Authenticode) &&
        Equals(Pdf, other.Pdf) &&
        QueuedJobCount == other.QueuedJobCount &&
        ActiveJobCount == other.ActiveJobCount &&
        Equals(CurrentJob, other.CurrentJob) &&
        RecentJobs.SequenceEqual(other.RecentJobs) &&
        SessionGeneration == other.SessionGeneration &&
        Certificates.SequenceEqual(other.Certificates);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(SnapshotVersion);
        hash.Add(GeneratedAtUtc);
        hash.Add(ConnectionId);
        hash.Add(ServiceAvailable);
        hash.Add(AgentConnected);
        hash.Add(AgentSessionId);
        hash.Add(HeartbeatSessionId);
        hash.Add(HeartbeatAgeMilliseconds);
        hash.Add(SimplySignProcessRunning);
        hash.Add(SimplySignProcessSessionId);
        hash.Add(Authenticode);
        hash.Add(Pdf);
        hash.Add(QueuedJobCount);
        hash.Add(ActiveJobCount);
        hash.Add(CurrentJob);
        hash.Add(SessionGeneration);
        foreach (var recent in RecentJobs)
        {
            hash.Add(recent);
        }

        foreach (var certificate in Certificates)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }
}
