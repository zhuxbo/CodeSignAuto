using System.Text.Json.Serialization;

namespace CodeSignAuto.Protocol;

public abstract record AgentMessage;

public abstract record JobTerminalMessage(Guid JobId, Guid DispatchId) : AgentMessage;

public static class AgentCapabilityPolicy
{
    private static readonly HashSet<string> Supported = new(StringComparer.Ordinal)
    {
        "authenticode", "pdf",
    };

    public static bool IsValid(IReadOnlyList<string>? capabilities) =>
        capabilities is { Count: > 0 } &&
        capabilities.All(Supported.Contains) &&
        capabilities.Distinct(StringComparer.Ordinal).Count() == capabilities.Count;
}

public sealed record AgentHello(
    int ProtocolVersion,
    int ProcessId,
    int SessionId,
    string UserSid,
    string AgentVersion,
    IReadOnlyList<string> Capabilities) : AgentMessage;

public sealed record AgentHeartbeat : AgentMessage
{
    public AgentHeartbeat(
        int sessionId,
        string simplySignStatus,
        string tokenStatus,
        string certificateStatus,
        string keyStatus,
        Guid? currentJobId,
        int? simplySignProcessSessionId = null,
        CapabilitySnapshot? authenticode = null,
        CapabilitySnapshot? pdf = null)
    {
        throw InvalidSessionContract();
    }

    [JsonConstructor]
    public AgentHeartbeat(
        int sessionId,
        string simplySignStatus,
        string tokenStatus,
        string certificateStatus,
        string keyStatus,
        Guid? currentJobId,
        int? simplySignProcessSessionId,
        CapabilitySnapshot? authenticode,
        CapabilitySnapshot? pdf,
        long sessionGeneration,
        IReadOnlyList<SessionTransitionEvidence>? sessionTransitions = null,
        IReadOnlyList<CertificateSummary>? certificates = null)
    {
        if (sessionGeneration <= 0 ||
            authenticode is null ||
            pdf is null ||
            ManagementSnapshotReasonCodes.IsPdfToolFailure(authenticode.ReasonCode) ||
            !SimplySignSessionContractPolicy.IsValid(sessionGeneration, authenticode, pdf) ||
            !SessionTransitionEvidence.IsValidHistory(sessionGeneration, sessionTransitions))
        {
            throw InvalidSessionContract();
        }

        SessionId = sessionId;
        SimplySignStatus = simplySignStatus;
        TokenStatus = tokenStatus;
        CertificateStatus = certificateStatus;
        KeyStatus = keyStatus;
        CurrentJobId = currentJobId;
        SimplySignProcessSessionId = simplySignProcessSessionId;
        Authenticode = authenticode;
        Pdf = pdf;
        SessionGeneration = sessionGeneration;
        SessionTransitions = new SessionTransitionHistory(sessionTransitions ?? []);
        Certificates = new CertificateSummaryCollection(certificates ?? []);
    }

    public int SessionId { get; }
    public string SimplySignStatus { get; }
    public string TokenStatus { get; }
    public string CertificateStatus { get; }
    public string KeyStatus { get; }
    public Guid? CurrentJobId { get; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? SimplySignProcessSessionId { get; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CapabilitySnapshot? Authenticode { get; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CapabilitySnapshot? Pdf { get; }
    public long SessionGeneration { get; }
    public IReadOnlyList<SessionTransitionEvidence> SessionTransitions { get; }
    public IReadOnlyList<CertificateSummary> Certificates { get; }

    private static ProtocolException InvalidSessionContract() =>
        new("invalid_message", "The SimplySign session heartbeat contract is invalid.");

    private sealed class SessionTransitionHistory : IReadOnlyList<SessionTransitionEvidence>
    {
        private readonly SessionTransitionEvidence[] _items;

        public SessionTransitionHistory(IReadOnlyList<SessionTransitionEvidence> items) =>
            _items = items.ToArray();

        public int Count => _items.Length;

        public SessionTransitionEvidence this[int index] => _items[index];

        public IEnumerator<SessionTransitionEvidence> GetEnumerator() =>
            ((IEnumerable<SessionTransitionEvidence>)_items).GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            _items.GetEnumerator();

        public override bool Equals(object? obj) =>
            obj is IReadOnlyList<SessionTransitionEvidence> other &&
            _items.SequenceEqual(other);

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
}

public sealed record SessionTransitionEvidence
{
    public const int MaximumRetained = 64;

    [JsonConstructor]
    public SessionTransitionEvidence(
        long sequence,
        SimplySignSessionState state,
        long sessionGeneration,
        DateTimeOffset transitionedAtUtc,
        int attempt)
    {
        if (sequence <= 0 ||
            !Enum.IsDefined(state) ||
            sessionGeneration <= 0 ||
            transitionedAtUtc == default ||
            transitionedAtUtc.Offset != TimeSpan.Zero ||
            attempt is < 0 or > 2)
        {
            throw new ProtocolException("invalid_message", "The session transition evidence is invalid.");
        }

        Sequence = sequence;
        State = state;
        SessionGeneration = sessionGeneration;
        TransitionedAtUtc = transitionedAtUtc;
        Attempt = attempt;
    }

    public long Sequence { get; }
    public SimplySignSessionState State { get; }
    public long SessionGeneration { get; }
    public DateTimeOffset TransitionedAtUtc { get; }
    public int Attempt { get; }

    internal static bool IsValidHistory(
        long currentGeneration,
        IReadOnlyList<SessionTransitionEvidence>? transitions)
    {
        if (transitions is null)
        {
            return true;
        }

        if (transitions.Count > MaximumRetained || transitions.Any(static item => item is null))
        {
            return false;
        }

        SessionTransitionEvidence? previous = null;
        foreach (var item in transitions)
        {
            if (item.SessionGeneration > currentGeneration ||
                previous is not null &&
                (item.Sequence != previous.Sequence + 1 ||
                    item.SessionGeneration < previous.SessionGeneration))
            {
                return false;
            }

            previous = item;
        }

        return true;
    }
}

public sealed record ManagementSnapshotRequest(Guid RequestId) : AgentMessage;

public sealed record ManagementSnapshotResponse(
    Guid RequestId,
    ManagementSnapshot? Snapshot,
    string? ErrorCode,
    Guid? CorrelationId) : AgentMessage;

public sealed record PrepareSimplySignSessionCommand(Guid RequestId) : AgentMessage;

public sealed record PrepareSimplySignSessionResult(
    Guid RequestId,
    SimplySignSessionState State,
    string? ErrorCode) : AgentMessage;

public sealed record SignJobCommand(
    Guid JobId,
    Guid DispatchId,
    int AttemptNumber,
    string Extension,
    string CanonicalParametersJson,
    long InputSize,
    string InputSha256) : AgentMessage;

public sealed record JobProgress(Guid JobId, Guid DispatchId, int Percent, string Stage) : AgentMessage;

public sealed record JobCompleted(Guid JobId, Guid DispatchId, long OutputSize, string OutputSha256)
    : JobTerminalMessage(JobId, DispatchId);

public sealed record JobFailed(Guid JobId, Guid DispatchId, string ErrorCode, string ErrorMessage)
    : JobTerminalMessage(JobId, DispatchId);
