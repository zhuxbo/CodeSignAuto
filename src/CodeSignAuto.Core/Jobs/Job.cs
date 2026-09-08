namespace CodeSignAuto.Core.Jobs;

public sealed record Job(
    Guid Id,
    JobState State,
    SigningParameters Parameters)
{
    public FileKind Kind { get; init; }

    public string OriginalName { get; init; } = string.Empty;

    public string Extension { get; init; } = string.Empty;

    public string CanonicalParametersJson { get; init; } = string.Empty;

    public string InputSha256 { get; init; } = string.Empty;

    public long InputSize { get; init; }

    public string? ResultSha256 { get; init; }

    public long? ResultSize { get; init; }

    public Guid? DispatchId { get; init; }

    public Guid? LeaseConnectionId { get; init; }

    public string? ErrorCode { get; init; }

    public string? ErrorMessage { get; init; }

    public int AttemptCount { get; init; }

    public string RequestFingerprint { get; init; } = string.Empty;

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    public string Source { get; init; } = "api";

    public Guid CorrelationId { get; init; }
}
