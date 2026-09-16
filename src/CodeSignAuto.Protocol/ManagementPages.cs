using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using ParsedProductVersion = CodeSignAuto.Core.Versioning.ProductVersion;

namespace CodeSignAuto.Protocol;

public sealed record JobPageCursor
{
    public JobPageCursor(string bucket, DateTimeOffset createdAtUtc, Guid jobId, DateTimeOffset asOfUtc)
    {
        if (bucket is not ("active" or "terminal") ||
            createdAtUtc == default || createdAtUtc.Offset != TimeSpan.Zero ||
            asOfUtc == default || asOfUtc.Offset != TimeSpan.Zero ||
            createdAtUtc > asOfUtc || jobId == Guid.Empty)
        {
            throw new ArgumentException("The job page cursor is invalid.");
        }

        Bucket = bucket;
        CreatedAtUtc = createdAtUtc;
        JobId = jobId;
        AsOfUtc = asOfUtc;
    }

    public string Bucket { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public Guid JobId { get; }
    public DateTimeOffset AsOfUtc { get; }
}

public sealed record JobPageItem
{
    private static readonly HashSet<string> Sources = new(StringComparer.Ordinal) { "api", "local" };
    private static readonly HashSet<string> Kinds = new(StringComparer.Ordinal) { "authenticode", "pdf" };
    private static readonly HashSet<string> States = new(StringComparer.Ordinal)
    {
        "queued", "waiting_for_agent", "signing", "verifying", "succeeded", "failed", "expired",
    };

    public JobPageItem(
        Guid jobId,
        string source,
        string kind,
        string state,
        string originalName,
        DateTimeOffset createdAtUtc,
        DateTimeOffset? startedAtUtc,
        DateTimeOffset? completedAtUtc,
        string? errorCode,
        Guid correlationId,
        bool hasResult)
    {
        if (jobId == Guid.Empty || correlationId == Guid.Empty ||
            !Sources.Contains(source) || !Kinds.Contains(kind) || !States.Contains(state) ||
            !IsSafeBaseName(originalName) || !IsUtc(createdAtUtc) ||
            startedAtUtc is { } started && (!IsUtc(started) || started < createdAtUtc) ||
            completedAtUtc is { } completed && (!IsUtc(completed) || completed < createdAtUtc) ||
            state is "succeeded" or "failed" or "expired" && completedAtUtc is null ||
            state is not ("succeeded" or "failed" or "expired") && completedAtUtc is not null ||
            state == "succeeded" && (errorCode is not null || !hasResult) ||
            state == "failed" && (!ManagementJobCodes.IsErrorCode(errorCode) || hasResult) ||
            state == "expired" && (errorCode != "job_expired" || hasResult) ||
            state is not ("succeeded" or "failed" or "expired") && (errorCode is not null || hasResult))
        {
            throw new ArgumentException("The job page item is invalid.");
        }

        JobId = jobId;
        Source = source;
        Kind = kind;
        State = state;
        OriginalName = originalName;
        CreatedAtUtc = createdAtUtc;
        StartedAtUtc = startedAtUtc;
        CompletedAtUtc = completedAtUtc;
        ErrorCode = errorCode;
        CorrelationId = correlationId;
        HasResult = hasResult;
    }

    public Guid JobId { get; }
    public string Source { get; }
    public string Kind { get; }
    public string State { get; }
    public string OriginalName { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public DateTimeOffset? StartedAtUtc { get; }
    public DateTimeOffset? CompletedAtUtc { get; }
    public string? ErrorCode { get; }
    public Guid CorrelationId { get; }
    public bool HasResult { get; }

    private static bool IsUtc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;

    private static bool IsSafeBaseName(string? value) =>
        value is { Length: > 0 and <= 255 } &&
        string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) &&
        value.All(static character => !char.IsControl(character));
}

public sealed record JobPageRequest(Guid RequestId, JobPageCursor? Cursor) : AgentMessage;

public sealed record JobPageResponse(
    Guid RequestId,
    IReadOnlyList<JobPageItem> Items,
    JobPageCursor? NextCursor,
    string? ErrorCode,
    Guid? CorrelationId) : AgentMessage;

public sealed record TerminalJobWatermark
{
    public TerminalJobWatermark(long sequence)
    {
        if (sequence < 0)
        {
            throw new ArgumentException("The terminal job watermark is invalid.");
        }

        Sequence = sequence;
    }

    public long Sequence { get; }
}

public sealed record TerminalJobCursor
{
    public TerminalJobCursor(long lastSequence, long snapshotSequence)
    {
        if (lastSequence <= 0 || snapshotSequence <= 0 || lastSequence > snapshotSequence)
        {
            throw new ArgumentException("The terminal job cursor is invalid.");
        }

        LastSequence = lastSequence;
        SnapshotSequence = snapshotSequence;
    }

    public long LastSequence { get; }
    public long SnapshotSequence { get; }
}

public sealed record TerminalJobEventItem
{
    public TerminalJobEventItem(long sequence, JobPageItem item)
    {
        if (sequence <= 0 || item is null ||
            item.State is not ("succeeded" or "failed" or "expired") ||
            item.CompletedAtUtc is null)
        {
            throw new ArgumentException("The terminal job event is invalid.");
        }

        Sequence = sequence;
        Item = item;
    }

    public long Sequence { get; }
    public JobPageItem Item { get; }
}

public sealed record TerminalJobDeltaRequest(
    Guid RequestId,
    TerminalJobWatermark? Watermark,
    TerminalJobCursor? Cursor) : AgentMessage;

public sealed record TerminalJobDeltaResponse(
    Guid RequestId,
    IReadOnlyList<TerminalJobEventItem> Items,
    TerminalJobCursor? NextCursor,
    TerminalJobWatermark? Watermark,
    string? ErrorCode,
    Guid? CorrelationId) : AgentMessage;

public sealed record ServiceSettingsSummary
{
    public const long FixedMaximumUploadBytes = 512L * 1024 * 1024;

    [JsonConstructor]
    public ServiceSettingsSummary(
        int listenPort,
        long maximumUploadBytes,
        int retentionHours,
        string productVersion)
    {
        ParsedProductVersion? parsedProductVersion = null;
        var validProductVersion = productVersion is { Length: > 0 and <= 64 } &&
            ParsedProductVersion.TryParse(productVersion, out parsedProductVersion);
        if (listenPort is < 1 or > 65535 ||
            maximumUploadBytes != FixedMaximumUploadBytes ||
            retentionHours is < 0 or > 168 ||
            !validProductVersion)
        {
            throw new ArgumentException("The service settings summary is invalid.");
        }

        ListenPort = listenPort;
        MaximumUploadBytes = maximumUploadBytes;
        RetentionHours = retentionHours;
        ProductVersion = parsedProductVersion!.Display;
    }

    public int ListenPort { get; }
    public long MaximumUploadBytes { get; }
    public int RetentionHours { get; }
    public string ProductVersion { get; }

}

public sealed record ServiceSettingsRequest(Guid RequestId) : AgentMessage;

public sealed record ServiceSettingsResponse(
    Guid RequestId,
    ServiceSettingsSummary? Summary,
    string? ErrorCode,
    Guid? CorrelationId) : AgentMessage;

public sealed record ClearJobHistoryRequest(Guid RequestId, DateTimeOffset CompletedBeforeUtc) : AgentMessage;

public sealed record ClearJobHistoryResponse(
    Guid RequestId, int DeletedCount, string? ErrorCode, Guid? CorrelationId) : AgentMessage;
