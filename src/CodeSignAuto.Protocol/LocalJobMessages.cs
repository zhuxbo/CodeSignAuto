namespace CodeSignAuto.Protocol;

public sealed record LocalJobCreateRequest(
    Guid RequestId,
    string OriginalName,
    string Extension,
    long DeclaredSize,
    string CanonicalParametersJson) : AgentMessage;

public sealed record LocalJobUploadLease(
    Guid RequestId,
    Guid JobId,
    string LeaseId,
    string RelativePartPath,
    DateTimeOffset ExpiresAtUtc) : AgentMessage;

public sealed record LocalJobUploadCompleted(
    Guid RequestId,
    Guid JobId,
    string LeaseId,
    long ActualSize,
    string Sha256) : AgentMessage;

public sealed record LocalJobAccepted(Guid RequestId, Guid JobId) : AgentMessage;

public enum LocalJobRejectionDisposition
{
    Transient,
    Definitive,
}

public sealed record LocalJobRejected(
    Guid RequestId,
    string ErrorCode,
    Guid CorrelationId) : AgentMessage
{
    public LocalJobRejectionDisposition GetDisposition() =>
        LocalJobRejectionPolicy.Classify(ErrorCode);
}

public static class LocalJobRejectionPolicy
{
    public static LocalJobRejectionDisposition Classify(string? errorCode) =>
        errorCode is
            "local_request_conflict" or
            "local_upload_expired" or
            "local_upload_identity_mismatch" or
            "local_upload_size_mismatch" or
            "local_upload_hash_mismatch" or
            "local_upload_invalid_path" or
            "local_upload_missing" or
            "local_upload_cleanup_failed" or
            "invalid_parameters" or
            "unsupported_type" or
            "file_signature_mismatch" or
            "file_too_large" or
            "local_source_changed" or
            "local_source_empty" or
            "local_source_invalid"
            ? LocalJobRejectionDisposition.Definitive
            : LocalJobRejectionDisposition.Transient;
}

public sealed record LocalJobResultRequest(Guid RequestId, Guid JobId) : AgentMessage;

public sealed record LocalJobResultMetadata(
    Guid RequestId,
    Guid JobId,
    string Extension,
    long Size,
    string Sha256) : AgentMessage;
