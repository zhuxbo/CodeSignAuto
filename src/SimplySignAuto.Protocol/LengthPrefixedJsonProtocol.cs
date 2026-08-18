using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimplySignAuto.Core.Versioning;

namespace SimplySignAuto.Protocol;

public sealed class ProtocolException : Exception
{
    public ProtocolException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

public static class LengthPrefixedJsonProtocol
{
    public const int ProtocolVersion = 3;
    public const int MaximumPayloadLength = 512 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly ConditionalWeakTable<Stream, LengthPrefixedJsonWriter> Writers = new();
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.Ordinal)
    {
        ".pdf", ".exe", ".dll", ".msi", ".sys", ".cat",
    };
    private static readonly HashSet<string> AllowedProgressStages = new(StringComparer.Ordinal)
    {
        "signing", "verifying",
    };
    private static readonly HashSet<string> AllowedLocalErrorCodes = new(StringComparer.Ordinal)
    {
        "local_request_conflict", "local_upload_expired", "local_upload_identity_mismatch",
        "local_upload_size_mismatch", "local_upload_hash_mismatch", "local_upload_invalid_path",
        "local_upload_missing", "local_upload_cleanup_failed", "local_job_unavailable",
        "local_result_not_succeeded", "local_result_metadata_mismatch", "invalid_parameters",
        "unsupported_type", "file_signature_mismatch", "file_too_large", "internal_error",
    };
    private static readonly HashSet<string> AllowedErrorCodes = new(StringComparer.Ordinal)
    {
        "invalid_parameters", "unsupported_type", "file_signature_mismatch", "file_too_large",
        "idempotency_conflict", "agent_unavailable", "agent_session_zero", "agent_wrong_user",
        "agent_already_running", "agent_protocol_mismatch", "otp_missing", "otp_wrong_user",
        "otp_corrupt", "otp_profile_invalid", "clock_not_synchronized", "simplysign_exe_missing",
        "simplysign_close_timeout", "simplysign_login_failed", "token_missing", "certificate_missing",
        "private_key_missing", "pkcs11_session_lost", "signtool_missing", "invalid_signable_file",
        "already_signed", "authenticode_sign_failed", "authenticode_verify_failed", "pdf_helper_missing",
        "pdf_helper_tampered", "pdf_invalid", "pdf_sign_failed", "pdf_verify_failed", "tsa_failed",
        "spool_write_failed", "input_corrupt", "result_corrupt", "recovery_exhausted", "job_expired",
        "certificate_catalog_unavailable", "certificate_not_found", "certificate_serial_ambiguous",
        "certificate_not_usable",
        "internal_error",
    };
    private static readonly HashSet<string> AllowedStartupPreparationErrorCodes = new(StringComparer.Ordinal)
    {
        "simplysign_login_failed", "certificate_catalog_unavailable", "internal_error",
    };

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!IsSupportedContract(typeof(T)))
        {
            throw Error("unsupported_message_contract", "The requested message contract is not supported.");
        }

        var header = new byte[sizeof(int)];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32BigEndian(header);
        if (length is <= 0 or > MaximumPayloadLength)
        {
            throw Error("invalid_frame_length", "The message frame length is invalid.");
        }

        var rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var payload = rented.AsMemory(0, length);
            await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
            var message = Deserialize(payload);
            if (message is not T typed)
            {
                throw Error("unexpected_message_type", "The message type does not match the requested contract.");
            }

            ValidateMessage(message);

            return typed;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public static Task WriteAsync<T>(Stream stream, T message, CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        return GetWriter(stream).WriteAsync(message, cancellationToken);
    }

    public static LengthPrefixedJsonWriter GetWriter(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return Writers.GetValue(stream, static connection => new LengthPrefixedJsonWriter(connection));
    }

    internal static async Task WriteFrameAsync<T>(
        Stream stream,
        T message,
        CancellationToken cancellationToken,
        Action? frameStarted = null)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message is not AgentMessage agentMessage || !IsSupportedMessage(agentMessage))
        {
            throw Error("unsupported_message_contract", "The supplied message contract is not supported.");
        }

        ValidateMessage(agentMessage);

        byte[] payload;
        try
        {
            payload = Serialize(agentMessage);
        }
        catch (JsonException)
        {
            throw Error("invalid_message", "The message could not be serialized.");
        }

        try
        {
            if (payload.Length > MaximumPayloadLength)
            {
                throw Error("message_too_large", "The message exceeds the allowed size.");
            }

            var header = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);
            frameStarted?.Invoke();
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(payload);
        }
    }

    private static AgentMessage Deserialize(ReadOnlyMemory<byte> payload)
    {
        try
        {
            _ = StrictUtf8.GetCharCount(payload.Span);
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !HasOnlyProperties(root, "version", "type", "payload") ||
                !root.TryGetProperty("version", out var version) ||
                version.ValueKind != JsonValueKind.Number ||
                !version.TryGetInt32(out var protocolVersion))
            {
                throw Error("invalid_message", "The message envelope is invalid.");
            }

            if (protocolVersion != ProtocolVersion)
            {
                throw Error("unsupported_protocol_version", "The protocol version is not supported.");
            }

            if (!root.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("payload", out var messagePayload) ||
                messagePayload.ValueKind != JsonValueKind.Object ||
                !HasUniquePropertiesRecursively(messagePayload))
            {
                throw Error("invalid_message", "The message envelope is invalid.");
            }

            return typeElement.GetString() switch
            {
                "agent_hello" => DeserializePayload<AgentHello>(messagePayload),
                "agent_heartbeat" => DeserializePayload<AgentHeartbeat>(messagePayload),
                "sign_job_command" => DeserializePayload<SignJobCommand>(messagePayload),
                "job_progress" => DeserializePayload<JobProgress>(messagePayload),
                "job_completed" => DeserializePayload<JobCompleted>(messagePayload),
                "job_failed" => DeserializePayload<JobFailed>(messagePayload),
                "management_snapshot_request" => DeserializePayload<ManagementSnapshotRequest>(messagePayload),
                "management_snapshot_response" => DeserializePayload<ManagementSnapshotResponse>(messagePayload),
                "prepare_simplysign_session_command" => DeserializePayload<PrepareSimplySignSessionCommand>(messagePayload),
                "prepare_simplysign_session_result" => DeserializePayload<PrepareSimplySignSessionResult>(messagePayload),
                "local_job_create_request" => DeserializePayload<LocalJobCreateRequest>(messagePayload),
                "local_job_upload_lease" => DeserializePayload<LocalJobUploadLease>(messagePayload),
                "local_job_upload_completed" => DeserializePayload<LocalJobUploadCompleted>(messagePayload),
                "local_job_accepted" => DeserializePayload<LocalJobAccepted>(messagePayload),
                "local_job_rejected" => DeserializePayload<LocalJobRejected>(messagePayload),
                "local_job_result_request" => DeserializePayload<LocalJobResultRequest>(messagePayload),
                "local_job_result_metadata" => DeserializePayload<LocalJobResultMetadata>(messagePayload),
                "job_page_request" => DeserializePayload<JobPageRequest>(messagePayload),
                "job_page_response" => DeserializePayload<JobPageResponse>(messagePayload),
                "terminal_job_delta_request" => DeserializePayload<TerminalJobDeltaRequest>(messagePayload),
                "terminal_job_delta_response" => DeserializePayload<TerminalJobDeltaResponse>(messagePayload),
                "service_settings_request" => DeserializePayload<ServiceSettingsRequest>(messagePayload),
                "service_settings_response" => DeserializePayload<ServiceSettingsResponse>(messagePayload),
                "admin_control_hello" => DeserializePayload<AdminControlHello>(messagePayload),
                "admin_control_accepted" => DeserializePayload<AdminControlAccepted>(messagePayload),
                "agent_control_request" => DeserializePayload<AgentControlRequest>(messagePayload),
                "agent_control_response" => DeserializePayload<AgentControlResponse>(messagePayload),
                _ => throw Error("unknown_message_type", "The message type is not recognized."),
            };
        }
        catch (ProtocolException)
        {
            throw;
        }
        catch (DecoderFallbackException)
        {
            throw Error("invalid_message", "The message payload is invalid.");
        }
        catch (JsonException)
        {
            throw Error("invalid_message", "The message payload is invalid.");
        }
        catch (FormatException)
        {
            throw Error("invalid_message", "The message payload is invalid.");
        }
        catch (ArgumentException)
        {
            throw Error("invalid_message", "The message payload is invalid.");
        }
    }

    private static T DeserializePayload<T>(JsonElement payload)
        where T : AgentMessage =>
        payload.Deserialize<T>(SerializerOptions) ?? throw Error("invalid_message", "The message payload is invalid.");

    private static byte[] Serialize(AgentMessage message)
    {
        var type = MessageType(message);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteNumber("version", ProtocolVersion);
        writer.WriteString("type", type);
        writer.WritePropertyName("payload");
        JsonSerializer.Serialize(writer, message, message.GetType(), SerializerOptions);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    private static string MessageType(AgentMessage message) => message switch
    {
        AgentHello => "agent_hello",
        AgentHeartbeat => "agent_heartbeat",
        SignJobCommand => "sign_job_command",
        JobProgress => "job_progress",
        JobCompleted => "job_completed",
        JobFailed => "job_failed",
        ManagementSnapshotRequest => "management_snapshot_request",
        ManagementSnapshotResponse => "management_snapshot_response",
        PrepareSimplySignSessionCommand => "prepare_simplysign_session_command",
        PrepareSimplySignSessionResult => "prepare_simplysign_session_result",
        LocalJobCreateRequest => "local_job_create_request",
        LocalJobUploadLease => "local_job_upload_lease",
        LocalJobUploadCompleted => "local_job_upload_completed",
        LocalJobAccepted => "local_job_accepted",
        LocalJobRejected => "local_job_rejected",
        LocalJobResultRequest => "local_job_result_request",
        LocalJobResultMetadata => "local_job_result_metadata",
        JobPageRequest => "job_page_request",
        JobPageResponse => "job_page_response",
        TerminalJobDeltaRequest => "terminal_job_delta_request",
        TerminalJobDeltaResponse => "terminal_job_delta_response",
        ServiceSettingsRequest => "service_settings_request",
        ServiceSettingsResponse => "service_settings_response",
        AdminControlHello => "admin_control_hello",
        AdminControlAccepted => "admin_control_accepted",
        AgentControlRequest => "agent_control_request",
        AgentControlResponse => "agent_control_response",
        _ => throw Error("unsupported_message_contract", "The supplied message contract is not supported."),
    };

    private static bool IsSupportedMessage(AgentMessage message) => message is
        AgentHello or AgentHeartbeat or SignJobCommand or JobProgress or JobCompleted or JobFailed or
        ManagementSnapshotRequest or ManagementSnapshotResponse or
        PrepareSimplySignSessionCommand or PrepareSimplySignSessionResult or
        LocalJobCreateRequest or LocalJobUploadLease or LocalJobUploadCompleted or
        LocalJobAccepted or LocalJobRejected or LocalJobResultRequest or LocalJobResultMetadata or
        JobPageRequest or JobPageResponse or TerminalJobDeltaRequest or TerminalJobDeltaResponse or
        ServiceSettingsRequest or ServiceSettingsResponse or
        AdminControlHello or AdminControlAccepted or AgentControlRequest or AgentControlResponse;

    private static bool IsSupportedContract(Type contract) => contract == typeof(AgentMessage) ||
        contract == typeof(AgentHello) ||
        contract == typeof(AgentHeartbeat) ||
        contract == typeof(SignJobCommand) ||
        contract == typeof(JobProgress) ||
        contract == typeof(JobCompleted) ||
        contract == typeof(JobFailed) ||
        contract == typeof(ManagementSnapshotRequest) ||
        contract == typeof(ManagementSnapshotResponse) ||
        contract == typeof(PrepareSimplySignSessionCommand) ||
        contract == typeof(PrepareSimplySignSessionResult) ||
        contract == typeof(LocalJobCreateRequest) ||
        contract == typeof(LocalJobUploadLease) ||
        contract == typeof(LocalJobUploadCompleted) ||
        contract == typeof(LocalJobAccepted) ||
        contract == typeof(LocalJobRejected) ||
        contract == typeof(LocalJobResultRequest) ||
        contract == typeof(LocalJobResultMetadata) ||
        contract == typeof(JobPageRequest) ||
        contract == typeof(JobPageResponse) ||
        contract == typeof(TerminalJobDeltaRequest) ||
        contract == typeof(TerminalJobDeltaResponse) ||
        contract == typeof(ServiceSettingsRequest) ||
        contract == typeof(ServiceSettingsResponse) ||
        contract == typeof(AdminControlHello) ||
        contract == typeof(AdminControlAccepted) ||
        contract == typeof(AgentControlRequest) ||
        contract == typeof(AgentControlResponse);

    private static void ValidateMessage(AgentMessage message)
    {
        var valid = message switch
        {
            AgentHello hello =>
                hello.ProtocolVersion == ProtocolVersion &&
                hello.ProcessId > 0 &&
                hello.SessionId > 0 &&
                IsSafeText(hello.UserSid, 184) &&
                hello.AgentVersion is { Length: > 0 and <= 64 } &&
                ProductVersion.TryParse(hello.AgentVersion, out _) &&
                AgentCapabilityPolicy.IsValid(hello.Capabilities),
            AgentHeartbeat heartbeat =>
                heartbeat.SessionId > 0 &&
                IsSafeIdentifier(heartbeat.SimplySignStatus, 64) &&
                IsSafeIdentifier(heartbeat.TokenStatus, 64) &&
                IsSafeIdentifier(heartbeat.CertificateStatus, 64) &&
                IsSafeIdentifier(heartbeat.KeyStatus, 64) &&
                heartbeat.CurrentJobId != Guid.Empty &&
                heartbeat.SimplySignProcessSessionId is null or >= 0 &&
                (heartbeat.Authenticode is null) == (heartbeat.Pdf is null),
            SignJobCommand command =>
                HasDispatchIdentity(command.JobId, command.DispatchId) &&
                command.AttemptNumber is >= 1 and <= 2 &&
                AllowedExtensions.Contains(command.Extension) &&
                command.CanonicalParametersJson is { Length: >= 2 and <= 32_768 } &&
                !HasUnsafeControl(command.CanonicalParametersJson) &&
                command.InputSize >= 0 &&
                IsLowerSha256(command.InputSha256),
            JobProgress progress =>
                HasDispatchIdentity(progress.JobId, progress.DispatchId) &&
                progress.Percent is >= 0 and <= 100 &&
                AllowedProgressStages.Contains(progress.Stage),
            JobCompleted completed =>
                HasDispatchIdentity(completed.JobId, completed.DispatchId) &&
                completed.OutputSize >= 0 &&
                IsLowerSha256(completed.OutputSha256),
            JobFailed failed =>
                HasDispatchIdentity(failed.JobId, failed.DispatchId) &&
                AllowedErrorCodes.Contains(failed.ErrorCode) &&
                IsSafeText(failed.ErrorMessage, 256),
            ManagementSnapshotRequest request => request.RequestId != Guid.Empty,
            ManagementSnapshotResponse response =>
                response.RequestId != Guid.Empty &&
                (response.Snapshot is not null && response.ErrorCode is null && response.CorrelationId is null ||
                    response.Snapshot is null && response.ErrorCode == "management_unavailable" &&
                    response.CorrelationId is { } correlationId && correlationId != Guid.Empty),
            PrepareSimplySignSessionCommand command => command.RequestId != Guid.Empty,
            PrepareSimplySignSessionResult result =>
                result.RequestId != Guid.Empty &&
                (result.State == SimplySignSessionState.Ready && result.ErrorCode is null ||
                    result.State == SimplySignSessionState.Failed &&
                    AllowedStartupPreparationErrorCodes.Contains(result.ErrorCode ?? string.Empty)),
            LocalJobCreateRequest request =>
                request.RequestId != Guid.Empty &&
                IsCanonicalOriginalName(request.OriginalName, request.Extension) &&
                request.DeclaredSize is >= 1 and <= 512L * 1024 * 1024 &&
                request.CanonicalParametersJson is { Length: >= 2 and <= 32_768 } &&
                !HasUnsafeControl(request.CanonicalParametersJson),
            LocalJobUploadLease lease =>
                lease.RequestId != Guid.Empty &&
                lease.JobId != Guid.Empty &&
                IsLowerLease(lease.LeaseId) &&
                IsCanonicalPartPath(lease.JobId, lease.RelativePartPath) &&
                lease.ExpiresAtUtc != default &&
                lease.ExpiresAtUtc.Offset == TimeSpan.Zero,
            LocalJobUploadCompleted completed =>
                completed.RequestId != Guid.Empty &&
                completed.JobId != Guid.Empty &&
                IsLowerLease(completed.LeaseId) &&
                completed.ActualSize is >= 1 and <= 512L * 1024 * 1024 &&
                IsLowerSha256(completed.Sha256),
            LocalJobAccepted accepted =>
                accepted.RequestId != Guid.Empty && accepted.JobId != Guid.Empty,
            LocalJobRejected rejected =>
                rejected.RequestId != Guid.Empty &&
                rejected.CorrelationId != Guid.Empty &&
                AllowedLocalErrorCodes.Contains(rejected.ErrorCode),
            LocalJobResultRequest request =>
                request.RequestId != Guid.Empty && request.JobId != Guid.Empty,
            LocalJobResultMetadata result =>
                result.RequestId != Guid.Empty &&
                result.JobId != Guid.Empty &&
                AllowedExtensions.Contains(result.Extension) &&
                result.Size >= 1 &&
                IsLowerSha256(result.Sha256),
            JobPageRequest request =>
                request.RequestId != Guid.Empty,
            JobPageResponse response =>
                response.RequestId != Guid.Empty &&
                response.Items is { Count: <= 100 } &&
                response.Items.All(static item => item is not null) &&
                (response.ErrorCode is null && response.CorrelationId is null ||
                    response.ErrorCode == "management_unavailable" &&
                    response.CorrelationId is { } pageCorrelation && pageCorrelation != Guid.Empty &&
                    response.Items.Count == 0 && response.NextCursor is null),
            TerminalJobDeltaRequest request =>
                request.RequestId != Guid.Empty &&
                (request.Cursor is null ||
                    request.Watermark is { } lowerBound &&
                    request.Cursor.LastSequence > lowerBound.Sequence &&
                    request.Cursor.SnapshotSequence > lowerBound.Sequence),
            TerminalJobDeltaResponse response =>
                response.RequestId != Guid.Empty &&
                response.Items is { Count: <= 100 } &&
                response.Items.All(static item => item is not null) &&
                response.Items.Select(static item => item.Sequence).SequenceEqual(
                    response.Items.Select(static item => item.Sequence).Order()) &&
                response.Items.Select(static item => item.Sequence).Distinct().Count() == response.Items.Count &&
                (response.ErrorCode is null && response.CorrelationId is null &&
                    response.Watermark is not null &&
                    response.Items.All(item => item.Sequence <= response.Watermark.Sequence) &&
                    (response.NextCursor is null ||
                        response.Items.Count > 0 &&
                        response.NextCursor.LastSequence == response.Items[^1].Sequence &&
                        response.NextCursor.SnapshotSequence == response.Watermark.Sequence) ||
                    response.ErrorCode == "management_unavailable" &&
                    response.CorrelationId is { } deltaCorrelation && deltaCorrelation != Guid.Empty &&
                    response.Items.Count == 0 && response.NextCursor is null && response.Watermark is null),
            ServiceSettingsRequest request => request.RequestId != Guid.Empty,
            ServiceSettingsResponse response =>
                response.RequestId != Guid.Empty &&
                (response.Summary is not null && response.ErrorCode is null && response.CorrelationId is null ||
                    response.Summary is null && response.ErrorCode == "management_unavailable" &&
                    response.CorrelationId is { } settingsCorrelation && settingsCorrelation != Guid.Empty),
            AdminControlHello hello =>
                hello.ProtocolVersion == AdminControlContract.ProtocolVersion &&
                hello.ProcessId > 0 && hello.SessionId > 0 &&
                IsSafeText(hello.UserSid, 184),
            AdminControlAccepted accepted =>
                accepted.ProtocolVersion == AdminControlContract.ProtocolVersion,
            AgentControlRequest request =>
                request.RequestId != Guid.Empty &&
                AdminControlContract.IsOperation(request.Operation) &&
                (request.Operation == AdminControlContract.ImportOtp
                    ? IsSafeOtpUri(request.OtpUri)
                    : request.OtpUri is null),
            AgentControlResponse response => IsValidControlResponse(response),
            _ => false,
        };

        if (!valid)
        {
            throw Error("invalid_message", "The message payload is invalid.");
        }
    }

    private static bool HasDispatchIdentity(Guid jobId, Guid dispatchId) =>
        jobId != Guid.Empty && dispatchId != Guid.Empty;

    private static bool IsLowerSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsLowerLease(string? value) =>
        value is { Length: 32 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsSafeOtpUri(string? value) =>
        value is { Length: >= 1 and <= 4096 } &&
        !HasUnsafeControl(value) &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase);

    private static bool IsValidControlResponse(AgentControlResponse response)
    {
        if (response.RequestId == Guid.Empty || !AdminControlContract.IsOperation(response.Operation))
        {
            return false;
        }

        if (response.ErrorCode is not null)
        {
            return AdminControlContract.IsErrorCode(response.ErrorCode) &&
                response.CorrelationId is { } correlationId && correlationId != Guid.Empty &&
                response.Heartbeat is null && response.TotpCode is null &&
                response.RemainingSeconds is null && response.ExpiresAtUtc is null;
        }

        if (response.CorrelationId is not null)
        {
            return false;
        }

        if (response.Operation == AdminControlContract.GenerateTotp)
        {
            return response.Heartbeat is null &&
                response.TotpCode is { Length: 6 } &&
                response.TotpCode.All(static character => character is >= '0' and <= '9') &&
                response.RemainingSeconds is >= 1 and <= 30 &&
                response.ExpiresAtUtc is { } expires && expires != default && expires.Offset == TimeSpan.Zero;
        }

        return response.Heartbeat is not null && response.TotpCode is null &&
            response.RemainingSeconds is null && response.ExpiresAtUtc is null;
    }

    private static bool IsCanonicalOriginalName(string? value, string? extension)
    {
        if (value is not { Length: > 0 and <= 255 } ||
            extension is null || !AllowedExtensions.Contains(extension) ||
            !string.Equals(extension, extension.ToLowerInvariant(), StringComparison.Ordinal) ||
            HasUnsafeControl(value) ||
            value.IndexOfAny(['/', '\\']) >= 0 ||
            value is "." or ".." ||
            !string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) ||
            !string.Equals(Path.GetExtension(value), extension, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    private static bool IsCanonicalPartPath(Guid jobId, string? value)
    {
        if (value is null)
        {
            return false;
        }

        foreach (var extension in AllowedExtensions)
        {
            if (string.Equals(
                value,
                $"{jobId:N}/input{extension}.part",
                StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSafeIdentifier(string? value, int maximumLength) =>
        IsSafeText(value, maximumLength) &&
        value!.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');

    private static bool IsSafeText(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength && !HasUnsafeControl(value);

    private static bool HasUnsafeControl(string value) => value.Any(char.IsControl);

    private static bool HasOnlyProperties(JsonElement value, params string[] expected)
    {
        var names = value.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
        return names.SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    private static bool HasUniquePropertiesRecursively(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.Object => HasUniqueObjectProperties(value),
            JsonValueKind.Array => value.EnumerateArray().All(HasUniquePropertiesRecursively),
            _ => true,
        };
    }

    private static bool HasUniqueObjectProperties(JsonElement value)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return value.EnumerateObject().All(property =>
            names.Add(property.Name) && HasUniquePropertiesRecursively(property.Value));
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw Error("unexpected_eof", "The message frame ended unexpectedly.");
            }

            offset += read;
        }
    }

    private static ProtocolException Error(string code, string message) => new(code, message);
}

public sealed class LengthPrefixedJsonWriter
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    internal LengthPrefixedJsonWriter(Stream stream)
    {
        _stream = stream;
    }

    public async Task WriteAsync<T>(T message, CancellationToken cancellationToken)
        where T : class =>
        await WriteAsync(message, cancellationToken, frameStarted: null).ConfigureAwait(false);

    public async Task WriteAsync<T>(
        T message,
        CancellationToken cancellationToken,
        Action? frameStarted)
        where T : class
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await LengthPrefixedJsonProtocol
                .WriteFrameAsync(_stream, message, cancellationToken, frameStarted)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
