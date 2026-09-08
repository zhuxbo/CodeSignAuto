using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service.Ipc;
using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.Service.Api;

public sealed record CreateJobResponse(
    Guid JobId,
    string State,
    string StatusUrl,
    string ResultUrl,
    DateTimeOffset? ExpiresAt)
{
    public static CreateJobResponse From(Job job) => new(
        job.Id,
        JobEndpoints.StateName(job.State),
        $"/v1/jobs/{job.Id:D}",
        $"/v1/jobs/{job.Id:D}/result",
        job.ExpiresAt);
}

public sealed record JobStatusResponse(
    Guid JobId,
    string State,
    string OriginalName,
    string InputSha256,
    string? ResultSha256,
    string? ErrorCode,
    string? ErrorMessage,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    DateTimeOffset? ExpiresAt);

public sealed record ApiProblem(string Type, string Title, int Status, string Code, string CorrelationId, Guid? JobId = null)
{
    public static ApiProblem Create(string code, string correlationId, string title, int status = 401, Guid? jobId = null) =>
        new("about:blank", title, status, code, correlationId, jobId);
}

public static class JobEndpoints
{
    internal const long MaxFileBytes = 512L * 1024 * 1024;
    internal const int MaxParametersBytes = 64 * 1024;
    internal const int MaxBoundaryBytes = 70;
    internal const int MaxSectionHeadersCount = 8;
    internal const int MaxSectionHeadersBytes = 4 * 1024;
    internal const int MaxMultipartFramingBytes = 1024;
    internal const long MaxMultipartOverheadBytes =
        MaxParametersBytes + (2L * MaxSectionHeadersBytes) + MaxMultipartFramingBytes;
    internal const long MaxRequestBodyBytes = MaxFileBytes + MaxMultipartOverheadBytes;

    public static RouteGroupBuilder MapJobEndpoints(this RouteGroupBuilder routes)
    {
        routes.MapPost("/jobs", (HttpContext context, IJobStore jobs, ISpoolStore spool, IJobDispatcher dispatcher,
                IUploadedContentValidator contentValidator,
                JobRetentionPolicy retention, TimeProvider timeProvider,
                IAgentHealthStatusSource agentHealth, IAgentOnDemandLogin onDemandLogin,
                IUpgradeAdmissionGate upgradeGate) =>
            CreateAsync(context, jobs, spool, dispatcher, contentValidator, retention, timeProvider,
                agentHealth, onDemandLogin, upgradeGate));
        routes.MapPost("/sign", (HttpContext context, IJobStore jobs, ISpoolStore spool, IJobDispatcher dispatcher,
                IJobCompletionNotifier notifier, JobRetentionPolicy retention,
                IUploadedContentValidator contentValidator, TimeProvider timeProvider,
                IAgentHealthStatusSource agentHealth, IAgentOnDemandLogin onDemandLogin,
                IUpgradeAdmissionGate upgradeGate, int waitSeconds = 120) =>
            SignAsync(context, jobs, spool, dispatcher, notifier, contentValidator, retention, timeProvider,
                agentHealth, onDemandLogin, upgradeGate, waitSeconds));
        routes.MapGet("/jobs/{jobId:guid}", GetAsync);
        routes.MapGet("/jobs/{jobId:guid}/result", DownloadAsync);
        return routes;
    }

    private static async Task<IResult> CreateAsync(
        HttpContext context,
        IJobStore jobs,
        ISpoolStore spool,
        IJobDispatcher dispatcher,
        IUploadedContentValidator contentValidator,
        JobRetentionPolicy retention,
        TimeProvider timeProvider,
        IAgentHealthStatusSource agentHealth,
        IAgentOnDemandLogin onDemandLogin,
        IUpgradeAdmissionGate upgradeGate)
    {
        var outcome = await TryCreateAsync(
            context, jobs, spool, dispatcher, contentValidator, retention, timeProvider,
            agentHealth, onDemandLogin, upgradeGate);
        return outcome.Error ?? Results.Accepted(
            $"/v1/jobs/{outcome.Job!.Id:D}",
            CreateJobResponse.From(outcome.Job));
    }

    private static async Task<IResult> SignAsync(
        HttpContext context,
        IJobStore jobs,
        ISpoolStore spool,
        IJobDispatcher dispatcher,
        IJobCompletionNotifier notifier,
        IUploadedContentValidator contentValidator,
        JobRetentionPolicy retention,
        TimeProvider timeProvider,
        IAgentHealthStatusSource agentHealth,
        IAgentOnDemandLogin onDemandLogin,
        IUpgradeAdmissionGate upgradeGate,
        int waitSeconds)
    {
        if (waitSeconds is < 1 or > 120)
        {
            return Problem(context, "invalid_parameters", StatusCodes.Status400BadRequest, "waitSeconds must be between 1 and 120.");
        }

        var outcome = await TryCreateAsync(
            context, jobs, spool, dispatcher, contentValidator, retention, timeProvider,
            agentHealth, onDemandLogin, upgradeGate);
        if (outcome.Error is not null)
        {
            return outcome.Error;
        }

        var job = outcome.Job!;
        if (job.State == JobState.Succeeded)
        {
            return await DownloadJobAsync(context, job, jobs, spool, CancellationToken.None);
        }

        if (job.State == JobState.Failed)
        {
            return Problem(
                context,
                job.ErrorCode ?? "internal_error",
                StatusCodes.Status500InternalServerError,
                "The signing job failed.",
                job.Id);
        }

        if (job.State == JobState.Expired)
        {
            return Problem(context, "job_expired", StatusCodes.Status410Gone,
                "The signing job has expired.", job.Id);
        }

        using var timeoutCancellation = new CancellationTokenSource(
            TimeSpan.FromSeconds(waitSeconds),
            timeProvider);
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted,
            timeoutCancellation.Token);
        try
        {
            var completed = await notifier.WaitAsync(job.Id, waitCancellation.Token);
            if (completed.State == JobState.Succeeded)
            {
                return await DownloadJobAsync(context, completed, jobs, spool, CancellationToken.None);
            }

            if (completed.State == JobState.Failed)
            {
                return Problem(context, completed.ErrorCode ?? "internal_error", StatusCodes.Status500InternalServerError,
                    "The signing job failed.", completed.Id);
            }


            if (completed.State == JobState.Expired)
            {
                return Problem(context, "job_expired", StatusCodes.Status410Gone,
                    "The signing job has expired.", completed.Id);
            }
        }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested)
        {
            // A synchronous timeout changes only this response; the persisted job keeps running.
        }

        return Results.Accepted($"/v1/jobs/{job.Id:D}", CreateJobResponse.From(job));
    }

    private static async Task<IResult> GetAsync(Guid jobId, HttpContext context, IJobStore jobs)
    {
        var job = await jobs.GetAsync(jobId, context.RequestAborted);
        if (job is null)
        {
            return Problem(context, "job_not_found", StatusCodes.Status404NotFound, "The signing job was not found.");
        }

        return Results.Ok(new JobStatusResponse(
            job.Id,
            StateName(job.State),
            job.OriginalName,
            job.InputSha256,
            job.ResultSha256,
            job.ErrorCode,
            SafeErrorMessage(job.ErrorMessage),
            job.CreatedAt,
            job.StartedAt,
            job.CompletedAt,
            job.ExpiresAt));
    }

    private static async Task<IResult> DownloadAsync(Guid jobId, HttpContext context, IJobStore jobs, ISpoolStore spool)
    {
        var job = await jobs.GetAsync(jobId, context.RequestAborted);
        if (job is null)
        {
            return Problem(context, "job_not_found", StatusCodes.Status404NotFound, "The signing job was not found.");
        }

        return await DownloadJobAsync(context, job, jobs, spool, context.RequestAborted);
    }

    private static async Task<IResult> DownloadJobAsync(
        HttpContext context,
        Job job,
        IJobStore jobs,
        ISpoolStore spool,
        CancellationToken cancellationToken)
    {
        if (job.State == JobState.Expired)
        {
            return Problem(context, "job_expired", StatusCodes.Status410Gone, "The signing job has expired.", job.Id);
        }

        if (job.State != JobState.Succeeded ||
            job.ResultSize is null ||
            string.IsNullOrWhiteSpace(job.ResultSha256))
        {
            return Problem(context, "job_not_complete", StatusCodes.Status409Conflict, "The signing job is not complete.", job.Id);
        }

        try
        {
            var stream = await spool.OpenVerifiedResultAsync(
                job.Id,
                job.Extension,
                job.ResultSize.Value,
                job.ResultSha256,
                cancellationToken);
            var contentType = job.Extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase)
                ? "application/pdf"
                : "application/octet-stream";
            return Results.File(stream, contentType, DownloadName(job.OriginalName, job.Extension), enableRangeProcessing: false);
        }
        catch (SpoolException)
        {
            try
            {
                await jobs.TryFailSucceededResultAsync(
                    job.Id,
                    job.ResultSize.Value,
                    job.ResultSha256,
                    "result_corrupt",
                    "The signed result failed integrity verification.",
                    CancellationToken.None);
            }
            catch
            {
                // The integrity result is stable even if persisting the defensive state transition fails.
            }

            return Problem(context, "result_corrupt", StatusCodes.Status500InternalServerError, "The signed result is unavailable.", job.Id);
        }
    }

    private static async Task<CreateOutcome> TryCreateAsync(
        HttpContext context,
        IJobStore jobs,
        ISpoolStore spool,
        IJobDispatcher dispatcher,
        IUploadedContentValidator contentValidator,
        JobRetentionPolicy retention,
        TimeProvider timeProvider,
        IAgentHealthStatusSource agentHealth,
        IAgentOnDemandLogin onDemandLogin,
        IUpgradeAdmissionGate upgradeGate)
    {
        await using var admission = await upgradeGate
            .TryEnterAsync(context.RequestAborted)
            .ConfigureAwait(false);
        if (admission is null)
        {
            return new(null, Problem(
                context,
                "upgrade_in_progress",
                StatusCodes.Status503ServiceUnavailable,
                "The service is draining for an upgrade."));
        }

        var jobId = Guid.NewGuid();
        var retainSpool = false;
        var spoolMutationStarted = false;
        try
        {
            if (context.Request.ContentLength is > MaxRequestBodyBytes)
            {
                return new(null, Problem(
                    context,
                    "file_too_large",
                    StatusCodes.Status413PayloadTooLarge,
                    "The uploaded file is too large."));
            }

            if (!TryGetBoundary(context.Request.ContentType, out var boundary))
            {
                return new(null, Problem(context, "invalid_parameters", StatusCodes.Status400BadRequest, "A multipart request is required."));
            }

            if (!TryReadIdempotencyKey(context, out var idempotencyKey))
            {
                return new(null, Problem(context, "invalid_parameters", StatusCodes.Status400BadRequest, "Idempotency-Key is invalid."));
            }

            var isIdempotencyReplay = idempotencyKey is not null &&
                await jobs.GetByIdempotencyKeyAsync("api", idempotencyKey, context.RequestAborted)
                    .ConfigureAwait(false) is not null;

            var reader = new MultipartReader(boundary, context.Request.Body)
            {
                HeadersCountLimit = MaxSectionHeadersCount,
                HeadersLengthLimit = MaxSectionHeadersBytes,
            };
            SigningParameters? parameters = null;
            string? originalName = null;
            FileKind? fileKind = null;
            SpoolFile? written = null;
            while (await ReadNextSectionAsync(reader, context.RequestAborted) is { } section)
            {
                if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition) ||
                    !string.Equals(disposition.DispositionType.Value, "form-data", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ValidationException("invalid_parameters");
                }

                var name = HeaderUtilities.RemoveQuotes(disposition.Name).Value;
                if (name == "parameters" && parameters is null && !disposition.FileName.HasValue && !disposition.FileNameStar.HasValue)
                {
                    var parametersJson = await ReadMultipartParametersAsync(section.Body, context.RequestAborted);
                    parameters = SigningParameters.Parse(parametersJson);
                    if (!isIdempotencyReplay && fileKind is not null &&
                        ValidateAdmission(context, agentHealth, timeProvider, fileKind, parameters) is { } parametersProblem)
                    {
                        return new(null, parametersProblem);
                    }
                }
                else if (name == "file" && written is null && (disposition.FileName.HasValue || disposition.FileNameStar.HasValue))
                {
                    originalName = ValidateOriginalName(
                        HeaderUtilities.RemoveQuotes(disposition.FileNameStar.HasValue ? disposition.FileNameStar : disposition.FileName).Value);
                    var extension = Path.GetExtension(originalName).ToLowerInvariant();
                    fileKind = SigningRequestValidator.ValidateExtension(originalName);
                    if (!isIdempotencyReplay && ShouldAttemptAutomaticLogin(agentHealth, timeProvider, fileKind.Value))
                    {
                        _ = await onDemandLogin.LoginAsync(context.RequestAborted).ConfigureAwait(false);
                    }

                    if (!isIdempotencyReplay &&
                        ValidateAdmission(context, agentHealth, timeProvider, fileKind, parameters) is { } fileProblem)
                    {
                        return new(null, fileProblem);
                    }

                    spoolMutationStarted = true;
                    written = await WriteMultipartFileAsync(spool, jobId, extension, section.Body, context.RequestAborted);
                }
                else
                {
                    throw new ValidationException("invalid_parameters");
                }
            }

            if (parameters is null || originalName is null || fileKind is null ||
                written is null || written.Size == 0)
            {
                throw new ValidationException("invalid_parameters");
            }

            var prefix = new byte[8];
            int prefixLength;
            await using (var input = new FileStream(written.Path, FileMode.Open, FileAccess.Read, FileShare.Read, prefix.Length, FileOptions.Asynchronous))
            {
                prefixLength = await input.ReadAsync(prefix, context.RequestAborted);
            }

            var verifiedKind = SigningRequestValidator.ValidateFile(originalName, prefix.AsSpan(0, prefixLength));
            if (verifiedKind != fileKind || ParameterKind(parameters) != verifiedKind)
            {
                throw new ValidationException("invalid_parameters");
            }

            contentValidator.Validate(written.Path, Path.GetExtension(originalName).ToLowerInvariant(), parameters);
            var requested = new Job(jobId, JobState.Queued, parameters)
            {
                OriginalName = originalName,
                Extension = Path.GetExtension(originalName).ToLowerInvariant(),
                InputSize = written.Size,
                InputSha256 = written.Sha256,
                ExpiresAt = retention.GetExpiresAt(timeProvider.GetUtcNow().ToUniversalTime()),
            };
            if (!isIdempotencyReplay &&
                ValidateAdmission(context, agentHealth, timeProvider, verifiedKind, parameters) is { } finalProblem)
            {
                return new(null, finalProblem);
            }

            var stored = await jobs.CreateAsync(requested, idempotencyKey is null ? null : "api", idempotencyKey, context.RequestAborted);
            if (stored.Id == jobId)
            {
                retainSpool = true;
                dispatcher.Enqueue(stored.Id);
            }

            return new(stored, null);
        }
        catch (SpoolException exception) when (exception.Code == "file_too_large")
        {
            return new(null, Problem(context, exception.Code, StatusCodes.Status413PayloadTooLarge, "The uploaded file is too large."));
        }
        catch (ValidationException exception)
        {
            return new(null, Problem(context, exception.Code, StatusCodes.Status400BadRequest, "The request is invalid."));
        }
        catch (IdempotencyConflictException exception)
        {
            return new(null, Problem(context, exception.Code, StatusCodes.Status409Conflict, "The idempotency key conflicts with another request."));
        }
        catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            return new(null, Problem(context, "internal_error", StatusCodes.Status500InternalServerError, "The request could not be completed."));
        }
        finally
        {
            if (spoolMutationStarted && !retainSpool)
            {
                await spool.DeleteJobAsync(jobId, CancellationToken.None);
            }
        }
    }

    private static IResult? ValidateAdmission(
        HttpContext context,
        IAgentHealthStatusSource agentHealth,
        TimeProvider timeProvider,
        FileKind? fileKind,
        SigningParameters? parameters)
    {
        var health = agentHealth.CurrentHealth;
        var heartbeat = health?.Heartbeat;
        var now = timeProvider.GetUtcNow().ToUniversalTime();
        if (health is null ||
            heartbeat is null ||
            health.ConnectionId == Guid.Empty ||
            health.SessionId <= 0 ||
            heartbeat.SessionId != health.SessionId ||
            heartbeat.SimplySignProcessSessionId != health.SessionId ||
            health.LastHeartbeatUtc is not { } receivedAt ||
            !AgentCapabilityPolicy.IsValid(health.Capabilities))
        {
            return AdmissionProblem(context, "service_unavailable");
        }

        var age = now - receivedAt.ToUniversalTime();
        if (age < TimeSpan.Zero || age > AgentPipeServer.HeartbeatTimeout)
        {
            return AdmissionProblem(context, "service_unavailable");
        }

        if (parameters is not null && fileKind is not null && ParameterKind(parameters) != fileKind)
        {
            return AdmissionProblem(context, "invalid_parameters");
        }

        var requiredKind = fileKind ?? (parameters is null ? null : ParameterKind(parameters));
        if (requiredKind is null)
        {
            return null;
        }

        var alias = requiredKind == FileKind.Pdf ? "pdf" : "authenticode";
        var capability = requiredKind == FileKind.Pdf ? heartbeat.Pdf : heartbeat.Authenticode;
        var capabilityIsCurrent = capability?.Session is { } capabilitySession &&
            capabilitySession.SessionId == health.SessionId &&
            capabilitySession.SessionGeneration == heartbeat.SessionGeneration;
        if (!health.Capabilities.Contains(alias, StringComparer.Ordinal) ||
            !capabilityIsCurrent ||
            capability is not
            {
                Configured: true,
                Ready: true,
                ReasonCode: "ready",
                TokenPresent: true,
                TokenMatches: true,
                CertificatePresent: true,
                CertificateMatches: true,
                PrivateKeyPresent: true,
                PrivateKeyMatches: true,
                Session: { State: SimplySignSessionState.Ready },
            })
        {
            var code = requiredKind == FileKind.Pdf && capabilityIsCurrent
                ? capability?.ReasonCode switch
                {
                    "pdf_support_not_installed" => "pdf_support_not_installed",
                    "pdf_helper_tampered" => "pdf_helper_tampered",
                    _ => "service_unavailable",
                }
                : requiredKind == FileKind.Pdf && !health.Capabilities.Contains(alias, StringComparer.Ordinal)
                    ? "pdf_support_not_installed"
                : "service_unavailable";
            return AdmissionProblem(context, code);
        }

        if (parameters is null)
        {
            return null;
        }

        var matches = heartbeat.Certificates
            .Where(certificate => string.Equals(
                certificate.SerialNumber,
                parameters.CertificateSerialNumber,
                StringComparison.Ordinal))
            .ToArray();
        if (matches.Length == 0)
        {
            return AdmissionProblem(context, "certificate_not_found");
        }

        if (matches.Length != 1 || matches.Any(certificate =>
                certificate.UnavailableReason == "certificate_serial_ambiguous"))
        {
            return AdmissionProblem(context, "certificate_serial_ambiguous");
        }

        var requested = matches[0];
        if (!requested.CatalogCurrent)
        {
            return AdmissionProblem(context, "certificate_catalog_unavailable");
        }

        var usable = requiredKind == FileKind.Pdf
            ? requested.PdfUsable
            : requested.AuthenticodeUsable;
        return usable
            ? null
            : AdmissionProblem(context, "certificate_not_usable");
    }

    private static bool ShouldAttemptAutomaticLogin(
        IAgentHealthStatusSource agentHealth,
        TimeProvider timeProvider,
        FileKind requiredKind)
    {
        var health = agentHealth.CurrentHealth;
        var heartbeat = health?.Heartbeat;
        if (health is null ||
            heartbeat is null ||
            health.ConnectionId == Guid.Empty ||
            health.SessionId <= 0 ||
            heartbeat.SessionId != health.SessionId ||
            !AgentCapabilityPolicy.IsValid(health.Capabilities) ||
            health.LastHeartbeatUtc is not { } receivedAt)
        {
            return false;
        }

        var age = timeProvider.GetUtcNow().ToUniversalTime() - receivedAt.ToUniversalTime();
        if (age < TimeSpan.Zero || age > AgentPipeServer.HeartbeatTimeout)
        {
            return false;
        }

        var alias = requiredKind == FileKind.Pdf ? "pdf" : "authenticode";
        if (!health.Capabilities.Contains(alias, StringComparer.Ordinal))
        {
            return false;
        }

        var capability = requiredKind == FileKind.Pdf ? heartbeat.Pdf : heartbeat.Authenticode;
        if (requiredKind == FileKind.Pdf && capability?.ReasonCode is
            "pdf_support_not_installed" or "pdf_helper_tampered")
        {
            return false;
        }

        var capabilityReady = capability is
        {
            Ready: true,
            ReasonCode: "ready",
            Session: { State: SimplySignSessionState.Ready } session,
        } &&
            session.SessionId == health.SessionId &&
            session.SessionGeneration == heartbeat.SessionGeneration;
        return heartbeat.SimplySignProcessSessionId != health.SessionId || !capabilityReady;
    }

    private static FileKind ParameterKind(SigningParameters parameters) => parameters switch
    {
        AuthenticodeParameters => FileKind.Authenticode,
        PdfParameters => FileKind.Pdf,
        _ => throw new ValidationException("invalid_parameters"),
    };

    private static IResult AdmissionProblem(HttpContext context, string code) => code switch
    {
        "invalid_parameters" => Problem(
            context, code, StatusCodes.Status400BadRequest, "The request is invalid."),
        "certificate_not_found" => Problem(
            context, code, StatusCodes.Status400BadRequest, "The requested certificate was not found."),
        "certificate_serial_ambiguous" => Problem(
            context, code, StatusCodes.Status400BadRequest, "The requested certificate is ambiguous."),
        "certificate_not_usable" => Problem(
            context, code, StatusCodes.Status400BadRequest, "The requested certificate cannot sign this file type."),
        "certificate_catalog_unavailable" => Problem(
            context, code, StatusCodes.Status503ServiceUnavailable, "The certificate catalog is unavailable."),
        "pdf_support_not_installed" => Problem(
            context, code, StatusCodes.Status503ServiceUnavailable, "PDF signing support is not installed."),
        "pdf_helper_tampered" => Problem(
            context, code, StatusCodes.Status503ServiceUnavailable, "PDF signing support failed integrity verification."),
        _ => Problem(
            context, "service_unavailable", StatusCodes.Status503ServiceUnavailable, "The signing service is not ready."),
    };

    internal static string StateName(JobState state) => state switch
    {
        JobState.WaitingForAgent => "waiting_for_agent",
        _ => state.ToString().ToLowerInvariant(),
    };

    private static bool TryGetBoundary(string? contentType, out string boundary)
    {
        boundary = string.Empty;
        if (!MediaTypeHeaderValue.TryParse(contentType, out var parsed) ||
            !string.Equals(parsed.MediaType.Value, "multipart/form-data", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        boundary = HeaderUtilities.RemoveQuotes(parsed.Boundary).Value ?? string.Empty;
        return boundary.Length is > 0 and <= MaxBoundaryBytes;
    }

    private static bool TryReadIdempotencyKey(HttpContext context, out string? key)
    {
        key = null;
        var values = context.Request.Headers["Idempotency-Key"];
        if (values.Count == 0)
        {
            return true;
        }

        if (values.Count != 1 || values[0] is not { Length: >= 1 and <= 128 } value || value.Any(character => character is < '!' or > '~'))
        {
            return false;
        }

        key = value;
        return true;
    }

    private static async Task<string> ReadParametersAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (memory.Length + read > MaxParametersBytes)
            {
                throw new ValidationException("invalid_parameters");
            }

            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(memory.ToArray());
        }
        catch (DecoderFallbackException)
        {
            throw new ValidationException("invalid_parameters");
        }
    }

    private static async Task<string> ReadMultipartParametersAsync(Stream stream, CancellationToken cancellationToken)
    {
        try
        {
            return await ReadParametersAsync(stream, cancellationToken);
        }
        catch (IOException)
        {
            throw new ValidationException("invalid_parameters");
        }
    }

    private static async Task<SpoolFile> WriteMultipartFileAsync(
        ISpoolStore spool,
        Guid jobId,
        string extension,
        Stream stream,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var limited = new MultipartFileSectionStream(stream, MaxFileBytes);
            return await spool.WriteInputAsync(jobId, extension, limited, MaxFileBytes, cancellationToken);
        }
        catch (SpoolException exception) when (exception.Code == "invalid_extension")
        {
            throw new ValidationException("unsupported_type");
        }
        catch (SpoolException)
        {
            throw;
        }
        catch (IOException)
        {
            throw new ValidationException("invalid_parameters");
        }
    }

    private static async Task<MultipartSection?> ReadNextSectionAsync(MultipartReader reader, CancellationToken cancellationToken)
    {
        try
        {
            return await reader.ReadNextSectionAsync(cancellationToken);
        }
        catch (IOException)
        {
            throw new ValidationException("invalid_parameters");
        }
        catch (InvalidDataException)
        {
            throw new ValidationException("invalid_parameters");
        }
    }

    private static string ValidateOriginalName(string? supplied)
    {
        var name = supplied ?? string.Empty;
        if (name.Length is < 1 or > 255 ||
            string.IsNullOrWhiteSpace(name) ||
            name.Any(char.IsControl) ||
            name.IndexOfAny(['/', '\\', ':']) >= 0 ||
            name is "." or ".." ||
            Path.IsPathFullyQualified(name) ||
            !string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal))
        {
            throw new ValidationException("invalid_parameters");
        }

        return name;
    }

    private static string DownloadName(string originalName, string extension)
    {
        var stem = Path.GetFileNameWithoutExtension(ValidateOriginalName(originalName));
        var name = stem + ".signed" + extension;
        return new string(name.Where(character => !char.IsControl(character)).ToArray());
    }

    private static string? SafeErrorMessage(string? errorMessage) =>
        string.IsNullOrWhiteSpace(errorMessage) ? null : "The signing job failed.";

    private static IResult Problem(HttpContext context, string code, int status, string title, Guid? jobId = null) =>
        Results.Json(
            ApiProblem.Create(code, context.TraceIdentifier, title, status, jobId),
            statusCode: status,
            contentType: "application/problem+json");

    private sealed record CreateOutcome(Job? Job, IResult? Error);
}

public sealed record JobRetentionPolicy
{
    public JobRetentionPolicy(int hours)
    {
        if (hours is < 0 or > 168)
        {
            throw new ArgumentOutOfRangeException(nameof(hours));
        }

        Hours = hours;
    }

    public int Hours { get; }

    public DateTimeOffset? GetExpiresAt(DateTimeOffset createdAt) =>
        Hours == 0 ? null : createdAt.AddHours(Hours);
}
