using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;

namespace SimplySignAuto.Service.Api;

public static class HealthEndpoints
{
    private static readonly string[] KnownCapabilities = ["authenticode", "pdf"];

    public static IEndpointRouteBuilder MapHealthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health/live", CheckLivenessAsync).AllowAnonymous();
        return endpoints;
    }

    public static RouteGroupBuilder MapReadinessEndpoint(this RouteGroupBuilder routes)
    {
        routes.MapGet("/health/ready", CheckReadinessAsync);
        return routes;
    }

    private static async Task<IResult> CheckLivenessAsync(IJobStore jobs, HttpContext context)
    {
        try
        {
            await jobs.CheckHealthAsync(context.RequestAborted);
            return Results.Ok(new { status = "live" });
        }
        catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            return UnavailableProblem(context);
        }
    }

    private static async Task<IResult> CheckReadinessAsync(
        IJobStore jobs,
        IAgentHealthStatusSource agentStatus,
        TimeProvider timeProvider,
        HttpContext context)
    {
        JobQueueSnapshot queue;
        try
        {
            await jobs.CheckHealthAsync(context.RequestAborted);
            queue = await jobs.GetQueueSnapshotAsync(context.RequestAborted);
        }
        catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            return UnavailableProblem(context);
        }

        var snapshot = agentStatus.CurrentHealth;
        var heartbeat = snapshot?.Heartbeat;
        var age = snapshot?.LastHeartbeatUtc is { } heartbeatAt
            ? timeProvider.GetUtcNow() - heartbeatAt
            : (TimeSpan?)null;
        var heartbeatIsCurrent = snapshot is { SessionId: > 0 } &&
            heartbeat is not null &&
            heartbeat.SessionId == snapshot.SessionId &&
            age is { } measuredAge &&
            measuredAge >= TimeSpan.Zero &&
            measuredAge <= AgentPipeServer.HeartbeatTimeout;
        var processReady = heartbeatIsCurrent &&
            heartbeat!.SimplySignProcessSessionId == snapshot!.SessionId;
        var capabilitiesAreValid = AgentCapabilityPolicy.IsValid(snapshot?.Capabilities);
        var configured = capabilitiesAreValid
            ? snapshot!.Capabilities.ToHashSet(StringComparer.Ordinal)
            : [];
        var pdfIsCurrentAndNotInstalled = heartbeatIsCurrent &&
            configured.Contains("pdf") &&
            heartbeat!.Pdf is
            {
                Ready: false,
                ReasonCode: "pdf_support_not_installed",
                Session: { } pdfSession,
            } &&
            pdfSession.SessionGeneration == heartbeat.SessionGeneration &&
            pdfSession.SessionId == snapshot!.SessionId;
        var requiredCapabilities = configured
            .Where(capability => capability != "pdf" || !pdfIsCurrentAndNotInstalled)
            .ToHashSet(StringComparer.Ordinal);
        var capabilityStatus = KnownCapabilities.ToDictionary(
            capability => capability,
            capability =>
            {
                var isConfigured = configured.Contains(capability);
                var reported = capability == "authenticode"
                    ? heartbeat?.Authenticode
                    : heartbeat?.Pdf;
                var isCurrent = heartbeatIsCurrent &&
                    reported?.Session is { } session &&
                    session.SessionGeneration == heartbeat!.SessionGeneration &&
                    session.SessionId == snapshot!.SessionId;
                return new CapabilityHealth(
                    isConfigured && isCurrent &&
                        reported!.Ready &&
                        reported.Session!.State == SimplySignSessionState.Ready,
                    isConfigured && isCurrent && reported!.CertificatePresent && reported.CertificateMatches,
                    isConfigured && isCurrent && reported!.PrivateKeyPresent && reported.PrivateKeyMatches);
            },
            StringComparer.Ordinal);
        var tokenReady = heartbeatIsCurrent &&
            requiredCapabilities.Count > 0 &&
            requiredCapabilities.All(capability =>
            {
                var reported = capability == "authenticode" ? heartbeat!.Authenticode : heartbeat!.Pdf;
                return reported?.Session?.SessionGeneration == heartbeat.SessionGeneration &&
                    reported.TokenPresent && reported.TokenMatches;
            });
        var catalogReady = heartbeatIsCurrent && requiredCapabilities.All(capability =>
            heartbeat!.Certificates.Any(certificate =>
                certificate.CatalogCurrent &&
                (capability == "authenticode"
                    ? certificate.AuthenticodeUsable
                    : certificate.PdfUsable)));
        var ready = capabilitiesAreValid &&
            heartbeatIsCurrent &&
            configured.Count > 0 &&
            processReady &&
            tokenReady &&
            catalogReady &&
            requiredCapabilities.All(capability => capabilityStatus[capability].Ready);
        var response = new ReadinessResponse(
            ready ? "ready" : "not_ready",
            new AgentHealth(snapshot is not null, snapshot?.SessionId ?? 0, age is null ? null : Math.Max(0, (int)age.Value.TotalSeconds)),
            new SimplySignHealth(processReady, tokenReady),
            new SessionHealth(
                heartbeat?.SessionGeneration ?? 0,
                heartbeat?.SessionTransitions ?? []),
            capabilityStatus,
            queue);
        return Results.Json(response, statusCode: ready ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
    }

    private static IResult UnavailableProblem(HttpContext context) =>
        Results.Json(
            ApiProblem.Create("service_unavailable", context.TraceIdentifier, "The service is unavailable.", StatusCodes.Status503ServiceUnavailable),
            statusCode: StatusCodes.Status503ServiceUnavailable,
            contentType: "application/problem+json");

    private sealed record ReadinessResponse(
        string Service,
        AgentHealth Agent,
        SimplySignHealth SimplySign,
        SessionHealth Session,
        IReadOnlyDictionary<string, CapabilityHealth> Capabilities,
        JobQueueSnapshot Queue);

    private sealed record AgentHealth(bool Connected, int SessionId, int? HeartbeatAgeSeconds);

    private sealed record SimplySignHealth(bool Process, bool Token);

    private sealed record SessionHealth(
        long Generation,
        IReadOnlyList<SessionTransitionEvidence> Transitions);

    private sealed record CapabilityHealth(bool Ready, bool Certificate, bool PrivateKey);
}
