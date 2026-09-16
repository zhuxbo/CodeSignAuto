using CodeSignAuto.Protocol;
using CodeSignAuto.App.UI.Localization;

namespace CodeSignAuto.App.UI.Status;

public enum OverallReadiness
{
    Ready,
    Partial,
    ActionRequired,
}

public sealed record OverallStatus(
    OverallReadiness Overall,
    IReadOnlyList<string> Reasons,
    Guid? CorrelationId = null,
    bool AuthenticodeReady = false,
    bool PdfReady = false);

public static class ReadinessStatusMapper
{
    private const long MaximumHeartbeatAgeMilliseconds = 15_000;

    public static OverallStatus Map(ManagementSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var reasons = new List<string>();
        if (!snapshot.ServiceAvailable)
        {
            AddReason(reasons, "service_unavailable");
        }

        if (!snapshot.AgentConnected)
        {
            AddReason(reasons, "agent_unavailable");
        }

        if (snapshot.AgentSessionId <= 0 || snapshot.HeartbeatSessionId <= 0)
        {
            AddReason(reasons, "agent_session_invalid");
        }
        else if (snapshot.AgentSessionId != snapshot.HeartbeatSessionId)
        {
            AddReason(reasons, "heartbeat_invalid");
        }

        if (snapshot.HeartbeatAgeMilliseconds is null)
        {
            AddReason(reasons, "heartbeat_missing");
        }
        else if (snapshot.HeartbeatAgeMilliseconds < 0)
        {
            AddReason(reasons, "heartbeat_invalid");
        }
        else if (snapshot.HeartbeatAgeMilliseconds > MaximumHeartbeatAgeMilliseconds)
        {
            AddReason(reasons, "heartbeat_stale");
        }

        if (!snapshot.SimplySignProcessRunning)
        {
            AddReason(reasons, "process_missing");
        }
        else if (snapshot.SimplySignProcessSessionId != snapshot.AgentSessionId)
        {
            AddReason(reasons, "process_session_mismatch");
        }

        var infrastructureReady = reasons.Count == 0;
        var authenticodeReady = infrastructureReady && snapshot.Authenticode.Configured && snapshot.Certificates.Any(
            static certificate => certificate.CatalogCurrent && certificate.AuthenticodeUsable);
        var pdfExtensionMissing = !snapshot.Pdf.Configured ||
            string.Equals(
                snapshot.Pdf.ReasonCode,
                "pdf_support_not_installed",
                StringComparison.Ordinal);
        var pdfExtensionTampered = string.Equals(
            snapshot.Pdf.ReasonCode,
            "pdf_helper_tampered",
            StringComparison.Ordinal);
        var pdfReady = infrastructureReady &&
            !pdfExtensionMissing &&
            !pdfExtensionTampered &&
            snapshot.Certificates.Any(
            static certificate => certificate.CatalogCurrent && certificate.PdfUsable);
        if (infrastructureReady && !authenticodeReady)
        {
            AddReason(
                reasons,
                !snapshot.Authenticode.Configured ||
                HasCurrentSession(snapshot.SessionGeneration, snapshot.Authenticode)
                    ? CertificateReason(snapshot.Certificates)
                    : "heartbeat_invalid");
        }

        if (infrastructureReady && pdfExtensionTampered)
        {
            AddReason(reasons, "pdf_helper_tampered");
        }
        else if (infrastructureReady && !pdfExtensionMissing && !pdfReady)
        {
            AddReason(
                reasons,
                !snapshot.Pdf.Configured ||
                HasCurrentSession(snapshot.SessionGeneration, snapshot.Pdf)
                    ? CertificateReason(snapshot.Certificates)
                    : "heartbeat_invalid");
        }

        if (!infrastructureReady)
        {
            return new OverallStatus(
                OverallReadiness.ActionRequired,
                reasons.AsReadOnly(),
                AuthenticodeReady: authenticodeReady,
                PdfReady: pdfReady);
        }

        if (pdfExtensionMissing)
        {
            return new OverallStatus(
                authenticodeReady
                    ? OverallReadiness.Ready
                    : OverallReadiness.ActionRequired,
                reasons.AsReadOnly(),
                AuthenticodeReady: authenticodeReady,
                PdfReady: false);
        }

        var readyCapabilities = (authenticodeReady ? 1 : 0) + (pdfReady ? 1 : 0);
        return new OverallStatus(
            readyCapabilities switch
            {
                2 => OverallReadiness.Ready,
                1 => OverallReadiness.Partial,
                _ => OverallReadiness.ActionRequired,
            },
            reasons.AsReadOnly(),
            AuthenticodeReady: authenticodeReady,
            PdfReady: pdfReady);
    }

    public static OverallStatus ServiceUnavailable(Guid correlationId) =>
        new(OverallReadiness.ActionRequired, Array.AsReadOnly(["service_unavailable"]), correlationId);

    public static bool IsCurrentReady(long sessionGeneration, CapabilitySnapshot? capability) =>
        HasCurrentSession(sessionGeneration, capability) &&
        capability!.Ready &&
        capability.Session!.State == SimplySignSessionState.Ready;

    public static bool HasCurrentSession(long sessionGeneration, CapabilitySnapshot? capability) =>
        capability?.Session is { } session &&
        sessionGeneration > 0 &&
        session.SessionGeneration == sessionGeneration;

    public static string CapabilityStateText(long sessionGeneration, CapabilitySnapshot? capability)
    {
        var state = HasCurrentSession(sessionGeneration, capability)
            ? capability!.Session!.State
            : SimplySignSessionState.Unknown;
        return state switch
        {
            SimplySignSessionState.Unknown => UiCulture.Text("SessionUnknown"),
            SimplySignSessionState.Checking => UiCulture.Text("SessionChecking"),
            SimplySignSessionState.Ready => UiCulture.Text("SessionReady"),
            SimplySignSessionState.LoginRequired => UiCulture.Text("SessionLoginRequired"),
            SimplySignSessionState.Loginning => UiCulture.Text("SessionLoggingIn"),
            SimplySignSessionState.WaitToken => UiCulture.Text("SessionWaitToken"),
            SimplySignSessionState.Failed => UiCulture.Text("SessionFailed"),
            _ => UiCulture.Text("SessionUnknown"),
        };
    }

    private static void AddReason(List<string> reasons, string reason)
    {
        if (ManagementSnapshotReasonCodes.IsAllowed(reason) && !reasons.Contains(reason, StringComparer.Ordinal))
        {
            reasons.Add(reason);
        }
    }

    private static string CertificateReason(IReadOnlyList<CertificateSummary> certificates)
    {
        if (certificates.Count == 0)
        {
            return "certificate_missing";
        }

        if (certificates.All(static certificate => !certificate.CatalogCurrent))
        {
            return "catalog_stale";
        }

        return certificates
            .Where(static certificate => certificate.CatalogCurrent)
            .Select(static certificate => certificate.UnavailableReason)
            .FirstOrDefault(ManagementSnapshotReasonCodes.IsAllowed)
            ?? "certificate_missing";
    }
}
