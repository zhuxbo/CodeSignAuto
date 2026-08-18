using SimplySignAuto.Protocol;

namespace SimplySignAuto.Service.Tests;

internal static class ProtocolV3TestFixtures
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);

    public static AgentHeartbeat Heartbeat(
        int sessionId = 7,
        Guid? currentJobId = null,
        string simplySignStatus = "ready",
        string tokenStatus = "ready",
        string certificateStatus = "ready",
        string keyStatus = "ready",
        bool authenticodeConfigured = true,
        bool pdfConfigured = true,
        long sessionGeneration = 1,
        IReadOnlyList<SessionTransitionEvidence>? transitions = null,
        IReadOnlyList<CertificateSummary>? certificates = null) =>
        new(
            sessionId,
            simplySignStatus,
            tokenStatus,
            certificateStatus,
            keyStatus,
            currentJobId,
            sessionId,
            authenticodeConfigured
                ? ReadyCapability("authenticode", sessionId, sessionGeneration)
                : CapabilitySnapshot.NotConfigured(),
            pdfConfigured
                ? ReadyCapability("pdf", sessionId, sessionGeneration)
                : CapabilitySnapshot.NotConfigured(),
            sessionGeneration,
            transitions,
            certificates);

    public static CapabilitySnapshot ReadyCapability(
        string alias = "test",
        int sessionId = 7,
        long sessionGeneration = 1) =>
        new(
            true,
            true,
            true,
            "34567890",
            true,
            true,
            "abcdef12",
            true,
            true,
            "1234abcd",
            true,
            "ready",
            DateTimeOffset.Parse("2027-08-09T00:00:00Z"),
            "89ABCDEF",
            ReadySession(alias, sessionId, sessionGeneration));

    public static SimplySignSessionSnapshot ReadySession(
        string alias,
        int sessionId = 7,
        long sessionGeneration = 1) =>
        new(
            SimplySignSessionState.Ready,
            sessionGeneration,
            Now,
            Now,
            sessionId,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            "ready",
            0,
            null,
            true,
            sessionId);
}
