using CodeSignAuto.Protocol;

namespace CodeSignAuto.Agent.Tests;

internal static class ProtocolV3TestFixtures
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);

    public static AgentHeartbeat Heartbeat(
        int sessionId = 7,
        Guid? currentJobId = null,
        long sessionGeneration = 1) =>
        new(
            sessionId,
            "ready",
            "ready",
            "ready",
            "ready",
            currentJobId,
            sessionId,
            ReadyCapability("authenticode", sessionId, sessionGeneration),
            ReadyCapability("pdf", sessionId, sessionGeneration),
            sessionGeneration);

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
