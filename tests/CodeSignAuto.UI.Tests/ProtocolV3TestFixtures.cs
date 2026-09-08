using CodeSignAuto.Protocol;

namespace CodeSignAuto.UI.Tests;

internal static class ProtocolV3TestFixtures
{
    private static readonly DateTimeOffset Now =
        new(2026, 8, 9, 0, 0, 0, TimeSpan.Zero);

    public static CapabilitySnapshot Ready(string alias = "test") =>
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
            Session(alias, SimplySignSessionState.Ready, "ready", ready: true));

    public static CapabilitySnapshot TokenMissing(string alias = "test") =>
        new(
            true,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            false,
            null,
            false,
            "token_missing",
            session: Session(alias, SimplySignSessionState.WaitToken, "token_missing", ready: false));

    private static SimplySignSessionSnapshot Session(
        string alias,
        SimplySignSessionState state,
        string reasonCode,
        bool ready) =>
        new(
            state,
            1,
            Now,
            Now,
            ready ? 7 : null,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            ready,
            reasonCode,
            0,
            null,
            ready,
            ready ? 7 : null);
}
