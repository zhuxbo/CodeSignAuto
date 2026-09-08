using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Protocol.Tests;

public sealed class SimplySignSessionStateTests
{
    [Theory]
    [InlineData(SimplySignSessionState.Unknown, "UNKNOWN")]
    [InlineData(SimplySignSessionState.Checking, "CHECKING")]
    [InlineData(SimplySignSessionState.Ready, "READY")]
    [InlineData(SimplySignSessionState.LoginRequired, "LOGIN_REQUIRED")]
    [InlineData(SimplySignSessionState.Loginning, "LOGINNING")]
    [InlineData(SimplySignSessionState.WaitToken, "WAIT_TOKEN")]
    [InlineData(SimplySignSessionState.Failed, "FAILED")]
    public void State_round_trips_with_exact_wire_value(
        SimplySignSessionState state,
        string wireValue)
    {
        Assert.Equal(state, SimplySignSessionStatePolicy.ParseExact(wireValue));
        Assert.Equal(wireValue, SimplySignSessionStatePolicy.Format(state));
    }

    [Theory]
    [InlineData("ready")]
    [InlineData("PARTIAL")]
    [InlineData("LOGGING_IN")]
    [InlineData("")]
    public void Unknown_or_case_variant_state_is_rejected(string value)
    {
        var error = Assert.Throws<ProtocolException>(() =>
            SimplySignSessionStatePolicy.ParseExact(value));

        Assert.Equal("invalid_message", error.Code);
    }

    [Fact]
    public void Undefined_state_cannot_be_formatted()
    {
        var error = Assert.Throws<ProtocolException>(() =>
            SimplySignSessionStatePolicy.Format((SimplySignSessionState)99));

        Assert.Equal("invalid_message", error.Code);
    }

    [Theory]
    [MemberData(nameof(AllStateCausePairs))]
    public void Transition_matrix_is_exact(
        SimplySignSessionState from,
        SimplySignSessionState to,
        TransitionCause cause,
        bool expected)
    {
        Assert.Equal(expected, SimplySignSessionTransitionPolicy.IsAllowed(from, to, cause));
    }

    [Fact]
    public void Ready_snapshot_requires_interactive_session_and_all_pkcs11_facts()
    {
        var ready = ReadySnapshot();

        Assert.Equal(SimplySignSessionState.Ready, ready.State);
        Assert.True(ready.Ready);
        Assert.Equal(7, ready.SessionId);
        Assert.True(ready.TokenPresent);
        Assert.True(ready.TokenMatches);
        Assert.True(ready.CertificatePresent);
        Assert.True(ready.CertificateMatches);
        Assert.True(ready.PrivateKeyPresent);
        Assert.True(ready.PrivateKeyMatches);

        Assert.Throws<ArgumentException>(() => ReadySnapshot(sessionId: 0));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(tokenPresent: false));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(tokenMatches: false));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(certificatePresent: false));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(certificateMatches: false));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(privateKeyPresent: false));
        Assert.Throws<ArgumentException>(() => ReadySnapshot(privateKeyMatches: false));
    }

    [Theory]
    [InlineData(SimplySignSessionState.Unknown)]
    [InlineData(SimplySignSessionState.Checking)]
    [InlineData(SimplySignSessionState.LoginRequired)]
    [InlineData(SimplySignSessionState.Loginning)]
    [InlineData(SimplySignSessionState.WaitToken)]
    [InlineData(SimplySignSessionState.Failed)]
    public void Non_ready_state_cannot_claim_ready(SimplySignSessionState state)
    {
        Assert.Throws<ArgumentException>(() => new SimplySignSessionSnapshot(
            state,
            3,
            Utc(10),
            Utc(9),
            7,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            "ready",
            0,
            null));
    }

    [Fact]
    public void Non_ready_state_cannot_use_ready_reason()
    {
        Assert.Throws<ArgumentException>(() => UnknownSnapshot(
            generation: 3,
            probedMinute: 10,
            transitionedMinute: 9,
            reasonCode: "ready"));
    }

    [Theory]
    [InlineData(SimplySignSessionState.Unknown, "checking")]
    [InlineData(SimplySignSessionState.Checking, "login_required")]
    [InlineData(SimplySignSessionState.LoginRequired, "loginning")]
    [InlineData(SimplySignSessionState.Loginning, "wait_token")]
    [InlineData(SimplySignSessionState.WaitToken, "failed")]
    [InlineData(SimplySignSessionState.Failed, "wait_token")]
    public void State_rejects_reason_owned_by_another_state(
        SimplySignSessionState state,
        string reasonCode)
    {
        Assert.Throws<ArgumentException>(() => new SimplySignSessionSnapshot(
            state,
            3,
            Utc(10),
            Utc(9),
            7,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            reasonCode,
            0,
            null));
    }

    [Fact]
    public void Same_state_resend_preserves_transition_time_and_generation()
    {
        var previous = UnknownSnapshot(3, 10, 9);
        var validResend = UnknownSnapshot(3, 11, 9);
        var changedTransitionTime = UnknownSnapshot(3, 11, 10);
        var changedGeneration = UnknownSnapshot(4, 11, 9);

        Assert.True(SimplySignSessionTransitionPolicy.IsAllowed(
            previous,
            validResend,
            TransitionCause.Normal));
        Assert.False(SimplySignSessionTransitionPolicy.IsAllowed(
            previous,
            changedTransitionTime,
            TransitionCause.Normal));
        Assert.False(SimplySignSessionTransitionPolicy.IsAllowed(
            previous,
            changedGeneration,
            TransitionCause.Normal));
    }

    [Fact]
    public void Invalidated_transition_requires_unknown_and_strictly_newer_generation()
    {
        var previous = ReadySnapshot();
        var sameGeneration = UnknownSnapshot(3, 11, 10, "invalidated");
        var newerGeneration = UnknownSnapshot(4, 11, 10, "invalidated");

        Assert.False(SimplySignSessionTransitionPolicy.IsAllowed(
            previous,
            sameGeneration,
            TransitionCause.Invalidated));
        Assert.True(SimplySignSessionTransitionPolicy.IsAllowed(
            previous,
            newerGeneration,
            TransitionCause.Invalidated));
    }

    [Theory]
    [InlineData("otpauth://totp/profile?secret=AAAAAAAA")]
    [InlineData("failed because token serial 1234567890")]
    public void Snapshot_rejects_non_allowlisted_reason(string reason)
    {
        Assert.Throws<ArgumentException>(() => ReadySnapshot(reasonCode: reason));
    }

    public static TheoryData<SimplySignSessionState, SimplySignSessionState, TransitionCause, bool>
        AllStateCausePairs()
    {
        SimplySignSessionState[] states =
        [
            SimplySignSessionState.Unknown,
            SimplySignSessionState.Checking,
            SimplySignSessionState.Ready,
            SimplySignSessionState.LoginRequired,
            SimplySignSessionState.Loginning,
            SimplySignSessionState.WaitToken,
            SimplySignSessionState.Failed,
        ];
        var data = new TheoryData<SimplySignSessionState, SimplySignSessionState, TransitionCause, bool>();
        foreach (var from in states)
        {
            foreach (var to in states)
            {
                data.Add(from, to, TransitionCause.Normal, NormalExpected(from, to));
                data.Add(from, to, TransitionCause.Invalidated, to == SimplySignSessionState.Unknown);
            }
        }

        return data;
    }

    private static bool NormalExpected(SimplySignSessionState from, SimplySignSessionState to) =>
        from == to || (from, to) switch
        {
            (SimplySignSessionState.Unknown, SimplySignSessionState.Checking) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.Ready) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.LoginRequired) => true,
            (SimplySignSessionState.Checking, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.Ready, SimplySignSessionState.Checking) => true,
            (SimplySignSessionState.LoginRequired, SimplySignSessionState.Loginning) => true,
            (SimplySignSessionState.Loginning, SimplySignSessionState.WaitToken) => true,
            (SimplySignSessionState.Loginning, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.Ready) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.LoginRequired) => true,
            (SimplySignSessionState.WaitToken, SimplySignSessionState.Failed) => true,
            (SimplySignSessionState.Failed, SimplySignSessionState.Checking) => true,
            _ => false,
        };

    private static SimplySignSessionSnapshot ReadySnapshot(
        int sessionId = 7,
        bool tokenPresent = true,
        bool tokenMatches = true,
        bool certificatePresent = true,
        bool certificateMatches = true,
        bool privateKeyPresent = true,
        bool privateKeyMatches = true,
        string reasonCode = "ready") =>
        new(
            SimplySignSessionState.Ready,
            3,
            Utc(10),
            Utc(9),
            sessionId,
            tokenPresent,
            tokenMatches,
            certificatePresent,
            certificateMatches,
            privateKeyPresent,
            privateKeyMatches,
            true,
            reasonCode,
            0,
            null,
            true,
            7);

    private static SimplySignSessionSnapshot UnknownSnapshot(
        long generation,
        int probedMinute,
        int transitionedMinute,
        string reasonCode = "unknown") =>
        new(
            SimplySignSessionState.Unknown,
            generation,
            Utc(probedMinute),
            Utc(transitionedMinute),
            null,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            reasonCode,
            0,
            null);

    private static DateTimeOffset Utc(int minute) =>
        new(2026, 8, 9, 0, minute, 0, TimeSpan.Zero);
}
