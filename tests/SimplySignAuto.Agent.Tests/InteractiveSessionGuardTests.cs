using SimplySignAuto.Agent.Sessions;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class InteractiveSessionGuardTests
{
    private const string ExpectedSid = "S-1-5-21-1000-2000-3000-4000";

    [Fact]
    public void Rejects_a_process_outside_the_configured_interactive_session()
    {
        (int SessionId, string ActualSid, bool IsInteractive, string ExpectedCode)[] cases =
        [
            (0, ExpectedSid, true, "agent_session_zero"),
            (7, "S-1-5-21-1000-2000-3000-4001", true, "agent_wrong_user"),
            (7, ExpectedSid, false, "agent_not_interactive"),
        ];
        foreach (var (sessionId, actualSid, isInteractive, expectedCode) in cases)
        {
            var source = new FakeInteractiveSessionSource(
                new InteractiveSessionState(sessionId, actualSid, isInteractive));

            var error = Assert.Throws<AgentStartupException>(() =>
                new InteractiveSessionGuard(source).ValidateCurrentProcess(ExpectedSid));

            Assert.Equal(expectedCode, error.Code);
            Assert.DoesNotContain(ExpectedSid, error.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(actualSid, error.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Rejects_missing_or_malformed_configured_sid_before_reading_process_state()
    {
        string[] invalidSids = ["", "not-a-sid", "S-2-5-21-1000", "S-1-5-21-1-secret", "S-1-5-21-4294967296"];
        foreach (var configuredSid in invalidSids)
        {
            var source = new ThrowingInteractiveSessionSource();

            var error = Assert.Throws<AgentStartupException>(() =>
                new InteractiveSessionGuard(source).ValidateCurrentProcess(configuredSid));

            Assert.Equal("agent_configuration_invalid", error.Code);
            Assert.Equal(0, source.ReadCalls);
            if (configuredSid.Length > 0)
            {
                Assert.DoesNotContain(configuredSid, error.Message, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Returns_only_the_verified_session_identity()
    {
        var source = new FakeInteractiveSessionSource(
            new InteractiveSessionState(7, ExpectedSid, HasInteractiveWindowStation: true));

        var result = new InteractiveSessionGuard(source).ValidateCurrentProcess(ExpectedSid);

        Assert.Equal(7, result.SessionId);
        Assert.Equal(ExpectedSid, result.UserSid);
        Assert.Equal("4000", result.UserSidSuffix);
    }

    [Fact]
    public void Production_source_explicitly_rejects_non_windows_execution()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var error = Assert.Throws<AgentStartupException>(() =>
            new InteractiveSessionGuard().ValidateCurrentProcess(ExpectedSid));

        Assert.Equal("agent_not_interactive", error.Code);
        Assert.DoesNotContain("PlatformNotSupported", error.Message, StringComparison.Ordinal);
    }

    private sealed class FakeInteractiveSessionSource(InteractiveSessionState state) : IInteractiveSessionSource
    {
        public InteractiveSessionState ReadCurrent() => state;
    }

    private sealed class ThrowingInteractiveSessionSource : IInteractiveSessionSource
    {
        public int ReadCalls { get; private set; }

        public InteractiveSessionState ReadCurrent()
        {
            ReadCalls++;
            throw new InvalidOperationException("The source must not be called.");
        }
    }
}
