using System.ComponentModel;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Agent.Signing;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentDiagnosticTests
{
    [Fact]
    public void Preserves_full_diagnostics_and_redacts_only_the_actual_totp_secret()
    {
        const string secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var error = CaptureException(secret);
        var process = ProcessResult.Exited(
            "SimplySignPdfSigner.exe",
            23,
            TimeSpan.FromMilliseconds(125),
            $"stdout email=user@example.test user=signing path=C:\\ProgramData\\SimplySignAuto token=123456 secret={secret}",
            $"stderr Authorization: Bearer visible-token otpauth://totp/Certum:user@example.test?issuer=Certum&secret={secret}&digits=6");
        var writer = new StringWriter();
        var sink = new TextWriterAgentDiagnosticSink(writer);

        sink.Report(
            new AgentDiagnostic(
                "certificate_catalog_process",
                "certificate_catalog_unavailable",
                new InvalidOperationException("outer", error),
                process),
            secret);

        var diagnostic = writer.ToString();
        Assert.DoesNotContain(secret, diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("otpauth://totp/Certum:user@example.test?issuer=Certum&secret=[REDACTED_TOTP_SECRET]&digits=6", diagnostic, StringComparison.Ordinal);
        Assert.Contains("stable_code=certificate_catalog_unavailable", diagnostic, StringComparison.Ordinal);
        Assert.Contains("stage=certificate_catalog_process", diagnostic, StringComparison.Ordinal);
        Assert.Contains("exception_type=System.ComponentModel.Win32Exception", diagnostic, StringComparison.Ordinal);
        Assert.Contains("message=source_path=C:\\source\\catalog.cs line=73 email=user@example.test", diagnostic, StringComparison.Ordinal);
        Assert.Contains("hresult=0x80004005", diagnostic, StringComparison.Ordinal);
        Assert.Contains("win32_error=32", diagnostic, StringComparison.Ordinal);
        Assert.Contains("exception_depth=1", diagnostic, StringComparison.Ordinal);
        Assert.Contains(nameof(CaptureException), diagnostic, StringComparison.Ordinal);
        Assert.Contains("process_exit_code=23", diagnostic, StringComparison.Ordinal);
        Assert.Contains("stdout email=user@example.test user=signing path=C:\\ProgramData\\SimplySignAuto token=123456", diagnostic, StringComparison.Ordinal);
        Assert.Contains("stderr Authorization: Bearer visible-token", diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public void Throwing_writer_and_sink_never_change_the_business_flow()
    {
        var diagnostic = new AgentDiagnostic("stage", "stable", new InvalidOperationException("failure"));
        var writerSink = new TextWriterAgentDiagnosticSink(new ThrowingWriter());
        var safeSink = new ThrowingAgentDiagnosticSink().Safe();

        writerSink.Report(diagnostic);
        safeSink.Report(diagnostic);
        safeSink.Report(diagnostic, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    }

    private static Exception CaptureException(string secret)
    {
        try
        {
            throw new Win32Exception(
                32,
                $"source_path=C:\\source\\catalog.cs line=73 email=user@example.test secret={secret}");
        }
        catch (Exception error)
        {
            return error;
        }
    }


    private sealed class ThrowingWriter : StringWriter
    {
        public override void WriteLine(string? value) => throw new InvalidOperationException("writer_failed");
    }

    private sealed class ThrowingAgentDiagnosticSink : IAgentDiagnosticSink
    {
        public void Report(AgentDiagnostic diagnostic) => throw new InvalidOperationException("sink_failed");
    }
}

internal sealed class RecordingAgentDiagnosticSink : IAgentDiagnosticSink
{
    public List<AgentDiagnostic> Diagnostics { get; } = [];

    public void Report(AgentDiagnostic diagnostic) => Diagnostics.Add(diagnostic);
}
