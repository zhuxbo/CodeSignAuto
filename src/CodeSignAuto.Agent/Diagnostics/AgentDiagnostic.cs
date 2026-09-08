using System.ComponentModel;
using System.Globalization;
using System.Text;
using CodeSignAuto.Agent.Signing;

namespace CodeSignAuto.Agent.Diagnostics;

public sealed record AgentDiagnostic(
    string Stage,
    string StableCode,
    Exception? Exception = null,
    ProcessResult? Process = null);

public interface IAgentDiagnosticSink
{
    void Report(AgentDiagnostic diagnostic);

    void Report(AgentDiagnostic diagnostic, string actualTotpSecret) => Report(diagnostic);
}

public sealed class NullAgentDiagnosticSink : IAgentDiagnosticSink
{
    public static NullAgentDiagnosticSink Instance { get; } = new();

    private NullAgentDiagnosticSink()
    {
    }

    public void Report(AgentDiagnostic diagnostic)
    {
    }
}

public sealed class TextWriterAgentDiagnosticSink(TextWriter writer) : IAgentDiagnosticSink
{
    private readonly TextWriter _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    public void Report(AgentDiagnostic diagnostic)
        => ReportCore(diagnostic, null);

    public void Report(AgentDiagnostic diagnostic, string actualTotpSecret)
        => ReportCore(diagnostic, actualTotpSecret);

    private void ReportCore(AgentDiagnostic diagnostic, string? actualTotpSecret)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        try
        {
            var text = Format(diagnostic);
            text = CodeSignAuto.Core.Security.SecretRedactor.Redact(text, actualTotpSecret);
            _writer.WriteLine(text);
            _writer.Flush();
        }
        catch (Exception)
        {
        }
    }

    internal static string Format(AgentDiagnostic diagnostic)
    {
        var output = new StringBuilder()
            .AppendLine("agent_diagnostic_begin")
            .Append("stable_code=").AppendLine(diagnostic.StableCode)
            .Append("stage=").AppendLine(diagnostic.Stage);
        var effectiveException = diagnostic.Exception ?? diagnostic.Process?.FailureException;
        if (effectiveException is { } error)
        {
            output.AppendLine("exception_begin").AppendLine(FormatExceptionChain(error)).AppendLine("exception_end");
        }

        if (diagnostic.Process is { } process)
        {
            output
                .Append("process_executable=").AppendLine(process.ExecutableName)
                .Append("process_termination=").AppendLine(process.Termination.ToString())
                .Append("process_exit_code=").AppendLine(process.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty)
                .Append("process_failure_code=").AppendLine(process.FailureCode ?? string.Empty)
                .Append("process_stdout_truncated=").AppendLine(process.StandardOutputTruncated.ToString(CultureInfo.InvariantCulture))
                .Append("process_stderr_truncated=").AppendLine(process.StandardErrorTruncated.ToString(CultureInfo.InvariantCulture))
                .AppendLine("process_stdout_begin")
                .AppendLine(process.StandardOutput)
                .AppendLine("process_stdout_end")
                .AppendLine("process_stderr_begin")
                .AppendLine(process.StandardError)
                .AppendLine("process_stderr_end");
        }

        return output.Append("agent_diagnostic_end").ToString();
    }

    private static string FormatExceptionChain(Exception error)
    {
        var output = new StringBuilder();
        var depth = 0;
        for (var current = error; current is not null; current = current.InnerException, depth++)
        {
            if (output.Length > 0)
            {
                output.AppendLine("inner_exception");
            }

            output
                .Append("exception_depth=").AppendLine(depth.ToString(CultureInfo.InvariantCulture))
                .Append("exception_type=").AppendLine(current.GetType().FullName)
                .Append("message=").AppendLine(current.Message)
                .Append("hresult=0x").AppendLine(((uint)current.HResult).ToString("X8", CultureInfo.InvariantCulture))
                .Append("win32_error=").AppendLine(
                    current is Win32Exception native
                        ? native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)
                        : string.Empty)
                .AppendLine("stack_begin")
                .AppendLine(current.StackTrace ?? string.Empty);
            output.AppendLine("stack_end");
        }

        return output.ToString().TrimEnd();
    }
}

public static class AgentDiagnosticSinkExtensions
{
    public static IAgentDiagnosticSink Safe(this IAgentDiagnosticSink? sink) =>
        sink is SafeAgentDiagnosticSink
            ? sink
            : new SafeAgentDiagnosticSink(sink ?? NullAgentDiagnosticSink.Instance);

    private sealed class SafeAgentDiagnosticSink(IAgentDiagnosticSink inner) : IAgentDiagnosticSink
    {
        public void Report(AgentDiagnostic diagnostic)
        {
            try
            {
                inner.Report(diagnostic);
            }
            catch (Exception)
            {
            }
        }

        public void Report(AgentDiagnostic diagnostic, string actualTotpSecret)
        {
            try
            {
                inner.Report(diagnostic, actualTotpSecret);
            }
            catch (Exception)
            {
            }
        }
    }
}
