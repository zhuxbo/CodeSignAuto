using CodeSignAuto.Core.Diagnostics;
using Microsoft.Extensions.Logging;

namespace CodeSignAuto.Service;

// Framework messages may contain request data. Persist category/event identifiers and exceptions only.
internal sealed class DiagnosticLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new Logger(categoryName);
    public void Dispose() { }

    private sealed class Logger(string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            DiagnosticLog.Write(category, exception,
                debug: logLevel < LogLevel.Warning, result: eventId.Id);
        }
    }
}
