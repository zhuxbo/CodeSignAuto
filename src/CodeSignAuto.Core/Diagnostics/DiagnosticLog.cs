using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CodeSignAuto.Core.Diagnostics;

/// <summary>Local, best-effort diagnostics. Callers supply stable event codes, never user data.</summary>
public static class DiagnosticLog
{
    private static readonly object Gate = new();
    private static DiagnosticSession? _current;

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CodeSignAuto", "logs", "diagnostics");

    public static IDisposable Start(string component)
    {
        lock (Gate)
        {
            _current?.Dispose();
            _current = new DiagnosticSession(DefaultDirectory, component, IsDebugEnabled());
        }
        AppDomain.CurrentDomain.UnhandledException += OnUnhandled;
        TaskScheduler.UnobservedTaskException += OnUnobserved;
        Write("process_started");
        return new Lifetime();
    }

    public static void Write(string code, Exception? error = null, bool debug = false, int? result = null)
    {
        lock (Gate)
        {
            _current?.Write(code, error, debug, result);
        }
    }

    private static bool IsDebugEnabled()
    {
        try
        {
            var paths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CodeSignAuto", "diagnostics.json"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CodeSignAuto", "diagnostics.json"),
            };
            foreach (var path in paths)
            {
                if (!File.Exists(path) || new FileInfo(path).Length > 4096) continue;
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                if (document.RootElement.TryGetProperty("debug", out var debug) && debug.ValueKind == JsonValueKind.True)
                    return true;
            }
        }
        catch (Exception) { }
        return false;
    }

    private static void OnUnhandled(object sender, UnhandledExceptionEventArgs args) =>
        Write("unhandled_exception", args.ExceptionObject as Exception);

    private static void OnUnobserved(object? sender, UnobservedTaskExceptionEventArgs args) =>
        Write("unobserved_task_exception", args.Exception);

    private sealed class Lifetime : IDisposable
    {
        public void Dispose()
        {
            AppDomain.CurrentDomain.UnhandledException -= OnUnhandled;
            TaskScheduler.UnobservedTaskException -= OnUnobserved;
            lock (Gate)
            {
                _current?.Write("process_exiting");
                _current?.Dispose();
                _current = null;
            }
        }
    }
}

public sealed class DiagnosticSession : IDisposable
{
    private const long DefaultFileLimit = 4 * 1024 * 1024;
    private const int RetainedFiles = 16;
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly string _component;
    private readonly bool _debug;
    private readonly long _fileLimit;
    private readonly string _run = Guid.NewGuid().ToString("N");
    private readonly string _version = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
    private FileStream? _stream;
    private int _part;
    private bool _disposed;

    public DiagnosticSession(string directory, string component, bool debug = false, long fileLimit = DefaultFileLimit)
    {
        _directory = Path.GetFullPath(directory);
        _component = SafeCode(component);
        _debug = debug;
        ArgumentOutOfRangeException.ThrowIfLessThan(fileLimit, 1024);
        _fileLimit = fileLimit;
    }

    public void Write(string code, Exception? error = null, bool debug = false, int? result = null)
    {
        if (debug && !_debug) return;
        lock (_gate)
        {
            if (_disposed) return;
            try
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    utc = DateTimeOffset.UtcNow,
                    version = _version,
                    os = Environment.OSVersion.VersionString,
                    runtime = Environment.Version.ToString(),
                    process = Environment.ProcessId,
                    session = Process.GetCurrentProcess().SessionId,
                    thread = Environment.CurrentManagedThreadId,
                    run = _run,
                    component = _component,
                    level = error is not null ? "error" : debug ? "debug" : "information",
                    code = SafeCode(code),
                    result,
                    exceptions = Describe(error),
                });
                if (_stream is null || _stream.Length + bytes.Length + 1 > _fileLimit)
                    OpenNext();
                _stream!.Write(bytes);
                _stream.WriteByte((byte)'\n');
                _stream.Flush(flushToDisk: true);
            }
            catch (Exception)
            {
                try { _stream?.Dispose(); } catch (Exception) { }
                _stream = null;
            }
        }
    }

    private void OpenNext()
    {
        _stream?.Dispose();
        _stream = null;
        RejectLinks(_directory);
        Directory.CreateDirectory(_directory);
        RejectLinks(_directory);
        var files = new DirectoryInfo(_directory).EnumerateFiles("diagnostic-*.jsonl")
            .OrderByDescending(file => file.LastWriteTimeUtc).ToArray();
        for (var i = 0; i < files.Length; i++)
        {
            if (i < RetainedFiles - 1 && files[i].LastWriteTimeUtc >= DateTime.UtcNow.AddDays(-14)) continue;
            try
            {
                if ((files[i].Attributes & FileAttributes.ReparsePoint) == 0) files[i].Delete();
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        _stream = new FileStream(Path.Combine(_directory,
            $"diagnostic-{_component}-{Environment.ProcessId}-{_run}-{_part++}.jsonl"),
            FileMode.CreateNew, FileAccess.Write, FileShare.Read);
    }

    public static void RejectLinks(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current is not null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("diagnostic_link_not_allowed");
    }

    private static object[] Describe(Exception? error)
    {
        if (error is null) return [];
        var pending = new Queue<Exception>();
        var seen = new HashSet<Exception>(ReferenceEqualityComparer.Instance);
        var result = new List<object>();
        pending.Enqueue(error);
        while (pending.Count > 0 && result.Count < 32)
        {
            var current = pending.Dequeue();
            if (!seen.Add(current)) continue;
            // Message, Data, ActualValue and source paths may contain credentials or document content.
            result.Add(new
            {
                type = current.GetType().FullName,
                hresult = current.HResult,
                nativeError = current is System.ComponentModel.Win32Exception native ? (int?)native.NativeErrorCode : null,
                stack = FormatStack(current),
            });
            if (current is AggregateException aggregate)
                foreach (var child in aggregate.InnerExceptions) pending.Enqueue(child);
            else if (current.InnerException is { } child) pending.Enqueue(child);
        }
        return result.ToArray();
    }

    private static string FormatStack(Exception error)
    {
        var stack = new StackTrace(error, fNeedFileInfo: false).ToString();
        return stack.Length <= 16384 ? stack : stack[..16384] + "\n[stack truncated]";
    }

    private static string SafeCode(string code) =>
        Regex.IsMatch(code, "^[A-Za-z][A-Za-z0-9_.-]{0,95}$", RegexOptions.CultureInvariant)
            ? code : "invalid_diagnostic_code";

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            try { _stream?.Dispose(); } catch (Exception) { }
            _stream = null;
        }
    }
}
