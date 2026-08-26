using System.Text;

namespace SimplySignAuto.App.UI;

internal static class DesktopDiagnosticLog
{
    private const long DefaultMaximumBytes = 64L * 1024 * 1024;
    private const string FileName = "desktop-agent.log";

    public static TextWriter Open()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localApplicationData)
            ? TextWriter.Null
            : Open(Path.Combine(localApplicationData, "SimplySignAuto"), DefaultMaximumBytes);
    }

    internal static TextWriter Open(string rootPath, long maximumBytes)
        => LocalDiagnosticLog.Open(GetPath(rootPath), maximumBytes);

    internal static string GetPath(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        return Path.Combine(Path.GetFullPath(rootPath), "logs", FileName);
    }
}

internal static class UninstallDiagnosticLog
{
    private const long DefaultMaximumBytes = 1024L * 1024;
    private const string FileName = "uninstall.log";

    public static TextWriter Open()
    {
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localApplicationData)
            ? TextWriter.Null
            : Open(Path.Combine(localApplicationData, "SimplySignAuto"), DefaultMaximumBytes);
    }

    internal static TextWriter Open(string rootPath, long maximumBytes) =>
        LocalDiagnosticLog.Open(GetPath(rootPath), maximumBytes);

    internal static string GetPath(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        return Path.Combine(Path.GetFullPath(rootPath), "logs", FileName);
    }
}

internal static class LocalDiagnosticLog
{
    public static TextWriter Open(string path, long maximumBytes)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            return TextWriter.Synchronized(new BoundedUtf8LogWriter(path, maximumBytes));
        }
        catch (Exception)
        {
            return TextWriter.Null;
        }
    }

    private sealed class BoundedUtf8LogWriter : TextWriter
    {
        private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);
        private static readonly byte[] OversizedEntry = Utf8.GetBytes(
            "desktop_diagnostic_entry_exceeded_log_limit" + Environment.NewLine);

        private readonly FileStream _stream;
        private readonly long _maximumBytes;

        public BoundedUtf8LogWriter(string path, long maximumBytes)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(maximumBytes, OversizedEntry.Length);
            _maximumBytes = maximumBytes;
            _stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
            _stream.Position = _stream.Length;
        }

        public override Encoding Encoding => Utf8;

        public override void Write(char value) => Write(value.ToString());

        public override void Write(string? value) => WriteBytes(Utf8.GetBytes(value ?? string.Empty));

        public override void WriteLine(string? value) =>
            WriteBytes(Utf8.GetBytes((value ?? string.Empty) + Environment.NewLine));

        public override Task WriteLineAsync(string? value)
        {
            WriteLine(value);
            return Task.CompletedTask;
        }

        public override void Flush() => _stream.Flush();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _stream.Dispose();
            }

            base.Dispose(disposing);
        }

        private void WriteBytes(byte[] bytes)
        {
            if (bytes.LongLength > _maximumBytes)
            {
                bytes = OversizedEntry;
            }

            if (_stream.Length + bytes.LongLength > _maximumBytes)
            {
                _stream.SetLength(0);
                _stream.Position = 0;
            }

            _stream.Write(bytes);
        }
    }
}
