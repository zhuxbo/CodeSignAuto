namespace SimplySignAuto.App.UI.Testing;

public sealed class UiTestOwnedDirectory : IDisposable
{
    private const string MarkerName = ".ssa-ui-owner";
    private readonly string _marker;
    private int _disposed;

    private UiTestOwnedDirectory(string path, string marker)
    {
        Path = path;
        _marker = marker;
    }

    public string Path { get; }

    public static UiTestOwnedDirectory Create()
    {
        var directory = Directory.CreateTempSubdirectory("SSA-UI-");
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("ui_test_temp_invalid");
        }

        var marker = Guid.NewGuid().ToString("N");
        using (var stream = new FileStream(
            System.IO.Path.Combine(directory.FullName, MarkerName),
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None))
        using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false, true)))
        {
            writer.Write(marker);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        return new UiTestOwnedDirectory(directory.FullName, marker);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            var directory = new DirectoryInfo(Path);
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
                !string.Equals(
                    File.ReadAllText(System.IO.Path.Combine(Path, MarkerName)),
                    _marker,
                    StringComparison.Ordinal))
            {
                return;
            }

            directory.Delete(recursive: true);
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
        }
    }
}
