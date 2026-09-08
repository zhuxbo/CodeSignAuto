using System.Diagnostics;

var resultsIndex = Array.IndexOf(args, "--results-directory");
var pidDirectory = resultsIndex >= 0 && resultsIndex + 1 < args.Length
    ? Path.GetFullPath(args[resultsIndex + 1])
    : args.Length == 2 && args[0] == "--coverage-hang-child"
        ? Path.GetFullPath(args[1])
        : Directory.GetCurrentDirectory();
Directory.CreateDirectory(pidDirectory);
if (args.Contains("--coverage-hang-child", StringComparer.Ordinal))
{
    File.WriteAllText(
        Path.Combine(pidDirectory, "coverage-hang-child.pid"),
        Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return;
}

File.WriteAllText(
    Path.Combine(pidDirectory, "coverage-hang-parent.pid"),
    Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
var start = new ProcessStartInfo
{
    FileName = Environment.ProcessPath ?? throw new InvalidOperationException("process_path_missing"),
    WorkingDirectory = Directory.GetCurrentDirectory(),
    UseShellExecute = false,
    CreateNoWindow = true,
};
start.ArgumentList.Add("--coverage-hang-child");
start.ArgumentList.Add(pidDirectory);
using var child = Process.Start(start) ?? throw new InvalidOperationException("child_start_failed");
if (File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "coverage-parent-exits.mode")))
{
    return;
}

await Task.Delay(Timeout.InfiniteTimeSpan);
