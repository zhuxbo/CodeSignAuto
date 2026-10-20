using CodeSignAuto.Core.Diagnostics;
using Microsoft.Win32;

namespace CodeSignAuto.App.Commands;

internal static class ExportDiagnosticsCommand
{
    public static int Execute(string outputPath, TextWriter output, TextWriter error)
    {
        try
        {
            DiagnosticArchive.Create(outputPath, GetDirectories());
            output.WriteLine("diagnostics_exported");
            output.WriteLine("Review manifest.json for unavailable sources; use an elevated console to include other accounts.");
            return 0;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException)
        {
            DiagnosticLog.Write("diagnostics_export_failed", failure);
            error.WriteLine("diagnostics_export_failed");
            return 1;
        }
    }

    private static IEnumerable<DiagnosticSource> GetDirectories()
    {
        var paths = new List<DiagnosticSource>
        {
            new(DiagnosticLog.DefaultDirectory, System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "unknown"),
        };
        using var profiles = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (profiles is not null)
        {
            foreach (var name in profiles.GetSubKeyNames())
            {
                using var profile = profiles.OpenSubKey(name);
                if (profile?.GetValue("ProfileImagePath") is string root)
                    paths.Add(new DiagnosticSource(Path.Combine(Environment.ExpandEnvironmentVariables(root),
                        "AppData", "Local", "CodeSignAuto", "logs", "diagnostics"), name));
            }
        }
        // LocalSystem does not always have a ProfileList entry.
        paths.Add(new DiagnosticSource(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "config", "systemprofile", "AppData", "Local", "CodeSignAuto", "logs", "diagnostics"), "S-1-5-18"));
        return paths;
    }
}
