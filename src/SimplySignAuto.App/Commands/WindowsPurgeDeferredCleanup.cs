using System.Text;
using System.Xml.Linq;

namespace SimplySignAuto.App.Commands;

internal sealed class WindowsPurgeDeferredCleanup
{
    private readonly IWindowsCommandRunner _runner = new DefaultWindowsCommandRunner();

    public async Task WriteManifestAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        var expectedManifestPath = PurgeQuarantineManifestCodec.ExpectedManifestPath(plan.OperationId);
        if (!string.Equals(plan.ManifestPath, expectedManifestPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        var manifest = PurgeQuarantineManifestCodec.Create(plan);
        var manifestDirectory = Path.GetDirectoryName(plan.ManifestPath)
            ?? throw new InstallException("purge_manifest_invalid");
        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadDirectory(manifestDirectory),
            directory: true);
        if (WindowsPathSafety.EntryExists(plan.ManifestPath))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        await WindowsAtomicProtectedFile.WriteNewAsync(
            plan.ManifestPath,
            PurgeQuarantineManifestCodec.Serialize(manifest),
            cancellationToken).ConfigureAwait(false);
        _ = VerifyManifestFile(plan);
    }

    public async Task ScheduleAsync(
        PurgeIsolationPlan plan,
        CancellationToken cancellationToken)
    {
        EnsureWindows();
        _ = VerifyManifestFile(plan);
        var manifestDirectory = Path.GetDirectoryName(plan.ManifestPath)
            ?? throw new InstallException("purge_manifest_invalid");
        var taskXmlPath = Path.Combine(
            manifestDirectory,
            $"{plan.OperationId}.{Guid.NewGuid():N}.task.xml");
        try
        {
            if (WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
            {
                throw new InstallException("purge_cleanup_task_exists");
            }

            await WindowsAtomicProtectedFile.WriteNewAsync(
                taskXmlPath,
                Encoding.UTF8.GetBytes(WindowsPurgeCleanupTaskXml.Create(plan)),
                cancellationToken).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Create", "/TN", plan.CleanupTaskName, "/XML", taskXmlPath],
                "purge_cleanup_registration_failed",
                cancellationToken).ConfigureAwait(false);
            await WindowsPurgeCleanupTask.VerifyAsync(plan, _runner, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            DeleteProtectedTemporary(taskXmlPath);
        }
    }

    public async Task RollbackTaskAsync(PurgeIsolationPlan plan)
    {
        EnsureWindows();
        if (WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
        {
            await WindowsPurgeCleanupTask.VerifyAsync(
                plan,
                _runner,
                CancellationToken.None).ConfigureAwait(false);
            await _runner.RunCheckedAsync(
                "schtasks.exe",
                ["/Delete", "/TN", plan.CleanupTaskName, "/F"],
                "uninstall_state_uncertain",
                CancellationToken.None).ConfigureAwait(false);
            if (WindowsPurgeCleanupTask.Exists(plan.CleanupTaskName))
            {
                throw new InstallException("uninstall_state_uncertain");
            }
        }
    }

    public void RemoveManifest(PurgeIsolationPlan plan)
    {
        EnsureWindows();
        if (WindowsPathSafety.EntryExists(plan.ManifestPath))
        {
            VerifyManifestFile(plan);
            File.Delete(plan.ManifestPath);
        }
    }

    internal static PurgeQuarantineManifest VerifyManifestFile(PurgeIsolationPlan plan)
    {
        if (!File.Exists(plan.ManifestPath) || WindowsPathSafety.IsReparse(plan.ManifestPath))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.ReadFile(plan.ManifestPath),
            directory: false);
        var manifest = PurgeQuarantineManifestCodec.Deserialize(File.ReadAllText(plan.ManifestPath));
        var expected = PurgeQuarantineManifestCodec.Create(plan);
        if (!PurgeQuarantineManifestCodec.MatchesExpected(manifest, expected))
        {
            throw new InstallException("purge_manifest_invalid");
        }

        return manifest;
    }

    private static void DeleteProtectedTemporary(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        if (WindowsPathSafety.IsReparse(path))
        {
            throw new InstallException("uninstall_state_uncertain");
        }

        File.Delete(path);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }
    }
}

internal static class WindowsPurgeCleanupTask
{
    public static bool Exists(string taskName)
    {
        dynamic? service = null;
        dynamic? folder = null;
        dynamic? task = null;
        try
        {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
            service.Connect();
            folder = service.GetFolder("\\");
            try
            {
                task = folder.GetTask(taskName);
                return true;
            }
            catch (Exception error) when (WindowsInstallResourceLookup.IsTaskNotFound(error))
            {
                return false;
            }
        }
        catch
        {
            throw new InstallException("uninstall_state_uncertain");
        }
        finally
        {
            Release(task);
            Release(folder);
            Release(service);
        }
    }

    public static async Task VerifyAsync(
        PurgeIsolationPlan plan,
        IWindowsCommandRunner runner,
        CancellationToken cancellationToken)
    {
        var query = await runner.RunCheckedAsync(
            "schtasks.exe",
            ["/Query", "/TN", plan.CleanupTaskName, "/XML"],
            "uninstall_state_uncertain",
            cancellationToken).ConfigureAwait(false);
        if (!WindowsPurgeCleanupTaskXml.IsOwned(query.StandardOutput, plan))
        {
            throw new InstallException("uninstall_state_uncertain");
        }
    }

    private static void Release(object? value)
    {
        if (value is not null && System.Runtime.InteropServices.Marshal.IsComObject(value))
        {
            _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(value);
        }
    }
}

internal static class WindowsPurgeCleanupTaskXml
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static string Create(PurgeIsolationPlan plan)
    {
        var command = Command(plan);
        var arguments = Arguments(plan);
        return new XDocument(
        new XDeclaration("1.0", "UTF-8", null),
        new XElement(Ns + "Task",
            new XAttribute("version", "1.4"),
            new XElement(Ns + "RegistrationInfo",
                new XElement(Ns + "Description", PurgeQuarantineManifestCodec.OwnerMarker),
                new XElement(Ns + "Source", plan.OperationId)),
            new XElement(Ns + "Triggers",
                new XElement(Ns + "BootTrigger",
                    new XElement(Ns + "Enabled", "true"))),
                new XElement(Ns + "Principals",
                    new XElement(Ns + "Principal",
                        new XAttribute("id", "System"),
                        new XElement(Ns + "UserId", "S-1-5-18"),
                        new XElement(Ns + "RunLevel", "HighestAvailable"))),
            new XElement(Ns + "Settings",
                new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                new XElement(Ns + "StartWhenAvailable", "true"),
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "ExecutionTimeLimit", "PT1H")),
            new XElement(Ns + "Actions",
                new XAttribute("Context", "System"),
                new XElement(Ns + "Exec",
                    new XElement(Ns + "Command", command),
                    new XElement(Ns + "Arguments", arguments)))))
            .ToString(SaveOptions.DisableFormatting);
    }

    public static bool IsOwned(string xml, PurgeIsolationPlan plan)
    {
        try
        {
            var document = XDocument.Parse(xml, LoadOptions.None);
            var bootEnabled = Value(document, "BootTrigger", "Enabled");
            var taskEnabled = Value(document, "Settings", "Enabled");
            return document.Root?.Name == Ns + "Task" &&
                HasOnlyDirectChild(document.Root, "Actions", "Exec") &&
                HasOnlyDirectChild(document.Root, "Triggers", "BootTrigger") &&
                HasOnlyDirectChild(document.Root, "Principals", "Principal") &&
                Value(document, "RegistrationInfo", "Description") == PurgeQuarantineManifestCodec.OwnerMarker &&
                Value(document, "RegistrationInfo", "Source") == plan.OperationId &&
                document.Descendants(Ns + "BootTrigger").Count() == 1 &&
                IsEnabledOrDefault(bootEnabled) &&
                Value(document, "Principal", "UserId") == "S-1-5-18" &&
                document.Descendants(Ns + "LogonType").Count() == 0 &&
                Value(document, "Principal", "RunLevel") == "HighestAvailable" &&
                Value(document, "Settings", "MultipleInstancesPolicy") == "IgnoreNew" &&
                Value(document, "Settings", "StartWhenAvailable") == "true" &&
                IsEnabledOrDefault(taskEnabled) &&
                Value(document, "Settings", "ExecutionTimeLimit") == "PT1H" &&
                document.Descendants(Ns + "Exec").Count() == 1 &&
                Value(document, "Exec", "Command") == Command(plan) &&
                Value(document, "Exec", "Arguments") == Arguments(plan);
        }
        catch
        {
            return false;
        }
    }

    private static string Command(PurgeIsolationPlan plan) =>
        ProgramFilesCleanupRoot(plan) is null
            ? plan.ExecutablePath
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "cmd.exe");

    private static string Arguments(PurgeIsolationPlan plan)
    {
        var cleanupArguments =
            $"purge-quarantine --manifest {WindowsCommandLine.Quote(plan.ManifestPath)}";
        var programFilesRoot = ProgramFilesCleanupRoot(plan);
        if (programFilesRoot is null)
        {
            return cleanupArguments;
        }

        var inner =
            $"start \"\" /wait /b {WindowsCommandLine.Quote(plan.ExecutablePath)} {cleanupArguments}" +
            $" && del /f /q {WindowsCommandLine.Quote(plan.ExecutablePath)}" +
            $" && rmdir {WindowsCommandLine.Quote(programFilesRoot)}";
        return $"/d /q /s /c \"{inner}\"";
    }

    private static string? ProgramFilesCleanupRoot(
        PurgeIsolationPlan plan)
    {
        var programFilesRoot = Path.GetDirectoryName(plan.ExecutablePath);
        if (programFilesRoot is null ||
            !string.Equals(
                Path.GetFileName(programFilesRoot),
                "SimplySignAuto",
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFileName(plan.ExecutablePath),
                InstallMediaPaths.ExecutableFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return programFilesRoot;
    }

    private static bool IsEnabledOrDefault(string? value) => value is null or "true";

    private static bool HasOnlyDirectChild(
        XElement task,
        string containerName,
        string childName)
    {
        var containers = task.Elements(Ns + containerName).ToArray();
        if (containers.Length != 1)
        {
            return false;
        }

        var children = containers[0].Elements().ToArray();
        return children.Length == 1 && children[0].Name == Ns + childName;
    }

    private static string? Value(XDocument document, string parent, string child) =>
        document.Descendants(Ns + parent).SingleOrDefault()?.Element(Ns + child)?.Value;
}
