using System.Runtime.InteropServices;
using System.Security.Principal;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.Commands;

internal static class WindowsDesktopShortcut
{
    public static void CreateExact(
        CreateDesktopShortcut action,
        SecurityIdentifier signingUser)
    {
        EnsureValid(action);
        if (File.Exists(action.Path) || Directory.Exists(action.Path))
        {
            throw new InstallException("install_resource_exists");
        }

        var parent = Path.GetDirectoryName(action.Path)!;
        if (!Directory.Exists(parent) || WindowsPathSafety.IsReparse(parent))
        {
            throw new InstallException("desktop_shortcut_failed");
        }

        var temporary = action with
        {
            Path = Path.Combine(
                parent,
                $".SimplySignAuto.{Guid.NewGuid():N}.part.lnk"),
        };
        var promoted = false;
        try
        {
            Write(temporary);
            WindowsInstallAcl.ApplyFile(
                temporary.Path,
                InstallAclProfile.AdministratorsOnly,
                signingUser);
            VerifyExact(temporary, signingUser, "desktop_shortcut_failed");
            File.Move(temporary.Path, action.Path);
            promoted = true;
            VerifyExact(action, signingUser, "desktop_shortcut_failed");
            NotifyShell(action.Path, ShellChangeCreated);
        }
        catch (InstallException)
        {
            TryRemoveCreated(temporary, signingUser);
            if (promoted)
            {
                TryRemoveCreated(action, signingUser);
            }
            throw;
        }
        catch
        {
            TryRemoveCreated(temporary, signingUser);
            if (promoted)
            {
                TryRemoveCreated(action, signingUser);
            }
            throw new InstallException("desktop_shortcut_failed");
        }
    }

    public static bool IsExact(CreateDesktopShortcut action)
    {
        try
        {
            return Read(action.Path) is { } shortcut && Matches(shortcut, action);
        }
        catch
        {
            return false;
        }
    }

    public static void VerifyExact(
        CreateDesktopShortcut action,
        SecurityIdentifier signingUser,
        string errorCode)
    {
        try
        {
            using var stream = NoFollowFile.OpenRead(action.Path, FileShare.Read, 4096);
            WindowsInstallAcl.VerifyFile(
                action.Path,
                InstallAclProfile.AdministratorsOnly,
                signingUser);
            if (!PlatformLocalFileIdentityProvider.Instance.TryGetIdentity(
                    stream.SafeFileHandle,
                    out var identity) ||
                identity.LinkCount != 1 ||
                !IsExact(action))
            {
                throw new IOException("desktop_shortcut_invalid");
            }
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException(errorCode);
        }
    }

    public static void RemoveExact(
        CreateDesktopShortcut action,
        string errorCode,
        SecurityIdentifier? signingUser = null)
    {
        if (!File.Exists(action.Path))
        {
            return;
        }

        try
        {
            if (signingUser is not null)
            {
                VerifyExact(action, signingUser, errorCode);
            }
            else if (!IsExact(action))
            {
                throw new InstallException(errorCode);
            }

            File.Delete(action.Path);
            if (File.Exists(action.Path))
            {
                throw new InstallException(errorCode);
            }

            NotifyShell(action.Path, ShellChangeDeleted);
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException(errorCode);
        }
    }

    private static void TryRemoveCreated(
        CreateDesktopShortcut action,
        SecurityIdentifier signingUser)
    {
        if (!File.Exists(action.Path))
        {
            return;
        }

        try
        {
            RemoveExact(action, "install_state_uncertain", signingUser);
        }
        catch
        {
            throw new InstallException("install_state_uncertain");
        }
    }

    private static void Write(CreateDesktopShortcut action)
    {
        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(
                Type.GetTypeFromProgID("WScript.Shell", throwOnError: true)!)!;
            dynamic dynamicShell = shell;
            shortcut = dynamicShell.CreateShortcut(action.Path);
            dynamic dynamicShortcut = shortcut;
            dynamicShortcut.TargetPath = action.TargetPath;
            dynamicShortcut.Arguments = string.Empty;
            dynamicShortcut.WorkingDirectory = Path.GetDirectoryName(action.TargetPath)!;
            dynamicShortcut.IconLocation = $"{action.TargetPath},0";
            dynamicShortcut.Description = action.OwnerMarker;
            dynamicShortcut.WindowStyle = 1;
            dynamicShortcut.Save();
        }
        finally
        {
            Release(shortcut);
            Release(shell);
        }
    }

    private static ShortcutSnapshot? Read(string path)
    {
        if (!File.Exists(path) || WindowsPathSafety.IsReparse(path))
        {
            return null;
        }

        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(
                Type.GetTypeFromProgID("WScript.Shell", throwOnError: true)!)!;
            dynamic dynamicShell = shell;
            shortcut = dynamicShell.CreateShortcut(path);
            dynamic dynamicShortcut = shortcut;
            return new ShortcutSnapshot(
                (string)dynamicShortcut.TargetPath,
                (string)dynamicShortcut.Arguments,
                (string)dynamicShortcut.WorkingDirectory,
                (string)dynamicShortcut.IconLocation,
                (string)dynamicShortcut.Description);
        }
        finally
        {
            Release(shortcut);
            Release(shell);
        }
    }

    private static bool Matches(ShortcutSnapshot shortcut, CreateDesktopShortcut action) =>
        PathEquals(shortcut.TargetPath, action.TargetPath) &&
        string.IsNullOrEmpty(shortcut.Arguments) &&
        PathEquals(shortcut.WorkingDirectory, Path.GetDirectoryName(action.TargetPath)!) &&
        string.Equals(shortcut.IconLocation, $"{action.TargetPath},0", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(shortcut.Description, action.OwnerMarker, StringComparison.Ordinal);

    private static void EnsureValid(CreateDesktopShortcut action)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        if (!Path.IsPathFullyQualified(action.Path) ||
            !Path.IsPathFullyQualified(action.TargetPath) ||
            !File.Exists(action.TargetPath) ||
            WindowsPathSafety.IsReparse(action.TargetPath) ||
            !string.Equals(Path.GetExtension(action.Path), ".lnk", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(action.Path), action.Path, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(action.TargetPath), action.TargetPath, StringComparison.OrdinalIgnoreCase) ||
            !HasValidOwnerMarker(action.OwnerMarker))
        {
            throw new InstallException("desktop_shortcut_failed");
        }
    }

    private static bool HasValidOwnerMarker(string marker)
    {
        const string prefix = "SimplySignAuto/v1/";
        return marker.StartsWith(prefix, StringComparison.Ordinal) &&
            InstallOwnershipMarker.IsInstanceId(marker[prefix.Length..]);
    }

    private static bool PathEquals(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    private static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }

    private static void NotifyShell(string path, uint change) =>
        SHChangeNotify(change, ShellNotifyPathW | ShellNotifyFlushNoWait, path, nint.Zero);

    private const uint ShellChangeCreated = 0x00000002;
    private const uint ShellChangeDeleted = 0x00000004;
    private const uint ShellNotifyPathW = 0x0005;
    private const uint ShellNotifyFlushNoWait = 0x3000;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern void SHChangeNotify(
        uint eventId,
        uint flags,
        string item1,
        nint item2);

    private sealed record ShortcutSnapshot(
        string TargetPath,
        string Arguments,
        string WorkingDirectory,
        string IconLocation,
        string Description);
}
