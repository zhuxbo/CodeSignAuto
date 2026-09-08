using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace CodeSignAuto.Core.Security;

public enum NoFollowPathEntryKind
{
    Missing,
    RegularFile,
    Directory,
    ReparsePoint,
}

public static class NoFollowFile
{
    private const uint GenericRead = 0x80000000;
    private const uint OpenExisting = 3;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const int FileAttributeTagInfo = 9;

    public static FileStream OpenRead(string path, FileShare share, int bufferSize)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (bufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bufferSize));
        }

        SafeFileHandle handle;
        if (OperatingSystem.IsWindows())
        {
            handle = CreateFile(
                path,
                GenericRead,
                ToNativeShare(share),
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint | FileFlagSequentialScan,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw NativeOpenFailure();
            }

            if (!GetFileInformationByHandleEx(
                    handle,
                    FileAttributeTagInfo,
                    out var attributes,
                    (uint)Marshal.SizeOf<FileAttributeTagInformation>()) ||
                (attributes.FileAttributes & (FileAttributeReparsePoint | FileAttributeDirectory)) != 0)
            {
                handle.Dispose();
                throw NativeOpenFailure();
            }
        }
        else if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            var noFollow = OperatingSystem.IsMacOS() ? 0x00000100 : 0x00020000;
            var closeOnExec = OperatingSystem.IsMacOS() ? 0x01000000 : 0x00080000;
            var descriptor = Open(path, noFollow | closeOnExec, 0);
            if (descriptor < 0)
            {
                throw NativeOpenFailure();
            }

            handle = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        }
        else
        {
            throw new PlatformNotSupportedException("No-follow file handles are unavailable.");
        }

        try
        {
            return new FileStream(handle, FileAccess.Read, bufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public static NoFollowPathEntryKind InspectPathEntry(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        try
        {
            var info = new FileInfo(path);
            if (info.LinkTarget is not null)
            {
                return NoFollowPathEntryKind.ReparsePoint;
            }

            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                return NoFollowPathEntryKind.ReparsePoint;
            }

            return (attributes & FileAttributes.Directory) != 0
                ? NoFollowPathEntryKind.Directory
                : NoFollowPathEntryKind.RegularFile;
        }
        catch (FileNotFoundException)
        {
            return NoFollowPathEntryKind.Missing;
        }
        catch (DirectoryNotFoundException)
        {
            return NoFollowPathEntryKind.Missing;
        }
    }

    private static uint ToNativeShare(FileShare share)
    {
        uint native = 0;
        if ((share & FileShare.Read) != 0)
        {
            native |= 0x00000001;
        }

        if ((share & FileShare.Write) != 0)
        {
            native |= 0x00000002;
        }

        if ((share & FileShare.Delete) != 0)
        {
            native |= 0x00000004;
        }

        return native;
    }

    private static IOException NativeOpenFailure()
    {
        var error = Marshal.GetLastPInvokeError();
        return new IOException(
            "Unable to open a regular file without following links.",
            new Win32Exception(error));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInformation
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int informationClass,
        out FileAttributeTagInformation information,
        uint bufferSize);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags, int mode);
}
