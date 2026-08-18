using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SimplySignAuto.Core.Security;

public readonly record struct LocalFileIdentity(
    ulong VolumeId,
    ulong FileIdHigh,
    ulong FileIdLow,
    uint LinkCount)
{
    public bool RefersToSameFile(LocalFileIdentity other) =>
        VolumeId == other.VolumeId &&
        FileIdHigh == other.FileIdHigh &&
        FileIdLow == other.FileIdLow;
}

public interface ILocalFileIdentityProvider
{
    bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity identity);
}

public sealed class PlatformLocalFileIdentityProvider : ILocalFileIdentityProvider
{
    public static PlatformLocalFileIdentityProvider Instance { get; } = new();

    private PlatformLocalFileIdentityProvider()
    {
    }

    public bool TryGetIdentity(SafeFileHandle handle, out LocalFileIdentity identity)
    {
        identity = default;
        if (handle.IsInvalid || handle.IsClosed)
        {
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandle(handle, out var information))
            {
                return false;
            }

            identity = new LocalFileIdentity(
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow,
                information.NumberOfLinks);
            return information.NumberOfLinks > 0;
        }

        if (!OperatingSystem.IsMacOS() && !OperatingSystem.IsLinux())
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(256);
        try
        {
            if (FStat(handle.DangerousGetHandle().ToInt32(), buffer) != 0)
            {
                return false;
            }

            if (OperatingSystem.IsMacOS())
            {
                var device = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                var linkCount = unchecked((ushort)Marshal.ReadInt16(buffer, 6));
                var inode = unchecked((ulong)Marshal.ReadInt64(buffer, 8));
                identity = new LocalFileIdentity(device, 0, inode, linkCount);
            }
            else
            {
                var device = unchecked((ulong)Marshal.ReadInt64(buffer, 0));
                var inode = unchecked((ulong)Marshal.ReadInt64(buffer, 8));
                var linkCount = unchecked((ulong)Marshal.ReadInt64(buffer, 16));
                if (linkCount > uint.MaxValue)
                {
                    return false;
                }

                identity = new LocalFileIdentity(device, 0, inode, (uint)linkCount);
            }

            return identity.LinkCount > 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int FStat(int fileDescriptor, IntPtr buffer);
}
