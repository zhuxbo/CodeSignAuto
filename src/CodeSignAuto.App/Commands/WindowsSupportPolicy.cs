using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CodeSignAuto.App.Commands;

internal sealed record WindowsSupportSnapshot(
    byte ProductType,
    uint OperatingSystemSku,
    int BuildNumber,
    string InstallationType,
    bool Is64BitOperatingSystem);

internal static class WindowsSupportPolicy
{
    public static bool IsSupported(WindowsSupportSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!snapshot.Is64BitOperatingSystem)
        {
            return false;
        }

        return snapshot.ProductType switch
        {
            1 => string.Equals(snapshot.InstallationType, "Client", StringComparison.Ordinal) &&
                IsSupportedClient(snapshot.OperatingSystemSku, snapshot.BuildNumber),
            3 => string.Equals(snapshot.InstallationType, "Server", StringComparison.Ordinal) &&
                snapshot.OperatingSystemSku is 7 or 8 &&
                snapshot.BuildNumber is 17763 or 20348 or 26100,
            _ => false,
        };
    }

    public static bool IsCurrentWindowsSupported()
    {
        try
        {
            return IsSupported(WindowsSupportSnapshotReader.Read());
        }
        catch (Exception error) when (
            error is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsSupportedClient(uint sku, int buildNumber) => buildNumber switch
    {
        14393 or 17763 => sku is 125 or 126 or 129 or 130,
        19044 => sku is 125 or 126 or 129 or 130 or 191 or 207,
        19045 => true,
        22631 => sku is 4 or 27 or 72 or 84 or 140 or 141 or 171 or 172 or 175,
        26100 or 26200 or 28000 => sku is
            4 or 27 or 48 or 49 or 72 or 84 or 98 or 99 or 100 or 101 or 121 or 122 or
            125 or 126 or 129 or 130 or 138 or 139 or 140 or 141 or 161 or 162 or 164 or
            165 or 171 or 172 or 175 or 188 or 191 or 202 or 203 or 207,
        _ => false,
    };
}

internal static class WindowsSupportSnapshotReader
{
    private const string CurrentVersionPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    public static WindowsSupportSnapshot Read()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InvalidOperationException("windows_required");
        }

        var version = new OsVersionInfo
        {
            Size = (uint)Marshal.SizeOf<OsVersionInfo>(),
        };
        if (RtlGetVersion(ref version) != 0)
        {
            throw new InvalidOperationException("windows_version_lookup_failed");
        }

        if (!GetProductInfo(
                version.MajorVersion,
                version.MinorVersion,
                version.ServicePackMajor,
                version.ServicePackMinor,
                out var operatingSystemSku))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        using var key = Registry.LocalMachine.OpenSubKey(CurrentVersionPath, writable: false);
        var installationType = key?.GetValue("InstallationType") as string;
        if (string.IsNullOrEmpty(installationType))
        {
            throw new InvalidOperationException("windows_installation_type_lookup_failed");
        }

        return new WindowsSupportSnapshot(
            version.ProductType,
            operatingSystemSku,
            checked((int)version.BuildNumber),
            installationType,
            Environment.Is64BitOperatingSystem);
    }

    [DllImport("ntdll.dll")]
    private static extern int RtlGetVersion(ref OsVersionInfo versionInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProductInfo(
        uint osMajorVersion,
        uint osMinorVersion,
        ushort servicePackMajor,
        ushort servicePackMinor,
        out uint returnedProductType);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OsVersionInfo
    {
        public uint Size;
        public uint MajorVersion;
        public uint MinorVersion;
        public uint BuildNumber;
        public uint PlatformId;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ServicePackVersion;

        public ushort ServicePackMajor;
        public ushort ServicePackMinor;
        public ushort SuiteMask;
        public byte ProductType;
        public byte Reserved;
    }
}
