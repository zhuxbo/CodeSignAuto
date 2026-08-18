using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SimplySignAuto.App.Commands;

internal interface IAtomicProtectedDirectoryOperations
{
    void VerifyTrustedAnchor(string path);

    bool EntryExistsNoFollow(string path);

    void CreateNewWithSecurity(string path);

    void VerifyCreated(string path);
}

internal sealed class AtomicProtectedDirectoryCreator(
    IAtomicProtectedDirectoryOperations operations)
{
    public void Create(string trustedAnchor, string path)
    {
        var created = false;
        try
        {
            if (!IsDirectChild(trustedAnchor, path))
            {
                throw new InstallException("uninstall_path_invalid");
            }

            operations.VerifyTrustedAnchor(trustedAnchor);
            if (operations.EntryExistsNoFollow(path))
            {
                throw new InstallException("uninstall_path_invalid");
            }

            operations.CreateNewWithSecurity(path);
            created = true;
            operations.VerifyCreated(path);
        }
        catch when (created)
        {
            throw new InstallException("uninstall_state_uncertain");
        }
        catch (InstallException error) when (error.Code == "uninstall_path_invalid")
        {
            throw;
        }
        catch
        {
            throw new InstallException("uninstall_path_invalid");
        }
    }

    private static bool IsDirectChild(string parent, string child)
    {
        var normalizedParent = parent.TrimEnd('\\', '/');
        if (child.Length <= normalizedParent.Length + 1 ||
            !child.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase) ||
            child[normalizedParent.Length] is not ('\\' or '/'))
        {
            return false;
        }

        return child[(normalizedParent.Length + 1)..].IndexOfAny(['\\', '/']) < 0;
    }
}

internal sealed class WindowsAtomicProtectedDirectoryOperations : IAtomicProtectedDirectoryOperations
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public void VerifyTrustedAnchor(string path)
    {
        EnsureWindows();
        EnsureCanonical(path);
        var security = WindowsNoFollowSecurity.ReadDirectory(path);
        WindowsNoFollowSecurity.VerifyTrustedAnchor(security);
    }

    public bool EntryExistsNoFollow(string path)
    {
        EnsureWindows();
        EnsureCanonical(path);
        return WindowsNoFollowSecurity.DirectoryEntryExists(path);
    }

    public void CreateNewWithSecurity(string path)
    {
        EnsureWindows();
        EnsureCanonical(path);
        var parent = Path.GetDirectoryName(path) ?? throw new InstallException("uninstall_path_invalid");
        if (!string.Equals(
                Path.GetFullPath(parent),
                parent,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var binary = WindowsInstallAcl
            .CreateDirectorySecurity(InstallAclProfile.AdministratorsOnly, LocalSystem)
            .GetSecurityDescriptorBinaryForm();
        WindowsNativeProtectedObject.CreateDirectory(path, binary);
    }

    public void VerifyCreated(string path)
    {
        EnsureWindows();
        EnsureCanonical(path);
        var security = WindowsNoFollowSecurity.ReadDirectory(path);
        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(security, directory: true);
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }
    }

    private static void EnsureCanonical(string path)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
        {
            throw new InstallException("uninstall_path_invalid");
        }
    }
}

internal static class WindowsAtomicProtectedFile
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public static async Task WriteNewAsync(
        string path,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InstallException("windows_required");
        }

        var binary = WindowsInstallAcl
            .CreateFileSecurity(InstallAclProfile.AdministratorsOnly, LocalSystem)
            .GetSecurityDescriptorBinaryForm();
        var created = false;
        try
        {
            await using (var stream = new FileStream(
                WindowsNativeProtectedObject.CreateFile(path, binary),
                FileAccess.Write,
                4096,
                isAsync: true))
            {
                created = true;
                await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            var security = WindowsNoFollowSecurity.ReadFile(path);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(security, directory: false);
        }
        catch
        {
            if (created)
            {
                try
                {
                    var security = WindowsNoFollowSecurity.ReadFile(path);
                    WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(security, directory: false);
                    File.Delete(path);
                }
                catch
                {
                    throw new InstallException("uninstall_state_uncertain");
                }
            }

            throw;
        }
    }

}

internal static class WindowsNativeProtectedObject
{
    private const uint GenericWrite = 0x40000000;
    private const uint CreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;

    public static void CreateDirectory(string path, byte[] securityDescriptor)
    {
        var descriptor = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(),
                InheritHandle = false,
            };
            if (!CreateDirectoryW(path, ref attributes))
            {
                throw new IOException(
                    "Atomic protected directory creation failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            descriptor.Free();
        }
    }

    public static SafeFileHandle CreateFile(string path, byte[] securityDescriptor)
    {
        var descriptor = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(),
                InheritHandle = false,
            };
            var handle = CreateFileW(
                path,
                GenericWrite,
                0,
                ref attributes,
                CreateNew,
                FileAttributeNormal | FileFlagOverlapped | FileFlagWriteThrough,
                nint.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException(
                    "Atomic protected file creation failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            return handle;
        }
        finally
        {
            descriptor.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path,
        uint desiredAccess,
        uint shareMode,
        ref SecurityAttributes securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);
}

internal sealed record WindowsNoFollowSecuritySnapshot(
    FileAttributes Attributes,
    RawSecurityDescriptor Security);

internal sealed record WindowsTrustedAnchorRuleSnapshot(
    string Identity,
    int AccessMask,
    bool IsAllow,
    bool AppliesToAnchor);

internal static class WindowsTrustedAnchorAcl
{
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    private static readonly HashSet<string> TrustedIdentities = new(StringComparer.Ordinal)
    {
        LocalSystemSid,
        AdministratorsSid,
        TrustedInstallerSid,
    };

    public static void Verify(
        string? ownerIdentity,
        IReadOnlyList<WindowsTrustedAnchorRuleSnapshot> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (ownerIdentity is null || !TrustedIdentities.Contains(ownerIdentity))
        {
            throw new InstallException("uninstall_path_invalid");
        }

        const int dangerous = (int)(
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership);
        foreach (var rule in rules)
        {
            if (!rule.IsAllow ||
                !rule.AppliesToAnchor ||
                (rule.AccessMask & dangerous) == 0)
            {
                continue;
            }

            if (!TrustedIdentities.Contains(rule.Identity))
            {
                throw new InstallException("uninstall_path_invalid");
            }
        }
    }
}

internal static class WindowsNoFollowSecurity
{
    private const uint GenericRead = 0x80000000;
    private const uint Delete = 0x00010000;
    private const uint ReadControl = 0x00020000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint ShareReadWriteDelete = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int FileAttributeTagInfoClass = 9;
    private const uint SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SddlRevision1 = 1;
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";

    public static bool DirectoryEntryExists(string path)
    {
        using var handle = Open(path, directory: true, throwIfMissing: false);
        return handle is not null;
    }

    public static WindowsNoFollowSecuritySnapshot ReadDirectory(string path) =>
        Read(path, directory: true);

    public static WindowsNoFollowSecuritySnapshot ReadFile(string path) =>
        Read(path, directory: false);

    internal static SafeFileHandle OpenDirectoryHandle(string path) =>
        Open(path, directory: true, throwIfMissing: true, shareDelete: false)!;

    internal static SafeFileHandle OpenReadFileHandle(string path) =>
        Open(path, directory: false, throwIfMissing: true, GenericRead)!;

    internal static SafeFileHandle OpenReadFileHandleExclusive(string path) =>
        Open(path, directory: false, throwIfMissing: true, GenericRead, shareWrite: false, shareDelete: false)!;

    internal static SafeFileHandle OpenRenameSourceHandle(string path) =>
        Open(path, directory: false, throwIfMissing: true, GenericRead | Delete, shareWrite: false, shareDelete: false)!;

    internal static ProtectedConfigurationIdentity ReadIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var index = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        return new ProtectedConfigurationIdentity($"{information.VolumeSerialNumber:x8}:{index:x16}");
    }

    public static void VerifyTrustedAnchor(WindowsNoFollowSecuritySnapshot snapshot)
    {
        VerifyNotReparse(snapshot);
        if (snapshot.Security.DiscretionaryAcl is not { } dacl)
        {
            throw new InstallException("uninstall_path_invalid");
        }

        var rules = new List<WindowsTrustedAnchorRuleSnapshot>(dacl.Count);
        foreach (GenericAce ace in dacl)
        {
            if (ace is not QualifiedAce qualified)
            {
                continue;
            }

            rules.Add(new WindowsTrustedAnchorRuleSnapshot(
                qualified.SecurityIdentifier.Value,
                qualified.AccessMask,
                qualified.AceQualifier == AceQualifier.AccessAllowed,
                !qualified.AceFlags.HasFlag(AceFlags.InheritOnly)));
        }

        WindowsTrustedAnchorAcl.Verify(snapshot.Security.Owner?.Value, rules);
    }

    public static void VerifyExactAdministratorsOnly(
        WindowsNoFollowSecuritySnapshot snapshot,
        bool directory)
    {
        VerifyNotReparse(snapshot);
        var dacl = snapshot.Security.DiscretionaryAcl;
        if (snapshot.Security.Owner?.Value != AdministratorsSid ||
            !snapshot.Security.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            dacl is not { Count: 2 })
        {
            throw new InstallException("acl_verification_failed");
        }

        var expectedFlags = directory
            ? AceFlags.ContainerInherit | AceFlags.ObjectInherit
            : AceFlags.None;
        var expectedMask = (int)FileSystemRights.FullControl;
        var expectedSids = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystemSid,
            AdministratorsSid,
        };
        foreach (GenericAce ace in dacl)
        {
            if (ace is not CommonAce common ||
                common.AceQualifier != AceQualifier.AccessAllowed ||
                common.AceFlags != expectedFlags ||
                common.AccessMask != expectedMask ||
                !expectedSids.Remove(common.SecurityIdentifier.Value))
            {
                throw new InstallException("acl_verification_failed");
            }
        }

        if (expectedSids.Count != 0)
        {
            throw new InstallException("acl_verification_failed");
        }
    }

    private static WindowsNoFollowSecuritySnapshot Read(string path, bool directory)
    {
        using var handle = Open(path, directory, throwIfMissing: true)!;
        return Read(handle);
    }

    internal static WindowsNoFollowSecuritySnapshot Read(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfoClass,
                out var tagInfo,
                (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        var status = GetSecurityInfo(
            handle,
            SeFileObject,
            OwnerSecurityInformation | DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var securityDescriptor);
        if (status != 0)
        {
            throw new Win32Exception((int)status);
        }

        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    securityDescriptor,
                    SddlRevision1,
                    OwnerSecurityInformation | DaclSecurityInformation,
                    out var sddlPointer,
                    out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                var sddl = Marshal.PtrToStringUni(sddlPointer) ?? throw new InvalidOperationException();
                return new WindowsNoFollowSecuritySnapshot(
                    (FileAttributes)tagInfo.FileAttributes,
                    new RawSecurityDescriptor(sddl));
            }
            finally
            {
                _ = LocalFree(sddlPointer);
            }
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    private static SafeFileHandle? Open(
        string path,
        bool directory,
        bool throwIfMissing,
        uint additionalAccess = 0,
        bool shareWrite = true,
        bool shareDelete = true)
    {
        var flags = FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0);
        var handle = CreateFileW(
            path,
            ReadControl | FileReadAttributes | additionalAccess,
            0x00000001 | (shareWrite ? 0x00000002u : 0) | (shareDelete ? 0x00000004u : 0),
            nint.Zero,
            OpenExisting,
            flags,
            nint.Zero);
        if (!handle.IsInvalid)
        {
            return handle;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (!throwIfMissing && error is 2 or 3)
        {
            return null;
        }

        throw new Win32Exception(error);
    }

    private static void VerifyNotReparse(WindowsNoFollowSecuritySnapshot snapshot)
    {
        if ((snapshot.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InstallException("uninstall_path_invalid");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle,
        int informationClass,
        out FileAttributeTagInfo information,
        uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint securityInformation,
        out nint owner,
        out nint group,
        out nint dacl,
        out nint sacl,
        out nint securityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        nint securityDescriptor,
        uint requestedStringSdRevision,
        uint securityInformation,
        out nint stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength);

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint memory);
}
