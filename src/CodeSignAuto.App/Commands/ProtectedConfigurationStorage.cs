using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Text;

namespace CodeSignAuto.App.Commands;

internal readonly record struct ProtectedConfigurationIdentity(string Value);

public sealed record ConfigureServiceRevision
{
    public ConfigureServiceRevision(string identity, string contentSha256)
    {
        if (identity is not { Length: > 0 and <= 128 } ||
            identity.Any(char.IsControl) ||
            contentSha256 is not { Length: 64 } ||
            contentSha256.Any(static value => value is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException("The protected configuration revision is invalid.");
        }

        Identity = identity;
        ContentSha256 = contentSha256;
    }

    public string Identity { get; }
    public string ContentSha256 { get; }
}

internal sealed record ProtectedConfigurationSnapshot(
    byte[] Content,
    ConfigureServiceRevision Revision);

internal interface IProtectedConfigurationDirectory : IDisposable
{
    ProtectedConfigurationIdentity Identity { get; }
}

internal interface IProtectedConfigurationFile : IDisposable
{
    ProtectedConfigurationIdentity Identity { get; }
}

internal interface IProtectedConfigurationOperations
{
    IProtectedConfigurationDirectory OpenProtectedParent(string path);

    IProtectedConfigurationFile OpenNoFollowConfiguration(
        IProtectedConfigurationDirectory parent,
        string fileName);

    Task<byte[]> ReadAllAsync(
        IProtectedConfigurationFile file,
        CancellationToken cancellationToken);

    Task<ConfigureServiceRevision> ReplaceVerifiedAsync(
        IProtectedConfigurationDirectory parent,
        string fileName,
        ConfigureServiceRevision expected,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken);
}

internal sealed class ProtectedConfigurationStorage(IProtectedConfigurationOperations operations)
{
    private const int MaximumConfigurationBytes = 1024 * 1024;

    public async Task<ProtectedConfigurationSnapshot> ReadSnapshotAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var (directory, fileName) = Split(path);
        try
        {
            using var parent = operations.OpenProtectedParent(directory);
            using var target = operations.OpenNoFollowConfiguration(parent, fileName);
            var content = await operations.ReadAllAsync(target, cancellationToken).ConfigureAwait(false);
            if (content.Length is 0 or > MaximumConfigurationBytes)
            {
                CryptographicOperations.ZeroMemory(content);
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            return new ProtectedConfigurationSnapshot(content, CreateRevision(target.Identity, content));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ConfigureServiceException)
        {
            throw;
        }
        catch
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }
    }

    public async Task<ConfigureServiceRevision> ReplaceAsync(
        string path,
        ConfigureServiceRevision expected,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (content.Length is 0 or > MaximumConfigurationBytes)
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        var (directory, fileName) = Split(path);
        try
        {
            using var parent = operations.OpenProtectedParent(directory);
            var replacement = await operations.ReplaceVerifiedAsync(
                parent,
                fileName,
                expected,
                content,
                cancellationToken).ConfigureAwait(false);
            var intendedHash = Hash(content.Span);
            if (!string.Equals(replacement.ContentSha256, intendedHash, StringComparison.Ordinal))
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            return replacement;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ConfigureServiceException)
        {
            throw;
        }
        catch
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }
    }

    private static ConfigureServiceRevision CreateRevision(
        ProtectedConfigurationIdentity identity,
        ReadOnlySpan<byte> content) =>
        new(identity.Value, Hash(content));

    private static string Hash(ReadOnlySpan<byte> content)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(content, hash);
        try
        {
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static (string Directory, string FileName) Split(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        var directory = Path.GetDirectoryName(path);
        var fileName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(directory) ||
            string.IsNullOrWhiteSpace(fileName) ||
            fileName.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0)
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        return (directory, fileName);
    }
}

internal sealed class WindowsProtectedConfigurationOperations(Action? beforeHandlePublish = null) :
    IProtectedConfigurationOperations
{
    public IProtectedConfigurationDirectory OpenProtectedParent(string path)
    {
        var handle = WindowsNoFollowSecurity.OpenDirectoryHandle(path);
        try
        {
            var security = WindowsNoFollowSecurity.Read(handle);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(security, directory: true);
            return new DirectoryLease(path, handle, WindowsNoFollowSecurity.ReadIdentity(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public IProtectedConfigurationFile OpenNoFollowConfiguration(
        IProtectedConfigurationDirectory parent,
        string fileName)
    {
        var directory = RequireDirectory(parent);
        VerifyParent(directory);
        var handle = WindowsNoFollowSecurity.OpenReadFileHandle(Path.Combine(directory.Path, fileName));
        try
        {
            var security = WindowsNoFollowSecurity.Read(handle);
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(security, directory: false);
            return new FileLease(handle, WindowsNoFollowSecurity.ReadIdentity(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public async Task<byte[]> ReadAllAsync(
        IProtectedConfigurationFile file,
        CancellationToken cancellationToken)
    {
        var target = RequireFile(file);
        var length = RandomAccess.GetLength(target.Handle);
        if (length is <= 0 or > 1024 * 1024)
        {
            throw new IOException("Protected configuration size is invalid.");
        }

        var content = GC.AllocateUninitializedArray<byte>((int)length);
        var offset = 0;
        while (offset < content.Length)
        {
            var read = await RandomAccess.ReadAsync(
                target.Handle,
                content.AsMemory(offset),
                offset,
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                CryptographicOperations.ZeroMemory(content);
                throw new EndOfStreamException();
            }

            offset += read;
        }

        return content;
    }

    public async Task<ConfigureServiceRevision> ReplaceVerifiedAsync(
        IProtectedConfigurationDirectory parent,
        string fileName,
        ConfigureServiceRevision expected,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        var directory = RequireDirectory(parent);
        VerifyParent(directory);
        var targetPath = Path.Combine(directory.Path, fileName);
        var temporary = Path.Combine(directory.Path, $".{fileName}.{Guid.NewGuid():N}.tmp");
        var published = false;
        try
        {
            await VerifyCurrentAsync(directory, fileName, expected, cancellationToken).ConfigureAwait(false);
            await WindowsAtomicProtectedFile.WriteNewAsync(
                temporary,
                content,
                cancellationToken).ConfigureAwait(false);
            var temporaryRevision = await ReadRevisionAsync(directory, Path.GetFileName(temporary), cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    temporaryRevision.ContentSha256,
                    Hash(content.Span),
                    StringComparison.Ordinal))
            {
                throw new ConfigureServiceException("configure_service_state_uncertain");
            }

            VerifyParent(directory);
            using (var targetGuard = OpenExclusiveConfiguration(directory, fileName))
            using (var temporaryGuard = OpenRenameSource(directory, Path.GetFileName(temporary)))
            {
                var prePublishTarget = await ReadRevisionAsync(targetGuard, cancellationToken).ConfigureAwait(false);
                var prePublishTemporary = await ReadRevisionAsync(temporaryGuard, cancellationToken).ConfigureAwait(false);
                if (prePublishTarget != expected || prePublishTemporary != temporaryRevision)
                {
                    throw new ConfigureServiceException("configure_service_state_uncertain");
                }

                beforeHandlePublish?.Invoke();
                cancellationToken.ThrowIfCancellationRequested();
                VerifyParent(directory);
                // Windows cannot replace the exact target while its old handle denies delete sharing.
                // The exclusive source handle guards the replacement through both readbacks.
                targetGuard.Dispose();
                WindowsHandleBoundFile.ReplaceByHandle(temporaryGuard.Handle, targetPath);
                published = true;

                var handleReplacement = await ReadRevisionAsync(temporaryGuard, cancellationToken).ConfigureAwait(false);
                if (handleReplacement != temporaryRevision)
                {
                    throw new ConfigureServiceException("configure_service_state_uncertain");
                }

                VerifyParent(directory);
                var pathReplacement = await ReadRevisionAsync(directory, fileName, cancellationToken).ConfigureAwait(false);
                if (pathReplacement != temporaryRevision)
                {
                    throw new ConfigureServiceException("configure_service_state_uncertain");
                }
            }

            return temporaryRevision;
        }
        catch when (published)
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }
        finally
        {
            if (!published && File.Exists(temporary) && !WindowsPathSafety.IsReparse(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private async Task VerifyCurrentAsync(
        DirectoryLease directory,
        string fileName,
        ConfigureServiceRevision expected,
        CancellationToken cancellationToken)
    {
        if (await ReadRevisionAsync(directory, fileName, cancellationToken).ConfigureAwait(false) != expected)
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }
    }

    private async Task<ConfigureServiceRevision> ReadRevisionAsync(
        DirectoryLease directory,
        string fileName,
        CancellationToken cancellationToken)
    {
        using var file = OpenNoFollowConfiguration(directory, fileName);
        return await ReadRevisionAsync(RequireFile(file), cancellationToken).ConfigureAwait(false);
    }

    private async Task<ConfigureServiceRevision> ReadRevisionAsync(
        FileLease file,
        CancellationToken cancellationToken)
    {
        var content = await ReadAllAsync(file, cancellationToken).ConfigureAwait(false);
        try
        {
            return new ConfigureServiceRevision(file.Identity.Value, Hash(content));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    private FileLease OpenExclusiveConfiguration(DirectoryLease directory, string fileName)
    {
        VerifyParent(directory);
        var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(
            Path.Combine(directory.Path, fileName));
        try
        {
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.Read(handle),
                directory: false);
            return new FileLease(handle, WindowsNoFollowSecurity.ReadIdentity(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private FileLease OpenRenameSource(DirectoryLease directory, string fileName)
    {
        VerifyParent(directory);
        var handle = WindowsNoFollowSecurity.OpenRenameSourceHandle(
            Path.Combine(directory.Path, fileName));
        try
        {
            WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
                WindowsNoFollowSecurity.Read(handle),
                directory: false);
            return new FileLease(handle, WindowsNoFollowSecurity.ReadIdentity(handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static string Hash(ReadOnlySpan<byte> content)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(content, hash);
        try
        {
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static DirectoryLease RequireDirectory(IProtectedConfigurationDirectory parent) =>
        parent as DirectoryLease ?? throw new ConfigureServiceException("configure_service_state_uncertain");

    private static FileLease RequireFile(IProtectedConfigurationFile file) =>
        file as FileLease ?? throw new ConfigureServiceException("configure_service_state_uncertain");

    private static void VerifyParent(DirectoryLease directory)
    {
        if (directory.Identity != WindowsNoFollowSecurity.ReadIdentity(directory.Handle))
        {
            throw new ConfigureServiceException("configure_service_state_uncertain");
        }

        WindowsNoFollowSecurity.VerifyExactAdministratorsOnly(
            WindowsNoFollowSecurity.Read(directory.Handle),
            directory: true);
    }

    private sealed class DirectoryLease(
        string path,
        SafeFileHandle handle,
        ProtectedConfigurationIdentity identity) : IProtectedConfigurationDirectory
    {
        public string Path { get; } = path;
        public SafeFileHandle Handle { get; } = handle;
        public ProtectedConfigurationIdentity Identity { get; } = identity;
        public void Dispose() => Handle.Dispose();
    }

    private sealed class FileLease(
        SafeFileHandle handle,
        ProtectedConfigurationIdentity identity) : IProtectedConfigurationFile
    {
        public SafeFileHandle Handle { get; } = handle;
        public ProtectedConfigurationIdentity Identity { get; } = identity;
        public void Dispose() => Handle.Dispose();
    }
}

internal static class WindowsHandleBoundFile
{
    private const int FileDispositionInfo = 4;
    private const int FileRenameInfoEx = 22;
    private const uint FileRenameFlagReplaceIfExists = 0x00000001;
    private const uint FileRenameFlagPosixSemantics = 0x00000002;
    private const uint FileRenameFlagIgnoreReadonlyAttribute = 0x00000040;

    public static void ReplaceByHandle(SafeFileHandle source, string targetPath)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException();
        }

        var information = CreateRenameInformation(targetPath);
        var buffer = Marshal.AllocHGlobal(information.Length);
        try
        {
            Marshal.Copy(information, 0, buffer, information.Length);
            if (!SetFileInformationByHandle(source, FileRenameInfoEx, buffer, (uint)information.Length))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void DeleteByHandle(SafeFileHandle source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException();
        }

        var buffer = Marshal.AllocHGlobal(1);
        try
        {
            Marshal.WriteByte(buffer, 1);
            if (!SetFileInformationByHandle(source, FileDispositionInfo, buffer, 1))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static byte[] CreateRenameInformation(string targetPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetPath);
        var fileName = Encoding.Unicode.GetBytes(Path.GetFullPath(targetPath));
        var fileNameLengthOffset = Marshal.OffsetOf<FileRenameInformation>(
            nameof(FileRenameInformation.FileNameLength)).ToInt32();
        var fileNameOffset = Marshal.OffsetOf<FileRenameInformation>(
            nameof(FileRenameInformation.FileName)).ToInt32();
        var bufferSize = checked(Marshal.SizeOf<FileRenameInformation>() + fileName.Length);
        var information = new byte[bufferSize];
        BinaryPrimitives.WriteUInt32LittleEndian(
            information,
            FileRenameFlagReplaceIfExists |
                FileRenameFlagPosixSemantics |
                FileRenameFlagIgnoreReadonlyAttribute);
        BinaryPrimitives.WriteInt32LittleEndian(
            information.AsSpan(fileNameLengthOffset, sizeof(int)),
            fileName.Length);
        fileName.CopyTo(information.AsSpan(fileNameOffset));
        return information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileRenameInformation
    {
        public uint Flags;
        public nint RootDirectory;
        public uint FileNameLength;
        public ushort FileName;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        nint fileInformation,
        uint bufferSize);
}
