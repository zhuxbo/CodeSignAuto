using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Core.Otp;

namespace SimplySignAuto.Agent.Security;

public interface IOtpStore
{
    string Path { get; }

    Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default);

    Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default);

    Task DeleteAsync(CancellationToken cancellationToken = default) =>
        Task.FromException(new OtpStoreException("otp_delete_failed"));
}

public sealed class OtpStoreException : Exception
{
    public OtpStoreException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed class DpapiOtpStore : IOtpStore
{
    private static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("SimplySignAuto/OtpStore/v1"));
    private readonly string path;

    public DpapiOtpStore()
        : this(System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SimplySignAuto",
            "otp.dat"))
    {
    }

    public DpapiOtpStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("A storage path is required.", nameof(path));
        }

        this.path = System.IO.Path.GetFullPath(path);
    }

    public string Path => path;

    public async Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        EnsureWindows();
        EnsureCertumProfile(profile);

        var plaintext = JsonSerializer.SerializeToUtf8Bytes(new StoredProfile(profile));
        try
        {
            var ciphertext = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                await WriteAtomicallyAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default)
    {
        EnsureWindows();

        try
        {
            EnsureCurrentUserOwnsFile();
        }
        catch (FileNotFoundException)
        {
            throw new OtpStoreException("otp_missing");
        }
        catch (UnauthorizedAccessException)
        {
            throw new OtpStoreException("otp_wrong_user");
        }

        byte[] ciphertext;
        try
        {
            ciphertext = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            throw new OtpStoreException("otp_missing");
        }
        catch (UnauthorizedAccessException)
        {
            throw new OtpStoreException("otp_wrong_user");
        }

        try
        {
            byte[] plaintext;
            try
            {
                plaintext = ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException)
            {
                throw new OtpStoreException("otp_corrupt");
            }

            try
            {
                var stored = JsonSerializer.Deserialize<StoredProfile>(plaintext);
                if (stored is null)
                {
                    throw new OtpStoreException("otp_profile_invalid");
                }

                var profile = new OtpauthProfile(
                    stored.Secret ?? string.Empty,
                    stored.Algorithm ?? string.Empty,
                    stored.Digits,
                    stored.Period,
                    stored.Issuer ?? string.Empty,
                    stored.Account ?? string.Empty);
                EnsureCertumProfile(profile);
                return profile;
            }
            catch (JsonException)
            {
                throw new OtpStoreException("otp_profile_invalid");
            }
            catch (OtpauthException)
            {
                throw new OtpStoreException("otp_profile_invalid");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        EnsureWindows();
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint) ||
                attributes.HasFlag(FileAttributes.Directory))
            {
                throw new OtpStoreException("otp_delete_failed");
            }

            EnsureCurrentUserOwnsFile();
            cancellationToken.ThrowIfCancellationRequested();
            File.Delete(path);
            if (File.Exists(path))
            {
                throw new OtpStoreException("otp_delete_failed");
            }

            return Task.CompletedTask;
        }
        catch (FileNotFoundException)
        {
            return Task.CompletedTask;
        }
        catch (DirectoryNotFoundException)
        {
            return Task.CompletedTask;
        }
        catch (UnauthorizedAccessException)
        {
            throw new OtpStoreException("otp_wrong_user");
        }
        catch (IOException)
        {
            throw new OtpStoreException("otp_delete_failed");
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI storage requires Windows.");
        }
    }

    private static void EnsureCertumProfile(OtpauthProfile profile)
    {
        if (!string.Equals(profile.Algorithm, "SHA256", StringComparison.Ordinal)
            || profile.Digits != 6
            || profile.Period != 30)
        {
            throw new OtpStoreException("otp_profile_invalid");
        }
    }

    private void EnsureCurrentUserOwnsFile()
    {
        var currentUser = GetCurrentUserSid();
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || owner != currentUser)
        {
            throw new OtpStoreException("otp_wrong_user");
        }
    }

    private async Task WriteAtomicallyAsync(byte[] ciphertext, CancellationToken cancellationToken)
    {
        var directory = System.IO.Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
        {
            throw new OtpStoreException("otp_profile_invalid");
        }

        Directory.CreateDirectory(directory);
        var temporaryPath = System.IO.Path.Combine(directory, $".{System.IO.Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = WindowsCurrentUserProtectedFile.CreateNew(temporaryPath))
            {
                await stream.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, path, true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static SecurityIdentifier GetCurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User ?? throw new OtpStoreException("otp_wrong_user");
    }

    private sealed class StoredProfile
    {
        public StoredProfile()
        {
        }

        public StoredProfile(OtpauthProfile profile)
        {
            Secret = profile.Secret;
            Algorithm = profile.Algorithm;
            Digits = profile.Digits;
            Period = profile.Period;
            Issuer = profile.Issuer;
            Account = profile.Account;
        }

        public string? Secret { get; set; }

        public string? Algorithm { get; set; }

        public int Digits { get; set; }

        public int Period { get; set; }

        public string? Issuer { get; set; }

        public string? Account { get; set; }
    }
}

internal static class WindowsCurrentUserProtectedFile
{
    private const uint GenericWrite = 0x40000000;
    private const uint CreationDispositionCreateNew = 1;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;

    public static FileStream CreateNew(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = identity.User ?? throw new OtpStoreException("otp_wrong_user");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentUser);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        var descriptorBytes = security.GetSecurityDescriptorBinaryForm();
        var descriptor = GCHandle.Alloc(descriptorBytes, GCHandleType.Pinned);
        SafeFileHandle handle;
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(),
                InheritHandle = false,
            };
            handle = CreateFileW(
                path,
                GenericWrite,
                0,
                ref attributes,
                CreationDispositionCreateNew,
                FileAttributeNormal | FileFlagOverlapped | FileFlagWriteThrough,
                nint.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException(
                    "Protected OTP file creation failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            descriptor.Free();
        }

        try
        {
            return new FileStream(handle, FileAccess.Write, bufferSize: 4096, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
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
