using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Core.Otp;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class DpapiOtpStoreTests
{
    [InteractiveWindowsFact]
    public async Task Saves_and_loads_for_current_windows_user()
    {
        var path = CreateStoragePath();
        try
        {
            var store = new DpapiOtpStore(path);
            var profile = CreateProfile();

            await store.SaveAsync(profile);
            var loaded = await store.LoadAsync();

            Assert.Equal("SHA256", loaded.Algorithm);
            Assert.Equal(6, loaded.Digits);
            Assert.Equal(30, loaded.Period);
            Assert.Equal("Certum", loaded.Issuer);
            Assert.Equal("test", loaded.Account);
            Assert.Equal(
                TotpGenerator.Generate(profile, DateTimeOffset.FromUnixTimeSeconds(59)),
                TotpGenerator.Generate(loaded, DateTimeOffset.FromUnixTimeSeconds(59)));
        }
        finally
        {
            DeleteStorageDirectory(path);
        }
    }

    [InteractiveWindowsFact]
    public async Task Reports_corrupt_when_ciphertext_is_tampered()
    {
        var path = CreateStoragePath();
        try
        {
            var store = new DpapiOtpStore(path);
            await store.SaveAsync(CreateProfile());
            var ciphertext = await File.ReadAllBytesAsync(path);
            ciphertext[0] ^= 0x01;
            await File.WriteAllBytesAsync(path, ciphertext);

            var exception = await Assert.ThrowsAsync<OtpStoreException>(() => store.LoadAsync());

            Assert.Equal("otp_corrupt", exception.Code);
        }
        finally
        {
            DeleteStorageDirectory(path);
        }
    }

    [WindowsFact]
    public async Task Reports_missing_for_missing_file()
    {
        var path = CreateStoragePath();

        var exception = await Assert.ThrowsAsync<OtpStoreException>(
            () => new DpapiOtpStore(path).LoadAsync());

        Assert.Equal("otp_missing", exception.Code);
    }

    [InteractiveWindowsFact]
    public async Task Protects_file_acl_for_current_user_and_system_only()
    {
        var path = CreateStoragePath();
        try
        {
            await new DpapiOtpStore(path).SaveAsync(CreateProfile());

            var security = new FileInfo(path).GetAccessControl();
            var owner = Assert.IsType<SecurityIdentifier>(security.GetOwner(typeof(SecurityIdentifier)));
            using var identity = WindowsIdentity.GetCurrent();
            Assert.Equal(identity.User, owner);
            Assert.True(security.AreAccessRulesProtected);

            var allowedSids = security
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == AccessControlType.Allow)
                .Select(rule => Assert.IsType<SecurityIdentifier>(rule.IdentityReference))
                .ToHashSet();
            Assert.True(allowedSids.SetEquals(new[]
            {
                owner,
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            }));
        }
        finally
        {
            DeleteStorageDirectory(path);
        }
    }

    [InteractiveWindowsFact]
    public async Task Delete_removes_only_the_current_user_store_and_is_idempotent_when_absent()
    {
        var path = CreateStoragePath();
        try
        {
            var store = new DpapiOtpStore(path);
            await store.SaveAsync(CreateProfile());
            Assert.True(File.Exists(path));

            await store.DeleteAsync();
            await store.DeleteAsync();

            Assert.False(File.Exists(path));
            var missing = await Assert.ThrowsAsync<OtpStoreException>(() => store.LoadAsync());
            Assert.Equal("otp_missing", missing.Code);
        }
        finally
        {
            DeleteStorageDirectory(path);
        }
    }

    [WindowsFact]
    public void Creates_temporary_file_with_protected_acl_before_writing()
    {
        var path = CreateStoragePath();
        Directory.CreateDirectory(Assert.IsType<string>(System.IO.Path.GetDirectoryName(path)));

        try
        {
            using var stream = WindowsCurrentUserProtectedFile.CreateNew(path);

            var security = new FileInfo(path).GetAccessControl();
            var owner = Assert.IsType<SecurityIdentifier>(security.GetOwner(typeof(SecurityIdentifier)));
            using var identity = WindowsIdentity.GetCurrent();
            Assert.Equal(identity.User, owner);
            Assert.True(security.AreAccessRulesProtected);
            var allowedRules = security
                .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Where(rule => rule.AccessControlType == AccessControlType.Allow)
                .ToArray();
            Assert.Equal(2, allowedRules.Length);
            Assert.All(allowedRules, rule => Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights));
            Assert.Contains(allowedRules, rule => rule.IdentityReference.Equals(owner));
            Assert.Contains(
                allowedRules,
                rule => rule.IdentityReference.Equals(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));
        }
        finally
        {
            DeleteStorageDirectory(path);
        }
    }

    [NonWindowsFact]
    public async Task Does_not_create_a_non_windows_encryption_fallback()
    {
        var store = new DpapiOtpStore(CreateStoragePath());

        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => store.SaveAsync(CreateProfile()));
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => store.LoadAsync());
    }

    private static OtpauthProfile CreateProfile() =>
        OtpauthProfile.Parse("otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30");

    private static string CreateStoragePath() =>
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"), "otp.dat");

    private static void DeleteStorageDirectory(string storagePath)
    {
        var directory = System.IO.Path.GetDirectoryName(storagePath);
        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

}

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows.";
        }
    }
}

public sealed class NonWindowsFactAttribute : FactAttribute
{
    public NonWindowsFactAttribute()
    {
        if (OperatingSystem.IsWindows())
        {
            Skip = "Non-Windows fallback assertion does not apply on Windows.";
        }
    }
}

public sealed class InteractiveWindowsFactAttribute : FactAttribute
{
    public InteractiveWindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows.";
        }
        else
        {
            using var process = Process.GetCurrentProcess();
            if (process.SessionId == 0)
            {
                Skip = "Requires an interactive Windows logon session for CurrentUser DPAPI.";
            }
        }
    }
}
