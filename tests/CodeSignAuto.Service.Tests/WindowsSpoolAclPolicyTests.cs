using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class WindowsSpoolAclPolicyTests
{
    private const string SigningUserSid = "S-1-5-21-1000-2000-3000-4000";
    private const string CreatorOwnerSid = "S-1-3-0";

    [Fact]
    public void Job_directory_grants_delete_only_to_new_child_files_and_input_reprotects_to_read_only()
    {
        var jobRules = WindowsSpoolAclRules.JobDirectory(SigningUserSid)
            .Where(rule => rule.IdentitySid == SigningUserSid)
            .ToArray();

        var parentRule = Assert.Single(jobRules, rule =>
            rule.PropagationFlags == PropagationFlags.None);
        Assert.Equal(
            (FileSystemRights)0,
            parentRule.Rights & FileSystemRights.DeleteSubdirectoriesAndFiles);
        Assert.Equal((FileSystemRights)0, parentRule.Rights & FileSystemRights.Delete);
        Assert.DoesNotContain(jobRules, rule => rule.Rights.HasFlag(FileSystemRights.Delete));
        var newFileDelete = Assert.Single(
            WindowsSpoolAclRules.JobDirectory(SigningUserSid),
            rule => rule.IdentitySid == CreatorOwnerSid && rule.Rights == FileSystemRights.Delete);
        Assert.Equal(InheritanceFlags.ObjectInherit, newFileDelete.InheritanceFlags);
        Assert.Equal(PropagationFlags.InheritOnly, newFileDelete.PropagationFlags);

        var inputSigningRule = Assert.Single(
            WindowsSpoolAclRules.Input(SigningUserSid),
            rule => rule.IdentitySid == SigningUserSid);
        Assert.Equal(FileSystemRights.Read, inputSigningRule.Rights);
        Assert.Equal(InheritanceFlags.None, inputSigningRule.InheritanceFlags);
        Assert.Equal(PropagationFlags.None, inputSigningRule.PropagationFlags);
    }

    [WindowsAdministratorFact]
    public void Manual_user_policy_keeps_the_signing_user_as_spool_owner()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "CodeSignAuto.ManualSpoolAcl.Contract",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var signingUser = WindowsIdentity.GetCurrent().User!;
        try
        {
            WindowsSpoolAclPolicy.ForManualUser(signingUser.Value).ProtectRoot(root);

            var security = new DirectoryInfo(root).GetAccessControl();
            Assert.True(security.AreAccessRulesProtected);
            Assert.Equal(
                signingUser,
                security.GetOwner(typeof(SecurityIdentifier)));
        }
        finally
        {
            Directory.Delete(root);
        }
    }

    [WindowsInteractiveFact]
    public void Windows_signing_user_can_delete_only_the_part_it_created()
    {
        var directory = Environment.GetEnvironmentVariable("SIMPLYSIGN_ACL_ACCEPTANCE_DIRECTORY");
        Assert.False(string.IsNullOrWhiteSpace(directory));
        Assert.True(Path.IsPathFullyQualified(directory));
        var canonical = Path.GetFullPath(directory);
        Assert.Equal(directory, canonical, StringComparer.OrdinalIgnoreCase);
        var item = new DirectoryInfo(canonical);
        Assert.True(item.Exists);
        Assert.False(item.Attributes.HasFlag(FileAttributes.ReparsePoint));
        Assert.True(item.GetAccessControl().AreAccessRulesProtected);

        var sibling = Path.Combine(canonical, "system-sibling.part");
        var ownPart = Path.Combine(canonical, "signing-user.part");
        Assert.True(File.Exists(sibling));
        Assert.False(File.Exists(ownPart));
        var siblingSecurity = new FileInfo(sibling).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        Assert.Equal(localSystem, siblingSecurity.GetOwner(typeof(SecurityIdentifier)));
        var beforeHash = SHA256.HashData(File.ReadAllBytes(sibling));
        var beforeSddl = siblingSecurity.GetSecurityDescriptorSddlForm(
            AccessControlSections.Owner | AccessControlSections.Access);

        File.WriteAllText(ownPart, "signing-user-owned-part", new UTF8Encoding(false, true));
        File.Delete(ownPart);
        Assert.False(File.Exists(ownPart));
        Assert.Throws<UnauthorizedAccessException>(() => File.Delete(sibling));

        Assert.True(File.Exists(sibling));
        Assert.Equal(beforeHash, SHA256.HashData(File.ReadAllBytes(sibling)));
        var afterSecurity = new FileInfo(sibling).GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        Assert.Equal(localSystem, afterSecurity.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(
            beforeSddl,
            afterSecurity.GetSecurityDescriptorSddlForm(
                AccessControlSections.Owner | AccessControlSections.Access));
    }

    private sealed class WindowsInteractiveFactAttribute : FactAttribute
    {
        public WindowsInteractiveFactAttribute()
        {
            if (!OperatingSystem.IsWindows() ||
                !string.Equals(
                    Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_INTERACTIVE_ACL_INTEGRATION"),
                    "1",
                    StringComparison.Ordinal))
            {
                Skip = "Requires the signing-user WTS interactive ACL fixture.";
            }
        }
    }

    private sealed class WindowsAdministratorFactAttribute : FactAttribute
    {
        public WindowsAdministratorFactAttribute()
        {
            if (!OperatingSystem.IsWindows() ||
                !string.Equals(
                    Environment.GetEnvironmentVariable("SIMPLYSIGN_RUN_ADMIN_INTEGRATION"),
                    "1",
                    StringComparison.Ordinal))
            {
                Skip = "Requires an explicitly enabled elevated Windows spool integration run.";
            }
        }
    }
}
