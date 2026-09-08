using System.Security.AccessControl;
using System.Security.Principal;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Service.Jobs;

internal sealed record WindowsSpoolAclRule(
    string IdentitySid,
    FileSystemRights Rights,
    InheritanceFlags InheritanceFlags,
    PropagationFlags PropagationFlags);

internal static class WindowsSpoolAclRules
{
    private const string LocalSystemSid = "S-1-5-18";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const string CreatorOwnerSid = "S-1-3-0";

    public static IReadOnlyList<WindowsSpoolAclRule> Root(string signingUserSid) =>
    [
        Rule(LocalSystemSid, FileSystemRights.FullControl),
        Rule(AdministratorsSid, FileSystemRights.FullControl),
        Rule(signingUserSid, FileSystemRights.ReadAndExecute),
    ];

    public static IReadOnlyList<WindowsSpoolAclRule> JobDirectory(string signingUserSid) =>
    [
        Inheritable(LocalSystemSid, FileSystemRights.FullControl),
        Inheritable(AdministratorsSid, FileSystemRights.FullControl),
        Inheritable(
            signingUserSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.Write | FileSystemRights.Synchronize),
        new WindowsSpoolAclRule(
            CreatorOwnerSid,
            FileSystemRights.Delete,
            InheritanceFlags.ObjectInherit,
            PropagationFlags.InheritOnly),
    ];

    public static IReadOnlyList<WindowsSpoolAclRule> Input(string signingUserSid) =>
    [
        Rule(LocalSystemSid, FileSystemRights.FullControl),
        Rule(AdministratorsSid, FileSystemRights.FullControl),
        Rule(signingUserSid, FileSystemRights.Read),
    ];

    private static WindowsSpoolAclRule Rule(string identitySid, FileSystemRights rights) =>
        new(identitySid, rights, InheritanceFlags.None, PropagationFlags.None);

    private static WindowsSpoolAclRule Inheritable(string identitySid, FileSystemRights rights) =>
        new(
            identitySid,
            rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None);
}

public sealed class WindowsSpoolAclPolicy : ISpoolAclPolicy
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private readonly SecurityIdentifier _owner;
    private readonly SecurityIdentifier _signingUser;

    public WindowsSpoolAclPolicy(string signingUserSid)
        : this(ParseSigningUser(signingUserSid), LocalSystem)
    {
    }

    private WindowsSpoolAclPolicy(
        SecurityIdentifier signingUser,
        SecurityIdentifier owner)
    {
        _signingUser = signingUser;
        _owner = owner;
    }

    public static WindowsSpoolAclPolicy ForManualUser(string signingUserSid)
    {
        var signingUser = ParseSigningUser(signingUserSid);
        return new WindowsSpoolAclPolicy(signingUser, signingUser);
    }

    private static SecurityIdentifier ParseSigningUser(string signingUserSid)
    {
        if (!CanonicalWindowsSid.IsValid(signingUserSid))
        {
            throw new ArgumentException("Signing user SID is invalid.", nameof(signingUserSid));
        }

        return new SecurityIdentifier(signingUserSid);
    }

    public void ProtectRoot(string path) => ProtectDirectory(path, Rules(WindowsSpoolAclRules.Root(_signingUser.Value)));

    public void ProtectJobDirectory(string path) => ProtectDirectory(
        path,
        Rules(WindowsSpoolAclRules.JobDirectory(_signingUser.Value)));

    public void ProtectInput(string path) => ProtectFile(path, Rules(WindowsSpoolAclRules.Input(_signingUser.Value)));

    public void ProtectFinalResult(string path) => ProtectFile(path, Rules(WindowsSpoolAclRules.Input(_signingUser.Value)));

    private static IReadOnlyList<FileSystemAccessRule> Rules(IReadOnlyList<WindowsSpoolAclRule> rules) =>
        rules.Select(rule => new FileSystemAccessRule(
            new SecurityIdentifier(rule.IdentitySid),
            rule.Rights,
            rule.InheritanceFlags,
            rule.PropagationFlags,
            AccessControlType.Allow)).ToArray();

    private void ProtectDirectory(string path, IReadOnlyList<FileSystemAccessRule> expected)
    {
        EnsureWindows();
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(_owner);
            foreach (var rule in expected)
            {
                security.AddAccessRule(rule);
            }

            new DirectoryInfo(path).SetAccessControl(security);
            Verify(new DirectoryInfo(path).GetAccessControl(), expected);
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or InvalidOperationException or
                SystemException)
        {
            throw new SpoolAclException();
        }
    }

    private void ProtectFile(string path, IReadOnlyList<FileSystemAccessRule> expected)
    {
        EnsureWindows();
        try
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(_owner);
            foreach (var rule in expected)
            {
                security.AddAccessRule(rule);
            }

            new FileInfo(path).SetAccessControl(security);
            Verify(new FileInfo(path).GetAccessControl(), expected);
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or InvalidOperationException or
                SystemException)
        {
            throw new SpoolAclException();
        }
    }

    private void Verify(FileSystemSecurity actual, IReadOnlyList<FileSystemAccessRule> expected)
    {
        var owner = actual.GetOwner(typeof(SecurityIdentifier));
        if (!actual.AreAccessRulesProtected || !_owner.Equals(owner))
        {
            throw new SpoolAclException();
        }

        var rules = actual.GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        if (rules.Length != expected.Count || expected.Any(wanted => !rules.Any(actualRule => SameRule(actualRule, wanted))))
        {
            throw new SpoolAclException();
        }
    }

    private static bool SameRule(FileSystemAccessRule left, FileSystemAccessRule right) =>
        left.IdentityReference.Equals(right.IdentityReference) &&
        left.AccessControlType == right.AccessControlType &&
        left.FileSystemRights == right.FileSystemRights &&
        left.InheritanceFlags == right.InheritanceFlags &&
        left.PropagationFlags == right.PropagationFlags &&
        !left.IsInherited;

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new SpoolAclException();
        }
    }
}
