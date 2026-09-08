using System.Reflection;
using CodeSignAuto.Core.Versioning;

namespace CodeSignAuto.App;

internal static class ApplicationVersion
{
    public static string ReadIdentity(Assembly assembly) => ReadVersion(assembly).Identity;

    public static string ReadDisplay(Assembly assembly) => ReadVersion(assembly).Display;

    public static string Read(Assembly assembly) => ReadIdentity(assembly);

    private static ProductVersion ReadVersion(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
        return ProductVersion.TryParse(informational, out var version)
            ? version!
            : throw new InvalidOperationException("application_version_invalid");
    }
}
