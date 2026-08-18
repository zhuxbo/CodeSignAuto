using SimplySignAuto.App;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class ApplicationEntryRouteTests
{
    [WindowsFact]
    public void Pdf_extension_route_accepts_only_exact_install_and_uninstall_commands()
    {
        const string mediaRoot = @"C:\ProgramData\SimplySignAuto\setup\pdf";

        var install = ApplicationEntryRoute.Parse(
            ["pdf-extension", "install", "--media-root", mediaRoot]);
        var uninstall = ApplicationEntryRoute.Parse(["pdf-extension", "uninstall"]);

        Assert.Equal(ApplicationEntryKind.PdfExtension, install.Kind);
        Assert.Equal(["install", "--media-root", mediaRoot], install.Arguments);
        Assert.False(install.ShowInitially);
        Assert.Equal(ApplicationEntryKind.PdfExtension, uninstall.Kind);
        Assert.Equal(["uninstall"], uninstall.Arguments);
        Assert.False(uninstall.ShowInitially);

        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["pdf-extension"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["pdf-extension", "install", "--media-root", "relative"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["pdf-extension", "uninstall", "extra"]).Kind);
    }
}
