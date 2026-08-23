using SimplySignAuto.App;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class ApplicationEntryRouteTests
{
    [Theory]
    [InlineData("manual")]
    [InlineData("service")]
    public void Setup_route_accepts_only_one_exact_installation_mode(string mode)
    {
        var route = ApplicationEntryRoute.Parse(["setup", "--mode", mode]);

        Assert.Equal(ApplicationEntryKind.Setup, route.Kind);
        Assert.Equal(["--mode", mode], route.Arguments);
        Assert.False(route.ShowInitially);

        Assert.Equal(ApplicationEntryKind.Invalid, ApplicationEntryRoute.Parse(["setup"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["setup", "--mode", "Manual"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["setup", "--mode", mode, "extra"]).Kind);
    }

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

    [Fact]
    public void Graphical_uninstall_marker_is_accepted_only_for_uninstall_entries()
    {
        var main = ApplicationEntryRoute.Parse(["uninstall", "--ui"]);
        var pdf = ApplicationEntryRoute.Parse(["pdf-extension", "uninstall", "--ui"]);

        Assert.Equal(ApplicationEntryKind.Uninstall, main.Kind);
        Assert.Empty(main.Arguments);
        Assert.True(main.ShowInitially);
        Assert.Equal(ApplicationEntryKind.PdfExtension, pdf.Kind);
        Assert.Equal(["uninstall"], pdf.Arguments);
        Assert.True(pdf.ShowInitially);

        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["uninstall", "--ui", "extra"]).Kind);
        Assert.Equal(
            ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["pdf-extension", "install", "--ui"]).Kind);
    }
}
