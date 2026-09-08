using CodeSignAuto.Service;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class ServiceSettingsCompositionTests
{
    [Theory]
    [InlineData("0.2.0", "0.2.0")]
    [InlineData("0.2.0-0.dev.17", "0.2.0-0.dev.17")]
    [InlineData("0.2.0-0.dev.17+build.7", "0.2.0-0.dev.17")]
    public void Service_settings_composition_accepts_one_exact_identity_and_returns_display(
        string identity,
        string expectedDisplay)
    {
        var version = ServiceHost.ComposeProductVersion(
            identity,
            new ProductComponentVersions(identity, identity));

        Assert.Equal(identity, version.Identity);
        Assert.Equal(expectedDisplay, version.Display);
    }

    [Theory]
    [InlineData("0.2.0+service.7", "0.2.0+agent.7", "0.2.0+service.7")]
    [InlineData("0.2.0+service.7", "0.2.0+service.7", "0.2.0+app.7")]
    [InlineData("0.2.0", "0.2.0-rc.1", "0.2.0")]
    [InlineData("0.2.0", "not-semver", "0.2.0")]
    public void Service_settings_composition_fails_closed_on_any_full_identity_mismatch(
        string serviceIdentity,
        string agentIdentity,
        string appIdentity)
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            ServiceHost.ComposeProductVersion(
                serviceIdentity,
                new ProductComponentVersions(agentIdentity, appIdentity)));

        Assert.Equal("product_version_mismatch", error.Message);
    }
}
