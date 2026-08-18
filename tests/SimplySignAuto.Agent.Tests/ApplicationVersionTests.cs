using System.Reflection;
using System.Reflection.Emit;
using SimplySignAuto.App;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class ApplicationVersionTests
{
    [Fact]
    public void Reads_canonical_identity_and_display_from_informational_semver()
    {
        const string semver = "1.2.3-rc.1+build.7";
        var assembly = CreateAssembly(semver);

        Assert.Equal(semver, ApplicationVersion.ReadIdentity(assembly));
        Assert.Equal("1.2.3-rc.1", ApplicationVersion.ReadDisplay(assembly));
    }

    [Fact]
    public void Reads_stable_display_with_exactly_three_numeric_parts()
    {
        var assembly = CreateAssembly("2.4.6+build.9");

        Assert.Equal("2.4.6", ApplicationVersion.ReadDisplay(assembly));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("release-candidate")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3-alpha.01")]
    [InlineData("1.2.3-α")]
    public void Rejects_missing_or_invalid_informational_version_with_stable_error(string? informationalVersion)
    {
        var assembly = CreateAssembly(informationalVersion);

        var identityError = Assert.Throws<InvalidOperationException>(
            () => ApplicationVersion.ReadIdentity(assembly));
        var displayError = Assert.Throws<InvalidOperationException>(
            () => ApplicationVersion.ReadDisplay(assembly));

        Assert.Equal("application_version_invalid", identityError.Message);
        Assert.Equal("application_version_invalid", displayError.Message);
    }

    private static AssemblyBuilder CreateAssembly(string? informationalVersion)
    {
        var assembly = AssemblyBuilder.DefineDynamicAssembly(
            new AssemblyName($"SimplySignAuto.VersionFixture.{Guid.NewGuid():N}")
            {
                Version = new Version(9, 8, 7, 6),
            },
            AssemblyBuilderAccess.Run);
        if (informationalVersion is not null)
        {
            var constructor = typeof(AssemblyInformationalVersionAttribute).GetConstructor([typeof(string)]);
            assembly.SetCustomAttribute(new CustomAttributeBuilder(constructor!, [informationalVersion]));
        }

        return assembly;
    }
}
