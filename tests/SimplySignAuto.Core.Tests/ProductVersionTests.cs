using SimplySignAuto.Core.Versioning;
using Xunit;

namespace SimplySignAuto.Core.Tests;

public sealed class ProductVersionTests
{
    [Theory]
    [InlineData("0.2.0", "0.2.0")]
    [InlineData("0.2.0-0.dev.17", "0.2.0-0.dev.17")]
    [InlineData("1.2.3-rc.1+build.7", "1.2.3-rc.1")]
    [InlineData("999999999999999999999999999999.2.3+001.sha-abc", "999999999999999999999999999999.2.3")]
    public void Parse_preserves_canonical_identity_and_omits_build_metadata_from_display(
        string identity,
        string display)
    {
        var version = ProductVersion.Parse(identity);

        Assert.Equal(identity, version.Identity);
        Assert.Equal(display, version.Display);
        Assert.Equal(identity, ProductVersion.Parse(version.Identity).Identity);
    }

    [Theory]
    [InlineData("0.2.0-0.dev.17", "0.2.0-alpha.1")]
    [InlineData("0.2.0-alpha.1", "0.2.0-beta.1")]
    [InlineData("0.2.0-beta.1", "0.2.0-rc.1")]
    [InlineData("0.2.0-rc.1", "0.2.0")]
    [InlineData("1.0.0-999999999999999999999999999999", "1.0.0-1000000000000000000000000000000")]
    [InlineData("1.0.0-1", "1.0.0-alpha")]
    [InlineData("1.0.0-Alpha", "1.0.0-alpha")]
    [InlineData("1.0.0-alpha", "1.0.0-alpha.1")]
    [InlineData("999999999999999999999999999999.0.0", "1000000000000000000000000000000.0.0")]
    public void ComparePrecedenceTo_uses_standard_semver_identifier_rules(string lower, string higher)
    {
        var lowerVersion = ProductVersion.Parse(lower);
        var higherVersion = ProductVersion.Parse(higher);

        Assert.True(lowerVersion.ComparePrecedenceTo(higherVersion) < 0);
        Assert.True(higherVersion.ComparePrecedenceTo(lowerVersion) > 0);
        Assert.True(lowerVersion.CompareTo(higherVersion) < 0);
    }

    [Theory]
    [InlineData("1.2.3+build.1", "1.2.3+build.2")]
    [InlineData("1.2.3-alpha+linux", "1.2.3-alpha+windows")]
    public void ComparePrecedenceTo_ignores_build_metadata(string left, string right)
    {
        Assert.Equal(
            0,
            ProductVersion.Parse(left).ComparePrecedenceTo(ProductVersion.Parse(right)));
    }

    [Theory]
    [InlineData("0.0.0")]
    [InlineData("1.2.3-alpha-1.0+build.01")]
    [InlineData("184467440737095516160.340282366920938463463374607431768211456.0")]
    public void TryParse_returns_the_parsed_version_for_valid_input(string input)
    {
        var parsed = ProductVersion.TryParse(input, out var version);

        Assert.True(parsed);
        Assert.NotNull(version);
        Assert.Equal(input, version.Identity);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("1")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("01.2.3")]
    [InlineData("1.02.3")]
    [InlineData("1.2.03")]
    [InlineData("1.2.3-")]
    [InlineData("1.2.3-alpha..1")]
    [InlineData("1.2.3-01")]
    [InlineData("1.2.3-alpha.01")]
    [InlineData("1.2.3+")]
    [InlineData("1.2.3+build..1")]
    [InlineData("1.2.3-alpha_beta")]
    [InlineData("1.2.3-alpha beta")]
    [InlineData("1.2.3-α")]
    [InlineData("1.2.3+构建")]
    [InlineData("١.2.3")]
    [InlineData("1.2.3\n")]
    public void TryParse_rejects_non_semver_input(string? input)
    {
        Assert.False(ProductVersion.TryParse(input, out var version));
        Assert.Null(version);
    }

    [Fact]
    public void Parse_rejects_invalid_input()
    {
        Assert.Throws<FormatException>(() => ProductVersion.Parse("1.2.3-alpha.01"));
        Assert.Throws<ArgumentNullException>(() => ProductVersion.Parse(null!));
    }

    [Fact]
    public void CompareTo_treats_null_as_lower_than_a_product_version()
    {
        Assert.True(ProductVersion.Parse("1.0.0").CompareTo(null) > 0);
    }
}
