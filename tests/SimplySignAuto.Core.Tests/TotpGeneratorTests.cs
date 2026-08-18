using System.Text;
using SimplySignAuto.Core.Otp;
using Xunit;

namespace SimplySignAuto.Core.Tests;

public sealed class TotpGeneratorTests
{
    [Theory]
    [InlineData(59L, "46119246")]
    [InlineData(1_111_111_109L, "68084774")]
    [InlineData(1_111_111_111L, "67062674")]
    [InlineData(1_234_567_890L, "91819424")]
    [InlineData(2_000_000_000L, "90698825")]
    [InlineData(20_000_000_000L, "77737706")]
    public void Matches_rfc6238_sha256_vectors(long unixSeconds, string expected)
    {
        var secret = Base32.Encode(Encoding.ASCII.GetBytes("12345678901234567890123456789012"));
        var profile = new OtpauthProfile(secret, "SHA256", 8, 30, "Certum", "test");

        Assert.Equal(expected, TotpGenerator.Generate(profile, DateTimeOffset.FromUnixTimeSeconds(unixSeconds)));
    }

    [Fact]
    public void Matches_certum_sha256_six_digit_profile()
    {
        var profile = OtpauthProfile.Parse("otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30");

        Assert.Equal("326456", TotpGenerator.Generate(profile, DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Fact]
    public void Parses_valid_base32_secret_with_four_padding_characters()
    {
        const string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";

        var profile = OtpauthProfile.Parse(
            $"otpauth://totp/Certum:test?secret={secret}&algorithm=SHA256&digits=6&period=30");

        Assert.Equal(secret, profile.Secret);
    }

    [Theory]
    [InlineData("SHA1", 6, 30)]
    [InlineData("SHA256", 8, 30)]
    [InlineData("SHA256", 6, 60)]
    public void Rejects_non_certum_parameters(string algorithm, int digits, int period)
    {
        var uri = $"otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm={algorithm}&digits={digits}&period={period}";

        Assert.Throws<OtpauthException>(() => OtpauthProfile.Parse(uri));
    }

    [Fact]
    public void Rejects_invalid_or_ambiguous_uri()
    {
        var uris = new[]
        {
            "https://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://hotp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&issuer=Certum&issuer=Certum",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&unexpected=value",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PX!JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=jbswy3dpehpk3pxpjbswy3dpehpk3pxp&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&issuer=Other",
            "otpauth://totp/Certum%ZZ:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30",
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30&issuer=Certum%ZZ",
        };

        foreach (var uri in uris)
        {
            Assert.Throws<OtpauthException>(() => OtpauthProfile.Parse(uri));
        }
    }

    [Fact]
    public void Parses_percent_encoded_diagnostic_fields_without_exposing_secret_in_string_form()
    {
        const string secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

        var profile = OtpauthProfile.Parse(
            $"otpauth://totp/Certum%20Code:test%40example.com?secret={secret}&algorithm=SHA256&digits=6&period=30&issuer=Certum%20Code");

        Assert.Equal("Certum Code", profile.Issuer);
        Assert.Equal("test@example.com", profile.Account);
        Assert.DoesNotContain(secret, profile.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_pre_epoch_time()
    {
        var profile = OtpauthProfile.Parse(
            "otpauth://totp/Certum:test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30");

        Assert.Throws<ArgumentOutOfRangeException>(
            () => TotpGenerator.Generate(profile, DateTimeOffset.FromUnixTimeSeconds(-1)));
    }
}
