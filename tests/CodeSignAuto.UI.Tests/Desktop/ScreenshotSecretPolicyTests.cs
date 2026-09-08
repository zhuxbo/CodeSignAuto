namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class ScreenshotSecretPolicyTests
{
    [Theory]
    [InlineData("Certum 激活内容", false, true)]
    [InlineData("OTP secret", false, true)]
    [InlineData("普通文本", true, true)]
    [InlineData("PDF 签名原因", false, false)]
    public void Secret_input_detection_is_explicit_and_fail_closed(
        string name,
        bool isPassword,
        bool expected)
    {
        Assert.Equal(expected, ScreenshotSecretPolicy.IsSecretInput(name, isPassword));
    }

    [Fact]
    public void Synthetic_secret_mutation_blocks_screenshot_attestation()
    {
        var error = Assert.Throws<InvalidDataException>(() => ScreenshotSecretPolicy.AssertEmpty(
            [new ScreenshotSecretInput("Certum 激活内容", "otpauth://totp/Synthetic?secret=NOTREAL")]));

        Assert.Equal("screenshot_secret_present", error.Message);
    }

    [Fact]
    public void Empty_secret_inputs_allow_attestation()
    {
        ScreenshotSecretPolicy.AssertEmpty(
            [new ScreenshotSecretInput("Certum 激活内容", string.Empty)]);
    }

    [Fact]
    public void Readable_secret_in_value_or_legacy_pattern_blocks_production_evidence()
    {
        var observations = new[]
        {
            new AutomationSecretObservation(
                "OTP secret",
                "otp-input",
                IsPassword: true,
                ValuePatternValue: string.Empty,
                LegacyAccessibleValue: "synthetic-readable-secret",
                PropertyValues: ["OTP secret", string.Empty, string.Empty]),
        };

        var error = Assert.Throws<InvalidDataException>(() =>
            ScreenshotSecretPolicy.AssertAutomationTreeSafe(observations));

        Assert.Equal("production_ui_secret_scan_failed", error.Message);
    }

    [Fact]
    public void Empty_secret_patterns_and_safe_public_properties_compute_clean_evidence()
    {
        Assert.True(ScreenshotSecretPolicy.AssertAutomationTreeSafe(
            [new AutomationSecretObservation(
                "OTP secret",
                "otp-input",
                true,
                string.Empty,
                string.Empty,
                ["OTP secret", "仅存储在 DPAPI", string.Empty])]));
    }
}
