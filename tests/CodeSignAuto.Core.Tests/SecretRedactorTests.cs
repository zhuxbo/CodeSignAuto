using CodeSignAuto.Core.Security;
using Xunit;

namespace CodeSignAuto.Core.Tests;

public sealed class SecretRedactorTests
{
    [Fact]
    public void Redacts_only_otpauth_secret_values_and_the_explicit_actual_secret()
    {
        const string secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const string input =
            "email=user@example.test path=C:\\ProgramData\\CodeSignAuto line=73 hresult=0x80004005 "
            + "Authorization: Bearer abc.def /autologin 123456 stdout=visible stderr=visible "
            + "otpauth://totp/Certum:user@example.test?issuer=Certum&secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&digits=6 "
            + "raw=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        var redacted = SecretRedactor.Redact(input, secret);

        Assert.DoesNotContain(secret, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("otpauth://totp/Certum:user@example.test?issuer=Certum&secret=[REDACTED_TOTP_SECRET]&digits=6", redacted, StringComparison.Ordinal);
        Assert.Contains("email=user@example.test path=C:\\ProgramData\\CodeSignAuto line=73 hresult=0x80004005", redacted, StringComparison.Ordinal);
        Assert.Contains("Authorization: Bearer abc.def /autologin 123456 stdout=visible stderr=visible", redacted, StringComparison.Ordinal);

        var escaped = SecretRedactor.Redact(
            "otpauth://totp/x?issuer=Certum&amp;secret=ABCDEFGHIJKLMNOPQRSTUV234567&amp;digits=6");
        Assert.Contains("&amp;secret=[REDACTED_TOTP_SECRET]&amp;digits=6", escaped, StringComparison.Ordinal);
    }

    [Fact]
    public void Leaves_non_secret_and_unidentified_base32_text_unchanged()
    {
        const string input =
            "job 12345 token 123456 Authorization: Bearer visible /autologin 654321 "
            + "base32-like=JBSWY3DPEHPK3PXP completed with status ready";

        Assert.Equal(input, SecretRedactor.Redact(input));
        Assert.Equal(input, SecretRedactor.Redact(input, "visible"));
    }
}
