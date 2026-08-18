using System.Text.Json;
using SimplySignAuto.Core.Security;
using Xunit;

namespace SimplySignAuto.Core.Tests;

public sealed class StrictJsonTests
{
    [Fact]
    public void Configuration_json_rejects_secret_shaped_string_values_without_echoing_them()
    {
        string[] secretShapes =
        [
            "otpauth://totp/Certum:test?secret=SYNTHETIC",
            "Authorization: synthetic-credential",
            "Bearer synthetic-credential",
            "/autologin 123456",
        ];

        foreach (var secretShape in secretShapes)
        {
            var json = JsonSerializer.Serialize(new { value = $"prefix {secretShape} suffix" });

            var failure = Assert.Throws<JsonException>(() =>
                StrictJson.RejectDuplicatePropertiesAndSecretShapes(json));

            Assert.DoesNotContain(secretShape, failure.Message, StringComparison.Ordinal);
        }
    }
}
