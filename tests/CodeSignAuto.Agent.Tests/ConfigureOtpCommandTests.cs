using CodeSignAuto.Agent.Security;
using CodeSignAuto.App.Commands;
using CodeSignAuto.Core.Otp;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class ConfigureOtpCommandTests
{
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    [Fact]
    public async Task Imports_from_stdin_and_prints_only_a_safe_summary()
    {
        var store = new RecordingOtpStore("C:\\ProgramData\\CodeSignAuto\\otp.dat");
        using var input = new StringReader(
            $"  otpauth://totp/Certum%0AConsole:test?secret={Secret}&algorithm=SHA256&digits=6&period=30&issuer=Certum%0AConsole  \r\n");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await ConfigureOtpCommand.ExecuteAsync(
            Array.Empty<string>(), input, output, error, store);

        Assert.Equal(0, exitCode);
        Assert.NotNull(store.SavedProfile);
        Assert.Equal("SHA256", store.SavedProfile.Algorithm);
        Assert.Equal(6, store.SavedProfile.Digits);
        Assert.Equal(30, store.SavedProfile.Period);
        Assert.Contains("issuer=\"Certum\\nConsole\"", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("account=\"test\"", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("path=\"C:\\\\ProgramData", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("otpauth://", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Single(output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public async Task Rejects_uri_arguments_before_reading_or_saving()
    {
        var store = new RecordingOtpStore("otp.dat");
        using var input = new ThrowingTextReader();
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await ConfigureOtpCommand.ExecuteAsync(
            new[] { "--uri", Secret }, input, output, error, store);

        Assert.Equal(2, exitCode);
        Assert.Null(store.SavedProfile);
        Assert.Equal(string.Empty, output.ToString());
        Assert.DoesNotContain(Secret, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_invalid_stdin_without_echoing_it()
    {
        const string invalidUri = "otpauth://totp/Certum:test?secret=PRIVATE";
        var store = new RecordingOtpStore("otp.dat");
        using var input = new StringReader(invalidUri);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await ConfigureOtpCommand.ExecuteAsync(
            Array.Empty<string>(), input, output, error, store);

        Assert.Equal(1, exitCode);
        Assert.Null(store.SavedProfile);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Equal($"otp_uri_invalid{Environment.NewLine}", error.ToString());
        Assert.DoesNotContain(invalidUri, error.ToString(), StringComparison.Ordinal);
    }

    private sealed class RecordingOtpStore(string path) : IOtpStore
    {
        public string Path { get; } = path;

        public OtpauthProfile? SavedProfile { get; private set; }

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default)
        {
            SavedProfile = profile;
            return Task.CompletedTask;
        }

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingTextReader : TextReader
    {
        public override Task<string> ReadToEndAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("stdin must not be read when arguments are present");
    }
}
