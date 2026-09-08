using System.Text.Json;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Core.Otp;

namespace CodeSignAuto.App.Commands;

public static class ConfigureOtpCommand
{
    public static async Task<int> ExecuteAsync(
        string[] args,
        TextReader input,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            args,
            input,
            output,
            error,
            new DpapiOtpStore(),
            cancellationToken).ConfigureAwait(false);
    }

    public static async Task<int> ExecuteAsync(
        string[] args,
        TextReader input,
        TextWriter output,
        TextWriter error,
        IOtpStore store,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(store);

        if (args.Length != 0)
        {
            await error.WriteLineAsync("Usage: CodeSignAuto.exe configure-otp < stdin").ConfigureAwait(false);
            return 2;
        }

        var uri = (await input.ReadToEndAsync(cancellationToken).ConfigureAwait(false)).Trim();
        if (uri.Length == 0)
        {
            await error.WriteLineAsync("otp_uri_required").ConfigureAwait(false);
            return 1;
        }

        try
        {
            var profile = OtpauthProfile.Parse(uri);
            await store.SaveAsync(profile, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"OTP configured: issuer={SafeValue(profile.Issuer)}, account={SafeValue(profile.Account)}, algorithm={profile.Algorithm}, digits={profile.Digits}, period={profile.Period}, path={SafeValue(store.Path)}").ConfigureAwait(false);
            return 0;
        }
        catch (OtpauthException)
        {
            await error.WriteLineAsync("otp_uri_invalid").ConfigureAwait(false);
            return 1;
        }
        catch (OtpStoreException exception)
        {
            await error.WriteLineAsync(exception.Code).ConfigureAwait(false);
            return 1;
        }
        catch (PlatformNotSupportedException)
        {
            await error.WriteLineAsync("otp_windows_required").ConfigureAwait(false);
            return 1;
        }
    }

    private static string SafeValue(string value) => JsonSerializer.Serialize(value);
}
