using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class SigningApiReleaseClientTests
{
    [WindowsFact]
    public async Task Client_uploads_polls_downloads_and_verifies_a_real_signed_result()
    {
        var input = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        Assert.True(File.Exists(input));
        var resultBytes = await File.ReadAllBytesAsync(input);
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await using var server = await SigningServer.StartAsync(token, resultBytes);
        using var root = new TemporaryDirectory();
        var output = Path.Combine(root.Path, "signed.exe");

        var result = await RunClientAsync(input, output, server.BaseUrl, token);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(resultBytes, await File.ReadAllBytesAsync(output));
        Assert.Equal(1, server.CreateCalls);
        Assert.Equal(2, server.StatusCalls);
        Assert.Equal(1, server.ResultCalls);
        Assert.Equal("Bearer " + token, server.Authorization);
        Assert.Equal(
            "release-test-" + Convert.ToHexString(SHA256.HashData(resultBytes)).ToLowerInvariant(),
            server.IdempotencyKey);
        using var parameters = JsonDocument.Parse(server.ParametersJson);
        Assert.Equal(
            ["appendSignature", "certificateSerialNumber", "digestAlgorithm", "kind"],
            parameters.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal("authenticode", parameters.RootElement.GetProperty("kind").GetString());
        Assert.Equal("sha256", parameters.RootElement.GetProperty("digestAlgorithm").GetString());
        Assert.False(parameters.RootElement.GetProperty("appendSignature").GetBoolean());
        Assert.DoesNotContain(token, result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain(token, result.StandardError, StringComparison.Ordinal);
        Assert.False(File.Exists(PartPath(output)));
    }

    [WindowsFact]
    public async Task Client_rejects_redirects_without_following_the_location()
    {
        var input = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await using var server = await SigningServer.StartRedirectAsync(token);
        using var root = new TemporaryDirectory();
        var output = Path.Combine(root.Path, "signed.exe");

        var result = await RunClientAsync(input, output, server.BaseUrl, token);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("release_signing_http_failed_302", result.StandardError, StringComparison.Ordinal);
        Assert.Equal(1, server.CreateCalls);
        Assert.Equal(0, server.RedirectTargetCalls);
        Assert.False(File.Exists(output));
        Assert.False(File.Exists(PartPath(output)));
        Assert.DoesNotContain(token, result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain(token, result.StandardError, StringComparison.Ordinal);
    }

    private static async Task<ProcessResult> RunClientAsync(
        string input,
        string output,
        string baseUrl,
        string token)
    {
        var script = Path.Combine(RepositoryRoot(), "scripts", "sign-via-simplysign.ps1");
        var wrapper = Path.Combine(Path.GetDirectoryName(output)!, "invoke-client.ps1");
        await File.WriteAllTextAsync(
            wrapper,
            """
            $ErrorActionPreference = 'Stop'
            try {
                . $args[0]
                $signature = Get-AuthenticodeSignature -LiteralPath $args[1]
                if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
                    throw 'release_test_input_signature_invalid'
                }
                Invoke-SimplySignArtifact `
                    -InputPath $args[1] `
                    -OutputPath $args[2] `
                    -BaseUrl $args[3] `
                    -BearerToken $env:SSA_RELEASE_TEST_TOKEN `
                    -CertificateSerialNumber $signature.SignerCertificate.SerialNumber `
                    -IdempotencyPrefix 'release-test' `
                    -Timeout ([TimeSpan]::FromSeconds(15))
                exit 0
            }
            catch {
                [Console]::Error.WriteLine($_.Exception.Message)
                exit 1
            }
            """,
            new UTF8Encoding(false));
        var start = new ProcessStartInfo
        {
            FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[]
                 {
                     "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", wrapper, script, input, output, baseUrl,
                 })
        {
            start.ArgumentList.Add(argument);
        }

        start.Environment["SSA_RELEASE_TEST_TOKEN"] = token;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("powershell_start_failed");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return new ProcessResult(process.ExitCode, await stdout, await stderr);
    }

    private static string PartPath(string output) =>
        Path.Combine(
            Path.GetDirectoryName(output)!,
            Path.GetFileNameWithoutExtension(output) + ".part" + Path.GetExtension(output));

    private static string RepositoryRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

    private sealed class SigningServer : IAsyncDisposable
    {
        private static readonly Guid JobId = Guid.Parse("f6c3d741-f441-46c2-933b-e70ec29d6433");
        private readonly WebApplication _application;
        private readonly string _token;
        private readonly byte[]? _result;
        private readonly bool _redirect;

        private SigningServer(WebApplication application, string baseUrl, string token, byte[]? result, bool redirect)
        {
            _application = application;
            BaseUrl = baseUrl;
            _token = token;
            _result = result;
            _redirect = redirect;
        }

        public string BaseUrl { get; }
        public int CreateCalls { get; private set; }
        public int StatusCalls { get; private set; }
        public int ResultCalls { get; private set; }
        public int RedirectTargetCalls { get; private set; }
        public string? Authorization { get; private set; }
        public string? IdempotencyKey { get; private set; }
        public string ParametersJson { get; private set; } = string.Empty;

        public static Task<SigningServer> StartAsync(string token, byte[] result) =>
            StartAsync(token, result, redirect: false);

        public static Task<SigningServer> StartRedirectAsync(string token) =>
            StartAsync(token, result: null, redirect: true);

        private static async Task<SigningServer> StartAsync(string token, byte[]? result, bool redirect)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0));
            var application = builder.Build();
            SigningServer? fixture = null;
            application.MapPost("/v1/jobs", async context =>
            {
                fixture!.CreateCalls++;
                fixture.Authorization = context.Request.Headers.Authorization.ToString();
                fixture.IdempotencyKey = context.Request.Headers["Idempotency-Key"].ToString();
                if (fixture._redirect)
                {
                    context.Response.StatusCode = StatusCodes.Status302Found;
                    context.Response.Headers.Location = "/redirect-target";
                    return;
                }

                Assert.Equal("Bearer " + fixture._token, fixture.Authorization);
                var form = await context.Request.ReadFormAsync();
                Assert.Single(form.Files);
                fixture.ParametersJson = Assert.Single(form["parameters"])
                    ?? throw new InvalidOperationException("parameters_missing");
                context.Response.StatusCode = StatusCodes.Status202Accepted;
                await context.Response.WriteAsJsonAsync(new
                {
                    jobId = JobId,
                    state = "queued",
                    statusUrl = $"/v1/jobs/{JobId:D}",
                    resultUrl = $"/v1/jobs/{JobId:D}/result",
                    expiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                });
            });
            application.MapGet("/redirect-target", () =>
            {
                fixture!.RedirectTargetCalls++;
                return Results.StatusCode(StatusCodes.Status500InternalServerError);
            });
            application.MapGet($"/v1/jobs/{JobId:D}", () =>
            {
                fixture!.StatusCalls++;
                return Results.Json(new
                {
                    jobId = JobId,
                    state = fixture.StatusCalls == 1 ? "signing" : "succeeded",
                    originalName = "powershell.exe",
                    inputSha256 = Convert.ToHexString(SHA256.HashData(fixture._result!)).ToLowerInvariant(),
                    resultSha256 = fixture.StatusCalls == 1
                        ? null
                        : Convert.ToHexString(SHA256.HashData(fixture._result!)).ToLowerInvariant(),
                    errorCode = (string?)null,
                    errorMessage = (string?)null,
                    createdAt = DateTimeOffset.UtcNow.AddSeconds(-1),
                    startedAt = DateTimeOffset.UtcNow,
                    completedAt = fixture.StatusCalls == 1
                        ? (DateTimeOffset?)null
                        : DateTimeOffset.UtcNow,
                    expiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                });
            });
            application.MapGet($"/v1/jobs/{JobId:D}/result", () =>
            {
                fixture!.ResultCalls++;
                return Results.Bytes(fixture._result!, "application/octet-stream");
            });
            await application.StartAsync();
            var addresses = application.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()?.Addresses;
            var baseUrl = Assert.Single(addresses!);
            fixture = new SigningServer(application, baseUrl, token, result, redirect);
            return fixture;
        }

        public async ValueTask DisposeAsync() => await _application.DisposeAsync();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory() => Path = Directory.CreateTempSubdirectory("SSA-SIGN-API-").FullName;
        public string Path { get; }
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows PowerShell and Authenticode.";
            }
        }
    }
}
