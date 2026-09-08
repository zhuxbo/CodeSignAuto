using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using CodeSignAuto.Service.Api;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class AuthenticationTests
{
    [Fact]
    public async Task Jobs_require_valid_bearer_token()
    {
        await using var factory = await TestServiceFactory.StartAsync();

        using var missing = TestUploads.PdfRequest();
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Client.SendAsync(missing)).StatusCode);

        using var wrong = TestUploads.PdfRequest();
        wrong.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Client.SendAsync(wrong)).StatusCode);
    }

    [Fact]
    public async Task Authentication_rejects_non_bearer_and_multiple_headers_without_leaking_details()
    {
        await using var factory = await TestServiceFactory.StartAsync();

        using var request = TestUploads.PdfRequest();
        request.Headers.TryAddWithoutValidation("Authorization", ["Basic dXNlcjpwYXNz", $"Bearer {TestServiceFactory.Token}"]);
        using var response = await factory.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<ApiProblem>();
        Assert.Equal("unauthorized", problem!.Code);
        Assert.False(string.IsNullOrWhiteSpace(problem.CorrelationId));
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(TestServiceFactory.Token, json, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(
            ["code", "correlationId", "jobId", "status", "title", "type"],
            document.RootElement.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.DoesNotContain(document.RootElement.EnumerateObject(), property => char.IsUpper(property.Name[0]));
    }

    [Fact]
    public async Task Liveness_is_the_only_unauthenticated_endpoint()
    {
        await using var factory = await TestServiceFactory.StartAsync();

        Assert.Equal(HttpStatusCode.OK, (await factory.Client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Client.GetAsync("/v1/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Client.GetAsync($"/v1/jobs/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task Real_app_service_entry_loads_aspnet_runtime_before_strict_configuration_validation()
    {
        var repositoryRoot = FindRepositoryRoot();
        var dotnet = ResolveCurrentDotnetHost(
            Environment.GetEnvironmentVariable("DOTNET_HOST_PATH"),
            RuntimeEnvironment.GetRuntimeDirectory());
        var application = Path.Combine(repositoryRoot, "src", "CodeSignAuto.App", "bin", "Release", "net10.0-windows", "CodeSignAuto.dll");
        var runtimeConfiguration = Path.ChangeExtension(application, ".runtimeconfig.json");
        using (var document = JsonDocument.Parse(await File.ReadAllTextAsync(runtimeConfiguration)))
        {
            var frameworks = document.RootElement
                .GetProperty("runtimeOptions")
                .GetProperty("frameworks")
                .EnumerateArray()
                .Select(framework => framework.GetProperty("name").GetString())
                .ToArray();
            Assert.Contains("Microsoft.AspNetCore.App", frameworks);
        }

        var defaultConfiguration = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CodeSignAuto",
            "service.json");
        if (File.Exists(defaultConfiguration))
        {
            return;
        }

        var startInfo = new ProcessStartInfo(dotnet)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add(application);
        startInfo.ArgumentList.Add("service");
        startInfo.ArgumentList.Add("--console");
        startInfo.ArgumentList.Add("--allow-http-loopback");
        startInfo.Environment.Remove("SIMPLYSIGN_API_TOKEN_HASH");

        using var process = Process.Start(startInfo)!;
        var standardError = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));

        Assert.NotEqual(0, process.ExitCode);
        Assert.Contains("service_configuration_missing", standardError, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft.AspNetCore.App", standardError, StringComparison.Ordinal);
        Assert.DoesNotContain("FileNotFoundException", standardError, StringComparison.Ordinal);
    }

    [Fact]
    public void Dotnet_host_resolver_rejects_relative_and_unrelated_existing_files()
    {
        var configuredHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        Assert.False(string.IsNullOrWhiteSpace(configuredHost));
        Assert.True(Path.IsPathFullyQualified(configuredHost!));
        var runtimeDirectory = RuntimeEnvironment.GetRuntimeDirectory();

        var resolvedHost = ResolveCurrentDotnetHost(configuredHost, runtimeDirectory);
        Assert.Equal(
            Path.GetFullPath(configuredHost),
            resolvedHost,
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

        Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(null, runtimeDirectory));
        Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(" ", runtimeDirectory));

        var relativeHost = Path.GetRandomFileName();
        File.WriteAllBytes(relativeHost, []);
        try
        {
            Assert.False(Path.IsPathFullyQualified(relativeHost));
            Assert.True(File.Exists(relativeHost));
            Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(relativeHost, runtimeDirectory));
        }
        finally
        {
            File.Delete(relativeHost);
        }

        var unrelatedHost = Path.GetTempFileName();
        try
        {
            Assert.Throws<InvalidOperationException>(() => ResolveCurrentDotnetHost(unrelatedHost, runtimeDirectory));
        }
        finally
        {
            File.Delete(unrelatedHost);
        }
    }

    private static string ResolveCurrentDotnetHost(string? configuredHost, string runtimeDirectory)
    {
        if (string.IsNullOrWhiteSpace(configuredHost) || !Path.IsPathFullyQualified(configuredHost))
        {
            throw new InvalidOperationException("DOTNET_HOST_PATH must be a fully-qualified path.");
        }

        var runtimeVersionDirectory = new DirectoryInfo(runtimeDirectory);
        var dotnetRoot = runtimeVersionDirectory.Parent?.Parent?.Parent
            ?? throw new InvalidOperationException("The current dotnet root could not be derived from the runtime directory.");
        var expectedHost = Path.GetFullPath(Path.Combine(
            dotnetRoot.FullName,
            OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet"));
        var actualHost = Path.GetFullPath(configuredHost);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (!string.Equals(actualHost, expectedHost, comparison) || !IsOrdinaryFile(actualHost))
        {
            throw new InvalidOperationException("DOTNET_HOST_PATH must identify the host for the current loaded runtime.");
        }

        return actualHost;
    }

    private static bool IsOrdinaryFile(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        var attributes = File.GetAttributes(path);
        return (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0;
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSignAuto.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Repository root was not found.");
    }
}
