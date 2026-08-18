using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Jobs;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class PdfSignerTests
{
    [Fact]
    public async Task Writes_exact_utf8_request_invokes_only_sign_once_and_accepts_helpers_internal_validation()
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(call =>
        {
            fixture.CapturedRequest = File.ReadAllBytes(call.Arguments[2]);
            WritePartFromRequest(fixture.CapturedRequest, "%PDF-signed"u8.ToArray());
            return Exited(0, "{\"ok\":true,\"failureCode\":null}\n");
        });
        var signer = fixture.CreateSigner(runner);

        var result = await signer.SignAsync(
            fixture.Context,
            fixture.Parameters(),
            fixture.Certificate,
            CancellationToken.None);

        var call = Assert.Single(runner.Calls);
        Assert.Equal(fixture.HelperPath, call.Executable);
        Assert.Equal(["sign", "--request", fixture.RequestPath], call.Arguments);
        Assert.DoesNotContain("validate", call.Arguments);
        Assert.NotNull(fixture.CapturedRequest);
        Assert.False(fixture.CapturedRequest!.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }));
        using var request = JsonDocument.Parse(fixture.CapturedRequest);
        Assert.Equal(
            [
                "box", "certificateIdHex", "fieldName", "inputPath", "location", "modulePath",
                "outputPath", "page", "privateKeyIdHex", "reason", "slotId", "tokenSerial", "tsaUrl",
            ],
            request.RootElement.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal(fixture.InputPath, request.RootElement.GetProperty("inputPath").GetString());
        Assert.Equal(fixture.PartPath, request.RootElement.GetProperty("outputPath").GetString());
        Assert.Equal(fixture.ModulePath, request.RootElement.GetProperty("modulePath").GetString());
        Assert.Equal(7, request.RootElement.GetProperty("slotId").GetInt64());
        Assert.Equal("synthetic-token", request.RootElement.GetProperty("tokenSerial").GetString());
        Assert.Equal("0011", request.RootElement.GetProperty("certificateIdHex").GetString());
        Assert.Equal("2233", request.RootElement.GetProperty("privateKeyIdHex").GetString());
        Assert.False(File.Exists(fixture.RequestPath));
        Assert.True(File.Exists(fixture.PartPath));
        Assert.Equal("%PDF-signed"u8.Length, result.Size);
        Assert.Equal(Sha256("%PDF-signed"u8.ToArray()), result.Sha256);
    }

    [Fact]
    public async Task Accepts_single_helper_response_terminated_by_windows_crlf()
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(call =>
        {
            WritePartFromRequest(File.ReadAllBytes(call.Arguments[2]), "%PDF-signed"u8.ToArray());
            return Exited(0, "{\"ok\":true,\"failureCode\":null}\r\n");
        });
        var signer = fixture.CreateSigner(runner);

        var result = await signer.SignAsync(
            fixture.Context,
            fixture.Parameters(),
            fixture.Certificate,
            CancellationToken.None);

        Assert.Equal("%PDF-signed"u8.Length, result.Size);
        Assert.Equal(Sha256("%PDF-signed"u8.ToArray()), result.Sha256);
    }

    [Fact]
    public async Task Missing_or_tampered_helper_never_launches()
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(_ => throw new InvalidOperationException("must not launch"));
        File.Delete(fixture.HelperPath);
        var missing = fixture.CreateSigner(runner);

        var missingError = await Assert.ThrowsAsync<SigningException>(() =>
            missing.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal("pdf_helper_missing", missingError.Code);
        File.WriteAllText(fixture.HelperPath, "tampered");
        var tampered = fixture.CreateSigner(runner);
        var tamperedError = await Assert.ThrowsAsync<SigningException>(() =>
            tampered.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));
        Assert.Equal("pdf_helper_tampered", tamperedError.Code);
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Each_pdf_operation_reresolves_helper_before_controlled_file_mutation()
    {
        using var fixture = new Fixture();
        var resolver = new SequenceInstalledPdfToolResolver(
            InstalledPdfToolResolution.Ready(new InstalledPdfTool(
                fixture.HelperPath,
                Sha256("frozen-helper"u8.ToArray()))),
            InstalledPdfToolResolution.Tampered());
        var runner = new RecordingRunner(call =>
        {
            var request = File.ReadAllBytes(call.Arguments[2]);
            WritePartFromRequest(request, "%PDF-signed"u8.ToArray());
            return Exited(0, "{\"ok\":true,\"failureCode\":null}\n");
        });
        var signer = fixture.CreateSigner(runner, resolver);

        _ = await signer.SignAsync(
            fixture.Context,
            fixture.Parameters(),
            fixture.Certificate,
            CancellationToken.None);
        File.Delete(fixture.PartPath);
        await File.WriteAllTextAsync(fixture.RequestPath, "sentinel");

        var failure = await Assert.ThrowsAsync<SigningException>(() => signer.SignAsync(
            fixture.Context,
            fixture.Parameters(),
            fixture.Certificate,
            CancellationToken.None));

        Assert.Equal("pdf_helper_tampered", failure.Code);
        Assert.Equal(2, resolver.Calls);
        Assert.Single(runner.Calls);
        Assert.Equal("sentinel", await File.ReadAllTextAsync(fixture.RequestPath));
    }

    [Fact]
    public async Task Absent_product_wide_helper_returns_stable_not_installed_code_without_launch()
    {
        using var fixture = new Fixture();
        var resolver = new SequenceInstalledPdfToolResolver(
            InstalledPdfToolResolution.NotInstalled());
        var runner = new RecordingRunner(_ => throw new InvalidOperationException("must not launch"));
        var signer = fixture.CreateSigner(runner, resolver);
        await File.WriteAllTextAsync(fixture.RequestPath, "sentinel");

        var failure = await Assert.ThrowsAsync<SigningException>(() => signer.SignAsync(
            fixture.Context,
            fixture.Parameters(),
            fixture.Certificate,
            CancellationToken.None));

        Assert.Equal("pdf_support_not_installed", failure.Code);
        Assert.Equal(1, resolver.Calls);
        Assert.Empty(runner.Calls);
        Assert.Equal("sentinel", await File.ReadAllTextAsync(fixture.RequestPath));
    }

    [Theory]
    [InlineData(10, "token_missing", "token_missing")]
    [InlineData(10, "token_identifier_mismatch", "token_missing")]
    [InlineData(10, "private_key_missing", "private_key_missing")]
    [InlineData(10, "pkcs11_session_lost", "pkcs11_session_lost")]
    [InlineData(10, "pkcs11_unavailable", "internal_error")]
    [InlineData(20, "input_modified", "input_corrupt")]
    [InlineData(20, "pdf_sign_failed", "pdf_sign_failed")]
    [InlineData(30, "pdf_validation_failed", "pdf_verify_failed")]
    [InlineData(20, "native_secret_failure", "internal_error")]
    public async Task Maps_only_stable_helper_failures(int exitCode, string helperCode, string expectedCode)
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(call =>
        {
            var request = File.ReadAllBytes(call.Arguments[2]);
            WritePartFromRequest(request, "%PDF-partial"u8.ToArray());
            return Exited(exitCode, $"{{\"ok\":false,\"failureCode\":\"{helperCode}\"}}\n");
        });
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal(expectedCode, error.Code);
        Assert.False(File.Exists(fixture.RequestPath));
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Single(runner.Calls);
    }

    [Theory]
    [InlineData(0, "{\"ok\":false,\"failureCode\":\"pdf_sign_failed\"}\n")]
    [InlineData(20, "{\"ok\":true,\"failureCode\":null}\n")]
    [InlineData(0, "{\"ok\":true,\"failureCode\":null}\n{\"ok\":true}\n")]
    [InlineData(0, "not-json\n")]
    public async Task Rejects_exit_json_mismatch_or_non_single_line_output(int exitCode, string stdout)
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(call =>
        {
            WritePartFromRequest(File.ReadAllBytes(call.Arguments[2]), "%PDF-partial"u8.ToArray());
            return Exited(exitCode, stdout);
        });
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal("internal_error", error.Code);
        Assert.False(File.Exists(fixture.RequestPath));
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Cancellation_cleans_request_and_part_and_propagates()
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new RecordingRunner(call =>
        {
            WritePartFromRequest(File.ReadAllBytes(call.Arguments[2]), "%PDF-partial"u8.ToArray());
            cancellation.Cancel();
            return ProcessResult.Failed(
                "SimplySignPdfSigner.exe",
                ProcessTermination.Cancelled,
                "process_cancelled",
                TimeSpan.Zero);
        });
        var signer = fixture.CreateSigner(runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.False(File.Exists(fixture.RequestPath));
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public void Profile_rejects_raw_control_characters_before_uri_or_path_canonicalization()
    {
        using var fixture = new Fixture();
        var hash = Sha256("frozen-helper"u8.ToArray());
        var pathWithControlDirectory = Path.Combine(fixture.Root, "bad\nfolder", "SimplySignPdfSigner.exe");

        Assert.Throws<ArgumentException>(() => PdfSigningProfile.Create(
            pathWithControlDirectory,
            hash,
            "http://time.certum.pl/"));
        Assert.Throws<ArgumentException>(() => PdfSigningProfile.Create(
            fixture.HelperPath,
            hash,
            "http://time.certum.pl/\r\nheader"));
    }

    [Fact]
    public async Task Canonicalizes_tsa_url_before_writing_controlled_request()
    {
        using var fixture = new Fixture();
        string? tsaUrl = null;
        var runner = new RecordingRunner(call =>
        {
            var requestBytes = File.ReadAllBytes(call.Arguments[2]);
            using var request = JsonDocument.Parse(requestBytes);
            tsaUrl = request.RootElement.GetProperty("tsaUrl").GetString();
            WritePartFromRequest(requestBytes, "%PDF-signed"u8.ToArray());
            return Exited(0, "{\"ok\":true,\"failureCode\":null}\n");
        });
        var profile = PdfSigningProfile.Create(
            fixture.HelperPath,
            Sha256("frozen-helper"u8.ToArray()),
            "http://time.certum.pl");
        var signer = new PdfSigner(runner, profile, fixture.Root, TimeSpan.FromSeconds(30));

        await signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default);

        Assert.Equal("http://time.certum.pl/", tsaUrl);
    }

    [Fact]
    public async Task Dangling_helper_reparse_is_tampered_not_missing()
    {
        using var fixture = new Fixture();
        File.Delete(fixture.HelperPath);
        try
        {
            File.CreateSymbolicLink(fixture.HelperPath, fixture.HelperPath + ".missing");
        }
        catch (Exception error) when (error is PlatformNotSupportedException or UnauthorizedAccessException)
        {
            return;
        }

        var signer = fixture.CreateSigner(new RecordingRunner(_ => throw new InvalidOperationException("must not launch")));

        var failure = await Assert.ThrowsAsync<SigningException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal("pdf_helper_tampered", failure.Code);
    }

    [Theory]
    [InlineData(ProcessTermination.LaunchFailed, "pdf_helper_missing")]
    [InlineData(ProcessTermination.TimedOut, "pdf_sign_failed")]
    [InlineData(ProcessTermination.IoFailed, "pdf_sign_failed")]
    public async Task Maps_runner_termination_without_parsing_incidental_output(
        ProcessTermination termination,
        string expectedCode)
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(_ => ProcessResult.Failed(
            "SimplySignPdfSigner.exe",
            termination,
            "process-secret",
            TimeSpan.Zero,
            standardOutput: "not-json secret"));
        var signer = fixture.CreateSigner(runner);

        var failure = await Assert.ThrowsAsync<SigningException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal(expectedCode, failure.Code);
        Assert.False(File.Exists(fixture.RequestPath));
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Successful_helper_cannot_return_success_when_request_cleanup_fails()
    {
        using var fixture = new Fixture();
        var runner = new RecordingRunner(call =>
        {
            var requestBytes = File.ReadAllBytes(call.Arguments[2]);
            WritePartFromRequest(requestBytes, "%PDF-signed"u8.ToArray());
            File.Delete(call.Arguments[2]);
            Directory.CreateDirectory(call.Arguments[2]);
            File.WriteAllText(Path.Combine(call.Arguments[2], "locked"), "x");
            return Exited(0, "{\"ok\":true,\"failureCode\":null}\n");
        });
        var signer = fixture.CreateSigner(runner);

        var failure = await Assert.ThrowsAsync<SigningException>(() =>
            signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, default));

        Assert.Equal("internal_error", failure.Code);
        Assert.False(File.Exists(fixture.PartPath));
    }

    private static void WritePartFromRequest(byte[] requestBytes, byte[] content)
    {
        using var request = JsonDocument.Parse(requestBytes);
        File.WriteAllBytes(request.RootElement.GetProperty("outputPath").GetString()!, content);
    }

    private static ProcessResult Exited(int exitCode, string stdout) =>
        ProcessResult.Exited("SimplySignPdfSigner.exe", exitCode, TimeSpan.Zero, stdout, string.Empty);

    private static string Sha256(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] _helperBytes = "frozen-helper"u8.ToArray();

        public Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            HelperPath = Path.Combine(Root, "SimplySignPdfSigner.exe");
            ModulePath = Path.Combine(Root, "SimplySignPKCS11.dll");
            File.WriteAllBytes(HelperPath, _helperBytes);
            File.WriteAllText(ModulePath, "synthetic-module");
            JobId = Guid.NewGuid();
            JobDirectory = Path.Combine(Root, JobId.ToString("N"));
            Directory.CreateDirectory(JobDirectory);
            InputPath = Path.Combine(JobDirectory, "input.pdf");
            PartPath = Path.Combine(JobDirectory, "result.part.pdf");
            RequestPath = Path.Combine(JobDirectory, "pdf-request.json");
            File.WriteAllBytes(InputPath, "%PDF-input"u8.ToArray());
            Context = new SigningContext(JobId, ".pdf");
            Certificate = new SigningCertificate(
                "Document signer",
                "11",
                ModulePath,
                7,
                "synthetic-token",
                "0011",
                "2233",
                "00112233445566778899AABBCCDDEEFF00112233",
                DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                SupportsAuthenticode: false,
                SupportsPdf: true);
        }

        public string Root { get; }
        public string HelperPath { get; }
        public string ModulePath { get; }
        public Guid JobId { get; }
        public string JobDirectory { get; }
        public string InputPath { get; }
        public string PartPath { get; }
        public string RequestPath { get; }
        public SigningContext Context { get; }
        public SigningCertificate Certificate { get; }
        public byte[]? CapturedRequest { get; set; }

        public PdfParameters Parameters() => new(
            "11",
            "sha256",
            2,
            new PdfBox(10, 20, 30, 40),
            "Signature1",
            "Approval",
            "Shanghai");

        public PdfSigner CreateSigner(
            IProcessRunner runner,
            IInstalledPdfToolResolver? resolver = null)
        {
            var profile = PdfSigningProfile.Create(
                HelperPath,
                Sha256(_helperBytes),
                "http://time.certum.pl/");
            return resolver is null
                ? new PdfSigner(runner, profile, Root, TimeSpan.FromSeconds(30))
                : new PdfSigner(runner, profile, Root, TimeSpan.FromSeconds(30), resolver);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class SequenceInstalledPdfToolResolver(
        params InstalledPdfToolResolution[] results) : IInstalledPdfToolResolver
    {
        private readonly Queue<InstalledPdfToolResolution> _results = new(results);

        public int Calls { get; private set; }

        public Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(_results.Dequeue());
        }
    }

    private sealed record Call(string Executable, IReadOnlyList<string> Arguments);

    private sealed class RecordingRunner(Func<Call, ProcessResult> callback) : IProcessRunner
    {
        public List<Call> Calls { get; } = [];

        public Task<ProcessResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            var call = new Call(executable, arguments.ToArray());
            Calls.Add(call);
            return Task.FromResult(callback(call));
        }

        public Task<ProcessLaunchResult> StartDetachedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
