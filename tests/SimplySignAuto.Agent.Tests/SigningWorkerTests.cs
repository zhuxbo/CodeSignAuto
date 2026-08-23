using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class SigningWorkerTests
{
    [Fact]
    public async Task Real_catalog_manager_lease_rejects_unique_and_missing_records_with_the_same_serial()
    {
        using var fixture = new Fixture();
        var first = CreateCatalogCertificate("CN=Unique", [0x11]);
        var second = CreateCatalogCertificate("CN=Missing", [0x11]);
        var catalog = new CertificateCatalog(
            new StaticCatalogSource(CatalogJson(
                CatalogRecord(first, "0011", "unique", "0011"),
                CatalogRecord(second, "0022", "missing", null))),
            TestPaths.Controlled("SimplySignPKCS11.dll"));
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(new RealChainDriver(), gate, catalog);
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf: pdf, controller: manager);

        var failed = Assert.IsType<JobFailed>(
            await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));

        Assert.Equal("certificate_serial_ambiguous", failed.ErrorCode);
        Assert.Equal(0, pdf.CallCount);
    }

    [Fact]
    public async Task Real_catalog_manager_worker_preserves_catalog_unavailable_after_two_bounded_login_attempts()
    {
        using var fixture = new Fixture();
        var catalog = new CertificateCatalog(
            new UnavailableCatalogSource(),
            TestPaths.Controlled("SimplySignPKCS11.dll"));
        var driver = new UnavailableChainDriver();
        await using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(driver, gate, catalog);
        var worker = fixture.CreateWorker(controller: manager);

        var failed = Assert.IsType<JobFailed>(
            await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));

        Assert.Equal("certificate_catalog_unavailable", failed.ErrorCode);
        Assert.Equal(2, driver.LoginCalls);
        var snapshot = manager.GetSnapshot();
        Assert.Equal(SimplySignSessionState.Failed, snapshot.State);
        Assert.Equal(2, snapshot.Attempt);
        Assert.Equal(driver.UtcNow + TimeSpan.FromSeconds(60), snapshot.NextRetryAtUtc);
    }

    [Fact]
    public async Task Ready_lease_is_held_until_the_real_pipe_writer_finishes_the_terminal_frame()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var worker = fixture.CreateWorker(
            pdf: new FakePdfSigner((_, _, _, _) => Task.FromResult(Result())),
            controller: controller);
        var command = fixture.PdfCommand();
        await using var stream = await TerminalBarrierStream.CreateAsync(command);
        var client = new AgentPipeClient(
            _ => ValueTask.FromResult<Stream>(stream),
            new InfiniteDelay());
        var session = new AgentPipeSession(client, worker);

        var run = session.RunAsync(
            new InteractiveSessionInfo(7, "S-1-5-21-1000", "1000"),
            new AgentReadiness("ready"),
            default);
        await stream.TerminalWriteEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, controller.ActiveLeases);
        stream.ReleaseTerminalWrite.TrySetResult();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(0, controller.ActiveLeases);
        await using var written = new MemoryStream(stream.WrittenBytes);
        Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        var terminal = Assert.IsType<JobCompleted>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(command.DispatchId, terminal.DispatchId);
    }

    [Fact]
    public async Task Cancelled_terminal_write_releases_the_lease_and_the_same_dispatch_can_publish_after_reconnect()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var worker = fixture.CreateWorker(
            pdf: new FakePdfSigner((_, _, _, _) => Task.FromResult(Result())),
            controller: controller);
        var command = fixture.PdfCommand();
        await using var interruptedStream = await TerminalBarrierStream.CreateAsync(command);
        var interruptedSession = new AgentPipeSession(
            new AgentPipeClient(
                _ => ValueTask.FromResult<Stream>(interruptedStream),
                new InfiniteDelay()),
            worker);
        using var interrupted = new CancellationTokenSource();

        var firstRun = interruptedSession.RunAsync(
            new InteractiveSessionInfo(7, "S-1-5-21-1000", "1000"),
            new AgentReadiness("ready"),
            interrupted.Token);
        await interruptedStream.TerminalWriteEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, controller.ActiveLeases);

        interrupted.Cancel();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(0, controller.ActiveLeases);
        await AssertOnlyPreterminalFramesWereWrittenAsync(interruptedStream.WrittenBytes);

        await using var retryStream = await TerminalBarrierStream.CreateAsync(command);
        retryStream.ReleaseTerminalWrite.TrySetResult();
        var retrySession = new AgentPipeSession(
            new AgentPipeClient(
                _ => ValueTask.FromResult<Stream>(retryStream),
                new InfiniteDelay()),
            worker);

        await retrySession.RunAsync(
            new InteractiveSessionInfo(7, "S-1-5-21-1000", "1000"),
            new AgentReadiness("ready"),
            default).WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(0, controller.ActiveLeases);
        await using var written = new MemoryStream(retryStream.WrittenBytes);
        Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        var terminal = Assert.IsType<JobCompleted>(
            await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal(command.DispatchId, terminal.DispatchId);
    }

    [Fact]
    public async Task Three_concurrent_commands_never_execute_two_signers_concurrently()
    {
        using var fixture = new Fixture();
        var concurrency = new ConcurrencyProbe();
        var pdf = new FakePdfSigner(async (_, _, _, cancellationToken) =>
        {
            await concurrency.EnterAsync(cancellationToken);
            return Result();
        });
        var worker = fixture.CreateWorker(pdf: pdf);
        var commands = Enumerable.Range(0, 3).Select(_ => fixture.PdfCommand()).ToArray();

        var results = await Task.WhenAll(commands.Select(command => worker.ExecuteAsync(command, NoProgress, default)));

        Assert.All(results, result => Assert.IsType<JobCompleted>(result));
        Assert.Equal(1, concurrency.MaxConcurrent);
        Assert.Equal(3, pdf.CallCount);
    }

    [Fact]
    public async Task Routes_by_strict_persisted_kind_and_extension_not_mime()
    {
        using var fixture = new Fixture();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var authenticode = new FakeAuthenticodeSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf, authenticode);

        var pdfResult = await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default);
        var exeResult = await worker.ExecuteAsync(fixture.AuthenticodeCommand(), NoProgress, default);

        Assert.IsType<JobCompleted>(pdfResult);
        Assert.IsType<JobCompleted>(exeResult);
        Assert.Equal(1, pdf.CallCount);
        Assert.Equal(1, authenticode.CallCount);
    }

    [Fact]
    public async Task Kind_extension_mismatch_is_rejected_before_any_signer()
    {
        using var fixture = new Fixture();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var authenticode = new FakeAuthenticodeSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf, authenticode);
        var valid = fixture.AuthenticodeCommand();
        var mismatched = valid with { CanonicalParametersJson = Fixture.PdfJson };

        var failed = Assert.IsType<JobFailed>(await worker.ExecuteAsync(mismatched, NoProgress, default));

        Assert.Equal("invalid_parameters", failed.ErrorCode);
        Assert.Equal(0, pdf.CallCount);
        Assert.Equal(0, authenticode.CallCount);
    }

    [Fact]
    public async Task Unconfigured_capability_returns_unsupported_type_before_controller_or_signer()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var authenticode = new FakeAuthenticodeSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(
            pdf,
            authenticode,
            controller,
            pdfConfigured: false);

        var failed = Assert.IsType<JobFailed>(
            await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));

        Assert.Equal("unsupported_type", failed.ErrorCode);
        Assert.Equal(0, controller.CallCount);
        Assert.Equal(0, pdf.CallCount);
        Assert.Equal(0, authenticode.CallCount);
    }

    [Fact]
    public async Task Unknown_certificate_serial_is_preserved_as_catalog_error_after_one_lease()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var authenticode = new FakeAuthenticodeSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf, authenticode, controller);
        var command = fixture.PdfCommand() with
        {
            CanonicalParametersJson = Fixture.PdfJson.Replace(
                "\"certificateSerialNumber\":\"0011\"",
                "\"certificateSerialNumber\":\"99\"",
                StringComparison.Ordinal),
        };

        var failed = Assert.IsType<JobFailed>(await worker.ExecuteAsync(command, NoProgress, default));

        Assert.Equal("certificate_not_found", failed.ErrorCode);
        Assert.Equal(1, controller.CallCount);
        Assert.Equal(0, pdf.CallCount);
        Assert.Equal(0, authenticode.CallCount);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("size")]
    [InlineData("hash")]
    [InlineData("symlink")]
    public async Task Missing_reparse_or_mismatched_input_returns_input_corrupt_without_signer(string kind)
    {
        using var fixture = new Fixture();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf: pdf);
        var command = fixture.PdfCommand();
        if (kind == "missing")
        {
            File.Delete(fixture.InputPath(command));
        }
        else if (kind == "size")
        {
            command = command with { InputSize = command.InputSize + 1 };
        }
        else if (kind == "hash")
        {
            command = command with { InputSha256 = new string('f', 64) };
        }
        else
        {
            var path = fixture.InputPath(command);
            var target = path + ".target";
            File.Move(path, target);
            try
            {
                File.CreateSymbolicLink(path, target);
            }
            catch (Exception error) when (error is PlatformNotSupportedException or UnauthorizedAccessException)
            {
                return;
            }
        }

        var failed = Assert.IsType<JobFailed>(await worker.ExecuteAsync(command, NoProgress, default));

        Assert.Equal("input_corrupt", failed.ErrorCode);
        Assert.Equal(0, pdf.CallCount);
    }

    [Fact]
    public async Task A_command_acquires_one_lease_resolves_normalized_serial_and_passes_selected_certificate()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf: pdf, controller: controller);
        var command = fixture.PdfCommand(attempt: 2);
        var progress = new List<(int Percent, string Stage)>();

        var completed = Assert.IsType<JobCompleted>(await worker.ExecuteAsync(
            command,
            (percent, stage, _) =>
            {
                progress.Add((percent, stage));
                return Task.CompletedTask;
            },
            default));

        Assert.Equal(command.JobId, completed.JobId);
        Assert.Equal(command.DispatchId, completed.DispatchId);
        Assert.Equal(1, controller.CallCount);
        Assert.Equal(1, pdf.CallCount);
        Assert.Equal("11", pdf.LastCertificate!.SerialNumber);
        Assert.True(pdf.LastCertificate.SupportsPdf);
        Assert.Equal([(10, "signing"), (90, "verifying")], progress);
    }

    [Fact]
    public async Task Every_job_acquires_a_fresh_ready_lease_and_holds_it_through_signing_verification()
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var pdf = new FakePdfSigner((_, _, _, _) =>
        {
            Assert.Equal(1, controller.ActiveLeases);
            return Task.FromResult(Result());
        });
        var worker = fixture.CreateWorker(pdf: pdf, controller: controller);

        var first = await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default);
        var second = await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default);

        Assert.IsType<JobCompleted>(first);
        Assert.IsType<JobCompleted>(second);
        Assert.Equal(2, controller.CallCount);
        Assert.Equal(2, controller.DisposedLeases);
        Assert.Equal(0, controller.ActiveLeases);
    }

    [Theory]
    [InlineData("cancelled")]
    [InlineData("unknown")]
    public async Task Prepublication_cancellation_or_unknown_failure_releases_lease_and_next_job_can_sign(
        string failure)
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var calls = 0;
        var pdf = new FakePdfSigner((_, _, _, _) => ++calls == 1
            ? failure == "cancelled"
                ? Task.FromException<SigningResult>(new OperationCanceledException("controlled cancellation"))
                : Task.FromException<SigningResult>(new InvalidOperationException("controlled unknown"))
            : Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf: pdf, controller: controller);

        if (failure == "cancelled")
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));
        }
        else
        {
            var failed = Assert.IsType<JobFailed>(
                await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));
            Assert.Equal("internal_error", failed.ErrorCode);
        }

        Assert.Equal(0, controller.ActiveLeases);
        Assert.Equal(1, controller.DisposedLeases);
        var next = await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default)
            .WaitAsync(TimeSpan.FromSeconds(1));
        Assert.IsType<JobCompleted>(next);
        Assert.Equal(0, controller.ActiveLeases);
        Assert.Equal(2, controller.DisposedLeases);
    }

    [Theory]
    [InlineData("token_missing")]
    [InlineData("pkcs11_session_lost")]
    [InlineData("certificate_missing")]
    [InlineData("private_key_missing")]
    public async Task Token_session_or_object_loss_invalidates_and_fails_without_retry(
        string failureCode)
    {
        using var fixture = new Fixture();
        var controller = new FakeController();
        var pdf = new FakePdfSigner((context, _, _, _) =>
        {
            var part = Path.Combine(fixture.Root, context.JobId.ToString("N"), "result.part.pdf");
            File.WriteAllText(part, "controlled-part");
            throw new SigningException(failureCode);
        });
        var worker = fixture.CreateWorker(pdf: pdf, controller: controller);
        var command = fixture.PdfCommand();

        var failed = Assert.IsType<JobFailed>(
            await worker.ExecuteAsync(command, NoProgress, default));

        Assert.Equal(failureCode, failed.ErrorCode);
        Assert.Equal(1, pdf.CallCount);
        Assert.Equal(1, controller.CallCount);
        Assert.Equal(1, controller.InvalidateCalls);
        Assert.Equal(1, controller.DisposedLeases);
    }

    [Theory]
    [InlineData("certificate_catalog_unavailable")]
    [InlineData("certificate_not_found")]
    [InlineData("certificate_serial_ambiguous")]
    [InlineData("certificate_not_usable")]
    public async Task Preserves_all_four_catalog_errors_without_signing(string catalogCode)
    {
        using var fixture = new Fixture();
        var controller = FakeController.ForCatalogFailure(catalogCode);
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()));
        var worker = fixture.CreateWorker(pdf: pdf, controller: controller);

        var failed = Assert.IsType<JobFailed>(
            await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));

        Assert.Equal(catalogCode, failed.ErrorCode);
        Assert.Equal(0, pdf.CallCount);
        Assert.Equal(1, controller.CallCount);
    }

    [Theory]
    [InlineData("authenticode_signature_enumeration_failed", "authenticode_verify_failed")]
    [InlineData("pkcs11_unavailable", "internal_error")]
    [InlineData("private_key_missing", "private_key_missing")]
    [InlineData("pdf_appearance_font_missing", "pdf_appearance_font_missing")]
    public async Task Sanitizes_signer_error_to_protocol_allowlist(string signerCode, string expectedCode)
    {
        using var fixture = new Fixture();
        var pdf = new FakePdfSigner((_, _, _, _) => Task.FromException<SigningResult>(new SigningException(signerCode)));
        var worker = fixture.CreateWorker(pdf: pdf);

        var failed = Assert.IsType<JobFailed>(await worker.ExecuteAsync(fixture.PdfCommand(), NoProgress, default));

        Assert.Equal(expectedCode, failed.ErrorCode);
        Assert.DoesNotContain(signerCode, failed.ErrorMessage, StringComparison.Ordinal);
    }

    [WindowsFact]
    public async Task Holds_input_handle_without_write_or_delete_sharing_until_signer_finishes()
    {
        using var fixture = new Fixture();
        var writeDenied = false;
        var renameDenied = false;
        var deleteDenied = false;
        var pdf = new FakePdfSigner((context, _, _, _) =>
        {
            var command = fixture.LastCommand!;
            var path = fixture.InputPath(command);
            try
            {
                using var write = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            }
            catch (IOException)
            {
                writeDenied = true;
            }

            try
            {
                File.Move(path, path + ".moved");
            }
            catch (IOException)
            {
                renameDenied = true;
            }

            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                deleteDenied = true;
            }

            return Task.FromResult(Result());
        });
        var worker = fixture.CreateWorker(pdf: pdf);
        var command = fixture.PdfCommand();
        fixture.LastCommand = command;

        Assert.IsType<JobCompleted>(await worker.ExecuteAsync(command, NoProgress, default));
        Assert.True(writeDenied);
        Assert.True(renameDenied);
        Assert.True(deleteDenied);
        Assert.True(File.Exists(fixture.InputPath(command)));
    }

    private static Task NoProgress(int percent, string stage, CancellationToken cancellationToken) => Task.CompletedTask;

    private static SigningResult Result() => new(17, new string('b', 64));

    private static byte[] CreateCatalogCertificate(string subject, byte[] serial)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            critical: true));
        using var issuer = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(31));
        using var certificate = request.Create(
            issuer.SubjectName,
            X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            serial);
        return certificate.Export(X509ContentType.Cert);
    }

    private static object CatalogRecord(
        byte[] der,
        string certificateIdHex,
        string privateKeyMatch,
        string? privateKeyIdHex) => new
        {
            slotId = 7,
            tokenSerial = "PUBLIC-TOKEN",
            certificateIdHex,
            privateKeyMatch,
            privateKeyIdHex,
            certificateDerBase64 = Convert.ToBase64String(der),
        };

    private static string CatalogJson(params object[] certificates) => JsonSerializer.Serialize(new
    {
        ok = true,
        failureCode = (string?)null,
        certificates,
    });

    private sealed class StaticCatalogSource(string json) : ICertificateCatalogSource
    {
        public Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken) =>
            Task.FromResult(json);
    }

    private sealed class UnavailableCatalogSource : ICertificateCatalogSource
    {
        public Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken) =>
            Task.FromException<string>(new SigningException("certificate_catalog_unavailable"));
    }

    private sealed class RealChainDriver : ISimplySignSessionDriver
    {
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
        public SimplySignProcessState CheckProcessOnly() => new(true, 7);
        public Task CloseAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<SimplySignAuto.Core.Otp.OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("login must not run");
        public Task<long> StartLoginAsync(
            SimplySignAuto.Core.Otp.OtpauthProfile profile,
            CancellationToken cancellationToken) => throw new InvalidOperationException("login must not run");
        public Task WaitForCounterAfterAsync(
            SimplySignAuto.Core.Otp.OtpauthProfile profile,
            long priorCounter,
            CancellationToken cancellationToken) => throw new InvalidOperationException("login must not run");
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class UnavailableChainDriver : ISimplySignSessionDriver
    {
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow { get; private set; } = DateTimeOffset.UnixEpoch;
        public int LoginCalls { get; private set; }
        public SimplySignProcessState CheckProcessOnly() => new(true, 7);
        public Task CloseAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<SimplySignAuto.Core.Otp.OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new SimplySignAuto.Core.Otp.OtpauthProfile(
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
                "SHA256",
                6,
                30,
                "Certum",
                "user"));
        public Task<long> StartLoginAsync(
            SimplySignAuto.Core.Otp.OtpauthProfile profile,
            CancellationToken cancellationToken) => Task.FromResult((long)++LoginCalls);
        public Task WaitForCounterAfterAsync(
            SimplySignAuto.Core.Otp.OtpauthProfile profile,
            long priorCounter,
            CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            UtcNow += delay;
            return Task.CompletedTask;
        }
    }

    private sealed class Fixture : IDisposable
    {
        public const string PdfJson = "{\"box\":[10,20,30,40],\"certificateSerialNumber\":\"0011\",\"digestAlgorithm\":\"sha256\",\"fieldName\":\"Signature1\",\"kind\":\"pdf\",\"page\":1}";
        private const string AuthenticodeJson = "{\"appendSignature\":false,\"certificateSerialNumber\":\"22\",\"digestAlgorithm\":\"sha256\",\"kind\":\"authenticode\"}";

        public Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public SignJobCommand? LastCommand { get; set; }

        public SignJobCommand PdfCommand(int attempt = 1) => CreateCommand(".pdf", PdfJson, "%PDF-input"u8.ToArray(), attempt);

        public SignJobCommand AuthenticodeCommand() => CreateCommand(".exe", AuthenticodeJson, "MZ-synthetic"u8.ToArray(), 1);

        public string InputPath(SignJobCommand command) =>
            Path.Combine(Root, command.JobId.ToString("N"), "input" + command.Extension);

        public SigningWorker CreateWorker(
            IPdfSigner? pdf = null,
            IAuthenticodeSigner? authenticode = null,
            ISimplySignSessionManager? controller = null,
            bool authenticodeConfigured = true,
            bool pdfConfigured = true) =>
            new(
                authenticodeConfigured
                    ? authenticode ?? new FakeAuthenticodeSigner((_, _, _, _) => Task.FromResult(Result()))
                    : null,
                pdfConfigured
                    ? pdf ?? new FakePdfSigner((_, _, _, _) => Task.FromResult(Result()))
                    : null,
                controller ?? new FakeController(),
                Root);

        private SignJobCommand CreateCommand(string extension, string json, byte[] input, int attempt)
        {
            var jobId = Guid.NewGuid();
            var directory = Path.Combine(Root, jobId.ToString("N"));
            Directory.CreateDirectory(directory);
            File.WriteAllBytes(Path.Combine(directory, "input" + extension), input);
            return new SignJobCommand(
                jobId,
                Guid.NewGuid(),
                attempt,
                extension,
                json,
                input.LongLength,
                Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant());
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed class FakePdfSigner(
        Func<SigningContext, PdfParameters, SigningCertificate, CancellationToken, Task<SigningResult>> callback) : IPdfSigner
    {
        public int CallCount { get; private set; }
        public SigningCertificate? LastCertificate { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            PdfParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            CallCount++;
            LastCertificate = certificate;
            return callback(context, parameters, certificate, cancellationToken);
        }
    }

    private sealed class FakeAuthenticodeSigner(
        Func<SigningContext, AuthenticodeParameters, SigningCertificate, CancellationToken, Task<SigningResult>> callback) : IAuthenticodeSigner
    {
        public int CallCount { get; private set; }

        public Task<SigningResult> SignAsync(
            SigningContext context,
            AuthenticodeParameters parameters,
            SigningCertificate certificate,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return callback(context, parameters, certificate, cancellationToken);
        }
    }

    private sealed class InfiniteDelay : IAgentDelay
    {
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
    }

    private static async Task AssertOnlyPreterminalFramesWereWrittenAsync(byte[] bytes)
    {
        await using var written = new MemoryStream(bytes);
        Assert.IsType<AgentHello>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.IsType<JobProgress>(await LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        var error = await Assert.ThrowsAsync<ProtocolException>(
            () => LengthPrefixedJsonProtocol.ReadAsync<AgentMessage>(written, default));
        Assert.Equal("unexpected_eof", error.Code);
    }

    private sealed class TerminalBarrierStream : Stream
    {
        private const int WritesBeforeTerminalPayload = 7;
        private readonly MemoryStream _input;
        private readonly MemoryStream _output = new();
        private int _writeCalls;

        private TerminalBarrierStream(byte[] input) => _input = new MemoryStream(input);

        public TaskCompletionSource TerminalWriteEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseTerminalWrite { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public byte[] WrittenBytes => _output.ToArray();

        public static async Task<TerminalBarrierStream> CreateAsync(AgentMessage command)
        {
            await using var input = new MemoryStream();
            await LengthPrefixedJsonProtocol.WriteAsync(input, command, default);
            return new TerminalBarrierStream(input.ToArray());
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _writeCalls) == WritesBeforeTerminalPayload + 1)
            {
                TerminalWriteEntered.TrySetResult();
                await ReleaseTerminalWrite.Task.WaitAsync(cancellationToken);
            }

            await _output.WriteAsync(buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ReleaseTerminalWrite.TrySetResult();
                _input.Dispose();
                _output.Dispose();
            }

            base.Dispose(disposing);
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class FakeController : ISimplySignSessionManager
    {
        private readonly SemaphoreSlim _leaseGate = new(1, 1);
        private readonly string? _acquireFailure;
        public int CallCount { get; private set; }
        public int InvalidateCalls { get; private set; }
        public int ActiveLeases { get; private set; }
        public int DisposedLeases { get; private set; }
        public CertificateCatalogSnapshot CatalogSnapshot { get; }

        public FakeController()
            : this(DefaultCatalog(), acquireFailure: null)
        {
        }

        private FakeController(CertificateCatalogSnapshot catalogSnapshot, string? acquireFailure)
        {
            CatalogSnapshot = catalogSnapshot;
            _acquireFailure = acquireFailure;
        }

        public static FakeController ForCatalogFailure(string code) => code switch
        {
            "certificate_catalog_unavailable" => new(DefaultCatalog(), code),
            "certificate_not_found" => new(Snapshot(new Dictionary<string, IReadOnlyList<SigningCertificate>>()), null),
            "certificate_serial_ambiguous" => new(Snapshot(new Dictionary<string, IReadOnlyList<SigningCertificate>>
            {
                ["11"] = [Certificate("11", pdf: true), Certificate("11", pdf: true) with { CertificateIdHex = "8899" }],
            }), null),
            "certificate_not_usable" => new(Snapshot(new Dictionary<string, IReadOnlyList<SigningCertificate>>
            {
                ["11"] = [Certificate("11", pdf: false)],
            }), null),
            _ => throw new ArgumentOutOfRangeException(nameof(code)),
        };

        public event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged { add { } remove { } }

        public SimplySignSessionSnapshot GetSnapshot() => Ready();

        public SimplySignCapabilityGroup GetCapabilityGroup() =>
            new(1, Ready(), CatalogSnapshot);

        public Task<SimplySignSessionSnapshot> PrepareStartupAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Ready());

        public Task<SimplySignSessionSnapshot> CheckAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => Task.FromResult(Ready());

        public Task<SimplySignSessionSnapshot> EnsureReadyAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => Task.FromResult(Ready());

        public async Task<IReadySignLease> AcquireReadySignLeaseAsync(
            CancellationToken cancellationToken)
        {
            await _leaseGate.WaitAsync(cancellationToken);
            CallCount++;
            if (_acquireFailure is not null)
            {
                _leaseGate.Release();
                throw new SigningException(_acquireFailure);
            }

            ActiveLeases++;
            return new Lease(this, Ready(), CatalogSnapshot, cancellationToken);
        }

        public void Invalidate() => InvalidateCalls++;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static SimplySignSessionSnapshot Ready()
        {
            var now = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
            return new SimplySignSessionSnapshot(
                SimplySignSessionState.Ready,
                1,
                now,
                now,
                7,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                "ready",
                0,
                null);
        }

        private static CertificateCatalogSnapshot DefaultCatalog() => Snapshot(
            new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal)
            {
                ["11"] = [Certificate("11", pdf: true)],
                ["22"] = [Certificate("22", pdf: false)],
            });

        private static CertificateCatalogSnapshot Snapshot(
            IReadOnlyDictionary<string, IReadOnlyList<SigningCertificate>> certificates) =>
            new(1, DateTimeOffset.Parse("2026-08-09T00:00:00Z"), certificates);

        private static SigningCertificate Certificate(string serial, bool pdf) => new(
            pdf ? "Document signer" : "Code signer",
            serial,
            TestPaths.Controlled("SimplySignPKCS11.dll"),
            pdf ? 7UL : 8UL,
            pdf ? "PDF-TOKEN" : "CODE-TOKEN",
            pdf ? "0011" : "4455",
            pdf ? "2233" : "6677",
            pdf ? "00112233445566778899AABBCCDDEEFF00112233" : "FFEEDDCCBBAA99887766554433221100FFEEDDCC",
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2030-01-01T00:00:00Z"),
            SupportsAuthenticode: !pdf,
            SupportsPdf: pdf);

        private sealed class Lease(
            FakeController owner,
            SimplySignSessionSnapshot snapshot,
            CertificateCatalogSnapshot catalogSnapshot,
            CancellationToken cancellationToken) : IReadySignLease
        {
            private FakeController? _owner = owner;

            public SimplySignSessionSnapshot Snapshot { get; } = snapshot;
            public CertificateCatalogSnapshot CatalogSnapshot { get; } = catalogSnapshot;
            public CancellationToken CancellationToken { get; } = cancellationToken;

            public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation) =>
                operation(CancellationToken);

            public ValueTask DisposeAsync()
            {
                var current = Interlocked.Exchange(ref _owner, null);
                if (current is not null)
                {
                    current.ActiveLeases--;
                    current.DisposedLeases++;
                    current._leaseGate.Release();
                }

                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class ConcurrencyProbe
    {
        private int _current;
        private int _max;

        public int MaxConcurrent => Volatile.Read(ref _max);

        public async Task EnterAsync(CancellationToken cancellationToken)
        {
            var current = Interlocked.Increment(ref _current);
            InterlockedExtensions.Max(ref _max, current);
            try
            {
                await Task.Delay(20, cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _current);
            }
        }
    }

    private static class InterlockedExtensions
    {
        public static void Max(ref int target, int value)
        {
            var current = Volatile.Read(ref target);
            while (current < value)
            {
                var observed = Interlocked.CompareExchange(ref target, value, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows file-sharing semantics.";
            }
        }
    }
}
