using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class AuthenticodeSignerTests
{
    private const string Thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
    private const string TimestampInputUrl = "http://time.certum.pl";
    private const string TimestampUrl = "http://time.certum.pl/";

    [Fact]
    public async Task Uses_selected_certificate_thumbprint_and_fixed_profile_tsa_in_exact_sha256_commands()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(
            _ => Exited(1),
            _ => Exited(0),
            _ => Exited(0));
        var signer = fixture.CreateSigner(runner);

        var result = await signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None);

        Assert.Collection(
            runner.Calls,
            call => Assert.Equal(["verify", "/pa", "/all", fixture.PartPath], call.Arguments),
            call => Assert.Equal(
                ["sign", "/fd", "SHA256", "/sha1", Thumbprint, "/tr", TimestampUrl, "/td", "SHA256", "/v", fixture.PartPath],
                call.Arguments),
            call => Assert.Equal(["verify", "/pa", "/all", "/v", fixture.PartPath], call.Arguments));
        Assert.All(runner.Calls, call => Assert.Equal(fixture.SignToolPath, call.Executable));
        Assert.Equal(fixture.InputBytes.LongLength, result.Size);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(fixture.InputBytes)).ToLowerInvariant(), result.Sha256);
        Assert.True(File.Exists(fixture.PartPath));
        Assert.False(File.Exists(Path.Combine(fixture.JobDirectory, "result.exe")));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Append_places_as_immediately_after_sign_and_skips_the_unsigned_precheck()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Exited(0), _ => Exited(0));
        const string oldThumbprint = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        var signer = fixture.CreateSigner(
            runner,
            new RecordingSignatureReader(
                _ => [oldThumbprint],
                _ => [oldThumbprint, Thumbprint]));

        await signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None);

        Assert.Collection(
            runner.Calls,
            call => Assert.Equal(
                ["sign", "/as", "/fd", "SHA256", "/sha1", Thumbprint, "/tr", TimestampUrl, "/td", "SHA256", "/v", fixture.PartPath],
                call.Arguments),
                call => Assert.Equal(["verify", "/pa", "/all", "/v", fixture.PartPath], call.Arguments));
    }

    [Fact]
    public async Task Append_creates_the_primary_signature_when_the_input_is_unsigned()
    {
        using var fixture = new SigningFixture();
        var reader = new RecordingSignatureReader(_ => [], _ => [Thumbprint]);
        var runner = new RecordingRunner(_ => Exited(0), _ => Exited(0));
        var signer = fixture.CreateSigner(runner, reader);

        await signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None);

        Assert.Equal(2, reader.CallCount);
        Assert.Collection(
            runner.Calls,
            call => Assert.Equal(
                ["sign", "/as", "/fd", "SHA256", "/sha1", Thumbprint, "/tr", TimestampUrl, "/td", "SHA256", "/v", fixture.PartPath],
                call.Arguments),
            call => Assert.Equal(["verify", "/pa", "/all", "/v", fixture.PartPath], call.Arguments));
    }

    [Fact]
    public void Windows_signature_reader_maps_only_trust_e_nosignature_to_an_empty_sequence()
    {
        const int trustENoSignature = unchecked((int)0x800B0100);
        var unsignedReader = new WindowsAuthenticodeSignatureReader(
            new RecordingWinTrustSignatureApi(_ => new WinTrustSignatureProbe(trustENoSignature, 0, null)));

        Assert.Empty(unsignedReader.ReadSignerThumbprints("controlled-input.exe"));

        foreach (var invalidStatus in new[]
                 {
                     unchecked((int)0x80096010), // TRUST_E_BAD_DIGEST
                     unchecked((int)0x800B0001), // TRUST_E_PROVIDER_UNKNOWN
                     unchecked((int)0x800B0003), // TRUST_E_SUBJECT_FORM_UNKNOWN
                 })
        {
            var damagedReader = new WindowsAuthenticodeSignatureReader(
                new RecordingWinTrustSignatureApi(_ => new WinTrustSignatureProbe(invalidStatus, 0, null)));

            var error = Assert.Throws<CryptographicException>(
                () => damagedReader.ReadSignerThumbprints("controlled-input.exe"));
            Assert.Equal("authenticode_signature_enumeration_failed", error.Message);
        }

        var responses = new Queue<WinTrustSignatureProbe>(
        [
            new WinTrustSignatureProbe(0, 1, Thumbprint),
            new WinTrustSignatureProbe(trustENoSignature, 0, null),
        ]);
        var missingSecondaryReader = new WindowsAuthenticodeSignatureReader(
            new RecordingWinTrustSignatureApi(_ => responses.Dequeue()));

        var missingSecondary = Assert.Throws<CryptographicException>(
            () => missingSecondaryReader.ReadSignerThumbprints("controlled-input.exe"));
        Assert.Equal("authenticode_signature_enumeration_failed", missingSecondary.Message);
    }

    [Fact]
    public async Task Existing_signature_without_append_returns_already_signed_and_never_signs()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Exited(0));
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("already_signed", error.Code);
        Assert.Single(runner.Calls);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Theory]
    [InlineData(ProcessTermination.LaunchFailed, "signtool_missing")]
    [InlineData(ProcessTermination.TimedOut, "authenticode_verify_failed")]
    [InlineData(ProcessTermination.IoFailed, "authenticode_verify_failed")]
    public async Task Unsigned_precheck_continues_only_after_an_exited_nonzero_result(
        ProcessTermination termination,
        string expectedCode)
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Failed(termination, "runner-secret", fixture));
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal(expectedCode, error.Code);
        Assert.Single(runner.Calls);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Cancellation_during_unsigned_precheck_cleans_up_and_never_signs()
    {
        using var fixture = new SigningFixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new RecordingRunner(_ =>
        {
            cancellation.Cancel();
            return Failed(ProcessTermination.Cancelled, "process_cancelled", fixture);
        });
        var signer = fixture.CreateSigner(runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.Single(runner.Calls);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Replaces_a_regular_stale_part_before_the_unsigned_precheck()
    {
        using var fixture = new SigningFixture();
        await File.WriteAllTextAsync(fixture.PartPath, "stale");
        var runner = new RecordingRunner(
            call =>
            {
                Assert.Equal(fixture.InputBytes, File.ReadAllBytes(fixture.PartPath));
                return Exited(1);
            },
            _ => Exited(0),
            _ => Exited(0));
        var signer = fixture.CreateSigner(runner);

        await signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None);

        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.PartPath));
    }

    [Theory]
    [InlineData(ProcessTermination.LaunchFailed, "process_launch_failed", "signtool_missing")]
    [InlineData(ProcessTermination.TimedOut, "process_timeout", "authenticode_sign_failed")]
    [InlineData(ProcessTermination.IoFailed, "process_io_failed", "authenticode_sign_failed")]
    public async Task Sign_process_failures_are_sanitized_and_delete_the_work_copy(
        ProcessTermination termination,
        string runnerCode,
        string expectedCode)
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(
            _ => Exited(1),
            _ => Failed(termination, runnerCode, fixture));
        var signer = fixture.CreateSigner(runner);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(fixture.InputPath));

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal(expectedCode, error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(fixture.InputPath)));
        Assert.DoesNotContain(Thumbprint, error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(TimestampUrl, error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(fixture.JobDirectory, error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-secret", error.Message, StringComparison.Ordinal);
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task Nonzero_sign_exit_maps_to_sign_failed_without_runner_output_leakage()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Exited(1), _ => Exited(7, fixture));
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_sign_failed", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task Post_verify_failure_deletes_part_and_never_reads_a_certificate()
    {
        using var fixture = new SigningFixture();
        var certificateReader = new RecordingSignatureReader(_ => throw new InvalidOperationException("must not read"));
        var runner = new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(1, fixture));
        var signer = fixture.CreateSigner(runner, certificateReader);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", error.Code);
        Assert.Equal(0, certificateReader.CallCount);
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Cancellation_during_post_verify_cleans_up_after_signing()
    {
        using var fixture = new SigningFixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new RecordingRunner(
            _ => Exited(1),
            _ => Exited(0),
            _ =>
            {
                cancellation.Cancel();
                return Failed(ProcessTermination.Cancelled, "process_cancelled", fixture);
            });
        var signer = fixture.CreateSigner(runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.Equal(3, runner.Calls.Count);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Non_append_requires_exactly_one_normalized_matching_signer()
    {
        using var fixture = new SigningFixture();
        var certificateReader = new RecordingSignatureReader(
            _ => ["00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33"]);
        var runner = new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(0));
        var signer = fixture.CreateSigner(runner, certificateReader);

        await signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None);

        Assert.Equal(1, certificateReader.CallCount);
        Assert.Equal(fixture.PartPath, certificateReader.LastPath);
        Assert.True(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Signer_mismatch_and_reader_exceptions_map_to_verify_failed_and_clean_up()
    {
        using var mismatchFixture = new SigningFixture();
        var mismatchSigner = mismatchFixture.CreateSigner(
            new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(0)),
            new RecordingSignatureReader(_ => ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"]));

        var mismatch = await Assert.ThrowsAsync<SigningException>(
            () => mismatchSigner.SignAsync(mismatchFixture.Context, mismatchFixture.Parameters(), mismatchFixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", mismatch.Code);
        Assert.False(File.Exists(mismatchFixture.PartPath));

        using var exceptionFixture = new SigningFixture();
        var exceptionSigner = exceptionFixture.CreateSigner(
            new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(0)),
            new RecordingSignatureReader(_ => throw new IOException(exceptionFixture.JobDirectory)));

        var readFailure = await Assert.ThrowsAsync<SigningException>(
            () => exceptionSigner.SignAsync(exceptionFixture.Context, exceptionFixture.Parameters(), exceptionFixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", readFailure.Code);
        Assert.False(File.Exists(exceptionFixture.PartPath));
        Assert.Empty(readFailure.ToString());
    }

    [Fact]
    public async Task Append_rejects_when_the_reader_reports_the_same_old_signature_without_a_new_one()
    {
        using var fixture = new SigningFixture();
        var reader = new RecordingSignatureReader(_ => [Thumbprint], _ => [Thumbprint]);
        var signer = fixture.CreateSigner(new RecordingRunner(_ => Exited(0), _ => Exited(0)), reader);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", error.Code);
        Assert.Equal(2, reader.CallCount);
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Append_rejects_extra_or_reordered_signatures_and_cleans_up()
    {
        const string oldThumbprint = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        foreach (var finalSigners in new IReadOnlyList<string>[]
                 {
                     [oldThumbprint, Thumbprint, Thumbprint],
                     [Thumbprint, oldThumbprint],
                 })
        {
            using var fixture = new SigningFixture();
            var reader = new RecordingSignatureReader(_ => [oldThumbprint], _ => finalSigners);
            var signer = fixture.CreateSigner(new RecordingRunner(_ => Exited(0), _ => Exited(0)), reader);

            var error = await Assert.ThrowsAsync<SigningException>(
                () => signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None));

            Assert.Equal("authenticode_verify_failed", error.Code);
            Assert.False(File.Exists(fixture.PartPath));
        }
    }

    [Fact]
    public async Task Non_append_rejects_multiple_signers_even_when_one_matches()
    {
        using var fixture = new SigningFixture();
        var signer = fixture.CreateSigner(
            new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(0)),
            new RecordingSignatureReader(_ => [Thumbprint, Thumbprint]));

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
    }

    [Fact]
    public async Task Append_reader_failure_before_signing_cleans_up_and_never_launches_signtool()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(
            runner,
            new RecordingSignatureReader(_ => throw new CryptographicException("unsafe-reader-detail")));

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None));

        Assert.Equal("authenticode_verify_failed", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(runner.Calls);
        Assert.Empty(error.ToString());
    }

    [Fact]
    public async Task Cancellation_during_sign_propagates_only_after_cleaning_the_work_copy()
    {
        using var fixture = new SigningFixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new RecordingRunner(
            _ => Exited(1),
            _ =>
            {
                cancellation.Cancel();
                return Failed(ProcessTermination.Cancelled, "process_cancelled", fixture);
            });
        var signer = fixture.CreateSigner(runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Cancellation_before_start_deletes_only_a_controlled_stale_part_and_launches_nothing()
    {
        using var fixture = new SigningFixture();
        await File.WriteAllTextAsync(fixture.PartPath, "stale");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Cancellation_during_streaming_copy_deletes_partial_output_and_never_launches()
    {
        using var fixture = new SigningFixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new RecordingRunner();
        var copier = new RecordingCopier((input, output, token) =>
        {
            File.WriteAllBytes(output, fixture.InputBytes[..16]);
            cancellation.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });
        var signer = fixture.CreateSigner(runner, copier: copier);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, cancellation.Token));

        Assert.Equal(1, copier.CallCount);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(runner.Calls);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Streaming_copy_io_failure_deletes_partial_output_and_returns_a_stable_code()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner();
        var copier = new RecordingCopier((input, output, token) =>
        {
            File.WriteAllBytes(output, fixture.InputBytes[..16]);
            throw new IOException("unsafe-copy-detail " + fixture.JobDirectory);
        });
        var signer = fixture.CreateSigner(runner, copier: copier);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("internal_error", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(runner.Calls);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
        Assert.Empty(error.ToString());
    }

    [Theory]
    [InlineData(".txt")]
    [InlineData(".pdf")]
    [InlineData("exe")]
    [InlineData("../.exe")]
    public async Task Rejects_an_invalid_context_extension_without_launching(string extension)
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(new SigningContext(fixture.JobId, extension), fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Empty(runner.Calls);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Theory]
    [InlineData(".exe")]
    [InlineData(".dll")]
    [InlineData(".msi")]
    [InlineData(".sys")]
    [InlineData(".cat")]
    public async Task Keeps_each_supported_authenticode_extension_as_the_work_copy_extension(string extension)
    {
        using var fixture = new SigningFixture(extension);
        var runner = new RecordingRunner(_ => Exited(0), _ => Exited(0));
        var signer = fixture.CreateSigner(
            runner,
            validator: extension is ".msi" or ".cat"
                ? new FixedFileValidator(isValid: true)
                : new AuthenticodeFileValidator());

        await signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None);

        Assert.True(File.Exists(fixture.PartPath));
        Assert.Equal(extension, Path.GetExtension(fixture.PartPath));
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public void Non_windows_production_validator_does_not_accept_plausible_msi_or_catalog_bytes()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new SigningFixture();
        var msiPath = Path.Combine(fixture.Root, "plausible.msi");
        var catalogPath = Path.Combine(fixture.Root, "plausible.cat");
        File.WriteAllBytes(msiPath, CreatePlausibleCompoundFileBytes());
        File.WriteAllBytes(catalogPath, CreatePlausibleCatalogSignedDataBytes());
        var validator = new AuthenticodeFileValidator();

        Assert.False(validator.IsValid(msiPath, ".msi"));
        Assert.False(validator.IsValid(catalogPath, ".cat"));
    }

    [Fact]
    public void Windows_production_catalog_validator_rejects_empty_catalog_like_signed_data_and_pe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new SigningFixture();
        var validator = new AuthenticodeFileValidator();
        var inputs = new Dictionary<string, byte[]>
        {
            ["empty.cat"] = [],
            ["catalog-like.cat"] = CreatePlausibleCatalogSignedDataBytes(),
            ["portable-executable.cat"] = File.ReadAllBytes(GetUnsignedHelloPePath()),
        };

        foreach (var (name, bytes) in inputs)
        {
            var path = Path.Combine(fixture.Root, name);
            File.WriteAllBytes(path, bytes);

            Assert.False(validator.IsValid(path, ".cat"));
        }
    }

    [Fact]
    public void Native_catalog_validation_uses_open_existing_requires_a_member_and_closes_every_valid_handle()
    {
        foreach (var invalidHandle in new[] { IntPtr.Zero, new IntPtr(-1) })
        {
            var invalidApi = new RecordingNativeFileValidationApi { CatalogHandle = invalidHandle };
            var invalidValidator = new AuthenticodeFileValidator(invalidApi);

            Assert.False(invalidValidator.IsValid("controlled.cat", ".cat"));
            Assert.Equal(0x00000004u, invalidApi.CatalogOpenFlags);
            Assert.Equal(0x00000100u, invalidApi.CatalogPublicVersion);
            Assert.Equal(0u, invalidApi.CatalogEncodingType);
            Assert.Equal(IntPtr.Zero, invalidApi.CatalogCryptographicProvider);
            Assert.Equal(0, invalidApi.CatalogEnumerateCount);
            Assert.Equal(0, invalidApi.CatalogCloseCount);
        }

        var emptyApi = new RecordingNativeFileValidationApi { CatalogHandle = new IntPtr(42) };
        var emptyValidator = new AuthenticodeFileValidator(emptyApi);

        Assert.False(emptyValidator.IsValid("controlled.cat", ".cat"));
        Assert.Equal(1, emptyApi.CatalogEnumerateCount);
        Assert.Equal(new IntPtr(42), emptyApi.LastEnumeratedCatalogHandle);
        Assert.Equal(IntPtr.Zero, emptyApi.LastPreviousCatalogMember);
        Assert.Equal(1, emptyApi.CatalogCloseCount);

        var validApi = new RecordingNativeFileValidationApi
        {
            CatalogHandle = new IntPtr(42),
            CatalogMember = new IntPtr(43),
        };
        var validValidator = new AuthenticodeFileValidator(validApi);

        Assert.True(validValidator.IsValid("controlled.cat", ".cat"));
        Assert.Equal(0x00000004u, validApi.CatalogOpenFlags);
        Assert.Equal(0x00000100u, validApi.CatalogPublicVersion);
        Assert.Equal(0u, validApi.CatalogEncodingType);
        Assert.Equal(1, validApi.CatalogEnumerateCount);
        Assert.Equal(new IntPtr(42), validApi.LastEnumeratedCatalogHandle);
        Assert.Equal(IntPtr.Zero, validApi.LastPreviousCatalogMember);
        Assert.Equal(1, validApi.CatalogCloseCount);
        Assert.Equal(new IntPtr(42), validApi.LastClosedCatalogHandle);

        var throwingApi = new RecordingNativeFileValidationApi
        {
            CatalogOpenException = new DllNotFoundException("unsafe-native-detail"),
        };
        var throwingValidator = new AuthenticodeFileValidator(throwingApi);

        Assert.False(throwingValidator.IsValid("controlled.cat", ".cat"));
        Assert.Equal(0, throwingApi.CatalogCloseCount);

        var throwingEnumerateApi = new RecordingNativeFileValidationApi
        {
            CatalogHandle = new IntPtr(42),
            CatalogEnumerateException = new EntryPointNotFoundException("unsafe-native-detail"),
        };
        var throwingEnumerateValidator = new AuthenticodeFileValidator(throwingEnumerateApi);

        Assert.False(throwingEnumerateValidator.IsValid("controlled.cat", ".cat"));
        Assert.Equal(1, throwingEnumerateApi.CatalogEnumerateCount);
        Assert.Equal(1, throwingEnumerateApi.CatalogCloseCount);
    }

    [Fact]
    public void Native_msi_validation_uses_readonly_mode_and_closes_every_returned_handle()
    {
        var successApi = new RecordingNativeFileValidationApi
        {
            MsiOpenResult = 0,
            MsiDatabaseHandle = 17,
        };
        var successValidator = new AuthenticodeFileValidator(successApi);

        Assert.True(successValidator.IsValid("controlled.msi", ".msi"));
        Assert.Equal(IntPtr.Zero, successApi.MsiPersistenceMode);
        Assert.Equal(1, successApi.MsiCloseCount);
        Assert.Equal(17u, successApi.LastClosedMsiHandle);

        var failedApi = new RecordingNativeFileValidationApi
        {
            MsiOpenResult = 1603,
            MsiDatabaseHandle = 18,
        };
        var failedValidator = new AuthenticodeFileValidator(failedApi);

        Assert.False(failedValidator.IsValid("controlled.msi", ".msi"));
        Assert.Equal(IntPtr.Zero, failedApi.MsiPersistenceMode);
        Assert.Equal(1, failedApi.MsiCloseCount);
        Assert.Equal(18u, failedApi.LastClosedMsiHandle);

        var zeroHandleApi = new RecordingNativeFileValidationApi { MsiOpenResult = 1603 };
        Assert.False(new AuthenticodeFileValidator(zeroHandleApi).IsValid("controlled.msi", ".msi"));
        Assert.Equal(0, zeroHandleApi.MsiCloseCount);

        var throwingApi = new RecordingNativeFileValidationApi
        {
            MsiOpenException = new EntryPointNotFoundException("unsafe-native-detail"),
        };
        Assert.False(new AuthenticodeFileValidator(throwingApi).IsValid("controlled.msi", ".msi"));
        Assert.Equal(0, throwingApi.MsiCloseCount);
    }

    [Theory]
    [InlineData(".exe")]
    [InlineData(".dll")]
    [InlineData(".sys")]
    [InlineData(".msi")]
    [InlineData(".cat")]
    public async Task Rejects_structurally_invalid_signable_files_before_launching_signtool(string extension)
    {
        using var fixture = new SigningFixture(extension);
        var corrupt = extension switch
        {
            ".exe" => "MZ\0\0not-a-pe"u8.ToArray(),
            ".dll" => new byte[256],
            ".sys" => "MZ"u8.ToArray(),
            ".msi" => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            ".cat" => [0x30, 0x03, 0x02, 0x01, 0x01],
            _ => throw new InvalidOperationException(),
        };
        await File.WriteAllBytesAsync(fixture.InputPath, corrupt);
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(append: true), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Empty(runner.Calls);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(corrupt, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Context_cannot_select_arbitrary_paths_and_never_touches_files_outside_the_derived_job_directory()
    {
        using var fixture = new SigningFixture();
        var outsideDirectory = Directory.CreateDirectory(Path.Combine(fixture.Root, "outside")).FullName;
        var outsideInput = Path.Combine(outsideDirectory, "input.exe");
        var outsideResult = Path.Combine(outsideDirectory, "result.exe.part");
        await File.WriteAllBytesAsync(outsideInput, fixture.InputBytes);
        await File.WriteAllTextAsync(outsideResult, "outside-part");
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(new SigningContext(Guid.NewGuid(), ".exe"), fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(outsideInput));
        Assert.Equal("outside-part", await File.ReadAllTextAsync(outsideResult));
        Assert.Empty(runner.Calls);
        Assert.Equal([nameof(SigningContext.Extension), nameof(SigningContext.JobId)],
            typeof(SigningContext).GetProperties().Select(property => property.Name).Order().ToArray());
    }

    [Fact]
    public async Task Rejects_empty_job_id_and_does_not_delete_the_real_job_input()
    {
        using var fixture = new SigningFixture();
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(new SigningContext(Guid.Empty, ".exe"), fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Ignores_a_non_guid_directory_even_when_it_contains_signable_names()
    {
        using var fixture = new SigningFixture();
        var nonGuidDirectory = Directory.CreateDirectory(Path.Combine(fixture.Root, "not-a-guid")).FullName;
        var nonGuidInput = Path.Combine(nonGuidDirectory, "input.exe");
        await File.WriteAllBytesAsync(nonGuidInput, fixture.InputBytes);
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(new SigningContext(Guid.NewGuid(), ".exe"), fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(nonGuidInput));
    }

    [Fact]
    public async Task Rejects_a_reparse_job_directory_without_touching_its_target()
    {
        using var fixture = new SigningFixture();
        var target = Directory.CreateDirectory(Path.Combine(fixture.Root, "target-job")).FullName;
        var targetInput = Path.Combine(target, "input.exe");
        await File.WriteAllBytesAsync(targetInput, fixture.InputBytes);
        Directory.Delete(fixture.JobDirectory, recursive: true);
        Directory.CreateSymbolicLink(fixture.JobDirectory, target);
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(targetInput));
    }

    [Fact]
    public void Rejects_a_reparse_spool_root_at_signer_construction()
    {
        using var fixture = new SigningFixture();
        var link = Path.Combine(Path.GetDirectoryName(fixture.Root)!, "root-link-" + Guid.NewGuid().ToString("N"));
        Directory.CreateSymbolicLink(link, fixture.Root);
        try
        {
            Assert.Throws<ArgumentException>(() => new AuthenticodeSigner(
                new RecordingRunner(),
                new RecordingSignatureReader(_ => [Thumbprint]),
                fixture.Profile,
                link,
                new ControlledFileCopier(),
                new AuthenticodeFileValidator(),
                TimeSpan.FromSeconds(5)));
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task Rejects_a_reparse_input_without_touching_its_target()
    {
        using var fixture = new SigningFixture();
        var target = Path.Combine(fixture.Root, "target.exe");
        await File.WriteAllBytesAsync(target, fixture.InputBytes);
        File.Delete(fixture.InputPath);
        File.CreateSymbolicLink(fixture.InputPath, target);
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(target));
    }

    [Fact]
    public async Task Rejects_and_unlinks_a_stale_reparse_part_without_touching_its_target()
    {
        using var fixture = new SigningFixture();
        var target = Path.Combine(fixture.Root, "target-part.exe");
        var targetBytes = "target-must-survive"u8.ToArray();
        await File.WriteAllBytesAsync(target, targetBytes);
        File.CreateSymbolicLink(fixture.PartPath, target);
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Equal(targetBytes, await File.ReadAllBytesAsync(target));
    }

    [Fact]
    public async Task Rejects_and_unlinks_a_dangling_result_symlink_without_creating_its_outside_target()
    {
        using var fixture = new SigningFixture();
        var outsideTarget = Path.Combine(fixture.Root, "outside-target.exe");
        File.CreateSymbolicLink(fixture.PartPath, outsideTarget);
        var signer = fixture.CreateSigner(new RecordingRunner());

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.False(File.Exists(outsideTarget));
        Assert.Null(new FileInfo(fixture.PartPath).LinkTarget);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Rejects_and_unlinks_a_result_symlink_loop_without_launching_or_mutating_input()
    {
        using var fixture = new SigningFixture();
        File.CreateSymbolicLink(fixture.PartPath, fixture.PartPath);
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("invalid_signable_file", error.Code);
        Assert.Null(new FileInfo(fixture.PartPath).LinkTarget);
        Assert.Empty(runner.Calls);
        Assert.Equal(fixture.InputBytes, await File.ReadAllBytesAsync(fixture.InputPath));
    }

    [Fact]
    public async Task Rejects_mismatched_selected_certificate_or_digest_before_copying()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner();
        var signer = fixture.CreateSigner(runner);

        foreach (var parameters in new[]
                 {
                     new AuthenticodeParameters("12", "sha256", false),
                     new AuthenticodeParameters("11", "SHA256", false),
                 })
        {
            var error = await Assert.ThrowsAsync<SigningException>(
                () => signer.SignAsync(fixture.Context, parameters, fixture.Certificate, CancellationToken.None));
            Assert.Equal("invalid_parameters", error.Code);
        }

        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(runner.Calls);
    }

    [Fact]
    public async Task Hash_read_failure_is_stable_and_deletes_the_part()
    {
        using var fixture = new SigningFixture();
        var reader = new RecordingSignatureReader(path =>
        {
            File.Delete(path);
            return [Thumbprint];
        });
        var signer = fixture.CreateSigner(
            new RecordingRunner(_ => Exited(1), _ => Exited(0), _ => Exited(0)),
            reader);

        var error = await Assert.ThrowsAsync<SigningException>(
            () => signer.SignAsync(fixture.Context, fixture.Parameters(), fixture.Certificate, CancellationToken.None));

        Assert.Equal("internal_error", error.Code);
        Assert.False(File.Exists(fixture.PartPath));
        Assert.Empty(error.ToString());
    }

    [Fact]
    public void Profile_validates_and_normalizes_all_command_argument_sources()
    {
        using var fixture = new SigningFixture();
        var profile = AuthenticodeSigningProfile.Create(
            fixture.SignToolPath,
            TimestampInputUrl);

        Assert.Empty(profile.ToString());
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create("signtool.exe", TimestampInputUrl));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(fixture.SignToolPath, "file:///timestamp"));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(fixture.SignToolPath, "https://user:password@example.test/tsa"));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(fixture.SignToolPath, null!));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(fixture.SignToolPath, "https://example.test/tsa\r\nheader"));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(
            Path.Combine(fixture.Root, "unsafe\nsegment", "signtool.exe"),
            TimestampInputUrl));
        Assert.Throws<ArgumentException>(() => AuthenticodeSigningProfile.Create(
            fixture.SignToolPath,
            "https://example.test/" + new string('a', 2048)));
    }

    [Fact]
    public async Task Public_value_objects_never_render_paths_or_configured_signing_material()
    {
        using var fixture = new SigningFixture();
        var signer = fixture.CreateSigner(new RecordingRunner(_ => Exited(0), _ => Exited(0)));

        var result = await signer.SignAsync(
            fixture.Context,
            fixture.Parameters(append: true),
            fixture.Certificate,
            CancellationToken.None);

        Assert.Empty(fixture.Context.ToString());
        Assert.Empty(fixture.Profile.ToString());
        Assert.Empty(result.ToString());
    }

    [Fact]
    public async Task Preflight_uses_only_the_absolute_profile_path_and_returns_sanitized_metadata()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Exited(0, fixture));
        var preflight = new SignToolPreflight(runner, fixture.Profile, new FixedMetadataReader("10.0.26100.0", isX64: true));

        var result = await preflight.CheckAsync(CancellationToken.None);

        Assert.True(result.Available);
        Assert.Null(result.ErrorCode);
        Assert.Equal("signtool.exe", result.ExecutableName);
        Assert.Equal("10.0.26100.0", result.FileVersion);
        Assert.Collection(runner.Calls, call =>
        {
            Assert.Equal(fixture.SignToolPath, call.Executable);
            Assert.Equal(["/?"], call.Arguments);
        });
        Assert.DoesNotContain(fixture.JobDirectory, result.ExecutableName, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.ToString());
    }

    [Theory]
    [InlineData(false, ProcessTermination.Exited, 0)]
    [InlineData(true, ProcessTermination.Exited, 7)]
    [InlineData(true, ProcessTermination.LaunchFailed, -1)]
    [InlineData(true, ProcessTermination.TimedOut, -1)]
    public async Task Missing_or_unusable_signtool_is_a_capability_failure_only(
        bool toolExists,
        ProcessTermination termination,
        int exitCode)
    {
        using var fixture = new SigningFixture();
        if (!toolExists)
        {
            File.Delete(fixture.SignToolPath);
        }

        var response = termination == ProcessTermination.Exited
            ? Exited(exitCode, fixture)
            : Failed(termination, "runner-secret", fixture);
        var runner = new RecordingRunner(_ => response);
        var preflight = new SignToolPreflight(runner, fixture.Profile, new FixedMetadataReader("10.0.26100.0", isX64: true));

        var result = await preflight.CheckAsync(CancellationToken.None);

        Assert.False(result.Available);
        Assert.Equal("signtool_missing", result.ErrorCode);
        Assert.Equal("signtool.exe", result.ExecutableName);
        Assert.Null(result.FileVersion);
        Assert.Equal(toolExists ? 1 : 0, runner.Calls.Count);
        Assert.Empty(result.ToString());
    }

    [Fact]
    public async Task Preflight_rejects_a_non_x64_executable_even_when_help_exits_zero()
    {
        using var fixture = new SigningFixture();
        var runner = new RecordingRunner(_ => Exited(0));
        var preflight = new SignToolPreflight(
            runner,
            fixture.Profile,
            new FixedMetadataReader("10.0.26100.0", isX64: false));

        var result = await preflight.CheckAsync(CancellationToken.None);

        Assert.False(result.Available);
        Assert.Equal("signtool_missing", result.ErrorCode);
        Assert.Null(result.FileVersion);
    }

    [Fact]
    public async Task Preflight_rejects_file_versions_with_controls_or_path_separators()
    {
        string[] invalidVersions = ["10.0.26100.0\nunsafe", "C:\\controlled\\signtool.exe", "/controlled/signtool.exe"];
        foreach (var version in invalidVersions)
        {
            using var fixture = new SigningFixture();
            var preflight = new SignToolPreflight(
                new RecordingRunner(_ => Exited(0)),
                fixture.Profile,
                new FixedMetadataReader(version, isX64: true));

            var result = await preflight.CheckAsync(CancellationToken.None);

            Assert.False(result.Available);
            Assert.Equal("signtool_missing", result.ErrorCode);
            Assert.Null(result.FileVersion);
        }
    }

    [Fact]
    public async Task Preflight_rejects_an_overlong_file_version()
    {
        using var fixture = new SigningFixture();
        var preflight = new SignToolPreflight(
            new RecordingRunner(_ => Exited(0)),
            fixture.Profile,
            new FixedMetadataReader(new string('1', 129), isX64: true));

        var result = await preflight.CheckAsync(CancellationToken.None);

        Assert.False(result.Available);
        Assert.Equal("signtool_missing", result.ErrorCode);
        Assert.Null(result.FileVersion);
    }

    [Fact]
    public void Non_windows_certificate_reader_is_stably_unavailable()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new SigningFixture();
        var reader = new WindowsAuthenticodeSignatureReader();

        Assert.Throws<PlatformNotSupportedException>(() => reader.ReadSignerThumbprints(fixture.InputPath));
    }

    [Fact]
    public void Unsigned_hello_fixture_has_an_empty_pe_certificate_table()
    {
        var projectDirectory = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Parent!.Parent!.FullName;
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        var executable = GetUnsignedHelloPePath(projectDirectory, configuration);

        Assert.True(File.Exists(executable), executable);
        AssertPortableExecutableHasNoCertificateTable(executable);
    }

    private static void AssertPortableExecutableHasNoCertificateTable(string path)
    {
        var bytes = File.ReadAllBytes(path);
        Assert.True(bytes.AsSpan().StartsWith("MZ"u8));
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3c, sizeof(int)));
        Assert.Equal("PE\0\0"u8.ToArray(), bytes.AsSpan(peOffset, 4).ToArray());
        var optionalHeader = peOffset + 24;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optionalHeader, sizeof(ushort)));
        var dataDirectoryOffset = magic switch
        {
            0x10b => optionalHeader + 96,
            0x20b => optionalHeader + 112,
            _ => throw new Xunit.Sdk.XunitException("Unexpected PE optional-header magic."),
        };
        var certificateEntry = dataDirectoryOffset + (4 * 8);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(certificateEntry, sizeof(uint))));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(certificateEntry + 4, sizeof(uint))));
    }

    private static string GetUnsignedHelloPePath(string? projectDirectory = null, string? configuration = null)
    {
        projectDirectory ??= new DirectoryInfo(AppContext.BaseDirectory).Parent!.Parent!.Parent!.FullName;
        configuration ??= new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        return Path.Combine(
            projectDirectory,
            "Fixtures",
            "UnsignedHello",
            "bin",
            configuration,
            "net10.0-windows",
            OperatingSystem.IsWindows() ? "UnsignedHello.exe" : "UnsignedHello.dll");
    }

    private static byte[] CreatePlausibleCompoundFileBytes()
    {
        const uint FreeSector = 0xFFFFFFFF;
        const uint EndOfChain = 0xFFFFFFFE;
        const uint FatSector = 0xFFFFFFFD;
        var bytes = new byte[1536];
        new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(24), 0x003E);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(26), 0x0003);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(28), 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(30), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(32), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(40), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(44), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(48), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(56), 4096);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(68), EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(72), 0);
        for (var offset = 76; offset < 512; offset += sizeof(uint))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), FreeSector);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(76), 1);
        for (var offset = 1024; offset < bytes.Length; offset += sizeof(uint))
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), FreeSector);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1024), EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1028), FatSector);
        return bytes;
    }

    private static byte[] CreatePlausibleCatalogSignedDataBytes()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var explicitContent = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
        writer.PushSequence(explicitContent);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
        writer.WriteNull();
        writer.PopSequence();
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.3.6.1.4.1.311.10.1");
        writer.PopSequence();
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(explicitContent);
        writer.PopSequence();
        return writer.Encode();
    }

    private static ProcessResult Exited(int exitCode, SigningFixture? fixture = null) =>
        ProcessResult.Exited(
            "signtool.exe",
            exitCode,
            TimeSpan.Zero,
            fixture is null ? string.Empty : $"runner-secret {Thumbprint}",
            fixture is null ? string.Empty : $"{TimestampUrl} {fixture.JobDirectory}");

    private static ProcessResult Failed(ProcessTermination termination, string failureCode, SigningFixture fixture) =>
        ProcessResult.Failed(
            "signtool.exe",
            termination,
            failureCode,
            TimeSpan.Zero,
            $"runner-secret {Thumbprint}",
            $"{TimestampUrl} {fixture.JobDirectory}");

    private sealed class SigningFixture : IDisposable
    {
        public SigningFixture(string extension = ".exe")
        {
            Root = Path.Combine(Path.GetTempPath(), "CodeSignAutoAuthenticodeTests", Guid.NewGuid().ToString("N"));
            JobId = Guid.NewGuid();
            JobDirectory = Path.Combine(Root, JobId.ToString("N"));
            Directory.CreateDirectory(JobDirectory);
            InputPath = Path.Combine(JobDirectory, "input" + extension);
            PartPath = Path.Combine(JobDirectory, "result.part" + extension);
            InputBytes = extension switch
            {
                ".exe" or ".dll" or ".sys" => File.ReadAllBytes(GetUnsignedHelloPePath()),
                ".msi" => CreatePlausibleCompoundFileBytes(),
                ".cat" => CreatePlausibleCatalogSignedDataBytes(),
                _ => "unsupported-fixture"u8.ToArray(),
            };
            File.WriteAllBytes(InputPath, InputBytes);
            SignToolPath = Path.Combine(Root, "signtool.exe");
            File.WriteAllBytes(SignToolPath, "fake-tool"u8.ToArray());
            Context = new SigningContext(JobId, extension);
            Profile = AuthenticodeSigningProfile.Create(
                SignToolPath,
                TimestampInputUrl);
            Certificate = new SigningCertificate(
                "Code signer",
                "11",
                Path.Combine(Root, "SimplySignPKCS11.dll"),
                7,
                "synthetic-token",
                "0011",
                "2233",
                Thumbprint,
                DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
                DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                SupportsAuthenticode: true,
                SupportsPdf: false);
        }

        public string Root { get; }

        public Guid JobId { get; }

        public string JobDirectory { get; }

        public string InputPath { get; }

        public string PartPath { get; }

        public string SignToolPath { get; }

        public byte[] InputBytes { get; }

        public SigningContext Context { get; }

        public AuthenticodeSigningProfile Profile { get; }

        public SigningCertificate Certificate { get; }

        public AuthenticodeParameters Parameters(bool append = false) =>
            new("11", "sha256", append);

        public AuthenticodeSigner CreateSigner(
            RecordingRunner runner,
            IAuthenticodeSignatureReader? reader = null,
            IControlledFileCopier? copier = null,
            IAuthenticodeFileValidator? validator = null) =>
            new(
                runner,
                reader ?? new RecordingSignatureReader(_ => [Thumbprint], _ => [Thumbprint, Thumbprint]),
                Profile,
                Root,
                copier ?? new ControlledFileCopier(),
                validator ?? new AuthenticodeFileValidator(),
                TimeSpan.FromSeconds(5));

        public void Dispose()
        {
            if (Directory.Exists(Root))
            {
                Directory.Delete(Root, recursive: true);
            }
        }
    }

    private sealed record ProcessCall(string Executable, IReadOnlyList<string> Arguments);

    private sealed class RecordingRunner : IProcessRunner
    {
        private readonly Queue<Func<ProcessCall, ProcessResult>> _responses;

        public RecordingRunner(params Func<ProcessCall, ProcessResult>[] responses)
        {
            _responses = new Queue<Func<ProcessCall, ProcessResult>>(responses);
        }

        public List<ProcessCall> Calls { get; } = [];

        public Task<ProcessResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            var call = new ProcessCall(executable, arguments.ToArray());
            Calls.Add(call);
            var response = _responses.Count > 0 ? _responses.Dequeue()(call) : Exited(0);
            return Task.FromResult(response);
        }

        public Task<ProcessLaunchResult> StartDetachedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class RecordingSignatureReader : IAuthenticodeSignatureReader
    {
        private readonly Queue<Func<string, IReadOnlyList<string>>> _callbacks;

        public RecordingSignatureReader(params Func<string, IReadOnlyList<string>>[] callbacks)
        {
            _callbacks = new Queue<Func<string, IReadOnlyList<string>>>(callbacks);
        }

        public int CallCount { get; private set; }

        public string? LastPath { get; private set; }

        public IReadOnlyList<string> ReadSignerThumbprints(string signedFilePath)
        {
            CallCount++;
            LastPath = signedFilePath;
            return _callbacks.Count > 0
                ? _callbacks.Dequeue()(signedFilePath)
                : throw new InvalidOperationException("No signature-reader response was configured.");
        }
    }

    private sealed class RecordingWinTrustSignatureApi(
        Func<WinTrustSignatureRequest, WinTrustSignatureProbe> callback) : IWinTrustSignatureApi
    {
        public WinTrustSignatureProbe Probe(WinTrustSignatureRequest request) => callback(request);
    }

    private sealed class RecordingNativeFileValidationApi : IAuthenticodeFileValidationApi
    {
        public uint MsiOpenResult { get; init; }

        public uint MsiDatabaseHandle { get; init; }

        public Exception? MsiOpenException { get; init; }

        public IntPtr MsiPersistenceMode { get; private set; }

        public int MsiCloseCount { get; private set; }

        public uint LastClosedMsiHandle { get; private set; }

        public IntPtr CatalogHandle { get; init; }

        public Exception? CatalogOpenException { get; init; }

        public IntPtr CatalogMember { get; init; }

        public Exception? CatalogEnumerateException { get; init; }

        public uint CatalogOpenFlags { get; private set; }

        public IntPtr CatalogCryptographicProvider { get; private set; }

        public uint CatalogPublicVersion { get; private set; }

        public uint CatalogEncodingType { get; private set; }

        public int CatalogEnumerateCount { get; private set; }

        public IntPtr LastEnumeratedCatalogHandle { get; private set; }

        public IntPtr LastPreviousCatalogMember { get; private set; }

        public int CatalogCloseCount { get; private set; }

        public IntPtr LastClosedCatalogHandle { get; private set; }

        public uint MsiOpenDatabase(
            string databasePath,
            IntPtr persistenceMode,
            out uint databaseHandle)
        {
            MsiPersistenceMode = persistenceMode;
            if (MsiOpenException is not null)
            {
                throw MsiOpenException;
            }

            databaseHandle = MsiDatabaseHandle;
            return MsiOpenResult;
        }

        public uint MsiCloseHandle(uint handle)
        {
            MsiCloseCount++;
            LastClosedMsiHandle = handle;
            return 0;
        }

        public IntPtr CryptCatOpen(
            string catalogPath,
            uint openFlags,
            IntPtr cryptographicProvider,
            uint publicVersion,
            uint encodingType)
        {
            CatalogOpenFlags = openFlags;
            CatalogCryptographicProvider = cryptographicProvider;
            CatalogPublicVersion = publicVersion;
            CatalogEncodingType = encodingType;
            if (CatalogOpenException is not null)
            {
                throw CatalogOpenException;
            }

            return CatalogHandle;
        }

        public IntPtr CryptCatEnumerateMember(IntPtr catalogHandle, IntPtr previousMember)
        {
            CatalogEnumerateCount++;
            LastEnumeratedCatalogHandle = catalogHandle;
            LastPreviousCatalogMember = previousMember;
            if (CatalogEnumerateException is not null)
            {
                throw CatalogEnumerateException;
            }

            return CatalogMember;
        }

        public bool CryptCatClose(IntPtr catalogHandle)
        {
            CatalogCloseCount++;
            LastClosedCatalogHandle = catalogHandle;
            return true;
        }
    }

    private sealed class RecordingCopier(
        Func<string, string, CancellationToken, Task> callback) : IControlledFileCopier
    {
        public int CallCount { get; private set; }

        public Task CopyAsync(string inputPath, string resultPartPath, CancellationToken cancellationToken)
        {
            CallCount++;
            return callback(inputPath, resultPartPath, cancellationToken);
        }
    }

    private sealed class FixedFileValidator(bool isValid) : IAuthenticodeFileValidator
    {
        public bool IsValid(string path, string extension) => isValid;
    }

    private sealed class FixedMetadataReader(string version, bool isX64) : ISignToolMetadataReader
    {
        public SignToolMetadata Read(string signToolPath) => new(version, isX64);
    }
}
