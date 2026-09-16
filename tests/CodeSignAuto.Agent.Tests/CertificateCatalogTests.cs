using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class CertificateCatalogTests : IDisposable
{

    [Fact]
    public async Task public_certificate_without_private_key_is_not_ready()
    {
        var der = CreateCertificate("CN=Public Certificate", [0x40],
            Now.AddDays(-1), Now.AddDays(30), codeSigning: true, digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(
            der, privateKeyMatch: "missing", privateKeyIdHex: null))));
        using var gate = new SigningOperationGate();
        await using var manager = new SimplySignSessionManager(new ProcessOnlyDriver(), gate, catalog);
        var snapshot = await manager.CheckAsync(SessionTrigger.ManualRefresh, default);
        Assert.Empty(catalog.Current!.BySerialNumber);
        Assert.Equal("private_key_missing", Assert.Single(catalog.DisplaySummaries).UnavailableReason);
        Assert.False(snapshot.Ready);
    }

    private sealed class ProcessOnlyDriver : ISimplySignSessionDriver
    {
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow => Now;
        public SimplySignProcessState CheckProcessOnly() => new(true, 7);
        public Task CloseAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<CodeSignAuto.Core.Otp.OtpauthProfile> LoadOtpAsync(CancellationToken token) => throw new NotSupportedException();
        public Task<long> StartLoginAsync(CodeSignAuto.Core.Otp.OtpauthProfile profile, CancellationToken token) => throw new NotSupportedException();
        public Task WaitForCounterAfterAsync(CodeSignAuto.Core.Otp.OtpauthProfile profile, long counter, CancellationToken token) => throw new NotSupportedException();
        public Task DelayAsync(TimeSpan delay, CancellationToken token) => throw new NotSupportedException();
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 12, 4, 0, 0, TimeSpan.Zero);
    private readonly List<X509Certificate2> _certificates = [];

    [Fact]
    public async Task Refresh_extracts_exact_cn_normalizes_serial_and_computes_sha1_from_der()
    {
        var der = CreateCertificate(
            "OU=Operations,CN=Exact Catalog Name",
            [0x00, 0x52, 0xA1, 0xB4, 0xC9],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var source = new CatalogSource(CatalogJson(Record(der)));
        var catalog = CreateCatalog(source);

        var snapshot = await catalog.RefreshAsync(default);

        var certificate = Assert.Single(snapshot.BySerialNumber["52A1B4C9"]);
        Assert.Equal("Exact Catalog Name", certificate.CommonName);
        Assert.Equal("52A1B4C9", certificate.SerialNumber);
        Assert.Equal(Convert.ToHexString(SHA1.HashData(der)), certificate.Sha1Thumbprint);
        Assert.Equal(TestPaths.Controlled("pkcs11.dll"), certificate.ModulePath);
        Assert.Equal(7UL, certificate.SlotId);
        Assert.Equal("TOKEN-PUBLIC-01", certificate.TokenSerial);
        Assert.Equal("c0ffee01", certificate.CertificateIdHex);
        Assert.Equal("c0ffee01", certificate.PrivateKeyIdHex);
        Assert.True(certificate.SupportsAuthenticode);
        Assert.False(certificate.SupportsPdf);
        Assert.Equal(TestPaths.Controlled("pkcs11.dll"), source.ModulePath);
    }

    [Fact]
    public async Task Refresh_accepts_a_valid_serial_containing_only_hexadecimal_letters()
    {
        var der = CreateCertificate(
            "CN=Letters Only Serial",
            [0xAB, 0xCD],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(der))));

        var snapshot = await catalog.RefreshAsync(default);

        Assert.Equal("ABCD", Assert.Single(snapshot.BySerialNumber).Key);
        Assert.Equal("ABCD", Assert.Single(catalog.DisplaySummaries).SerialNumber);
    }

    [Fact]
    public async Task Missing_or_multiple_exact_cn_uses_stable_display_value_without_hiding_certificate()
    {
        var missing = CreateCertificate(
            "OU=No Common Name",
            [0x10],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var multiple = CreateCertificate(
            "CN=First,CN=Second",
            [0x11],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(missing), Record(multiple, "c0ffee02"))));

        await catalog.RefreshAsync(default);

        Assert.All(catalog.DisplaySummaries, summary => Assert.Equal("（无通用名称）", summary.CommonName));
        Assert.Equal(2, catalog.Current!.BySerialNumber.Count);
    }

    [Fact]
    public async Task Purpose_flags_require_matching_eku_and_digital_signature_key_usage()
    {
        var authenticodeOnly = CreateCertificate(
            "CN=Code Only",
            [0x20],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var pdfOnly = CreateCertificate(
            "CN=PDF Only",
            [0x21],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: false,
            digitalSignature: true);
        var unsupported = CreateCertificate(
            "CN=Unsupported",
            [0x22],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: false,
            digitalSignature: false);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(
            Record(authenticodeOnly),
            Record(pdfOnly, "c0ffee02"),
            Record(unsupported, "c0ffee03"))));

        await catalog.RefreshAsync(default);

        var summaries = catalog.DisplaySummaries.ToDictionary(summary => summary.SerialNumber);
        Assert.True(summaries["20"].AuthenticodeUsable);
        Assert.False(summaries["20"].PdfUsable);
        Assert.False(summaries["21"].AuthenticodeUsable);
        Assert.True(summaries["21"].PdfUsable);
        Assert.False(summaries["22"].AuthenticodeUsable);
        Assert.False(summaries["22"].PdfUsable);
        Assert.Equal("unsupported_purpose", summaries["22"].UnavailableReason);
    }

    [Theory]
    [InlineData(2, 3, "not_yet_valid")]
    [InlineData(-30, -1, "expired")]
    public async Task Certificate_validity_controls_both_signing_purposes(
        int notBeforeDays,
        int notAfterDays,
        string expectedReason)
    {
        var der = CreateCertificate(
            "CN=Validity",
            [0x30],
            Now.AddDays(notBeforeDays),
            Now.AddDays(notAfterDays),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(der))));

        await catalog.RefreshAsync(default);

        var summary = Assert.Single(catalog.DisplaySummaries);
        Assert.False(summary.AuthenticodeUsable);
        Assert.False(summary.PdfUsable);
        Assert.Equal(expectedReason, summary.UnavailableReason);
        var error = Assert.Throws<SigningException>(() => catalog.Resolve(summary.SerialNumber, SigningKind.Pdf));
        Assert.Equal("certificate_not_usable", error.Code);
    }

    [Theory]
    [InlineData("missing", "private_key_missing")]
    [InlineData("ambiguous", "private_key_ambiguous")]
    public async Task Non_unique_private_key_is_displayed_but_never_enters_signing_snapshot(
        string privateKeyMatch,
        string expectedReason)
    {
        var der = CreateCertificate(
            "CN=Public Only",
            [0x40],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(
            der,
            privateKeyMatch: privateKeyMatch,
            privateKeyIdHex: null))));

        var snapshot = await catalog.RefreshAsync(default);

        Assert.Empty(snapshot.BySerialNumber);
        var summary = Assert.Single(catalog.DisplaySummaries);
        Assert.Equal(expectedReason, summary.UnavailableReason);
        Assert.False(summary.AuthenticodeUsable);
        Assert.False(summary.PdfUsable);
    }

    [Fact]
    public async Task Duplicate_serial_is_ambiguous_across_every_public_record_even_when_only_one_has_a_unique_key()
    {
        var first = CreateCertificate(
            "CN=Unique Key",
            [0x50],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var second = CreateCertificate(
            "CN=Missing Key",
            [0x50],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(
            Record(first),
            Record(second, "c0ffee02", "missing", null))));

        var snapshot = await catalog.RefreshAsync(default);

        Assert.Single(snapshot.BySerialNumber["50"]);
        Assert.Contains("50", snapshot.AmbiguousSerialNumbers);
        Assert.All(catalog.DisplaySummaries, summary =>
        {
            Assert.False(summary.AuthenticodeUsable);
            Assert.False(summary.PdfUsable);
            Assert.Equal("certificate_serial_ambiguous", summary.UnavailableReason);
        });
        var error = Assert.Throws<SigningException>(() => catalog.Resolve("50", SigningKind.Authenticode));
        Assert.Equal("certificate_serial_ambiguous", error.Code);
        var snapshotError = Assert.Throws<SigningException>(() =>
            snapshot.Resolve("0050", SigningKind.Authenticode, Now));
        Assert.Equal("certificate_serial_ambiguous", snapshotError.Code);
    }

    [Fact]
    public void Snapshot_defensively_copies_ambiguous_serial_numbers()
    {
        var mutable = new HashSet<string>(StringComparer.Ordinal) { "50" };
        var snapshot = new CertificateCatalogSnapshot(
            1,
            Now,
            new ReadOnlyDictionary<string, IReadOnlyList<SigningCertificate>>(
                new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal)),
            mutable);

        mutable.Clear();

        Assert.Contains("50", snapshot.AmbiguousSerialNumbers);
    }

    [Fact]
    public async Task Resolve_returns_stable_codes_for_unavailable_missing_ambiguous_and_unsupported_certificates()
    {
        var unique = CreateCertificate(
            "CN=PDF",
            [0x60],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: false,
            digitalSignature: true);
        var duplicateOne = CreateCertificate(
            "CN=Duplicate One",
            [0x61],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var duplicateTwo = CreateCertificate(
            "CN=Duplicate Two",
            [0x61],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(
            Record(unique),
            Record(duplicateOne, "c0ffee02"),
            Record(duplicateTwo, "c0ffee03"))));

        Assert.Equal(
            "certificate_catalog_unavailable",
            Assert.Throws<SigningException>(() => catalog.Resolve("60", SigningKind.Pdf)).Code);
        await catalog.RefreshAsync(default);
        Assert.Equal("60", catalog.Resolve("0060", SigningKind.Pdf).SerialNumber);
        Assert.Equal(
            "certificate_not_usable",
            Assert.Throws<SigningException>(() => catalog.Resolve("60", SigningKind.Authenticode)).Code);
        Assert.Equal(
            "certificate_not_found",
            Assert.Throws<SigningException>(() => catalog.Resolve("62", SigningKind.Pdf)).Code);
        Assert.Equal(
            "certificate_serial_ambiguous",
            Assert.Throws<SigningException>(() => catalog.Resolve("61", SigningKind.Pdf)).Code);
    }

    [Fact]
    public async Task Failed_refresh_does_not_publish_partial_snapshot_or_replace_last_summaries()
    {
        var first = CreateCertificate(
            "CN=First Generation",
            [0x70],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var second = CreateCertificate(
            "CN=Would Be Partial",
            [0x71],
            Now.AddDays(-1),
            Now.AddDays(30),
            codeSigning: true,
            digitalSignature: true);
        var source = new CatalogSource(
            CatalogJson(Record(first)),
            CatalogJson(Record(second), Record([0x01, 0x02, 0x03], "c0ffee02")));
        var catalog = CreateCatalog(source);
        var original = await catalog.RefreshAsync(default);
        var originalSummaries = catalog.DisplaySummaries;

        var error = await Assert.ThrowsAsync<SigningException>(() => catalog.RefreshAsync(default));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
        Assert.Same(original, catalog.Current);
        Assert.Same(originalSummaries, catalog.DisplaySummaries);
        Assert.Equal(1, catalog.Current!.Generation);
        Assert.Equal("70", Assert.Single(catalog.Current.BySerialNumber).Key);
    }

    [Fact]
    public async Task Successful_refresh_atomically_replaces_snapshot_and_increments_generation()
    {
        var first = CreateCertificate("CN=First", [0x80], Now.AddDays(-1), Now.AddDays(30), true, true);
        var second = CreateCertificate("CN=Second", [0x81], Now.AddDays(-1), Now.AddDays(30), true, true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(first)), CatalogJson(Record(second))));

        var generationOne = await catalog.RefreshAsync(default);
        var generationTwo = await catalog.RefreshAsync(default);

        Assert.Equal(1, generationOne.Generation);
        Assert.Equal(2, generationTwo.Generation);
        Assert.Equal("80", Assert.Single(generationOne.BySerialNumber).Key);
        Assert.Equal("81", Assert.Single(generationTwo.BySerialNumber).Key);
        Assert.Same(generationTwo, catalog.Current);
    }

    [Fact]
    public async Task Empty_success_response_does_not_publish_a_ready_catalog()
    {
        var catalog = CreateCatalog(new CatalogSource(CatalogJson()));

        var error = await Assert.ThrowsAsync<SigningException>(() => catalog.RefreshAsync(default));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
        Assert.Null(catalog.Current);
        Assert.Empty(catalog.DisplaySummaries);
    }

    [Fact]
    public async Task Invalidate_clears_signing_snapshot_and_retains_only_stale_public_summaries()
    {
        var der = CreateCertificate("CN=Stale", [0x90], Now.AddDays(-1), Now.AddDays(30), true, true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(der))));
        await catalog.RefreshAsync(default);

        catalog.Invalidate();

        Assert.Null(catalog.Current);
        var summary = Assert.Single(catalog.DisplaySummaries);
        Assert.Equal("Stale", summary.CommonName);
        Assert.False(summary.CatalogCurrent);
        Assert.False(summary.AuthenticodeUsable);
        Assert.False(summary.PdfUsable);
        Assert.Equal("catalog_stale", summary.UnavailableReason);
        var error = Assert.Throws<SigningException>(() => catalog.Resolve("90", SigningKind.Pdf));
        Assert.Equal("certificate_catalog_unavailable", error.Code);
    }

    [Fact]
    public async Task Invalidate_during_refresh_prevents_late_snapshot_publication_and_keeps_summaries_stale()
    {
        var first = CreateCertificate("CN=Current", [0x91], Now.AddDays(-1), Now.AddDays(30), true, true);
        var late = CreateCertificate("CN=Late", [0x92], Now.AddDays(-1), Now.AddDays(30), true, true);
        var source = new BlockingSecondCatalogSource(
            CatalogJson(Record(first)),
            CatalogJson(Record(late)));
        var catalog = CreateCatalog(source);
        _ = await catalog.RefreshAsync(default);

        var refresh = catalog.RefreshAsync(default);
        await source.SecondReadEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        catalog.Invalidate();
        source.ReleaseSecondRead.TrySetResult();

        var failure = await Assert.ThrowsAsync<SigningException>(() => refresh);
        Assert.Equal("certificate_catalog_unavailable", failure.Code);
        Assert.Null(catalog.Current);
        var stale = Assert.Single(catalog.DisplaySummaries);
        Assert.Equal("Current", stale.CommonName);
        Assert.False(stale.CatalogCurrent);
        Assert.False(stale.AuthenticodeUsable);
        Assert.False(stale.PdfUsable);
        Assert.Equal("catalog_stale", stale.UnavailableReason);
    }

    [Fact]
    public async Task Public_summary_projection_contains_no_internal_locator_or_der_fields()
    {
        var der = CreateCertificate("CN=Public", [0xA0], Now.AddDays(-1), Now.AddDays(30), true, true);
        var catalog = CreateCatalog(new CatalogSource(CatalogJson(Record(der))));

        await catalog.RefreshAsync(default);

        var json = JsonSerializer.Serialize(catalog.DisplaySummaries);
        Assert.DoesNotContain(Convert.ToBase64String(der), json, StringComparison.Ordinal);
        Assert.DoesNotContain("pkcs11.dll", json, StringComparison.Ordinal);
        Assert.DoesNotContain("TOKEN-PUBLIC-01", json, StringComparison.Ordinal);
        Assert.DoesNotContain("c0ffee01", json, StringComparison.Ordinal);
        Assert.Equal(
            [
                "AuthenticodeUsable", "CatalogCurrent", "CommonName", "NotAfterUtc", "NotBeforeUtc",
                "PdfUsable", "SerialNumber", "UnavailableReason",
            ],
            typeof(CertificateDisplaySummary).GetProperties().Select(property => property.Name).Order().ToArray());
    }

    [Theory]
    [InlineData("duplicate_top_level")]
    [InlineData("unknown_record_field")]
    [InlineData("unique_without_private_key")]
    [InlineData("missing_with_private_key")]
    public async Task Strict_schema_rejects_duplicate_unknown_or_inconsistent_catalog_fields(string mutation)
    {
        var der = CreateCertificate("CN=Schema", [0xB0], Now.AddDays(-1), Now.AddDays(30), true, true);
        var valid = CatalogJson(Record(der));
        var invalid = mutation switch
        {
            "duplicate_top_level" => valid.Replace("\"ok\":true", "\"ok\":true,\"ok\":true", StringComparison.Ordinal),
            "unknown_record_field" => valid.Replace("\"slotId\":7", "\"slotId\":7,\"label\":\"secret\"", StringComparison.Ordinal),
            "unique_without_private_key" => valid.Replace("\"privateKeyIdHex\":\"c0ffee01\"", "\"privateKeyIdHex\":null", StringComparison.Ordinal),
            _ => valid
                .Replace("\"privateKeyMatch\":\"unique\"", "\"privateKeyMatch\":\"missing\"", StringComparison.Ordinal),
        };
        var catalog = CreateCatalog(new CatalogSource(invalid));

        var error = await Assert.ThrowsAsync<SigningException>(() => catalog.RefreshAsync(default));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
        Assert.Null(catalog.Current);
        Assert.Empty(catalog.DisplaySummaries);
    }

    [Fact]
    public async Task Parser_failure_reports_the_original_exception_without_changing_the_stable_error_code()
    {
        var diagnostics = new RecordingAgentDiagnosticSink();
        var catalog = new CertificateCatalog(
            new CatalogSource("{\"ok\":true,\"certificates\":not-json}"),
            TestPaths.Controlled("pkcs11.dll"),
            new FixedTimeProvider(Now),
            diagnostics);

        var error = await Assert.ThrowsAsync<SigningException>(() => catalog.RefreshAsync(default));

        Assert.Equal("certificate_catalog_unavailable", error.Code);
        var diagnostic = Assert.Single(diagnostics.Diagnostics);
        Assert.Equal("certificate_catalog_parse", diagnostic.Stage);
        Assert.Equal("certificate_catalog_unavailable", diagnostic.StableCode);
        Assert.IsAssignableFrom<JsonException>(diagnostic.Exception);
    }

    public void Dispose()
    {
        foreach (var certificate in _certificates)
        {
            certificate.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private CertificateCatalog CreateCatalog(ICertificateCatalogSource source) =>
        new(source, TestPaths.Controlled("pkcs11.dll"), new FixedTimeProvider(Now));

    private byte[] CreateCertificate(
        string subject,
        byte[] serial,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool codeSigning,
        bool digitalSignature)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            new X500DistinguishedName(subject),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            digitalSignature ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyEncipherment,
            true));
        if (codeSigning)
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.3") },
                true));
        }
        else
        {
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.2.840.113583.1.1.5") },
                true));
        }

        using var issuer = request.CreateSelfSigned(Now.AddDays(-365), Now.AddDays(365));
        var certificate = request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1), notBefore, notAfter, serial);
        _certificates.Add(certificate);
        return certificate.Export(X509ContentType.Cert);
    }

    private static object Record(
        byte[] der,
        string certificateIdHex = "c0ffee01",
        string privateKeyMatch = "unique",
        string? privateKeyIdHex = "c0ffee01") =>
        new
        {
            slotId = 7,
            tokenSerial = "TOKEN-PUBLIC-01",
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

    private sealed class CatalogSource(params string[] results) : ICertificateCatalogSource
    {
        private readonly Queue<string> _results = new(results);

        public string? ModulePath { get; private set; }

        public Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ModulePath = modulePath;
            return Task.FromResult(_results.Dequeue());
        }
    }

    private sealed class BlockingSecondCatalogSource(string first, string second) : ICertificateCatalogSource
    {
        private int _calls;

        public TaskCompletionSource SecondReadEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseSecondRead { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                return first;
            }

            SecondReadEntered.TrySetResult();
            await ReleaseSecondRead.Task.WaitAsync(cancellationToken);
            return second;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
