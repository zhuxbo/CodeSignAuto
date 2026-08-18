using System.Text.Json;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.App.Tools;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class EmbeddedToolExtractorTests
{
    private const string ProductVersion = "0.16.0";
    private const string HelperVersion = "0.1.0";
    private static readonly string Sha256 = new('a', 64);
    private static readonly string Publisher = new('b', 64);

    [Fact]
    public void Pdf_extension_manifest_accepts_only_the_exact_offline_schema()
    {
        var manifest = PdfExtensionManifestCodec.Decode(ManifestJson());

        Assert.Equal(1, manifest.SchemaVersion);
        Assert.Equal(ProductVersion, manifest.ProductVersion);
        Assert.Equal(HelperVersion, manifest.HelperVersion);
        Assert.Equal(20_597_280, manifest.HelperLength);
        Assert.Equal(Sha256, manifest.HelperSha256);
        Assert.Equal(Publisher, manifest.PublisherCertificateSha256);
    }

    [Fact]
    public void Newer_main_accepts_an_older_pdf_extension_with_the_same_schema()
    {
        var manifest = PdfExtensionManifestCodec.Decode(
            ManifestJson(productVersion: "0.15.0"));

        Assert.Equal(1, manifest.SchemaVersion);
        Assert.Equal("0.15.0", manifest.ProductVersion);
        Assert.Equal(HelperVersion, manifest.HelperVersion);
    }

    [Theory]
    [InlineData("unknown", "true")]
    [InlineData("schemaVersion", "1")]
    public void Pdf_extension_manifest_rejects_unknown_and_duplicate_properties(
        string property,
        string value)
    {
        var json = ManifestJson()[..^1] + $",\"{property}\":{value}}}";

        Assert.Throws<PdfExtensionManifestException>(() =>
            PdfExtensionManifestCodec.Decode(json));
    }

    [Theory]
    [InlineData("productVersion")]
    [InlineData("helperVersion")]
    [InlineData("helperLength")]
    [InlineData("helperSha256")]
    [InlineData("publisherCertificateSha256")]
    public void Pdf_extension_manifest_rejects_missing_properties(string property)
    {
        using var document = JsonDocument.Parse(ManifestJson());
        var values = document.RootElement.EnumerateObject()
            .Where(item => !string.Equals(item.Name, property, StringComparison.Ordinal))
            .ToDictionary(item => item.Name, item => item.Value.Clone(), StringComparer.Ordinal);

        Assert.Throws<PdfExtensionManifestException>(() =>
            PdfExtensionManifestCodec.Decode(JsonSerializer.Serialize(values)));
    }

    [Theory]
    [InlineData("0.16", "0.16.0", 20_597_280, null, null)]
    [InlineData("0.16.0", "0.1", 20_597_280, null, null)]
    [InlineData("0.16.0", "0.1.0", 0, null, null)]
    [InlineData("0.16.0", "0.1.0", -1, null, null)]
    [InlineData("0.16.0", "0.1.0", 20_597_280, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null)]
    [InlineData("0.16.0", "0.1.0", 20_597_280, "abc", null)]
    [InlineData("0.16.0", "0.1.0", 20_597_280, null, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")]
    public void Pdf_extension_manifest_rejects_noncanonical_or_invalid_values(
        string productVersion,
        string helperVersion,
        long helperLength,
        string? sha256,
        string? publisher)
    {
        Assert.Throws<PdfExtensionManifestException>(() =>
            PdfExtensionManifestCodec.Decode(
                ManifestJson(
                    productVersion,
                    helperVersion,
                    helperLength,
                    sha256 ?? Sha256,
                    publisher ?? Publisher)));
    }

    [Theory]
    [InlineData("{\"schemaVersion\":1,//comment\n\"productVersion\":\"0.16.0\"}")]
    [InlineData("{\"schemaVersion\":1,}")]
    public void Pdf_extension_manifest_rejects_comments_and_trailing_commas(string json)
    {
        Assert.Throws<PdfExtensionManifestException>(() =>
            PdfExtensionManifestCodec.Decode(json));
    }

    [WindowsFact]
    public void Pdf_extension_paths_are_fixed_under_program_files()
    {
        var paths = PdfExtensionPaths.FromProgramFiles(@"C:\Program Files");

        Assert.Equal(@"C:\Program Files\SimplySignAuto PDF Support", paths.Root);
        Assert.Equal(@"C:\Program Files\SimplySignAuto PDF Support\extension.json", paths.Manifest);
        Assert.Equal(
            @"C:\Program Files\SimplySignAuto PDF Support\SimplySignPdfSigner.exe",
            paths.Helper);
    }

    [WindowsFact]
    public async Task Product_wide_resolver_returns_not_installed_only_when_extension_root_is_absent()
    {
        var security = new RecordingInstalledPdfToolSecurity(manifestJson: null);
        var resolver = CreateResolver(security);

        var resolution = await resolver.ResolveAsync(CancellationToken.None);

        Assert.Equal(InstalledPdfToolStatus.NotInstalled, resolution.Status);
        Assert.Equal("pdf_support_not_installed", resolution.FailureCode);
        Assert.Null(resolution.Tool);
        Assert.Equal(@"C:\Program Files\SimplySignAuto PDF Support", security.Paths?.Root);
        Assert.Null(security.HelperPath);
    }

    [WindowsFact]
    public async Task Product_wide_resolver_returns_verified_helper_from_fixed_extension_path()
    {
        var security = new RecordingInstalledPdfToolSecurity(ManifestJson());
        var resolver = CreateResolver(security);

        var resolution = await resolver.ResolveAsync(CancellationToken.None);

        Assert.Equal(InstalledPdfToolStatus.Ready, resolution.Status);
        Assert.Equal(string.Empty, resolution.FailureCode);
        Assert.NotNull(resolution.Tool);
        Assert.Equal(
            @"C:\Program Files\SimplySignAuto PDF Support\SimplySignPdfSigner.exe",
            resolution.Tool.ExecutablePath);
        Assert.Equal(Sha256, resolution.Tool.Sha256);
        Assert.Equal(resolution.Tool.ExecutablePath, security.HelperPath);
    }

    [WindowsTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Product_wide_resolver_maps_present_manifest_or_helper_mismatch_to_tampered(
        bool invalidManifest)
    {
        var security = new RecordingInstalledPdfToolSecurity(
            invalidManifest ? "{}" : ManifestJson())
        {
            HelperFailure = invalidManifest ? null : new IOException("fixture"),
        };

        var resolution = await CreateResolver(security).ResolveAsync(CancellationToken.None);

        Assert.Equal(InstalledPdfToolStatus.Tampered, resolution.Status);
        Assert.Equal("pdf_helper_tampered", resolution.FailureCode);
        Assert.Null(resolution.Tool);
    }

    private static string ManifestJson(
        string productVersion = ProductVersion,
        string helperVersion = HelperVersion,
        long helperLength = 20_597_280,
        string? sha256 = null,
        string? publisher = null) => JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            productVersion,
            helperVersion,
            helperLength,
            helperSha256 = sha256 ?? Sha256,
            publisherCertificateSha256 = publisher ?? Publisher,
        });

    private static WindowsInstalledPdfToolResolver CreateResolver(
        IInstalledPdfToolSecurity security) => new(
            @"C:\Program Files",
            security);

    private sealed class RecordingInstalledPdfToolSecurity(string? manifestJson)
        : IInstalledPdfToolSecurity
    {
        public Exception? HelperFailure { get; init; }

        public PdfExtensionPaths? Paths { get; private set; }

        public string? HelperPath { get; private set; }

        public Task<string?> ReadManifestAsync(
            PdfExtensionPaths paths,
            CancellationToken cancellationToken)
        {
            Paths = paths;
            return Task.FromResult(manifestJson);
        }

        public Task VerifyHelperAsync(
            string path,
            PdfExtensionManifest manifest,
            CancellationToken cancellationToken)
        {
            HelperPath = path;
            return HelperFailure is null
                ? Task.CompletedTask
                : Task.FromException(HelperFailure);
        }

        public Task<string?> ReadManifestAsync(
            PdfExtensionPaths paths,
            string signingUserSid,
            CancellationToken cancellationToken) =>
            ReadManifestAsync(paths, cancellationToken);

        public Task VerifyHelperAsync(
            string path,
            PdfExtensionManifest manifest,
            string signingUserSid,
            CancellationToken cancellationToken) =>
            VerifyHelperAsync(path, manifest, cancellationToken);
    }

    private sealed class WindowsTheoryAttribute : TheoryAttribute
    {
        public WindowsTheoryAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows path semantics.";
            }
        }
    }
}
