using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Core.Versioning;

namespace CodeSignAuto.App.Tools;

internal sealed record PdfExtensionManifest(
    int SchemaVersion,
    string ProductVersion,
    string HelperVersion,
    long HelperLength,
    string HelperSha256,
    string PublisherCertificateSha256);

internal sealed record PdfExtensionPaths(
    string Root,
    string Manifest,
    string Helper,
    string License,
    string ThirdPartyNotices)
{
    internal static PdfExtensionPaths FromProgramFiles(string programFilesRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(programFilesRoot);
        if (!Path.IsPathFullyQualified(programFilesRoot) || programFilesRoot.Any(char.IsControl))
        {
            throw new ArgumentException("pdf_extension_path_invalid", nameof(programFilesRoot));
        }

        var root = Path.GetFullPath(Path.Combine(programFilesRoot, "CodeSignAuto PDF Support"));
        return new PdfExtensionPaths(
            root,
            Path.Combine(root, "extension.json"),
            Path.Combine(root, "CodeSignAutoPdfSigner.exe"),
            Path.Combine(root, "LICENSE.txt"),
            Path.Combine(root, "THIRD-PARTY-NOTICES.txt"));
    }
}

internal sealed class PdfExtensionManifestException : Exception
{
    internal PdfExtensionManifestException()
        : base("pdf_extension_manifest_invalid")
    {
    }

    internal PdfExtensionManifestException(Exception innerException)
        : base("pdf_extension_manifest_invalid", innerException)
    {
    }
}

internal static class PdfExtensionManifestCodec
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    internal static PdfExtensionManifest Decode(string json)
    {
        try
        {
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            var manifest = JsonSerializer.Deserialize<PdfExtensionManifest>(json, SerializerOptions);
            if (manifest is null ||
                manifest.SchemaVersion != 1 ||
                !TryParseCanonicalVersion(manifest.ProductVersion) ||
                !TryParseCanonicalVersion(manifest.HelperVersion) ||
                manifest.HelperLength <= 0 ||
                !IsLowerHex(manifest.HelperSha256, 64) ||
                !IsLowerHex(manifest.PublisherCertificateSha256, 64))
            {
                throw new PdfExtensionManifestException();
            }

            return manifest;
        }
        catch (PdfExtensionManifestException)
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException
                or ArgumentException
                or FormatException
                or NotSupportedException)
        {
            throw new PdfExtensionManifestException(error);
        }
    }

    private static bool TryParseCanonicalVersion(string? value) =>
        ProductVersion.TryParse(value, out var parsed) &&
        parsed is not null &&
        string.Equals(parsed.Identity, value, StringComparison.Ordinal);

    private static bool IsLowerHex(string? value, int length) =>
        value is not null &&
        value.Length == length &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
