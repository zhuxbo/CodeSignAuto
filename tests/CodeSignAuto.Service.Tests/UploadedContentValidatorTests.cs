using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class UploadedContentValidatorTests
{
    [Theory]
    [InlineData(".exe")]
    [InlineData(".pdf")]
    public async Task Path_swap_after_no_follow_guard_cannot_substitute_the_parsed_container(string extension)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-SWAP-").FullName;
        try
        {
            var path = Path.Combine(root, "upload" + extension);
            var displaced = path + ".displaced";
            var replacement = extension == ".exe"
                ? await File.ReadAllBytesAsync(typeof(UploadedContentValidatorTests).Assembly.Location)
                : "not-a-pdf"u8.ToArray();
            await File.WriteAllBytesAsync(
                path,
                extension == ".exe" ? "MZ-invalid-original"u8.ToArray() : CreateSinglePagePdf());
            var observer = new SwappingObserver(displaced, replacement);
            var validator = new UploadedContentValidator(
                new AuthenticodeFileValidator(),
                PlatformLocalFileIdentityProvider.Instance,
                observer);
            SigningParameters parameters = extension == ".exe"
                ? new AuthenticodeParameters("52A1B4C9", "sha256", false)
                : new PdfParameters("6F09D233", "sha256", 1, new PdfBox(10, 10, 100, 50), "Signature1", null, null);

            var error = Assert.Throws<ValidationException>(() =>
                validator.Validate(path, extension, parameters));

            Assert.Equal("file_signature_mismatch", error.Code);
            Assert.True(observer.Swapped);
            Assert.True(File.Exists(displaced));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Portable_executable_is_parsed_from_the_guard_without_calling_the_path_validator()
    {
        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-PE-HANDLE-").FullName;
        try
        {
            var path = Path.Combine(root, "upload.exe");
            await File.WriteAllBytesAsync(
                path,
                await File.ReadAllBytesAsync(typeof(UploadedContentValidatorTests).Assembly.Location));
            var pathValidator = new RecordingPathValidator();
            var validator = new UploadedContentValidator(
                pathValidator,
                PlatformLocalFileIdentityProvider.Instance);

            validator.Validate(
                path,
                ".exe",
                new AuthenticodeParameters("52A1B4C9", "sha256", false));

            Assert.Equal(0, pathValidator.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(".msi")]
    [InlineData(".cat")]
    public async Task Native_only_container_types_hold_the_guard_and_require_the_path_validator(string extension)
    {
        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-NATIVE-PATH-").FullName;
        try
        {
            var path = Path.Combine(root, "upload" + extension);
            await File.WriteAllBytesAsync(path, "native-container"u8.ToArray());
            var accepted = new FixedPathValidator(true);
            var validator = new UploadedContentValidator(
                accepted,
                PlatformLocalFileIdentityProvider.Instance);

            validator.Validate(
                path,
                extension,
                new AuthenticodeParameters("52A1B4C9", "sha256", false));

            Assert.Equal([(path, extension)], accepted.Calls);

            var rejected = new FixedPathValidator(false);
            var rejection = new UploadedContentValidator(
                rejected,
                PlatformLocalFileIdentityProvider.Instance);
            var error = Assert.Throws<ValidationException>(() => rejection.Validate(
                path,
                extension,
                new AuthenticodeParameters("52A1B4C9", "sha256", false)));
            Assert.Equal("file_signature_mismatch", error.Code);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Invalid_identity_unsupported_container_and_malformed_pe_fail_closed()
    {
        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-FAIL-CLOSED-").FullName;
        try
        {
            var path = Path.Combine(root, "upload.exe");
            await File.WriteAllBytesAsync(path, "MZ-invalid"u8.ToArray());
            var authenticode = new FixedPathValidator(true);
            var missingIdentity = new UploadedContentValidator(
                authenticode,
                new MissingIdentityProvider());
            Assert.Equal(
                "file_signature_mismatch",
                Assert.Throws<ValidationException>(() => missingIdentity.Validate(
                    path,
                    ".exe",
                    new AuthenticodeParameters("52A1B4C9", "sha256", false))).Code);

            var validator = new UploadedContentValidator(
                authenticode,
                PlatformLocalFileIdentityProvider.Instance);
            Assert.Equal(
                "file_signature_mismatch",
                Assert.Throws<ValidationException>(() => validator.Validate(
                    path,
                    ".exe",
                    new AuthenticodeParameters("52A1B4C9", "sha256", false))).Code);
            Assert.Equal(
                "file_signature_mismatch",
                Assert.Throws<ValidationException>(() => validator.Validate(
                    path,
                    ".unknown",
                    new AuthenticodeParameters("52A1B4C9", "sha256", false))).Code);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Pdf_page_and_box_contract_is_checked_on_the_guard_stream()
    {
        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-PDF-BOUNDS-").FullName;
        try
        {
            var path = Path.Combine(root, "upload.pdf");
            await File.WriteAllBytesAsync(path, CreateSinglePagePdf());
            var validator = new UploadedContentValidator();

            var page = Assert.Throws<ValidationException>(() => validator.Validate(
                path,
                ".pdf",
                new PdfParameters("6F09D233", "sha256", 2, new PdfBox(10, 10, 100, 50), "Signature1", null, null)));
            var box = Assert.Throws<ValidationException>(() => validator.Validate(
                path,
                ".pdf",
                new PdfParameters("6F09D233", "sha256", 1, new PdfBox(10, 10, 700, 50), "Signature1", null, null)));

            Assert.Equal("invalid_parameters", page.Code);
            Assert.Equal("invalid_parameters", box.Code);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [WindowsFact]
    public async Task Native_path_validation_guard_denies_delete_during_the_native_call_window()
    {
        var root = Directory.CreateTempSubdirectory("SSA-UPLOAD-NATIVE-GUARD-").FullName;
        try
        {
            var path = Path.Combine(root, "upload.msi");
            await File.WriteAllBytesAsync(path, "native-path-guard"u8.ToArray());
            var observer = new DeleteAttemptObserver();
            var validator = new UploadedContentValidator(
                new AuthenticodeFileValidator(),
                PlatformLocalFileIdentityProvider.Instance,
                observer);

            var error = Assert.Throws<ValidationException>(() => validator.Validate(
                path,
                ".msi",
                new AuthenticodeParameters("52A1B4C9", "sha256", false)));

            Assert.Equal("file_signature_mismatch", error.Code);
            Assert.True(observer.DeleteWasDenied);
            Assert.True(File.Exists(path));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class SwappingObserver(string displaced, byte[] replacement)
        : IUploadedContentValidationObserver
    {
        public bool Swapped { get; private set; }

        public void AfterGuardOpened(string path, string extension)
        {
            File.Move(path, displaced);
            File.WriteAllBytes(path, replacement);
            Swapped = true;
        }
    }

    private sealed class DeleteAttemptObserver : IUploadedContentValidationObserver
    {
        public bool DeleteWasDenied { get; private set; }

        public void AfterGuardOpened(string path, string extension)
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                DeleteWasDenied = true;
            }
        }
    }

    private sealed class RecordingPathValidator : IAuthenticodeFileValidator
    {
        public int Calls { get; private set; }

        public bool IsValid(string path, string extension)
        {
            Calls++;
            throw new InvalidOperationException("path_validator_must_not_parse_portable_executable");
        }
    }

    private sealed class FixedPathValidator(bool result) : IAuthenticodeFileValidator
    {
        public List<(string Path, string Extension)> Calls { get; } = [];

        public bool IsValid(string path, string extension)
        {
            Calls.Add((path, extension));
            return result;
        }
    }

    private sealed class MissingIdentityProvider : ILocalFileIdentityProvider
    {
        public bool TryGetIdentity(
            Microsoft.Win32.SafeHandles.SafeFileHandle handle,
            out LocalFileIdentity identity)
        {
            identity = default;
            return false;
        }
    }

    private static byte[] CreateSinglePagePdf()
    {
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
        };
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, System.Text.Encoding.ASCII, leaveOpen: true)
        {
            NewLine = "\n",
        };
        writer.WriteLine("%PDF-1.4");
        writer.Flush();
        var offsets = new List<long> { 0 };
        for (var index = 0; index < objects.Length; index++)
        {
            offsets.Add(stream.Position);
            writer.WriteLine($"{index + 1} 0 obj");
            writer.WriteLine(objects[index]);
            writer.WriteLine("endobj");
            writer.Flush();
        }

        var xref = stream.Position;
        writer.WriteLine("xref");
        writer.WriteLine($"0 {objects.Length + 1}");
        writer.WriteLine("0000000000 65535 f ");
        foreach (var offset in offsets.Skip(1))
        {
            writer.WriteLine($"{offset:0000000000} 00000 n ");
        }

        writer.WriteLine("trailer");
        writer.WriteLine($"<< /Size {objects.Length + 1} /Root 1 0 R >>");
        writer.WriteLine("startxref");
        writer.WriteLine(xref);
        writer.WriteLine("%%EOF");
        writer.Flush();
        return stream.ToArray();
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows file sharing semantics.";
            }
        }
    }
}
