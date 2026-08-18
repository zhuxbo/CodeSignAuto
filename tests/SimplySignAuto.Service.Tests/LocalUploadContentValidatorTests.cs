using System.Security.Cryptography;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class LocalUploadContentValidatorTests
{
    [Fact]
    public async Task Native_path_exchange_is_rejected_against_the_hashed_upload_identity()
    {
        using var fixture = new Fixture();
        var jobId = Guid.NewGuid();
        var original = new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 1, 2, 3 };
        var partPath = fixture.Spool.GetInputPath(jobId, ".msi") + ".part";
        await File.WriteAllBytesAsync(partPath, original);
        await using var upload = await fixture.Spool.OpenLocalUploadAsync(jobId, ".msi");
        var displaced = partPath + ".displaced";
        var native = new ExchangingAuthenticodeValidator(displaced);
        var validator = new LocalUploadContentValidator(native);

        var error = Assert.Throws<ValidationException>(() => validator.Validate(
            upload,
            new AuthenticodeParameters("52A1B4C9", "sha256", false)));

        Assert.Equal("file_signature_mismatch", error.Code);
        if (OperatingSystem.IsWindows())
        {
            Assert.True(native.ExchangeWasDenied);
            Assert.False(File.Exists(displaced));
            Assert.Equal(original, await File.ReadAllBytesAsync(partPath));
        }
        else
        {
            Assert.False(native.ExchangeWasDenied);
            Assert.Equal(original, await File.ReadAllBytesAsync(displaced));
            Assert.Equal(
                SHA256.HashData("replacement"u8.ToArray()),
                SHA256.HashData(await File.ReadAllBytesAsync(partPath)));
        }
    }

    [Fact]
    public async Task Native_path_exchange_before_guard_is_rejected_against_the_open_upload_identity()
    {
        using var fixture = new Fixture();
        var jobId = Guid.NewGuid();
        var original = "original"u8.ToArray();
        var replacement = "replacement"u8.ToArray();
        var partPath = fixture.Spool.GetInputPath(jobId, ".msi") + ".part";
        await File.WriteAllBytesAsync(partPath, original);
        await using var upload = await fixture.Spool.OpenLocalUploadAsync(jobId, ".msi");
        var displaced = partPath + ".displaced";
        File.Move(partPath, displaced);
        await File.WriteAllBytesAsync(partPath, replacement);
        var native = new FixedAuthenticodeValidator(true);
        var validator = new LocalUploadContentValidator(native);

        var error = Assert.Throws<ValidationException>(() => validator.Validate(
            upload,
            new AuthenticodeParameters("52A1B4C9", "sha256", false)));

        Assert.Equal("file_signature_mismatch", error.Code);
        Assert.Empty(native.Calls);
        Assert.Equal(original, await File.ReadAllBytesAsync(displaced));
        Assert.Equal(replacement, await File.ReadAllBytesAsync(partPath));
    }

    [Theory]
    [InlineData(".msi")]
    [InlineData(".cat")]
    public async Task Native_local_upload_requires_a_valid_path_container_without_losing_the_upload_handle(
        string extension)
    {
        using var fixture = new Fixture();
        await using var upload = await fixture.PrepareUploadAsync(extension, "native-local"u8.ToArray());
        var accepted = new FixedAuthenticodeValidator(true);
        var validator = new LocalUploadContentValidator(accepted);

        validator.Validate(
            upload,
            new AuthenticodeParameters("52A1B4C9", "sha256", false));

        Assert.Equal([(upload.Path, extension)], accepted.Calls);
        var rejected = new LocalUploadContentValidator(new FixedAuthenticodeValidator(false));
        Assert.Equal(
            "file_signature_mismatch",
            Assert.Throws<ValidationException>(() => rejected.Validate(
                upload,
                new AuthenticodeParameters("52A1B4C9", "sha256", false))).Code);
    }

    [Fact]
    public async Task Local_pdf_validation_restores_the_upload_stream_after_success_and_failures()
    {
        using var fixture = new Fixture();
        await using var upload = await fixture.PrepareUploadAsync(".pdf", CreateSinglePagePdf());
        var validator = new LocalUploadContentValidator();
        var valid = new PdfParameters(
            "6F09D233",
            "sha256",
            1,
            new PdfBox(10, 10, 100, 50),
            "Signature1",
            null,
            null);

        validator.Validate(upload, valid);
        Assert.Equal(0, upload.Stream.Position);

        var page = Assert.Throws<ValidationException>(() => validator.Validate(
            upload,
            valid with { Page = 2 }));
        var box = Assert.Throws<ValidationException>(() => validator.Validate(
            upload,
            valid with { Box = new PdfBox(10, 10, 700, 50) }));

        Assert.Equal("invalid_parameters", page.Code);
        Assert.Equal("invalid_parameters", box.Code);
        Assert.Equal(0, upload.Stream.Position);
    }

    [Fact]
    public async Task Malformed_local_pdf_and_missing_identity_fail_closed()
    {
        using var fixture = new Fixture();
        await using var upload = await fixture.PrepareUploadAsync(".pdf", "not-a-pdf"u8.ToArray());
        var parameters = new PdfParameters(
            "6F09D233",
            "sha256",
            1,
            new PdfBox(10, 10, 100, 50),
            "Signature1",
            null,
            null);
        var malformed = new LocalUploadContentValidator();

        Assert.Equal(
            "file_signature_mismatch",
            Assert.Throws<ValidationException>(() => malformed.Validate(upload, parameters)).Code);

        var missingIdentity = new LocalUploadContentValidator(
            new FixedAuthenticodeValidator(true),
            new MissingIdentityProvider());
        await using var native = await fixture.PrepareUploadAsync(".msi", "native"u8.ToArray());
        Assert.Equal(
            "file_signature_mismatch",
            Assert.Throws<ValidationException>(() => missingIdentity.Validate(
                native,
                new AuthenticodeParameters("52A1B4C9", "sha256", false))).Code);
    }

    private sealed class ExchangingAuthenticodeValidator(string displaced) : IAuthenticodeFileValidator
    {
        public bool ExchangeWasDenied { get; private set; }

        public bool IsValid(string path, string extension)
        {
            try
            {
                File.Move(path, displaced);
            }
            catch (IOException)
            {
                ExchangeWasDenied = true;
                throw;
            }

            File.WriteAllText(path, "replacement");
            return true;
        }
    }

    private sealed class FixedAuthenticodeValidator(bool result) : IAuthenticodeFileValidator
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

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto-validator-" + Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            Spool = new SpoolStore(Path.Combine(_root, "spool"));
        }

        public SpoolStore Spool { get; }

        public async Task<LocalUploadFile> PrepareUploadAsync(string extension, byte[] bytes)
        {
            var jobId = Guid.NewGuid();
            var partPath = Spool.GetInputPath(jobId, extension) + ".part";
            await File.WriteAllBytesAsync(partPath, bytes);
            return await Spool.OpenLocalUploadAsync(jobId, extension);
        }

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
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
}
