using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using UglyToad.PdfPig;

namespace SimplySignAuto.Service.Jobs;

public interface ILocalUploadContentValidator
{
    void Validate(LocalUploadFile upload, SigningParameters parameters);
}

public sealed class LocalUploadContentValidator : ILocalUploadContentValidator
{
    private readonly IAuthenticodeFileValidator _authenticode;
    private readonly ILocalFileIdentityProvider _fileIdentities;

    public LocalUploadContentValidator(IAuthenticodeFileValidator? authenticode = null)
        : this(authenticode, PlatformLocalFileIdentityProvider.Instance)
    {
    }

    internal LocalUploadContentValidator(
        IAuthenticodeFileValidator? authenticode,
        ILocalFileIdentityProvider fileIdentities)
    {
        _authenticode = authenticode ?? new AuthenticodeFileValidator();
        _fileIdentities = fileIdentities ?? throw new ArgumentNullException(nameof(fileIdentities));
    }

    public void Validate(LocalUploadFile upload, SigningParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(upload);
        ArgumentNullException.ThrowIfNull(parameters);
        switch (parameters)
        {
            case AuthenticodeParameters when upload.Extension is ".msi" or ".cat":
                ValidateNativePath(upload);
                break;
            case PdfParameters pdf:
                ValidatePdf(upload.Stream, pdf);
                break;
        }
    }

    private void ValidateNativePath(LocalUploadFile upload)
    {
        try
        {
            using var guard = NoFollowFile.OpenRead(upload.Path, FileShare.Read, 1024 * 1024);
            VerifyIdentity(guard, upload.Identity);
            if (!_authenticode.IsValid(upload.Path, upload.Extension))
            {
                throw new ValidationException("file_signature_mismatch");
            }

            VerifyIdentity(guard, upload.Identity);
            using var pathReadback = NoFollowFile.OpenRead(upload.Path, FileShare.Read, 1024 * 1024);
            VerifyIdentity(pathReadback, upload.Identity);
        }
        catch (ValidationException)
        {
            throw;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            throw new ValidationException("file_signature_mismatch");
        }
    }

    private void VerifyIdentity(FileStream stream, LocalFileIdentity expected)
    {
        if (!_fileIdentities.TryGetIdentity(stream.SafeFileHandle, out var current) ||
            current.LinkCount != 1 ||
            !current.RefersToSameFile(expected))
        {
            throw new ValidationException("file_signature_mismatch");
        }
    }

    private static void ValidatePdf(Stream input, PdfParameters parameters)
    {
        input.Position = 0;
        try
        {
            using var document = PdfDocument.Open(new NonDisposingStream(input));
            if (parameters.Page > document.NumberOfPages)
            {
                throw new ValidationException("invalid_parameters");
            }

            var page = document.GetPage(parameters.Page);
            var bounds = page.CropBox.Bounds;
            if (parameters.Box.Left < bounds.Left || parameters.Box.Bottom < bounds.Bottom ||
                parameters.Box.Right > bounds.Right || parameters.Box.Top > bounds.Top)
            {
                throw new ValidationException("invalid_parameters");
            }
        }
        catch (ValidationException)
        {
            throw;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            throw new ValidationException("file_signature_mismatch");
        }
        finally
        {
            input.Position = 0;
        }
    }

    private sealed class NonDisposingStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        protected override void Dispose(bool disposing)
        {
        }
    }
}
