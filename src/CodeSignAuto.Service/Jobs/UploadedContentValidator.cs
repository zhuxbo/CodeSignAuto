using System.Reflection.PortableExecutable;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;
using UglyToad.PdfPig;

namespace CodeSignAuto.Service.Jobs;

public interface IUploadedContentValidator
{
    void Validate(string path, string extension, SigningParameters parameters);
}

internal interface IUploadedContentValidationObserver
{
    void AfterGuardOpened(string path, string extension);
}

public sealed class UploadedContentValidator : IUploadedContentValidator
{
    private readonly IAuthenticodeFileValidator _authenticode;
    private readonly ILocalFileIdentityProvider _fileIdentities;
    private readonly IUploadedContentValidationObserver? _observer;

    public UploadedContentValidator()
        : this(new AuthenticodeFileValidator(), PlatformLocalFileIdentityProvider.Instance)
    {
    }

    internal UploadedContentValidator(
        IAuthenticodeFileValidator authenticode,
        ILocalFileIdentityProvider fileIdentities)
        : this(authenticode, fileIdentities, null)
    {
    }

    internal UploadedContentValidator(
        IAuthenticodeFileValidator authenticode,
        ILocalFileIdentityProvider fileIdentities,
        IUploadedContentValidationObserver? observer)
    {
        _authenticode = authenticode ?? throw new ArgumentNullException(nameof(authenticode));
        _fileIdentities = fileIdentities ?? throw new ArgumentNullException(nameof(fileIdentities));
        _observer = observer;
    }

    public void Validate(string path, string extension, SigningParameters parameters)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(extension);
        ArgumentNullException.ThrowIfNull(parameters);
        try
        {
            using var guard = NoFollowFile.OpenRead(path, FileShare.Read, 1024 * 1024);
            if (!_fileIdentities.TryGetIdentity(guard.SafeFileHandle, out var identity) || identity.LinkCount != 1)
            {
                throw new ValidationException("file_signature_mismatch");
            }

            _observer?.AfterGuardOpened(path, extension);
            if (parameters is AuthenticodeParameters && extension is ".exe" or ".dll" or ".sys")
            {
                ValidatePortableExecutable(guard);
            }
            else if (parameters is AuthenticodeParameters && extension is ".msi" or ".cat")
            {
                if (!_authenticode.IsValid(path, extension))
                {
                    throw new ValidationException("file_signature_mismatch");
                }
            }
            else if (parameters is PdfParameters pdf)
            {
                ValidatePdf(guard, pdf);
            }
            else
            {
                throw new ValidationException("file_signature_mismatch");
            }

            VerifyIdentity(guard, identity);
            using var pathReadback = NoFollowFile.OpenRead(path, FileShare.Read, 1024 * 1024);
            VerifyIdentity(pathReadback, identity);
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
            current.LinkCount != 1 || !current.RefersToSameFile(expected))
        {
            throw new ValidationException("file_signature_mismatch");
        }
    }

    private static void ValidatePortableExecutable(Stream input)
    {
        input.Position = 0;
        using var reader = new PEReader(input, PEStreamOptions.LeaveOpen);
        var headers = reader.PEHeaders;
        if (headers.PEHeader is null || headers.CoffHeader.NumberOfSections <= 0 ||
            headers.PEHeader.Magic is not (PEMagic.PE32 or PEMagic.PE32Plus))
        {
            throw new ValidationException("file_signature_mismatch");
        }
    }

    private static void ValidatePdf(Stream input, PdfParameters parameters)
    {
        input.Position = 0;
        using var document = PdfDocument.Open(input);
        if (parameters.Page > document.NumberOfPages)
        {
            throw new ValidationException("invalid_parameters");
        }

        var bounds = document.GetPage(parameters.Page).CropBox.Bounds;
        if (parameters.Box.Left < bounds.Left || parameters.Box.Bottom < bounds.Bottom ||
            parameters.Box.Right > bounds.Right || parameters.Box.Top > bounds.Top)
        {
            throw new ValidationException("invalid_parameters");
        }
    }
}
