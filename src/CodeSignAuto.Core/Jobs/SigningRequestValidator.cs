using System.Collections.Frozen;

namespace CodeSignAuto.Core.Jobs;

public enum FileKind
{
    Authenticode,
    Pdf,
}

public sealed class ValidationException : Exception
{
    public ValidationException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

public static class SigningRequestValidator
{
    private static readonly FrozenSet<string> AuthenticodeExtensions =
        new[] { ".exe", ".dll", ".msi", ".sys", ".cat" }
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public static FileKind ValidateFile(string originalName, ReadOnlySpan<byte> prefix)
    {
        var kind = ValidateExtension(originalName);
        var extension = Path.GetExtension(Path.GetFileName(originalName)).ToLowerInvariant();
        if (kind == FileKind.Pdf)
        {
            return prefix.StartsWith("%PDF-"u8)
                ? FileKind.Pdf
                : throw new ValidationException("file_signature_mismatch");
        }

        if (extension is ".exe" or ".dll" or ".sys")
        {
            return prefix.StartsWith("MZ"u8)
                ? FileKind.Authenticode
                : throw new ValidationException("file_signature_mismatch");
        }

        return FileKind.Authenticode;
    }

    public static FileKind ValidateExtension(string originalName)
    {
        var extension = Path.GetExtension(Path.GetFileName(originalName)).ToLowerInvariant();
        if (extension == ".pdf")
        {
            return FileKind.Pdf;
        }

        return AuthenticodeExtensions.Contains(extension)
            ? FileKind.Authenticode
            : throw new ValidationException("unsupported_type");
    }
}
