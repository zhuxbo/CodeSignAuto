using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Agent.SimplySign;

public static class Pkcs11HelperHost
{
    public static Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default) =>
        Pkcs11HelperCommand.ExecuteAsync(
            args,
            output,
            error,
            new Pkcs11InteropHelperBackend(),
            cancellationToken);
}

internal interface IPkcs11HelperBackend
{
    IPkcs11HelperLibrary Load(string modulePath);
}

internal interface IPkcs11HelperLibrary : IDisposable
{
    IEnumerable<IPkcs11HelperSlot> GetSlots();
}

internal interface IPkcs11HelperSlot
{
    ulong SlotId { get; }

    string TokenSerial { get; }

    IPkcs11HelperSession OpenSession();
}

internal interface IPkcs11HelperSession : IDisposable
{
    IEnumerable<Pkcs11HelperObject> FindCertificates(byte[]? id);

    IEnumerable<Pkcs11HelperObject> FindPrivateKeys(byte[] id);
}

internal sealed record Pkcs11HelperObject(byte[]? Id, byte[]? Value);

internal static class Pkcs11HelperCommand
{
    private const int MaximumRequestBytes = 64 * 1024;
    private const int MaximumSlots = 32;
    private const int MaximumCertificates = 256;
    private const int MaximumIdentifierBytes = 128;
    private const int MaximumCertificateBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static Task<int> ExecuteAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        IPkcs11HelperBackend backend,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(backend);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            if (args.Length != 3 || args[1] != "--request" ||
                args[0] is not ("catalog" or "probe") ||
                string.IsNullOrWhiteSpace(args[2]) ||
                !Path.IsPathFullyQualified(args[2]))
            {
                return WriteAsync(output, InvalidRequest(), 2);
            }

            var requestJson = ReadRequest(args[2]);
            cancellationToken.ThrowIfCancellationRequested();
            return args[0] == "catalog"
                ? WriteAsync(output, ExecuteCatalog(requestJson, backend, cancellationToken), 0)
                : WriteAsync(output, ExecuteProbe(requestJson, backend, cancellationToken), 0);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception requestError) when (
            requestError is JsonException or IOException or UnauthorizedAccessException)
        {
            return WriteAsync(output, InvalidRequest(), 2);
        }
        catch (Pkcs11HelperContractException)
        {
            var response = args.Length > 0 && args[0] == "catalog"
                ? CatalogFailure("certificate_catalog_invalid")
                : ProbeFailure("pkcs11_unavailable");
            return WriteAsync(output, response, args.Length > 0 && args[0] == "catalog" ? 0 : 10);
        }
        catch (Pkcs11HelperTokenMissingException)
        {
            var response = args.Length > 0 && args[0] == "catalog"
                ? CatalogFailure("token_missing")
                : ProbeFailure("pkcs11_unavailable");
            return WriteAsync(output, response, args.Length > 0 && args[0] == "catalog" ? 0 : 10);
        }
        catch (Pkcs11HelperSessionLostException)
        {
            var response = args.Length > 0 && args[0] == "catalog"
                ? CatalogFailure("pkcs11_session_lost")
                : ProbeFailure("pkcs11_unavailable");
            return WriteAsync(output, response, 10);
        }
        catch (Pkcs11HelperProbeUnavailableException probeFailure)
        {
            return WriteAsync(
                output,
                ProbeFailure(
                    "pkcs11_unavailable",
                    probeFailure.TokenPresent,
                    probeFailure.CertificatePresent),
                10);
        }
        catch (Pkcs11HelperNativeUnavailableException)
        {
            var response = args.Length > 0 && args[0] == "catalog"
                ? CatalogFailure("pkcs11_unavailable")
                : ProbeFailure("pkcs11_unavailable");
            return WriteAsync(output, response, 10);
        }
        catch (Exception)
        {
            var response = args.Length > 0 && args[0] == "catalog"
                ? CatalogFailure("catalog_unexpected_error")
                : ProbeFailure("pkcs11_unavailable");
            return WriteAsync(output, response, 10);
        }
    }

    private static string ReadRequest(string requestPath)
    {
        var fullPath = Path.GetFullPath(requestPath);
        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.SequentialScan);
        if (stream.Length is <= 0 or > MaximumRequestBytes)
        {
            throw new JsonException();
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
        {
            throw new JsonException();
        }

        var json = StrictUtf8.GetString(bytes);
        StrictJson.RejectDuplicateProperties(json);
        return json;
    }

    private static object ExecuteCatalog(
        string json,
        IPkcs11HelperBackend backend,
        CancellationToken cancellationToken)
    {
        var request = JsonSerializer.Deserialize<CatalogRequest>(json, SerializerOptions)
            ?? throw new JsonException();
        ValidateModulePath(request.ModulePath);
        var records = new List<CatalogRecord>();
        var identities = new HashSet<string>(StringComparer.Ordinal);
        var slotCount = 0;

        using var library = backend.Load(Path.GetFullPath(request.ModulePath));
        foreach (var slot in library.GetSlots().Take(MaximumSlots + 1))
        {
            cancellationToken.ThrowIfCancellationRequested();
            slotCount++;
            if (slotCount > MaximumSlots)
            {
                return CatalogFailure("certificate_catalog_invalid");
            }

            if (!TryNormalizeTokenSerial(slot.TokenSerial, out var tokenSerial))
            {
                return CatalogFailure("certificate_catalog_invalid");
            }

            using var session = slot.OpenSession();
            foreach (var item in session.FindCertificates(null).Take(MaximumCertificates + 1))
            {
                if (records.Count == MaximumCertificates ||
                    !TryValidateCertificate(item, out var certificateId, out var der))
                {
                    return CatalogFailure("certificate_catalog_invalid");
                }

                var identity = string.Concat(
                    slot.SlotId.ToString(System.Globalization.CultureInfo.InvariantCulture), ":",
                    Convert.ToHexString(certificateId), ":",
                    Convert.ToHexString(SHA256.HashData(der)));
                if (!identities.Add(identity))
                {
                    return CatalogFailure("certificate_catalog_invalid");
                }

                var keys = session.FindPrivateKeys(certificateId).Take(2).ToArray();
                if (keys.Any(key => key.Id is null || !key.Id.AsSpan().SequenceEqual(certificateId)))
                {
                    return CatalogFailure("certificate_catalog_invalid");
                }

                var privateKeyMatch = keys.Length switch
                {
                    0 => "missing",
                    1 => "unique",
                    _ => "ambiguous",
                };
                records.Add(new CatalogRecord(
                    slot.SlotId,
                    tokenSerial,
                    Convert.ToHexString(certificateId).ToLowerInvariant(),
                    privateKeyMatch,
                    keys.Length == 1 ? Convert.ToHexString(keys[0].Id!).ToLowerInvariant() : null,
                    Convert.ToBase64String(der)));
            }
        }

        if (slotCount == 0)
        {
            return CatalogFailure("token_missing");
        }

        return new CatalogResponse(true, null, records);
    }

    private static object ExecuteProbe(
        string json,
        IPkcs11HelperBackend backend,
        CancellationToken cancellationToken)
    {
        var request = JsonSerializer.Deserialize<ProbeRequest>(json, SerializerOptions)
            ?? throw new JsonException();
        ValidateModulePath(request.ModulePath);
        if (!IsTokenSerial(request.TokenSerial) ||
            !TryDecodeIdentifier(request.CertificateIdHex, out var certificateId) ||
            !TryDecodeIdentifier(request.PrivateKeyIdHex, out var privateKeyId))
        {
            throw new JsonException();
        }

        var tokenPresent = false;
        var certificatePresent = false;
        try
        {
            using var library = backend.Load(Path.GetFullPath(request.ModulePath));
            var slots = library.GetSlots().Take(MaximumSlots + 1).ToArray();
            if (slots.Length > MaximumSlots)
            {
                return ProbeFailure("probe_failed");
            }

            var slot = slots.SingleOrDefault(candidate => candidate.SlotId == request.SlotId);
            if (slot is null)
            {
                return ProbeFailure("token_missing");
            }

            if (!TryNormalizeTokenSerial(slot.TokenSerial, out var tokenSerial) ||
                !string.Equals(tokenSerial, request.TokenSerial, StringComparison.Ordinal))
            {
                return ProbeFailure("token_identifier_mismatch");
            }

            tokenPresent = true;
            cancellationToken.ThrowIfCancellationRequested();
            using var session = slot.OpenSession();
            var certificates = session.FindCertificates(certificateId).Take(2).ToArray();
            if (certificates.Length == 0)
            {
                return ProbeFailure("certificate_missing", tokenPresent: true);
            }

            certificatePresent = true;
            if (certificates.Length != 1 ||
                certificates[0].Id is null ||
                !certificates[0].Id.AsSpan().SequenceEqual(certificateId) ||
                !TryValidateCertificate(certificates[0], out _, out var der))
            {
                return ProbeFailure(
                    "certificate_invalid",
                    tokenPresent: true,
                    certificatePresent: true);
            }

            using var certificate = X509CertificateLoader.LoadCertificate(der);
            var notAfter = new DateTimeOffset(certificate.NotAfter.ToUniversalTime())
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            var suffix = Convert.ToHexString(SHA256.HashData(der))[^8..];
            var keys = session.FindPrivateKeys(privateKeyId).Take(2).ToArray();
            if (keys.Length == 0)
            {
                return ProbeFailure(
                    "private_key_missing", true, true, notAfter, suffix);
            }

            if (keys.Length != 1 || keys[0].Id is null ||
                !keys[0].Id.AsSpan().SequenceEqual(privateKeyId))
            {
                return ProbeFailure(
                    "private_key_missing", true, true, notAfter, suffix);
            }

            return new ProbeResponse(true, true, true, true, null, notAfter, suffix);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            throw new Pkcs11HelperProbeUnavailableException(tokenPresent, certificatePresent);
        }
    }

    private static bool TryValidateCertificate(
        Pkcs11HelperObject item,
        out byte[] identifier,
        out byte[] der)
    {
        identifier = item.Id ?? [];
        der = item.Value ?? [];
        if (identifier.Length is <= 0 or > MaximumIdentifierBytes ||
            der.Length is <= 0 or > MaximumCertificateBytes)
        {
            return false;
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(der);
            return certificate.RawDataMemory.Span.SequenceEqual(der);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void ValidateModulePath(string modulePath)
    {
        if (string.IsNullOrWhiteSpace(modulePath) || !Path.IsPathFullyQualified(modulePath))
        {
            throw new JsonException();
        }
    }

    private static bool IsTokenSerial(string? value) =>
        value is { Length: > 0 and <= 128 } &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        value.All(static character => character is >= ' ' and <= '~');

    private static bool TryNormalizeTokenSerial(string? raw, out string normalized)
    {
        normalized = raw?.TrimEnd(' ', '\0') ?? string.Empty;
        return IsTokenSerial(normalized);
    }

    private static bool TryDecodeIdentifier(string? value, out byte[] identifier)
    {
        identifier = [];
        if (value is not { Length: > 0 and <= MaximumIdentifierBytes * 2 } ||
            value.Length % 2 != 0 ||
            value.Any(static character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            return false;
        }

        identifier = Convert.FromHexString(value);
        return true;
    }

    private static Task<int> WriteAsync(TextWriter output, object response, int exitCode)
    {
        output.WriteLine(JsonSerializer.Serialize(response, SerializerOptions));
        return Task.FromResult(exitCode);
    }

    private static object InvalidRequest() => new InvalidResponse(false, "invalid_request");

    private static object CatalogFailure(string code) =>
        new CatalogResponse(false, code, []);

    private static object ProbeFailure(
        string code,
        bool tokenPresent = false,
        bool certificatePresent = false,
        string? certificateNotAfterUtc = null,
        string? certificateThumbprintSuffix = null) =>
        new ProbeResponse(
            false,
            tokenPresent,
            certificatePresent,
            false,
            code,
            certificateNotAfterUtc,
            certificateThumbprintSuffix);

    private sealed record CatalogRequest
    {
        public required string ModulePath { get; init; }
    }

    private sealed record ProbeRequest
    {
        public required string ModulePath { get; init; }

        public required ulong SlotId { get; init; }

        public required string TokenSerial { get; init; }

        public required string CertificateIdHex { get; init; }

        public required string PrivateKeyIdHex { get; init; }
    }

    private sealed record InvalidResponse(bool Ok, string FailureCode);

    private sealed record CatalogResponse(
        bool Ok,
        string? FailureCode,
        IReadOnlyList<CatalogRecord> Certificates);

    private sealed record CatalogRecord(
        ulong SlotId,
        string TokenSerial,
        string CertificateIdHex,
        string PrivateKeyMatch,
        string? PrivateKeyIdHex,
        string CertificateDerBase64);

    private sealed record ProbeResponse(
        bool Ok,
        bool TokenPresent,
        bool CertificatePresent,
        bool PrivateKeyPresent,
        string? FailureCode,
        string? CertificateNotAfterUtc,
        string? CertificateThumbprintSuffix);
}
