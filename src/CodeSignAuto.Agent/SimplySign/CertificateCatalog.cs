using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.Agent.SimplySign;

public enum SigningKind
{
    Authenticode,
    Pdf,
}

public sealed record SigningCertificate(
    string CommonName,
    string SerialNumber,
    string ModulePath,
    ulong SlotId,
    string TokenSerial,
    string CertificateIdHex,
    string PrivateKeyIdHex,
    string Sha1Thumbprint,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    bool SupportsAuthenticode,
    bool SupportsPdf);

public sealed record CertificateDisplaySummary(
    string CommonName,
    string SerialNumber,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    bool AuthenticodeUsable,
    bool PdfUsable,
    bool CatalogCurrent,
    string? UnavailableReason);

internal sealed class ReadOnlySet<T>(IReadOnlySet<T> values) : IReadOnlySet<T>
{
    public int Count => values.Count;

    public bool Contains(T item) => values.Contains(item);

    public IEnumerator<T> GetEnumerator() => values.GetEnumerator();

    public bool IsProperSubsetOf(IEnumerable<T> other) => values.IsProperSubsetOf(other);

    public bool IsProperSupersetOf(IEnumerable<T> other) => values.IsProperSupersetOf(other);

    public bool IsSubsetOf(IEnumerable<T> other) => values.IsSubsetOf(other);

    public bool IsSupersetOf(IEnumerable<T> other) => values.IsSupersetOf(other);

    public bool Overlaps(IEnumerable<T> other) => values.Overlaps(other);

    public bool SetEquals(IEnumerable<T> other) => values.SetEquals(other);

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

public sealed record CertificateCatalogSnapshot(
    long Generation,
    DateTimeOffset RefreshedAtUtc,
    IReadOnlyDictionary<string, IReadOnlyList<SigningCertificate>> BySerialNumber,
    IReadOnlySet<string>? AmbiguousSerialNumbers = null)
{
    private static readonly IReadOnlySet<string> EmptyAmbiguousSerialNumbers =
        new ReadOnlySet<string>(new HashSet<string>(StringComparer.Ordinal));

    public IReadOnlySet<string> AmbiguousSerialNumbers { get; init; } =
        AmbiguousSerialNumbers is null
            ? EmptyAmbiguousSerialNumbers
            : new ReadOnlySet<string>(new HashSet<string>(AmbiguousSerialNumbers, StringComparer.Ordinal));

    public SigningCertificate Resolve(
        string serialNumber,
        SigningKind kind,
        DateTimeOffset now)
    {
        if (!CertificateSerialNumber.TryNormalize(serialNumber, out var normalized))
        {
            throw new SigningException("certificate_not_found");
        }

        if (AmbiguousSerialNumbers.Contains(normalized))
        {
            throw new SigningException("certificate_serial_ambiguous");
        }

        if (!BySerialNumber.TryGetValue(normalized, out var matches) || matches.Count == 0)
        {
            throw new SigningException("certificate_not_found");
        }

        if (matches.Count != 1)
        {
            throw new SigningException("certificate_serial_ambiguous");
        }

        var certificate = matches[0];
        var supported = kind switch
        {
            SigningKind.Authenticode => certificate.SupportsAuthenticode,
            SigningKind.Pdf => certificate.SupportsPdf,
            _ => false,
        };
        if (!supported || now < certificate.NotBeforeUtc || now > certificate.NotAfterUtc)
        {
            throw new SigningException("certificate_not_usable");
        }

        return certificate;
    }
}

public interface ICertificateCatalog
{
    CertificateCatalogSnapshot? Current { get; }

    IReadOnlyList<CertificateDisplaySummary> DisplaySummaries { get; }

    Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken);

    SigningCertificate Resolve(string serialNumber, SigningKind kind);

    void Invalidate();

    void Clear() => Invalidate();
}

public interface ICertificateCatalogSource
{
    Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken);
}

public sealed class CertificateCatalog : ICertificateCatalog
{
    private const string MissingCommonName = "（无通用名称）";
    private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";
    private const string DocumentSigningOid = "1.2.840.113583.1.1.5";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private static readonly IReadOnlyList<CertificateDisplaySummary> EmptySummaries =
        Array.AsReadOnly(Array.Empty<CertificateDisplaySummary>());

    private readonly object _sync = new();
    private readonly ICertificateCatalogSource _source;
    private readonly string _modulePath;
    private readonly TimeProvider _timeProvider;
    private readonly IAgentDiagnosticSink _diagnostics;
    private CertificateCatalogSnapshot? _current;
    private IReadOnlyList<CertificateDisplaySummary> _displaySummaries = EmptySummaries;
    private long _generation;
    private long _invalidationEpoch;

    public CertificateCatalog(
        ICertificateCatalogSource source,
        string modulePath,
        TimeProvider? timeProvider = null,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        if (string.IsNullOrWhiteSpace(modulePath) || !Path.IsPathFullyQualified(modulePath))
        {
            throw new ArgumentException("PKCS#11 module path must be absolute.", nameof(modulePath));
        }

        _modulePath = Path.GetFullPath(modulePath);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _diagnostics = diagnostics.Safe();
    }

    public CertificateCatalogSnapshot? Current
    {
        get
        {
            lock (_sync)
            {
                return _current;
            }
        }
    }

    public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries
    {
        get
        {
            lock (_sync)
            {
                return _displaySummaries;
            }
        }
    }

    public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        long refreshEpoch;
        lock (_sync)
        {
            refreshEpoch = _invalidationEpoch;
        }

        string output;
        try
        {
            output = await _source.ReadCatalogAsync(_modulePath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            _diagnostics.Report(new AgentDiagnostic(
                "certificate_catalog_source",
                "certificate_catalog_unavailable",
                error));
            throw Unavailable();
        }

        ParsedCatalog parsed;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            parsed = Parse(output, _modulePath, _timeProvider.GetUtcNow());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            _diagnostics.Report(new AgentDiagnostic(
                "certificate_catalog_parse",
                "certificate_catalog_unavailable",
                error));
            throw Unavailable();
        }

        lock (_sync)
        {
            if (_invalidationEpoch != refreshEpoch)
            {
                throw Unavailable();
            }

            var snapshot = new CertificateCatalogSnapshot(
                checked(++_generation),
                parsed.RefreshedAtUtc,
                parsed.BySerialNumber,
                parsed.AmbiguousSerials);
            _displaySummaries = parsed.DisplaySummaries;
            _current = snapshot;
            return snapshot;
        }
    }

    public SigningCertificate Resolve(string serialNumber, SigningKind kind)
    {
        CertificateCatalogSnapshot snapshot;
        lock (_sync)
        {
            snapshot = _current ?? throw Unavailable();
        }

        return snapshot.Resolve(serialNumber, kind, _timeProvider.GetUtcNow());
    }

    public void Invalidate()
    {
        lock (_sync)
        {
            checked
            {
                _invalidationEpoch++;
            }

            _current = null;
            _displaySummaries = Array.AsReadOnly(_displaySummaries
                .Select(static summary => summary with
                {
                    AuthenticodeUsable = false,
                    PdfUsable = false,
                    CatalogCurrent = false,
                    UnavailableReason = "catalog_stale",
                })
                .ToArray());
        }
    }

    public void Clear()
    {
        lock (_sync)
        {
            checked
            {
                _invalidationEpoch++;
            }

            _current = null;
            _displaySummaries = EmptySummaries;
        }
    }

    private static ParsedCatalog Parse(string output, string modulePath, DateTimeOffset refreshedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            throw Unavailable();
        }

        StrictJson.RejectDuplicateProperties(output);
        var response = JsonSerializer.Deserialize<HelperCatalogResponse>(output, SerializerOptions)
            ?? throw Unavailable();
        if (!response.Ok || response.FailureCode is not null ||
            response.Certificates is not { Count: > 0 })
        {
            throw Unavailable();
        }

        var records = new List<ParsedRecord>(response.Certificates.Count);
        foreach (var record in response.Certificates)
        {
            records.Add(ParseRecord(record, modulePath));
        }

        var serialCounts = records
            .GroupBy(static record => record.Certificate.SerialNumber, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);
        var ambiguousSerials = serialCounts
            .Where(static entry => entry.Value > 1)
            .Select(static entry => entry.Key)
            .ToHashSet(StringComparer.Ordinal);
        var signingGroups = records
            .Where(static record => record.PrivateKeyMatch == "unique")
            .GroupBy(static record => record.Certificate.SerialNumber, StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => (IReadOnlyList<SigningCertificate>)Array.AsReadOnly(
                    group.Select(static record => record.Certificate).ToArray()),
                StringComparer.Ordinal);
        var summaries = records.Select(record => ToSummary(record, ambiguousSerials, refreshedAtUtc)).ToArray();

        return new ParsedCatalog(
            refreshedAtUtc,
            new ReadOnlyDictionary<string, IReadOnlyList<SigningCertificate>>(signingGroups),
            new ReadOnlySet<string>(ambiguousSerials),
            Array.AsReadOnly(summaries));
    }

    private static ParsedRecord ParseRecord(HelperCatalogRecord record, string modulePath)
    {
        if (!IsIdentifier(record.TokenSerial) ||
            !IsHexIdentifier(record.CertificateIdHex) ||
            record.PrivateKeyMatch is not ("unique" or "missing" or "ambiguous") ||
            record.PrivateKeyMatch == "unique" != IsHexIdentifier(record.PrivateKeyIdHex) ||
            record.PrivateKeyMatch != "unique" && record.PrivateKeyIdHex is not null ||
            string.IsNullOrEmpty(record.CertificateDerBase64))
        {
            throw Unavailable();
        }

        var der = Convert.FromBase64String(record.CertificateDerBase64);
        if (der.Length == 0)
        {
            throw Unavailable();
        }

        using var certificate = X509CertificateLoader.LoadCertificate(der);
        if (!CertificateSerialNumber.TryNormalize(certificate.GetSerialNumberString(), out var serialNumber))
        {
            throw Unavailable();
        }

        var commonNames = certificate.SubjectName
            .EnumerateRelativeDistinguishedNames(reversed: false)
            .Where(static name => name.HasMultipleElements || name.GetSingleElementType().Value == "2.5.4.3")
            .Select(static name => name.HasMultipleElements ? null : name.GetSingleElementValue())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        var commonName = commonNames.Length == 1 ? commonNames[0]! : MissingCommonName;
        var notBeforeUtc = new DateTimeOffset(certificate.NotBefore.ToUniversalTime());
        var notAfterUtc = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
        var enhancedKeyUsageOids = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SelectMany(static extension => extension.EnhancedKeyUsages.Cast<Oid>())
            .Select(static oid => oid.Value)
            .ToHashSet(StringComparer.Ordinal);
        var supportsAuthenticode = enhancedKeyUsageOids.Contains(CodeSigningOid);
        var supportsPdf = enhancedKeyUsageOids.Contains(DocumentSigningOid) && certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .Any(static extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature));

        return new ParsedRecord(
            new SigningCertificate(
                commonName,
                serialNumber,
                modulePath,
                record.SlotId,
                record.TokenSerial,
                record.CertificateIdHex,
                record.PrivateKeyIdHex ?? string.Empty,
                Convert.ToHexString(SHA1.HashData(der)),
                notBeforeUtc,
                notAfterUtc,
                supportsAuthenticode,
                supportsPdf),
            record.PrivateKeyMatch);
    }

    private static CertificateDisplaySummary ToSummary(
        ParsedRecord record,
        IReadOnlySet<string> ambiguousSerials,
        DateTimeOffset now)
    {
        var certificate = record.Certificate;
        var unavailableReason = ambiguousSerials.Contains(certificate.SerialNumber)
            ? "certificate_serial_ambiguous"
            : now < certificate.NotBeforeUtc
                ? "not_yet_valid"
                : now > certificate.NotAfterUtc
                    ? "expired"
                    : record.PrivateKeyMatch switch
                    {
                        "missing" => "private_key_missing",
                        "ambiguous" => "private_key_ambiguous",
                        _ when !certificate.SupportsAuthenticode && !certificate.SupportsPdf => "unsupported_purpose",
                        _ => null,
                    };
        var generallyUsable = unavailableReason is null;
        return new CertificateDisplaySummary(
            certificate.CommonName,
            certificate.SerialNumber,
            certificate.NotBeforeUtc,
            certificate.NotAfterUtc,
            generallyUsable && certificate.SupportsAuthenticode,
            generallyUsable && certificate.SupportsPdf,
            true,
            unavailableReason);
    }

    private static bool IsIdentifier(string? value) =>
        value is { Length: > 0 and <= 256 } &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        value.All(static character => !char.IsControl(character));

    private static bool IsHexIdentifier(string? value) =>
        value is { Length: > 0 and <= 256 } &&
        value.Length % 2 == 0 &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static SigningException Unavailable() => new("certificate_catalog_unavailable");

    private sealed record ParsedRecord(SigningCertificate Certificate, string PrivateKeyMatch);

    private sealed record ParsedCatalog(
        DateTimeOffset RefreshedAtUtc,
        IReadOnlyDictionary<string, IReadOnlyList<SigningCertificate>> BySerialNumber,
        IReadOnlySet<string> AmbiguousSerials,
        IReadOnlyList<CertificateDisplaySummary> DisplaySummaries);

    private sealed record HelperCatalogResponse
    {
        public required bool Ok { get; init; }

        public required string? FailureCode { get; init; }

        public required IReadOnlyList<HelperCatalogRecord>? Certificates { get; init; }
    }

    private sealed record HelperCatalogRecord
    {
        public required ulong SlotId { get; init; }

        public required string TokenSerial { get; init; }

        public required string CertificateIdHex { get; init; }

        public required string PrivateKeyMatch { get; init; }

        public required string? PrivateKeyIdHex { get; init; }

        public required string CertificateDerBase64 { get; init; }
    }

}
