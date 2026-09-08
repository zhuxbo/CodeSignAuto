using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Runtime.ExceptionServices;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Core.Security;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.Diagnostics;

namespace CodeSignAuto.Agent.SimplySign;

public sealed class SimplySignException : Exception
{
    public SimplySignException(string code)
        : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed partial class CertificateAlias
{
    public CertificateAlias(
        string name,
        string modulePath,
        ulong slotId,
        string tokenSerial,
        string certificateIdHex,
        string privateKeyIdHex)
    {
        if (!AliasPattern().IsMatch(name)
            || string.IsNullOrWhiteSpace(modulePath)
            || !Path.IsPathFullyQualified(modulePath)
            || !IsNormalizedIdentifier(tokenSerial)
            || !IsNormalizedHexIdentifier(certificateIdHex)
            || !IsNormalizedHexIdentifier(privateKeyIdHex))
        {
            throw new SimplySignException("simplysign_configuration_invalid");
        }

        Name = name;
        ModulePath = Path.GetFullPath(modulePath);
        SlotId = slotId;
        TokenSerial = tokenSerial;
        CertificateIdHex = certificateIdHex;
        PrivateKeyIdHex = privateKeyIdHex;
    }

    public string Name { get; }

    public string ModulePath { get; }

    public ulong SlotId { get; }

    public string TokenSerial { get; }

    public string CertificateIdHex { get; }

    public string PrivateKeyIdHex { get; }

    public override string ToString() => Name;

    private static bool IsNormalizedIdentifier(string value) =>
        value.Length is > 0 and <= 256
        && string.Equals(value, value.Trim(), StringComparison.Ordinal)
        && value.All(static character => !char.IsControl(character));

    private static bool IsNormalizedHexIdentifier(string value) =>
        value.Length is > 0 and <= 256
        && value.Length % 2 == 0
        && value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_.-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex AliasPattern();
}

public sealed class ProbeResult
{
    private ProbeResult(
        bool processRunning,
        int? processSessionId,
        int expectedSessionId,
        bool tokenPresent,
        bool certificatePresent,
        bool privateKeyPresent,
        bool tokenIdentifierMatches,
        bool certificateIdentifierMatches,
        bool privateKeyIdentifierMatches,
        string? tokenSerial,
        string? certificateId,
        string? privateKeyId,
        string? failureCode,
        DateTimeOffset? certificateNotAfterUtc = null,
        string? certificateThumbprintSuffix = null,
        string? processFailureCode = null)
    {
        ProcessRunning = processRunning;
        ProcessSessionId = processSessionId;
        ExpectedSessionId = expectedSessionId;
        TokenPresent = tokenPresent;
        CertificatePresent = certificatePresent;
        PrivateKeyPresent = privateKeyPresent;
        TokenIdentifierMatches = tokenIdentifierMatches;
        CertificateIdentifierMatches = certificateIdentifierMatches;
        PrivateKeyIdentifierMatches = privateKeyIdentifierMatches;
        TokenSerial = tokenSerial;
        CertificateId = certificateId;
        PrivateKeyId = privateKeyId;
        FailureCode = failureCode;
        CertificateNotAfterUtc = certificateNotAfterUtc;
        CertificateThumbprintSuffix = certificateThumbprintSuffix;
        ProcessFailureCode = processFailureCode;
    }

    public bool ProcessRunning { get; }

    public int? ProcessSessionId { get; }

    public int ExpectedSessionId { get; }

    public bool TokenPresent { get; }

    public bool CertificatePresent { get; }

    public bool PrivateKeyPresent { get; }

    public bool TokenIdentifierMatches { get; }

    public bool CertificateIdentifierMatches { get; }

    public bool PrivateKeyIdentifierMatches { get; }

    public string? TokenSerial { get; }

    public string? CertificateId { get; }

    public string? PrivateKeyId { get; }

    public string? FailureCode { get; }

    public string? ProcessFailureCode { get; }

    public DateTimeOffset? CertificateNotAfterUtc { get; }

    public string? CertificateThumbprintSuffix { get; }

    public bool Ready =>
        ExpectedSessionId > 0
        && TokenPresent
        && CertificatePresent
        && PrivateKeyPresent
        && TokenIdentifierMatches
        && CertificateIdentifierMatches
        && PrivateKeyIdentifierMatches
        && !string.IsNullOrEmpty(TokenSerial)
        && !string.IsNullOrEmpty(CertificateId)
        && !string.IsNullOrEmpty(PrivateKeyId)
        && FailureCode is null;

    public static ProbeResult ReadyFor(int expectedSessionId) =>
        new(
            true,
            expectedSessionId,
            expectedSessionId,
            true,
            true,
            true,
            true,
            true,
            true,
            "configured-token",
            "00",
            "00",
            null,
            new DateTimeOffset(2027, 8, 9, 0, 0, 0, TimeSpan.Zero),
            "89ABCDEF");

    public static ProbeResult NotReadyFor(
        int expectedSessionId,
        string failureCode,
        bool processRunning = false,
        int? processSessionId = null,
        bool tokenPresent = false,
        bool certificatePresent = false,
        bool privateKeyPresent = false,
        bool tokenIdentifierMatches = true,
        bool certificateIdentifierMatches = true,
        bool privateKeyIdentifierMatches = true) =>
        new(
            processRunning,
            processSessionId ?? (processRunning ? expectedSessionId : null),
            expectedSessionId,
            tokenPresent,
            certificatePresent,
            privateKeyPresent,
            tokenIdentifierMatches,
            certificateIdentifierMatches,
            privateKeyIdentifierMatches,
            null,
            null,
            null,
            NormalizeFailureCode(failureCode));

    internal static ProbeResult FromHelper(
        int expectedSessionId,
        CertificateAlias alias,
        HelperProbeResponse response)
    {
        var failureCode = response.Ok ? null : NormalizeFailureCode(response.FailureCode);
        return new ProbeResult(
            true,
            expectedSessionId,
            expectedSessionId,
            response.TokenPresent,
            response.CertificatePresent,
            response.PrivateKeyPresent,
            response.FailureCode != "token_identifier_mismatch",
            response.FailureCode != "certificate_identifier_mismatch",
            response.FailureCode != "private_key_identifier_mismatch",
            response.Ok ? alias.TokenSerial : null,
            response.Ok ? alias.CertificateIdHex : null,
            response.Ok ? alias.PrivateKeyIdHex : null,
            failureCode,
            response.CertificateNotAfterUtc,
            response.CertificateThumbprintSuffix);
    }

    internal ProbeResult WithProcessDiagnostic(SimplySignProcessState processState)
    {
        var processFailure = processState.FailureCode is not null
            ? NormalizeProcessFailureCode(processState.FailureCode)
            : !processState.ProcessRunning
                ? "process_missing"
                : processState.SessionId is not > 0 || processState.SessionId != ExpectedSessionId
                    ? "process_session_mismatch"
                    : null;
        return new ProbeResult(
            processState.ProcessRunning,
            processState.ProcessRunning ? processState.SessionId : null,
            ExpectedSessionId,
            TokenPresent,
            CertificatePresent,
            PrivateKeyPresent,
            TokenIdentifierMatches,
            CertificateIdentifierMatches,
            PrivateKeyIdentifierMatches,
            TokenSerial,
            CertificateId,
            PrivateKeyId,
            FailureCode,
            CertificateNotAfterUtc,
            CertificateThumbprintSuffix,
            processFailure);
    }

    public override string ToString() => Ready ? "ProbeResult:ready" : $"ProbeResult:{FailureCode ?? "not_ready"}";

    private static string NormalizeFailureCode(string? code) => code switch
    {
        "process_missing" => code,
        "process_session_mismatch" => code,
        "process_probe_failed" => code,
        "token_missing" => code,
        "certificate_missing" => code,
        "private_key_missing" => code,
        "token_identifier_mismatch" => code,
        "certificate_identifier_mismatch" => code,
        "private_key_identifier_mismatch" => code,
        "probe_output_invalid" => code,
        "probe_request_invalid" => code,
        "probe_request_cleanup_failed" => code,
        "probe_token_unavailable" => code,
        "probe_process_failed" => code,
        _ => "probe_failed",
    };

    private static string NormalizeProcessFailureCode(string? code) => code switch
    {
        "process_missing" => code,
        "process_session_mismatch" => code,
        "process_probe_failed" => code,
        _ => "process_probe_failed",
    };
}

public interface ISimplySignProbe
{
    Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken);
}

public interface IProbeRequestStore
{
    string AllocatePath();

    Task WriteAsync(string path, string content, CancellationToken cancellationToken);

    Task DeleteAsync(string path);
}

public sealed class ControlledProbeRequestStore : IProbeRequestStore
{
    private static readonly Encoding Utf8WithoutBom = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private readonly string _requestRoot;

    public ControlledProbeRequestStore(string requestRoot)
    {
        if (string.IsNullOrWhiteSpace(requestRoot) || !Path.IsPathFullyQualified(requestRoot))
        {
            throw new SimplySignException("simplysign_configuration_invalid");
        }

        _requestRoot = Path.GetFullPath(requestRoot);
    }

    public string AllocatePath()
    {
        Directory.CreateDirectory(_requestRoot);
        return Path.Combine(_requestRoot, $"probe-{Guid.NewGuid():N}.json");
    }

    public async Task WriteAsync(string path, string content, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            await File.WriteAllTextAsync(path, content, Utf8WithoutBom, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        await using var stream = WindowsCurrentUserProtectedFile.CreateNew(path);
        await stream.WriteAsync(Utf8WithoutBom.GetBytes(content), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task DeleteAsync(string path)
    {
        File.Delete(path);
        return Task.CompletedTask;
    }
}

public sealed record SimplySignProcessState(bool ProcessRunning, int? SessionId, string? FailureCode = null);

public interface ISimplySignProcessSource
{
    SimplySignProcessState Read(int verifiedSessionId);

    bool IsRunningInSession(int sessionId);
}

public sealed class WindowsSimplySignProcessSource : ISimplySignProcessSource
{
    public SimplySignProcessState Read(int verifiedSessionId)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SimplySignProcessState(false, null, "process_probe_failed");
        }

        try
        {
            var sessions = GetRunningSessionIds();
            if (sessions.Count == 0)
            {
                return new SimplySignProcessState(false, null);
            }

            var sessionId = sessions.Contains(verifiedSessionId) ? verifiedSessionId : sessions[0];
            return new SimplySignProcessState(true, sessionId);
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return new SimplySignProcessState(false, null, "process_probe_failed");
        }
    }

    public bool IsRunningInSession(int sessionId)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            return GetRunningSessionIds().Contains(sessionId);
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return true;
        }
    }

    private static IReadOnlyList<int> GetRunningSessionIds()
    {
        var sessionIds = new List<int>();
        foreach (var process in Process.GetProcessesByName("SimplySignDesktop"))
        {
            using (process)
            {
                sessionIds.Add(process.SessionId);
            }
        }

        return sessionIds;
    }
}

public sealed class SimplySignProbe : ISimplySignProbe, ICertificateCatalogSource
{
    // 256 records, each with <= 64-KiB DER (87,384 Base64 ASCII bytes) and bounded
    // locator metadata, require at most 22,604,080 bytes. Keep a simple 24-MiB hard cap.
    public const int MaximumCatalogOutputBytes = 24 * 1024 * 1024;
    private static readonly TimeSpan HelperTimeout = TimeSpan.FromSeconds(15);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IProcessRunner _runner;
    private readonly ISimplySignProcessSource _processSource;
    private readonly string _helperExecutable;
    private readonly IProbeRequestStore _requestStore;
    private readonly int _verifiedSessionId;
    private readonly IAgentDiagnosticSink _diagnostics;

    public SimplySignProbe(
        IProcessRunner runner,
        ISimplySignProcessSource processSource,
        string helperExecutable,
        string requestRoot,
        InteractiveSessionInfo verifiedSession,
        IAgentDiagnosticSink? diagnostics = null)
        : this(
            runner,
            processSource,
            helperExecutable,
            new ControlledProbeRequestStore(requestRoot),
            verifiedSession,
            diagnostics)
    {
    }

    public SimplySignProbe(
        IProcessRunner runner,
        ISimplySignProcessSource processSource,
        string helperExecutable,
        IProbeRequestStore requestStore,
        InteractiveSessionInfo verifiedSession,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _processSource = processSource ?? throw new ArgumentNullException(nameof(processSource));
        _requestStore = requestStore ?? throw new ArgumentNullException(nameof(requestStore));
        _diagnostics = diagnostics.Safe();
        if (string.IsNullOrWhiteSpace(helperExecutable)
            || !Path.IsPathFullyQualified(helperExecutable)
            || verifiedSession is null
            || verifiedSession.SessionId <= 0)
        {
            throw new SimplySignException("simplysign_configuration_invalid");
        }

        _helperExecutable = Path.GetFullPath(helperExecutable);
        _verifiedSessionId = verifiedSession.SessionId;
    }

    public async Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(alias);
        cancellationToken.ThrowIfCancellationRequested();
        var processState = _processSource.Read(_verifiedSessionId);
        var cryptoResult = await ProbeWithRequestAsync(alias, cancellationToken).ConfigureAwait(false);
        return cryptoResult.WithProcessDiagnostic(processState);
    }

    public SimplySignProcessState CheckProcessOnly() => _processSource.Read(_verifiedSessionId);

    public Task<string> ReadCatalogAsync(string modulePath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(modulePath) || !Path.IsPathFullyQualified(modulePath))
        {
            throw new SigningException("certificate_catalog_unavailable");
        }

        cancellationToken.ThrowIfCancellationRequested();
        _ = _processSource.Read(_verifiedSessionId);
        return ReadCatalogWithRequestAsync(Path.GetFullPath(modulePath), cancellationToken);
    }

    private async Task<string> ReadCatalogWithRequestAsync(
        string modulePath,
        CancellationToken cancellationToken)
    {
        string? requestPath = null;
        try
        {
            requestPath = _requestStore.AllocatePath();
            await _requestStore.WriteAsync(
                requestPath,
                JsonSerializer.Serialize(new HelperCatalogRequest(modulePath), SerializerOptions),
                cancellationToken).ConfigureAwait(false);
            var process = await _runner.RunAsync(
                _helperExecutable,
                ["--internal-pkcs11-helper", "catalog", "--request", requestPath],
                HelperTimeout,
                MaximumCatalogOutputBytes,
                ProcessRunner.MaximumCapturedOutputBytes,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (process.Termination != ProcessTermination.Exited ||
                process.ExitCode != 0 ||
                process.StandardOutputTruncated ||
                !TryReadSingleJsonLine(process.StandardOutput, out var json))
            {
                _diagnostics.Report(new AgentDiagnostic(
                    "certificate_catalog_process",
                    "certificate_catalog_unavailable",
                    Process: process));
                throw new SigningException("certificate_catalog_unavailable");
            }

            return json;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SigningException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            _diagnostics.Report(new AgentDiagnostic(
                "certificate_catalog_request",
                "certificate_catalog_unavailable",
                error));
            throw new SigningException("certificate_catalog_unavailable");
        }
        finally
        {
            if (requestPath is not null)
            {
                try
                {
                    await _requestStore.DeleteAsync(requestPath).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    _diagnostics.Report(new AgentDiagnostic(
                        "certificate_catalog_cleanup",
                        "certificate_catalog_unavailable",
                        error));
                    throw new SigningException("certificate_catalog_unavailable");
                }
            }
        }
    }

    private async Task<ProbeResult> ProbeWithRequestAsync(
        CertificateAlias alias,
        CancellationToken cancellationToken)
    {
        string? requestPath = null;
        ProbeResult? result = null;
        OperationCanceledException? cancellation = null;
        var cleanupFailed = false;
        try
        {
            requestPath = _requestStore.AllocatePath();
            var request = new HelperProbeRequest(
                alias.ModulePath,
                alias.SlotId,
                alias.TokenSerial,
                alias.CertificateIdHex,
                alias.PrivateKeyIdHex);
            await _requestStore.WriteAsync(
                requestPath,
                JsonSerializer.Serialize(request, SerializerOptions),
                cancellationToken).ConfigureAwait(false);
            result = await RunHelperAsync(requestPath, alias, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException error) when (cancellationToken.IsCancellationRequested)
        {
            cancellation = error;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            _diagnostics.Report(new AgentDiagnostic("probe_request", "probe_request_invalid", error));
            result = ProbeResult.NotReadyFor(_verifiedSessionId, "probe_request_invalid", processRunning: true);
        }
        finally
        {
            if (requestPath is not null)
            {
                try
                {
                    await _requestStore.DeleteAsync(requestPath).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    _diagnostics.Report(new AgentDiagnostic(
                        "probe_request_cleanup",
                        "probe_request_cleanup_failed",
                        error));
                    cleanupFailed = true;
                }
            }
        }

        if (cancellation is not null)
        {
            ExceptionDispatchInfo.Capture(cancellation).Throw();
        }

        if (cleanupFailed)
        {
            return ProbeResult.NotReadyFor(
                _verifiedSessionId,
                "probe_request_cleanup_failed",
                processRunning: true);
        }

        return result
            ?? ProbeResult.NotReadyFor(_verifiedSessionId, "probe_request_invalid", processRunning: true);
    }

    private async Task<ProbeResult> RunHelperAsync(
        string requestPath,
        CertificateAlias alias,
        CancellationToken cancellationToken)
    {
        var process = await _runner.RunAsync(
            _helperExecutable,
            ["--internal-pkcs11-helper", "probe", "--request", requestPath],
            HelperTimeout,
            cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (process.StandardOutputTruncated)
        {
            ReportProbeProcess("probe_output_invalid", process);
            return ProbeResult.NotReadyFor(_verifiedSessionId, "probe_output_invalid", processRunning: true);
        }

        if (process.Termination != ProcessTermination.Exited)
        {
            ReportProbeProcess("probe_process_failed", process);
            return ProbeResult.NotReadyFor(_verifiedSessionId, "probe_process_failed", processRunning: true);
        }

        var exitFailure = process.ExitCode switch
        {
            0 => null,
            2 => "probe_request_invalid",
            10 => "probe_token_unavailable",
            _ => "probe_failed",
        };
        if (exitFailure is not null)
        {
            ReportProbeProcess(exitFailure, process);
            return ProbeResult.NotReadyFor(_verifiedSessionId, exitFailure, processRunning: true);
        }

        if (!TryParseSingleResponse(process.StandardOutput, out var response))
        {
            ReportProbeProcess("probe_output_invalid", process);
            return ProbeResult.NotReadyFor(_verifiedSessionId, "probe_output_invalid", processRunning: true);
        }

        if (response.Ok)
        {
            if (!response.TokenPresent
                || !response.CertificatePresent
                || !response.PrivateKeyPresent
                || response.FailureCode is not null
                || !IsValidCertificateMetadata(response))
            {
                ReportProbeProcess("probe_output_invalid", process);
                return ProbeResult.NotReadyFor(_verifiedSessionId, "probe_output_invalid", processRunning: true);
            }
        }
        else if (string.IsNullOrEmpty(response.FailureCode) ||
            response.CertificatePresent && !IsValidCertificateMetadata(response) ||
            !response.CertificatePresent &&
                (response.CertificateNotAfterUtc is not null || response.CertificateThumbprintSuffix is not null))
        {
            ReportProbeProcess("probe_output_invalid", process);
            return ProbeResult.NotReadyFor(_verifiedSessionId, "probe_output_invalid", processRunning: true);
        }

        return ProbeResult.FromHelper(_verifiedSessionId, alias, response);
    }

    private void ReportProbeProcess(string stableCode, ProcessResult process) =>
        _diagnostics.Report(new AgentDiagnostic("probe_process", stableCode, Process: process));

    private static bool IsValidCertificateMetadata(HelperProbeResponse response) =>
        response.CertificateNotAfterUtc is { } notAfter &&
        notAfter != default && notAfter.Offset == TimeSpan.Zero &&
        notAfter.Year is >= 2000 and <= 2100 &&
        response.CertificateThumbprintSuffix is { Length: 8 } suffix &&
        suffix.All(static character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool TryParseSingleResponse(string output, out HelperProbeResponse response)
    {
        response = null!;
        if (Encoding.UTF8.GetByteCount(output) > ProcessRunner.MaximumCapturedOutputBytes)
        {
            return false;
        }

        var json = output;
        if (json.EndsWith("\r\n", StringComparison.Ordinal))
        {
            json = json[..^2];
        }
        else if (json.EndsWith('\n'))
        {
            json = json[..^1];
        }

        if (string.IsNullOrWhiteSpace(json) || json.Contains('\r') || json.Contains('\n'))
        {
            return false;
        }

        try
        {
            StrictJson.RejectDuplicateProperties(json);
            response = JsonSerializer.Deserialize<HelperProbeResponse>(json, SerializerOptions)!;
            return response is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryReadSingleJsonLine(string output, out string json)
    {
        json = output;
        if (Encoding.UTF8.GetByteCount(output) > MaximumCatalogOutputBytes)
        {
            return false;
        }

        if (json.EndsWith("\r\n", StringComparison.Ordinal))
        {
            json = json[..^2];
        }
        else if (json.EndsWith('\n'))
        {
            json = json[..^1];
        }

        return !string.IsNullOrWhiteSpace(json) && !json.Contains('\r') && !json.Contains('\n');
    }
}

internal sealed record HelperCatalogRequest(string ModulePath);

internal sealed record HelperProbeRequest(
    string ModulePath,
    ulong SlotId,
    string TokenSerial,
    string CertificateIdHex,
    string PrivateKeyIdHex);

internal sealed record HelperProbeResponse
{
    public required bool Ok { get; init; }

    public required bool TokenPresent { get; init; }

    public required bool CertificatePresent { get; init; }

    public required bool PrivateKeyPresent { get; init; }

    public required string? FailureCode { get; init; }

    public DateTimeOffset? CertificateNotAfterUtc { get; init; }

    public string? CertificateThumbprintSuffix { get; init; }
}
