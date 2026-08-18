using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.App;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class Pkcs11HelperCommandTests
{
    [Fact]
    public void Internal_route_is_exact_and_distinct_from_public_helper_commands()
    {
        var request = Path.Combine(Path.GetTempPath(), "request.json");

        var route = ApplicationEntryRoute.Parse(
            ["--internal-pkcs11-helper", "catalog", "--request", request]);

        Assert.Equal(ApplicationEntryKind.Pkcs11Helper, route.Kind);
        Assert.Equal(["catalog", "--request", request], route.Arguments);
        Assert.Equal(ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["catalog", "--request", request]).Kind);
        Assert.Equal(ApplicationEntryKind.Invalid,
            ApplicationEntryRoute.Parse(["--internal-pkcs11-helper", "sign", "--request", request]).Kind);
    }

    [Fact]
    public void Internal_route_dispatches_before_desktop_elevation_logs_agent_and_service()
    {
        var program = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "SimplySignAuto.App",
            "Program.cs"));
        var helper = program.IndexOf("case ApplicationEntryKind.Pkcs11Helper:", StringComparison.Ordinal);

        Assert.True(helper >= 0);
        Assert.True(helper < program.IndexOf("case ApplicationEntryKind.Desktop:", StringComparison.Ordinal));
        Assert.True(helper < program.IndexOf("AdminDesktopElevation.IsElevated()", StringComparison.Ordinal));
        Assert.True(helper < program.IndexOf("DesktopDiagnosticLog.Open()", StringComparison.Ordinal));
        Assert.True(helper < program.IndexOf("case ApplicationEntryKind.AgentConsole:", StringComparison.Ordinal));
        Assert.True(helper < program.IndexOf("case ApplicationEntryKind.Service:", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(4, 0, "Api40")]
    [InlineData(4, 1, "Api41")]
    [InlineData(8, 0, "Api80")]
    [InlineData(8, 1, "Api81")]
    public void Native_adapter_uses_the_official_ulong_and_packing_dimensions(
        int nativeUnsignedLongSize,
        int packingSize,
        string expected)
    {
        Assert.Equal(expected,
            Pkcs11InteropAbiSelector.Select(nativeUnsignedLongSize, packingSize).ToString());
    }

    [Theory]
    [InlineData(4, "UInt32")]
    [InlineData(8, "UInt64")]
    public void Native_adapter_preserves_the_selected_unsigned_width_when_boxed(
        int nativeUnsignedLongSize,
        string expectedType)
    {
        var value = Pkcs11InteropNativeValue.Box(nativeUnsignedLongSize, 2);

        Assert.Equal(expectedType, value.GetType().Name);
        Assert.Equal(2UL, Convert.ToUInt64(value));
    }

    [Fact]
    public async Task Catalog_emits_the_existing_exact_envelope_without_private_material()
    {
        using var fixture = new RequestFixture();
        var certificate = CreateCertificate();
        var certificateId = Convert.FromHexString("c0ffee01");
        var session = new RecordingSession(
            [new Pkcs11HelperObject(certificateId, certificate)],
            [new Pkcs11HelperObject(certificateId, null)]);
        var backend = new RecordingBackend([
            new RecordingSlot(7, "CATALOG-ONE   ", session),
        ]);
        var request = fixture.Write("catalog.json", new { modulePath = fixture.ModulePath });
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            output,
            error,
            backend,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(string.Empty, error.ToString());
        Assert.Single(output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries));
        using var response = JsonDocument.Parse(output.ToString());
        Assert.Equal(["certificates", "failureCode", "ok"],
            response.RootElement.EnumerateObject().Select(item => item.Name).Order().ToArray());
        Assert.True(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal(JsonValueKind.Null, response.RootElement.GetProperty("failureCode").ValueKind);
        var record = Assert.Single(response.RootElement.GetProperty("certificates").EnumerateArray());
        Assert.Equal(7UL, record.GetProperty("slotId").GetUInt64());
        Assert.Equal("CATALOG-ONE", record.GetProperty("tokenSerial").GetString());
        Assert.Equal("c0ffee01", record.GetProperty("certificateIdHex").GetString());
        Assert.Equal("unique", record.GetProperty("privateKeyMatch").GetString());
        Assert.Equal("c0ffee01", record.GetProperty("privateKeyIdHex").GetString());
        Assert.Equal(Convert.ToBase64String(certificate), record.GetProperty("certificateDerBase64").GetString());
        Assert.DoesNotContain("private-key-material", output.ToString(), StringComparison.Ordinal);
        Assert.True(session.Disposed);
        Assert.True(backend.LibraryDisposed);
    }

    [Fact]
    public async Task Probe_selects_exact_slot_token_certificate_and_key_with_strict_response()
    {
        using var fixture = new RequestFixture();
        var certificate = CreateCertificate();
        var certificateId = Convert.FromHexString("c0ffee01");
        var privateKeyId = Convert.FromHexString("decafbad");
        var selected = new RecordingSession(
            [new Pkcs11HelperObject(certificateId, certificate)],
            [new Pkcs11HelperObject(privateKeyId, null)]);
        var backend = new RecordingBackend([
            new RecordingSlot(41, "OTHER", new RecordingSession([], [])),
            new RecordingSlot(42, "TEST-TOKEN-SERIAL-0001", selected),
        ]);
        var request = fixture.Write("probe.json", new
        {
            modulePath = fixture.ModulePath,
            slotId = 42,
            tokenSerial = "TEST-TOKEN-SERIAL-0001",
            certificateIdHex = "c0ffee01",
            privateKeyIdHex = "decafbad",
        });
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request],
            output,
            TextWriter.Null,
            backend,
            CancellationToken.None);

        Assert.Equal(0, exitCode);
        using var response = JsonDocument.Parse(output.ToString());
        Assert.True(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.True(response.RootElement.GetProperty("tokenPresent").GetBoolean());
        Assert.True(response.RootElement.GetProperty("certificatePresent").GetBoolean());
        Assert.True(response.RootElement.GetProperty("privateKeyPresent").GetBoolean());
        Assert.Equal(JsonValueKind.Null, response.RootElement.GetProperty("failureCode").ValueKind);
        Assert.Matches("^[0-9A-F]{8}$", response.RootElement
            .GetProperty("certificateThumbprintSuffix").GetString()!);
        Assert.EndsWith("Z", response.RootElement.GetProperty("certificateNotAfterUtc").GetString(),
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("9223372036854775808", 9223372036854775808UL)]
    [InlineData("18446744073709551615", ulong.MaxValue)]
    public async Task Probe_preserves_the_existing_full_unsigned_slot_domain(
        string jsonSlotId,
        ulong expectedSlotId)
    {
        using var fixture = new RequestFixture();
        var certificate = CreateCertificate();
        var request = fixture.WriteRaw("probe.json",
            $"{{\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)}," +
            $"\"slotId\":{jsonSlotId},\"tokenSerial\":\"TOKEN\"," +
            "\"certificateIdHex\":\"aa\",\"privateKeyIdHex\":\"bb\"}");
        var backend = new RecordingBackend([
            new RecordingSlot(expectedSlotId, "TOKEN", new RecordingSession(
                [new Pkcs11HelperObject([0xaa], certificate)],
                [new Pkcs11HelperObject([0xbb], null)])),
        ]);
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request], output, TextWriter.Null, backend, default);

        Assert.Equal(0, exitCode);
        Assert.True(JsonDocument.Parse(output.ToString()).RootElement.GetProperty("ok").GetBoolean());
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("true")]
    [InlineData("18446744073709551616")]
    public async Task Probe_rejects_non_unsigned_integer_slot_values(string jsonSlotId)
    {
        using var fixture = new RequestFixture();
        var request = fixture.WriteRaw("probe.json",
            $"{{\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)}," +
            $"\"slotId\":{jsonSlotId},\"tokenSerial\":\"TOKEN\"," +
            "\"certificateIdHex\":\"aa\",\"privateKeyIdHex\":\"bb\"}");
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request],
            output,
            TextWriter.Null,
            new RecordingBackend([]),
            default);

        Assert.Equal(2, exitCode);
        Assert.Equal("invalid_request", JsonDocument.Parse(output.ToString()).RootElement
            .GetProperty("failureCode").GetString());
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("identifier")]
    public async Task Strict_requests_reject_unknown_duplicate_and_oversized_identifiers_without_echo(string kind)
    {
        using var fixture = new RequestFixture();
        var request = kind switch
        {
            "unknown" => fixture.WriteRaw("secret-request.json",
                $"{{\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)},\"unknown\":true}}"),
            "duplicate" => fixture.WriteRaw("secret-request.json",
                $"{{\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)}," +
                $"\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)}}}"),
            _ => fixture.WriteRaw("secret-request.json",
                $"{{\"modulePath\":{JsonSerializer.Serialize(fixture.ModulePath)},\"slotId\":42," +
                $"\"tokenSerial\":\"secret\",\"certificateIdHex\":\"{new string('a', 258)}\"," +
                "\"privateKeyIdHex\":\"aa\"}"),
        };
        var command = kind == "identifier" ? "probe" : "catalog";
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            [command, "--request", request],
            output,
            error,
            new RecordingBackend([]),
            CancellationToken.None);

        Assert.Equal(2, exitCode);
        Assert.Equal("{\"ok\":false,\"failureCode\":\"invalid_request\"}" + Environment.NewLine,
            output.ToString());
        Assert.Equal(string.Empty, error.ToString());
        Assert.DoesNotContain("secret", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(request, output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Catalog_enforces_slot_certificate_der_identity_and_private_key_bounds()
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("catalog.json", new { modulePath = fixture.ModulePath });
        var certificate = CreateCertificate();
        var tooManySlots = Enumerable.Range(0, 33)
            .Select(index => new RecordingSlot(
                checked((ulong)index),
                $"TOKEN-{index}",
                new RecordingSession([], [])))
            .ToArray();
        var duplicateIdentity = new RecordingSession(
            [
                new Pkcs11HelperObject([1], certificate),
                new Pkcs11HelperObject([1], certificate),
            ],
            [
                new Pkcs11HelperObject([1], null),
                new Pkcs11HelperObject([1], null),
                new Pkcs11HelperObject([1], null),
            ]);

        var slotsFailure = await RunCatalogAsync(request, new RecordingBackend(tooManySlots));
        var identityFailure = await RunCatalogAsync(request, new RecordingBackend([
            new RecordingSlot(1, "TOKEN", duplicateIdentity),
        ]));
        var derFailure = await RunCatalogAsync(request, new RecordingBackend([
            new RecordingSlot(1, "TOKEN", new RecordingSession(
                [new Pkcs11HelperObject([1], new byte[(64 * 1024) + 1])], [])),
        ]));

        Assert.Equal("certificate_catalog_invalid", slotsFailure);
        Assert.Equal("certificate_catalog_invalid", identityFailure);
        Assert.Equal("certificate_catalog_invalid", derFailure);
        Assert.True(duplicateIdentity.PrivateKeyObservations <= 2);
    }

    [Fact]
    public async Task Catalog_rejects_the_global_257th_certificate_across_slots()
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("catalog.json", new { modulePath = fixture.ModulePath });
        var certificate = CreateCertificate();
        var first = Enumerable.Range(0, 256)
            .Select(index => new Pkcs11HelperObject(
                [(byte)(index >> 8), (byte)index],
                certificate))
            .ToArray();
        var backend = new RecordingBackend([
            new RecordingSlot(1, "TOKEN-ONE", new RecordingSession(first, [])),
            new RecordingSlot(2, "TOKEN-TWO", new RecordingSession(
                [new Pkcs11HelperObject([1, 0], certificate)], [])),
        ]);

        var failureCode = await RunCatalogAsync(request, backend);

        Assert.Equal("certificate_catalog_invalid", failureCode);
    }

    [Fact]
    public async Task Catalog_empty_slot_list_returns_token_missing_without_error_exit()
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("catalog.json", new { modulePath = fixture.ModulePath });
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            output,
            TextWriter.Null,
            new RecordingBackend([]),
            default);

        Assert.Equal(0, exitCode);
        using var response = JsonDocument.Parse(output.ToString());
        Assert.False(response.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("token_missing", response.RootElement.GetProperty("failureCode").GetString());
        Assert.Empty(response.RootElement.GetProperty("certificates").EnumerateArray());
    }

    [Theory]
    [InlineData(true, "certificate_invalid")]
    [InlineData(false, "private_key_missing")]
    public async Task Probe_reads_back_exact_ids_and_rejects_ambiguous_objects(
        bool duplicateCertificates,
        string expectedFailure)
    {
        using var fixture = new RequestFixture();
        var certificate = CreateCertificate();
        var certificateId = Convert.FromHexString("c0ffee01");
        var privateKeyId = Convert.FromHexString("decafbad");
        var certificates = duplicateCertificates
            ? new[]
            {
                new Pkcs11HelperObject(certificateId, certificate),
                new Pkcs11HelperObject(certificateId, certificate),
            }
            : [new Pkcs11HelperObject(certificateId, certificate)];
        var keys = duplicateCertificates
            ? new[] { new Pkcs11HelperObject(privateKeyId, null) }
            :
            [
                new Pkcs11HelperObject(privateKeyId, null),
                new Pkcs11HelperObject(privateKeyId, null),
            ];
        var session = new RecordingSession(certificates, keys);
        var request = fixture.Write("probe.json", new
        {
            modulePath = fixture.ModulePath,
            slotId = 42UL,
            tokenSerial = "TOKEN",
            certificateIdHex = "c0ffee01",
            privateKeyIdHex = "decafbad",
        });
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request],
            output,
            TextWriter.Null,
            new RecordingBackend([new RecordingSlot(42, "TOKEN", session)]),
            default);

        Assert.Equal(0, exitCode);
        Assert.Equal(expectedFailure, JsonDocument.Parse(output.ToString()).RootElement
            .GetProperty("failureCode").GetString());
        Assert.True(session.CertificateObservations <= 2);
        Assert.True(session.PrivateKeyObservations <= 2);
    }

    [Fact]
    public void Pkcs11_adapter_bounds_native_search_and_rejects_attribute_lengths_before_allocation()
    {
        var countNative = new RecordingLowLevelSession(
            [Enumerable.Range(0, 257).Select(static value => (ulong)value).ToArray()],
            new Pkcs11HelperAttributeLengths(1, 1));
        using var countSession = new Pkcs11InteropHelperSession(countNative);
        var oversizedNative = new RecordingLowLevelSession(
            [[1], []],
            new Pkcs11HelperAttributeLengths(129, 1));
        using var oversizedSession = new Pkcs11InteropHelperSession(oversizedNative);

        Assert.Throws<Pkcs11HelperContractException>(() =>
            countSession.FindCertificates(id: null).ToArray());
        Assert.Throws<Pkcs11HelperContractException>(() =>
            oversizedSession.FindCertificates(id: null).ToArray());

        Assert.Equal(257, countNative.LastMaximumObjects);
        Assert.True(countSession.ContractInvalid);
        Assert.Equal(1, oversizedNative.LengthReadCalls);
        Assert.Equal(0, oversizedNative.ValueReadCalls);
        Assert.True(oversizedSession.ContractInvalid);
    }

    [Fact]
    public void Pkcs11_adapter_drains_native_batches_and_finalizes_the_search_once()
    {
        var native = new RecordingLowLevelSession(
            [[1], [2], []],
            new Pkcs11HelperAttributeLengths(1, 1));
        using var session = new Pkcs11InteropHelperSession(native);

        var certificates = session.FindCertificates(id: null).ToArray();

        Assert.Equal(2, certificates.Length);
        Assert.Equal(3, native.FindCalls);
        Assert.Equal(1, native.FindFinalCalls);
        Assert.True(native.MaximumObjects.All(maximum => maximum is > 0 and <= 257));
    }

    [Theory]
    [InlineData("catalog", "token_missing", 0, "token_missing", false, false)]
    [InlineData("catalog", "session_lost", 10, "pkcs11_session_lost", false, false)]
    [InlineData("catalog", "unavailable", 10, "pkcs11_unavailable", false, false)]
    [InlineData("probe", "token_missing", 10, "pkcs11_unavailable", false, false)]
    [InlineData("probe", "session_lost", 10, "pkcs11_unavailable", false, false)]
    [InlineData("probe", "unavailable", 10, "pkcs11_unavailable", false, false)]
    public async Task Native_failure_classification_preserves_python_compatible_codes_exits_and_flags(
        string command,
        string failure,
        int expectedExit,
        string expectedCode,
        bool expectedTokenPresent,
        bool expectedCertificatePresent)
    {
        using var fixture = new RequestFixture();
        var request = command == "catalog"
            ? fixture.Write("catalog.json", new { modulePath = fixture.ModulePath })
            : fixture.Write("probe.json", new
            {
                modulePath = fixture.ModulePath,
                slotId = 1UL,
                tokenSerial = "TOKEN",
                certificateIdHex = "aa",
                privateKeyIdHex = "bb",
            });
        Exception nativeFailure = failure switch
        {
            "token_missing" => new Pkcs11HelperTokenMissingException(),
            "session_lost" => new Pkcs11HelperSessionLostException(),
            _ => new Pkcs11HelperNativeUnavailableException(),
        };
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            [command, "--request", request],
            output,
            TextWriter.Null,
            new ClassifiedFailureBackend(nativeFailure),
            default);

        Assert.Equal(expectedExit, exitCode);
        using var response = JsonDocument.Parse(output.ToString());
        Assert.Equal(expectedCode, response.RootElement.GetProperty("failureCode").GetString());
        if (command == "probe")
        {
            Assert.Equal(expectedTokenPresent,
                response.RootElement.GetProperty("tokenPresent").GetBoolean());
            Assert.Equal(expectedCertificatePresent,
                response.RootElement.GetProperty("certificatePresent").GetBoolean());
        }
    }

    [Theory]
    [InlineData(0x000000E0UL, "Pkcs11HelperTokenMissingException")]
    [InlineData(0x00000032UL, "Pkcs11HelperSessionLostException")]
    [InlineData(0x000000B0UL, "Pkcs11HelperSessionLostException")]
    [InlineData(0x000000B3UL, "Pkcs11HelperSessionLostException")]
    [InlineData(0x00000101UL, "Pkcs11HelperSessionLostException")]
    [InlineData(0x000000E1UL, "Pkcs11HelperNativeUnavailableException")]
    public void Native_return_codes_use_stable_token_session_and_environment_classes(
        ulong returnCode,
        string expectedException)
    {
        var error = Record.Exception(() => Pkcs11InteropReturnCode.ThrowIfFailed(returnCode));

        Assert.Equal(expectedException, Assert.IsAssignableFrom<Exception>(error).GetType().Name);
    }

    [Fact]
    public async Task Probe_failure_flags_match_the_existing_python_contract()
    {
        using var fixture = new RequestFixture();
        var certificateId = Convert.FromHexString("aa");
        var request = fixture.Write("probe.json", new
        {
            modulePath = fixture.ModulePath,
            slotId = 1UL,
            tokenSerial = "EXPECTED",
            certificateIdHex = "aa",
            privateKeyIdHex = "bb",
        });
        var mismatch = await RunProbeAsync(request, new RecordingBackend([
            new RecordingSlot(1, "OTHER", new RecordingSession([], [])),
        ]));
        var invalidCertificate = await RunProbeAsync(request, new RecordingBackend([
            new RecordingSlot(1, "EXPECTED", new RecordingSession(
                [new Pkcs11HelperObject(certificateId, [1])], [])),
        ]));

        AssertProbeFailure(mismatch, "token_identifier_mismatch", false, false);
        AssertProbeFailure(invalidCertificate, "certificate_invalid", true, true);
    }

    [Theory]
    [InlineData("load", false, false)]
    [InlineData("open", true, false)]
    [InlineData("certificate", true, false)]
    [InlineData("private_key", true, true)]
    public async Task Probe_native_failures_preserve_the_last_verified_stage_flags(
        string stage,
        bool expectedTokenPresent,
        bool expectedCertificatePresent)
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("probe.json", new
        {
            modulePath = fixture.ModulePath,
            slotId = 1UL,
            tokenSerial = "TOKEN",
            certificateIdHex = "aa",
            privateKeyIdHex = "bb",
        });
        using var output = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request],
            output,
            TextWriter.Null,
            new ProbeStageFailureBackend(stage, CreateCertificate()),
            default);

        Assert.Equal(10, exitCode);
        using var response = JsonDocument.Parse(output.ToString());
        Assert.Equal("pkcs11_unavailable", response.RootElement.GetProperty("failureCode").GetString());
        Assert.Equal(expectedTokenPresent,
            response.RootElement.GetProperty("tokenPresent").GetBoolean());
        Assert.Equal(expectedCertificatePresent,
            response.RootElement.GetProperty("certificatePresent").GetBoolean());
        Assert.False(response.RootElement.GetProperty("privateKeyPresent").GetBoolean());
    }

    [Fact]
    public async Task Catalog_distinguishes_unknown_native_return_from_unexpected_managed_failure()
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("catalog.json", new { modulePath = fixture.ModulePath });
        using var nativeOutput = new StringWriter();
        using var unexpectedOutput = new StringWriter();

        var nativeExit = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            nativeOutput,
            TextWriter.Null,
            new ClassifiedFailureBackend(new Pkcs11HelperNativeUnavailableException()),
            default);
        var unexpectedExit = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            unexpectedOutput,
            TextWriter.Null,
            new ThrowingBackend("managed defect"),
            default);

        Assert.Equal(10, nativeExit);
        Assert.Equal(10, unexpectedExit);
        Assert.Equal("pkcs11_unavailable", JsonDocument.Parse(nativeOutput.ToString()).RootElement
            .GetProperty("failureCode").GetString());
        Assert.Equal("catalog_unexpected_error", JsonDocument.Parse(unexpectedOutput.ToString()).RootElement
            .GetProperty("failureCode").GetString());
    }

    [Fact]
    public async Task Native_failures_return_only_stable_codes_and_no_request_or_module_data()
    {
        using var fixture = new RequestFixture();
        var request = fixture.Write("secret-token.json", new { modulePath = fixture.ModulePath });
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            output,
            error,
            new ClassifiedFailureBackend(new Pkcs11HelperNativeUnavailableException()),
            CancellationToken.None);

        Assert.Equal(10, exitCode);
        Assert.Equal("{\"ok\":false,\"failureCode\":\"pkcs11_unavailable\",\"certificates\":[]}" +
            Environment.NewLine, output.ToString());
        Assert.Equal(string.Empty, error.ToString());
        Assert.DoesNotContain("secret-token", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(fixture.ModulePath, output.ToString(), StringComparison.Ordinal);
    }

    private static async Task<string?> RunCatalogAsync(string request, IPkcs11HelperBackend backend)
    {
        using var output = new StringWriter();
        var exitCode = await Pkcs11HelperCommand.ExecuteAsync(
            ["catalog", "--request", request],
            output,
            TextWriter.Null,
            backend,
            CancellationToken.None);
        Assert.Equal(0, exitCode);
        using var response = JsonDocument.Parse(output.ToString());
        return response.RootElement.GetProperty("failureCode").GetString();
    }

    private static async Task<JsonElement> RunProbeAsync(
        string request,
        IPkcs11HelperBackend backend)
    {
        using var output = new StringWriter();
        Assert.Equal(0, await Pkcs11HelperCommand.ExecuteAsync(
            ["probe", "--request", request], output, TextWriter.Null, backend, default));
        return JsonDocument.Parse(output.ToString()).RootElement.Clone();
    }

    private static void AssertProbeFailure(
        JsonElement response,
        string failureCode,
        bool tokenPresent,
        bool certificatePresent)
    {
        Assert.Equal(failureCode, response.GetProperty("failureCode").GetString());
        Assert.Equal(tokenPresent, response.GetProperty("tokenPresent").GetBoolean());
        Assert.Equal(certificatePresent, response.GetProperty("certificatePresent").GetBoolean());
    }

    private static byte[] CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=PKCS11 test fixture", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2027-08-09T00:00:00Z"));
        return certificate.Export(X509ContentType.Cert);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null &&
            !File.Exists(Path.Combine(current.FullName, "SimplySignAuto.sln")))
        {
            current = current.Parent;
        }

        return current?.FullName ?? throw new InvalidOperationException("repository_root_not_found");
    }

    private sealed class RequestFixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));

        public RequestFixture()
        {
            Directory.CreateDirectory(_root);
            ModulePath = Path.Combine(_root, "SimplySignPKCS11.dll");
        }

        public string ModulePath { get; }

        public string Write(string name, object value) =>
            WriteRaw(name, JsonSerializer.Serialize(value, JsonSerializerOptions.Web));

        public string WriteRaw(string name, string value)
        {
            var path = Path.Combine(_root, name);
            File.WriteAllText(path, value);
            return path;
        }

        public void Dispose() => Directory.Delete(_root, recursive: true);
    }

    private sealed class RecordingBackend(IReadOnlyList<IPkcs11HelperSlot> slots) : IPkcs11HelperBackend
    {
        public bool LibraryDisposed { get; private set; }

        public IPkcs11HelperLibrary Load(string modulePath) => new Library(this, slots);

        private sealed class Library(
            RecordingBackend owner,
            IReadOnlyList<IPkcs11HelperSlot> slots) : IPkcs11HelperLibrary
        {
            public IEnumerable<IPkcs11HelperSlot> GetSlots() => slots;

            public void Dispose() => owner.LibraryDisposed = true;
        }
    }

    private sealed class ThrowingBackend(string message) : IPkcs11HelperBackend
    {
        public IPkcs11HelperLibrary Load(string modulePath) => throw new InvalidOperationException(message);
    }

    private sealed class ClassifiedFailureBackend(Exception failure) : IPkcs11HelperBackend
    {
        public IPkcs11HelperLibrary Load(string modulePath) => throw failure;
    }

    private sealed class ProbeStageFailureBackend(string stage, byte[] certificate) : IPkcs11HelperBackend
    {
        public IPkcs11HelperLibrary Load(string modulePath)
        {
            if (stage == "load")
            {
                throw new Pkcs11HelperNativeUnavailableException();
            }

            return new Library(stage, certificate);
        }

        private sealed class Library(string stage, byte[] certificate) : IPkcs11HelperLibrary
        {
            public IEnumerable<IPkcs11HelperSlot> GetSlots()
            {
                yield return new Slot(stage, certificate);
            }

            public void Dispose()
            {
            }
        }

        private sealed class Slot(string stage, byte[] certificate) : IPkcs11HelperSlot
        {
            public ulong SlotId => 1;

            public string TokenSerial => "TOKEN";

            public IPkcs11HelperSession OpenSession()
            {
                if (stage == "open")
                {
                    throw new Pkcs11HelperNativeUnavailableException();
                }

                return new Session(stage, certificate);
            }
        }

        private sealed class Session(string stage, byte[] certificate) : IPkcs11HelperSession
        {
            public IEnumerable<Pkcs11HelperObject> FindCertificates(byte[]? id)
            {
                if (stage == "certificate")
                {
                    throw new Pkcs11HelperNativeUnavailableException();
                }

                yield return new Pkcs11HelperObject([0xaa], certificate);
            }

            public IEnumerable<Pkcs11HelperObject> FindPrivateKeys(byte[] id)
            {
                if (stage == "private_key")
                {
                    throw new Pkcs11HelperNativeUnavailableException();
                }

                yield return new Pkcs11HelperObject([0xbb], null);
            }

            public void Dispose()
            {
            }
        }
    }

    private sealed class RecordingSlot(
        ulong slotId,
        string tokenSerial,
        IPkcs11HelperSession session) : IPkcs11HelperSlot
    {
        public ulong SlotId => slotId;

        public string TokenSerial => tokenSerial;

        public IPkcs11HelperSession OpenSession() => session;
    }

    private sealed class RecordingSession(
        IReadOnlyList<Pkcs11HelperObject> certificates,
        IReadOnlyList<Pkcs11HelperObject> privateKeys) : IPkcs11HelperSession
    {
        public bool Disposed { get; private set; }

        public int CertificateObservations { get; private set; }

        public int PrivateKeyObservations { get; private set; }

        public IEnumerable<Pkcs11HelperObject> FindCertificates(byte[]? id)
        {
            foreach (var certificate in certificates)
            {
                CertificateObservations++;
                yield return certificate;
            }
        }

        public IEnumerable<Pkcs11HelperObject> FindPrivateKeys(byte[] id)
        {
            foreach (var key in privateKeys)
            {
                PrivateKeyObservations++;
                yield return key;
            }
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class RecordingLowLevelSession(
        IReadOnlyList<IReadOnlyList<ulong>> batches,
        Pkcs11HelperAttributeLengths lengths) : IPkcs11LowLevelSession
    {
        private readonly Queue<IReadOnlyList<ulong>> _batches = new(batches);

        public int LastMaximumObjects => MaximumObjects.LastOrDefault();

        public List<int> MaximumObjects { get; } = [];

        public int FindCalls { get; private set; }

        public int FindFinalCalls { get; private set; }

        public int LengthReadCalls { get; private set; }

        public int ValueReadCalls { get; private set; }

        public IPkcs11LowLevelFindOperation BeginFind(
            Pkcs11HelperObjectClass objectClass,
            byte[]? id)
        {
            return new FindOperation(this);
        }

        public Pkcs11HelperAttributeLengths ReadAttributeLengths(
            ulong objectHandle,
            bool includeValue)
        {
            LengthReadCalls++;
            return lengths;
        }

        public Pkcs11HelperObject ReadAttributes(
            ulong objectHandle,
            Pkcs11HelperAttributeLengths expected,
            bool includeValue)
        {
            ValueReadCalls++;
            return new Pkcs11HelperObject([1], includeValue ? [1] : null);
        }

        public void Dispose()
        {
        }

        private sealed class FindOperation(RecordingLowLevelSession owner) : IPkcs11LowLevelFindOperation
        {
            public IReadOnlyList<ulong> Read(int maximumObjects)
            {
                owner.FindCalls++;
                owner.MaximumObjects.Add(maximumObjects);
                return owner._batches.Count == 0 ? [] : owner._batches.Dequeue();
            }

            public void Dispose() => owner.FindFinalCalls++;
        }
    }
}
