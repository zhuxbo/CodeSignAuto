from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.signers import PdfTimeStamper, SimpleSigner
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from CodeSignAuto_pdf_signer import (
    RequestError,
    SignRequest,
    load_validate_request,
    main,
    sign_pdf_with_signer,
)
from CodeSignAuto_pdf_validator import (
    ValidationFacts,
    ValidationRequest,
    _spawn_validate_with_pid,
    evaluate_validation_facts,
    spawn_validate,
    validate_signed_pdf,
)

SCRIPT = Path(__file__).parents[1] / "CodeSignAuto_pdf_signer.py"


def issue_certificate(
    common_name: str,
    *,
    organization_name: str | None = None,
    timestamping: bool = False,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_attributes = []
    if organization_name is not None:
        subject_attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name)
        )
    subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = x509.Name(subject_attributes)
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    certificate = builder.sign(key, hashes.SHA256())
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return asn1_x509.Certificate.load(certificate_der), asn1_keys.PrivateKeyInfo.load(key_der)


def write_two_page_pdf(path: Path) -> None:
    writer = PdfFileWriter(stream_xrefs=False)
    for _ in range(2):
        contents = writer.add_object(generic.StreamObject(stream_data=b""))
        writer.insert_page(PageObject(contents, media_box=(0, 0, 595, 842)))
    with path.open("wb") as stream:
        writer.write(stream)


def _write_public_certificate(path: Path, certificate: asn1_x509.Certificate) -> Path:
    path.write_bytes(certificate.dump())
    return path


@pytest.fixture
def signed_document(tmp_path: Path):
    signer_cert, signer_key = issue_certificate("Document signer")
    tsa_cert, tsa_key = issue_certificate("Test TSA", timestamping=True)
    signer_store = SimpleCertificateStore()
    signer_store.register(signer_cert)
    signer = SimpleSigner(signer_cert, signer_key, signer_store)
    tsa_store = SimpleCertificateStore()
    tsa_store.register(tsa_cert)
    timestamper = DummyTimeStamper(tsa_cert, tsa_key, tsa_store)

    input_path = tmp_path / "input.pdf"
    output_path = tmp_path / "result.pdf.part"
    write_two_page_pdf(input_path)
    request = SignRequest(
        module_path=tmp_path / "pkcs11.dll",
        slot_id=42,
        token_serial="TEST-TOKEN-SERIAL-0001",
        certificate_id=bytes.fromhex("c0ffee01"),
        private_key_id=bytes.fromhex("decafbad"),
        input_path=input_path,
        output_path=output_path,
        page_index=1,
        box=(200, 642, 548, 680),
        field_name="CertumDocumentSignature",
        reason="Document approval",
        location="CN",
        tsa_url="http://time.certum.pl",
    )
    before_hash = hashlib.sha256(input_path.read_bytes()).hexdigest()
    sign_pdf_with_signer(request, signer, timestamper)
    signer_root_path = tmp_path / "document-signer-root.cer"
    tsa_root_path = tmp_path / "timestamp-root.cer"
    signer_root_path.write_bytes(signer_cert.dump())
    tsa_root_path.write_bytes(tsa_cert.dump())
    validation_request = ValidationRequest(
        input_path=input_path,
        output_path=output_path,
        field_name=request.field_name,
        expected_signer_sha256=hashlib.sha256(signer_cert.dump()).hexdigest(),
        expected_input_sha256=before_hash,
        page_index=request.page_index,
        box=request.box,
        trust_roots=(signer_root_path, tsa_root_path),
        intermediate_certificates=(),
        require_trust=True,
    )
    return request, validation_request, before_hash


def validation_mapping(signed_document) -> dict[str, object]:
    request, validation_request, before_hash = signed_document
    return {
        "inputPath": str(request.input_path),
        "outputPath": str(request.output_path),
        "fieldName": request.field_name,
        "expectedInputSha256": before_hash,
        "expectedSignerSha256": validation_request.expected_signer_sha256,
        "page": request.page_index + 1,
        "box": list(request.box),
        "trustRoots": [str(path) for path in validation_request.trust_roots],
        "intermediateCertificates": [],
    }


def write_validation_request(tmp_path: Path, values: dict[str, object], name: str) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(values), encoding="utf-8")
    return path


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_validate_request_accepts_only_read_only_offline_schema(
    tmp_path: Path,
    signed_document,
) -> None:
    values = validation_mapping(signed_document)

    request = load_validate_request(
        write_validation_request(tmp_path, values, "validate-request.json")
    )

    assert request.input_path == Path(values["inputPath"])
    assert request.output_path == Path(values["outputPath"])
    assert request.page_index == 1
    assert request.box == (200.0, 642.0, 548.0, 680.0)
    assert request.expected_input_sha256 == values["expectedInputSha256"]
    assert request.trust_roots == tuple(Path(path) for path in values["trustRoots"])
    assert request.intermediate_certificates == ()


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("extra", True),
        ("page", 0),
        ("page", True),
        ("box", [200, 642, 200, 680]),
        ("fieldName", "bad field"),
        ("expectedInputSha256", "A" * 64),
        ("expectedSignerSha256", "a" * 63),
        ("modulePath", "/must-not-load-pkcs11"),
        ("tsaUrl", "https://must-not-use-network.invalid"),
        ("trustRoots", []),
        ("trustRoots", "not-an-array"),
        ("intermediateCertificates", ["relative.cer"]),
    ],
)
def test_validate_request_rejects_unknown_wrong_type_and_noncanonical_values(
    tmp_path: Path,
    signed_document,
    change: str,
    value: object,
) -> None:
    values = validation_mapping(signed_document)
    values[change] = value

    with pytest.raises(RequestError):
        load_validate_request(write_validation_request(tmp_path, values, f"bad-{change}.json"))


def test_validate_request_rejects_duplicate_and_same_file(
    tmp_path: Path,
    signed_document,
) -> None:
    values = validation_mapping(signed_document)
    duplicate = tmp_path / "duplicate-validate.json"
    duplicate.write_text(
        json.dumps(values)[:-1] + ',"page":1}',
        encoding="utf-8",
    )
    with pytest.raises(RequestError):
        load_validate_request(duplicate)

    values["outputPath"] = values["inputPath"]
    with pytest.raises(RequestError):
        load_validate_request(write_validation_request(tmp_path, values, "same-file.json"))


def test_validate_request_rejects_uncontrolled_trust_file(
    tmp_path: Path,
    signed_document,
) -> None:
    values = validation_mapping(signed_document)
    target = Path(values["trustRoots"][0])
    link = tmp_path / "linked-root.cer"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    values["trustRoots"] = [str(link)]

    with pytest.raises(RequestError):
        load_validate_request(write_validation_request(tmp_path, values, "linked-trust.json"))


def test_validate_cli_rejects_untrusted_signer_with_stable_safe_code(
    tmp_path: Path,
    signed_document,
) -> None:
    values = validation_mapping(signed_document)
    unrelated_cert, _ = issue_certificate("Unrelated root")
    unrelated_path = tmp_path / "unrelated-root.cer"
    unrelated_path.write_bytes(unrelated_cert.dump())
    values["trustRoots"] = [str(unrelated_path), values["trustRoots"][1]]
    request_path = write_validation_request(tmp_path, values, "untrusted-validate.json")

    result = run_cli("validate", "--request", str(request_path))

    assert result.returncode == 20
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "ok": False,
        "failureCode": "signer_untrusted",
        "signatureCount": 0,
        "wholeFile": False,
        "timestampPresent": False,
        "signerTrusted": False,
        "timestampTrusted": False,
        "timestampSignerSha256": None,
        "timestampUtc": None,
        "signerSuffix": None,
        "certificateNotAfterUtc": None,
        "page": None,
        "box": None,
        "fieldName": None,
        "inputUnchanged": False,
    }
    assert str(request_path) not in result.stdout
    assert str(unrelated_path) not in result.stdout


def test_validate_cli_returns_one_strict_safe_evidence_line_without_pkcs11_or_network(
    tmp_path: Path,
    signed_document,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    values = validation_mapping(signed_document)
    request_path = write_validation_request(tmp_path, values, "validate-cli.json")

    def forbidden_pkcs11(*_: object, **__: object) -> object:
        raise AssertionError("validate must not load PKCS11")

    monkeypatch.setattr("CodeSignAuto_pdf_signer.pkcs11.lib", forbidden_pkcs11)
    assert main(["validate", "--request", str(request_path)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    payload = json.loads(captured.out)
    assert set(payload) == {
        "ok",
        "failureCode",
        "signatureCount",
        "wholeFile",
        "timestampPresent",
        "signerTrusted",
        "timestampTrusted",
        "timestampSignerSha256",
        "timestampUtc",
        "signerSuffix",
        "certificateNotAfterUtc",
        "page",
        "box",
        "fieldName",
        "inputUnchanged",
    }
    assert payload == {
        "ok": True,
        "failureCode": None,
        "signatureCount": 1,
        "wholeFile": True,
        "timestampPresent": True,
        "signerTrusted": True,
        "timestampTrusted": True,
        "timestampSignerSha256": payload["timestampSignerSha256"],
        "timestampUtc": payload["timestampUtc"],
        "signerSuffix": str(values["expectedSignerSha256"])[-8:].upper(),
        "certificateNotAfterUtc": payload["certificateNotAfterUtc"],
        "page": 2,
        "box": [200.0, 642.0, 548.0, 680.0],
        "fieldName": "CertumDocumentSignature",
        "inputUnchanged": True,
    }
    assert payload["certificateNotAfterUtc"].endswith("Z")
    assert re.fullmatch(r"[0-9a-f]{64}", payload["timestampSignerSha256"])
    assert payload["timestampUtc"].endswith("Z")
    assert values["expectedSignerSha256"] not in captured.out
    assert str(request_path) not in captured.out
    assert str(values["inputPath"]) not in captured.out
    assert str(values["outputPath"]) not in captured.out


def test_validate_cli_tamper_is_stable_safe_and_does_not_modify_files(
    tmp_path: Path,
    signed_document,
) -> None:
    values = validation_mapping(signed_document)
    input_path = Path(values["inputPath"])
    output_path = Path(values["outputPath"])
    input_before = input_path.read_bytes()
    output_path.write_bytes(output_path.read_bytes()[:-32])
    output_before = output_path.read_bytes()
    request_path = write_validation_request(tmp_path, values, "tampered-validate.json")

    result = run_cli("validate", "--request", str(request_path))

    assert result.returncode == 20
    assert result.stderr == ""
    assert len(result.stdout.splitlines()) == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["failureCode"] in {
        "invalid_pdf",
        "signature_integrity_invalid",
        "partial_signature_coverage",
    }
    assert str(request_path) not in result.stdout
    assert str(output_path) not in result.stdout
    assert input_path.read_bytes() == input_before
    assert output_path.read_bytes() == output_before


def test_real_pyhanko_mechanics_use_second_page_exact_box_pades_sha256_and_timestamp(
    signed_document,
) -> None:
    request, validation_request, before_hash = signed_document

    assert hashlib.sha256(request.input_path.read_bytes()).hexdigest() == before_hash
    with request.output_path.open("rb") as stream:
        reader = PdfFileReader(stream)
        signatures = reader.embedded_regular_signatures
        assert len(signatures) == 1
        signature = signatures[0]
        assert signature.field_name == "CertumDocumentSignature"
        assert signature.sig_object["/SubFilter"] == "/ETSI.CAdES.detached"
        fields = list(enumerate_sig_fields(reader, with_name=request.field_name))
        assert len(fields) == 1
        field = fields[0][2].get_object()
        assert [float(value) for value in field["/Rect"]] == [200, 642, 548, 680]
        second_page_ref, _ = reader.find_page_for_modification(1)
        assert field.raw_get("/P").reference == second_page_ref.reference

    assert validate_signed_pdf(validation_request) == {"ok": True, "failureCode": None}


def test_visible_signature_uses_certificate_organization_and_colonized_local_utc_offset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer_cert, signer_key = issue_certificate(
        "opaque-certificate-common-name",
        organization_name="示例文档签名有限公司",
    )
    signer_store = SimpleCertificateStore()
    signer_store.register(signer_cert)
    signer = SimpleSigner(signer_cert, signer_key, signer_store)
    input_path = tmp_path / "input.pdf"
    output_path = tmp_path / "result.pdf.part"
    write_two_page_pdf(input_path)
    request = SignRequest(
        module_path=tmp_path / "pkcs11.dll",
        slot_id=42,
        token_serial="TEST-TOKEN-SERIAL-0001",
        certificate_id=bytes.fromhex("c0ffee01"),
        private_key_id=bytes.fromhex("decafbad"),
        input_path=input_path,
        output_path=output_path,
        page_index=1,
        box=(200, 642, 548, 680),
        field_name="CertumDocumentSignature",
        reason=None,
        location=None,
        tsa_url="http://time.example.test",
    )
    captured: dict[str, object] = {}

    class RecordingPdfSigner:
        def __init__(
            self,
            metadata,
            signer,
            *,
            timestamper,
            stamp_style=None,
            new_field_spec=None,
        ) -> None:
            captured["stamp_style"] = stamp_style

        def sign_pdf(self, writer, *, output, appearance_text_params=None) -> None:
            captured["appearance_text_params"] = appearance_text_params
            output.write(b"%PDF-recorded-output")

    monkeypatch.setattr("pyhanko.sign.signers.PdfSigner", RecordingPdfSigner)

    sign_pdf_with_signer(request, signer, timestamper=object())

    style = captured["stamp_style"]
    assert style is not None
    assert style.stamp_text == "%(organization)s\n%(ts)s"
    assert style.border_width == 0
    assert style.background is None
    assert captured["appearance_text_params"] == {
        "organization": "示例文档签名有限公司"
    }
    stamp = style.create_stamp(
        writer=None,
        box=BoxConstraints(width=348, height=38),
        text_params={
            "organization": "示例文档签名有限公司",
            "ts": "2026-08-18 15:19:05 UTC+0800",
        },
    )
    assert stamp.text_params == {
        "organization": "示例文档签名有限公司",
        "ts": "2026-08-18 15:19:05 UTC+08:00",
    }


@pytest.mark.skipif(os.name != "nt", reason="the production helper uses Windows system fonts")
def test_windows_visible_signature_embeds_the_chinese_organization_glyphs(
    tmp_path: Path,
) -> None:
    organization = "示例文档签名有限公司"
    signer_cert, signer_key = issue_certificate(
        "opaque-certificate-common-name",
        organization_name=organization,
    )
    tsa_cert, tsa_key = issue_certificate("Test TSA", timestamping=True)
    signer_store = SimpleCertificateStore()
    signer_store.register(signer_cert)
    tsa_store = SimpleCertificateStore()
    tsa_store.register(tsa_cert)
    input_path = tmp_path / "input.pdf"
    output_path = tmp_path / "result.pdf.part"
    write_two_page_pdf(input_path)
    request = SignRequest(
        module_path=tmp_path / "pkcs11.dll",
        slot_id=42,
        token_serial="TEST-TOKEN-SERIAL-0001",
        certificate_id=bytes.fromhex("c0ffee01"),
        private_key_id=bytes.fromhex("decafbad"),
        input_path=input_path,
        output_path=output_path,
        page_index=1,
        box=(200, 642, 548, 680),
        field_name="CertumDocumentSignature",
        reason=None,
        location=None,
        tsa_url="http://time.example.test",
    )

    sign_pdf_with_signer(
        request,
        SimpleSigner(signer_cert, signer_key, signer_store),
        DummyTimeStamper(tsa_cert, tsa_key, tsa_store),
    )

    with output_path.open("rb") as stream:
        reader = PdfFileReader(stream)
        field = list(enumerate_sig_fields(reader, with_name=request.field_name))[0][
            2
        ].get_object()
        appearance = field["/AP"]["/N"].get_object()
        fonts = appearance["/Resources"]["/Font"]
        unicode_maps = "\n".join(
            reference.get_object()["/ToUnicode"].get_object().data.decode("ascii")
            for reference in fonts.values()
        ).lower()
        for character in set(organization):
            assert f"<{ord(character):04x}>" in unicode_maps
        assert b"UTC\\053" in appearance.data
        assert b"\\072" in appearance.data


def test_validation_rejects_real_document_timestamp_plus_regular_signature(
    tmp_path: Path,
) -> None:
    signer_cert, signer_key = issue_certificate("Document signer")
    tsa_cert, tsa_key = issue_certificate("Test TSA", timestamping=True)
    signer_store = SimpleCertificateStore()
    signer_store.register(signer_cert)
    tsa_store = SimpleCertificateStore()
    tsa_store.register(tsa_cert)
    timestamper = DummyTimeStamper(tsa_cert, tsa_key, tsa_store)
    unsigned_path = tmp_path / "unsigned.pdf"
    timestamped_path = tmp_path / "timestamped.pdf"
    output_path = tmp_path / "result.pdf.part"
    write_two_page_pdf(unsigned_path)
    with unsigned_path.open("rb") as input_stream, timestamped_path.open("wb") as output_stream:
        PdfTimeStamper(timestamper, field_name="ExistingDocTimeStamp").timestamp_pdf(
            IncrementalPdfFileWriter(input_stream),
            md_algorithm="sha256",
            output=output_stream,
        )
    request = SignRequest(
        module_path=tmp_path / "pkcs11.dll",
        slot_id=42,
        token_serial="TEST-TOKEN-SERIAL-0001",
        certificate_id=bytes.fromhex("c0ffee01"),
        private_key_id=bytes.fromhex("decafbad"),
        input_path=timestamped_path,
        output_path=output_path,
        page_index=1,
        box=(200, 642, 548, 680),
        field_name="CertumDocumentSignature",
        reason="Document approval",
        location="CN",
        tsa_url="http://time.example.test",
    )
    sign_pdf_with_signer(
        request,
        SimpleSigner(signer_cert, signer_key, signer_store),
        timestamper,
    )
    validation_request = ValidationRequest(
        input_path=timestamped_path,
        output_path=output_path,
        field_name=request.field_name,
        expected_signer_sha256=hashlib.sha256(signer_cert.dump()).hexdigest(),
        expected_input_sha256=hashlib.sha256(timestamped_path.read_bytes()).hexdigest(),
        page_index=request.page_index,
        box=request.box,
        trust_roots=(
            _write_public_certificate(tmp_path / "document-root.cer", signer_cert),
            _write_public_certificate(tmp_path / "tsa-root.cer", tsa_cert),
        ),
        require_trust=True,
    )
    with output_path.open("rb") as stream:
        reader = PdfFileReader(stream)
        assert len(reader.embedded_signatures) == 2
        assert len(reader.embedded_regular_signatures) == 1

    assert validate_signed_pdf(validation_request) == {
        "ok": False,
        "failureCode": "unexpected_signature_count",
    }


class FakeQueue:
    def __init__(self) -> None:
        self.closed = False
        self.joined = False

    def close(self) -> None:
        self.closed = True

    def join_thread(self) -> None:
        self.joined = True


class TimeoutProcess:
    pid = 24680
    exitcode = -9

    def __init__(self) -> None:
        self.alive = True
        self.actions: list[str] = []

    def start(self) -> None:
        self.actions.append("start")

    def join(self, timeout: float) -> None:
        self.actions.append("join")

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.actions.append("terminate")

    def kill(self) -> None:
        self.actions.append("kill")
        self.alive = False

    def close(self) -> None:
        assert self.alive is False
        self.actions.append("close")


class FakeContext:
    def __init__(self, process: TimeoutProcess, result_queue: FakeQueue) -> None:
        self.process = process
        self.result_queue = result_queue

    def Queue(self, maxsize: int) -> FakeQueue:
        assert maxsize == 1
        return self.result_queue

    def Process(self, *, target: object, args: object) -> TimeoutProcess:
        return self.process


class StartFailureProcess(TimeoutProcess):
    pid = None

    def start(self) -> None:
        self.actions.append("start")
        raise RuntimeError("spawn unavailable")


def test_spawn_timeout_escalates_to_kill_and_closes_process_and_queue(tmp_path: Path) -> None:
    process = TimeoutProcess()
    result_queue = FakeQueue()
    context = FakeContext(process, result_queue)
    request = ValidationRequest(
        input_path=tmp_path / "input.pdf",
        output_path=tmp_path / "result.pdf.part",
        field_name="Signature1",
        expected_signer_sha256="a" * 64,
        expected_input_sha256="b" * 64,
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
    )

    result, worker_pid = _spawn_validate_with_pid(
        request,
        timeout_seconds=0.1,
        context_factory=lambda method: context,
    )

    assert result == {"ok": False, "failureCode": "validation_process_timeout"}
    assert worker_pid == process.pid
    assert process.actions == ["start", "join", "terminate", "join", "kill", "join", "close"]
    assert result_queue.closed is True
    assert result_queue.joined is True


def test_spawn_start_exception_is_stable_and_still_closes_queue(tmp_path: Path) -> None:
    process = StartFailureProcess()
    result_queue = FakeQueue()
    context = FakeContext(process, result_queue)
    request = ValidationRequest(
        input_path=tmp_path / "input.pdf",
        output_path=tmp_path / "result.pdf.part",
        field_name="Signature1",
        expected_signer_sha256="a" * 64,
        expected_input_sha256="b" * 64,
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
    )

    result, worker_pid = _spawn_validate_with_pid(
        request,
        timeout_seconds=0.1,
        context_factory=lambda method: context,
    )

    assert result == {"ok": False, "failureCode": "validation_process_failed"}
    assert worker_pid == -1
    assert process.actions == ["start"]
    assert result_queue.closed is True
    assert result_queue.joined is True


@pytest.mark.parametrize(
    ("changes", "expected_code"),
    [
        ({"signature_count": 0}, "signature_missing"),
        ({"signature_count": 2}, "unexpected_signature_count"),
        ({"intact": False}, "signature_integrity_invalid"),
        ({"valid": False}, "signature_integrity_invalid"),
        ({"whole_file": False}, "partial_signature_coverage"),
        ({"signer_sha256": "0" * 64}, "signer_mismatch"),
        ({"input_sha256": "0" * 64}, "input_hash_mismatch"),
        ({"timestamp_present": False}, "timestamp_missing"),
        ({"timestamp_intact": False}, "timestamp_invalid"),
        ({"timestamp_valid": False}, "timestamp_invalid"),
        ({"trusted": False}, "signer_untrusted"),
        ({"timestamp_trusted": False}, "timestamp_untrusted"),
        ({"timestamp_signer_sha256": ""}, "timestamp_metadata_invalid"),
        ({"timestamp_utc": ""}, "timestamp_metadata_invalid"),
        ({"digest_algorithm": "sha384"}, "digest_algorithm_mismatch"),
        ({"subfilter": "/adbe.pkcs7.detached"}, "pades_subfilter_missing"),
        ({"field_name": "Other"}, "signature_field_mismatch"),
        ({"widget_page_index": 0}, "signature_page_mismatch"),
        ({"widget_box": (1.0, 2.0, 3.0, 4.0)}, "signature_box_mismatch"),
        ({"certificate_not_after_utc": ""}, "certificate_metadata_invalid"),
    ],
)
def test_validation_rejects_every_required_integrity_boundary(
    tmp_path: Path, changes: dict[str, object], expected_code: str
) -> None:
    request = ValidationRequest(
        input_path=tmp_path / "input.pdf",
        output_path=tmp_path / "result.pdf.part",
        field_name="CertumDocumentSignature",
        expected_signer_sha256="a" * 64,
        expected_input_sha256="b" * 64,
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
        require_trust=True,
    )
    facts = ValidationFacts(
        signature_count=1,
        intact=True,
        valid=True,
        whole_file=True,
        signer_sha256="a" * 64,
        timestamp_present=True,
        timestamp_intact=True,
        timestamp_valid=True,
        trusted=True,
        timestamp_trusted=True,
        digest_algorithm="sha256",
        subfilter="/ETSI.CAdES.detached",
        field_name="CertumDocumentSignature",
        certificate_not_after_utc="2030-01-01T00:00:00Z",
        widget_page_index=1,
        widget_box=(200.0, 642.0, 548.0, 680.0),
        input_sha256="b" * 64,
        timestamp_signer_sha256="c" * 64,
        timestamp_utc="2026-08-09T00:00:00Z",
    )
    facts = facts.with_changes(**changes)

    assert evaluate_validation_facts(request, facts) == {
        "ok": False,
        "failureCode": expected_code,
    }


def test_validation_reopens_output_and_rejects_malformed_or_same_path(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(b"%PDF-input")
    input_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
    malformed = tmp_path / "malformed.pdf.part"
    malformed.write_bytes(b"not a pdf")
    trust_cert, _ = issue_certificate("Trust root")
    trust_path = _write_public_certificate(tmp_path / "trust-root.cer", trust_cert)
    request = ValidationRequest(
        input_path=input_path,
        output_path=malformed,
        field_name="CertumDocumentSignature",
        expected_signer_sha256="a" * 64,
        expected_input_sha256=input_sha256,
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
        trust_roots=(trust_path,),
        require_trust=True,
    )
    assert validate_signed_pdf(request) == {"ok": False, "failureCode": "invalid_pdf"}

    same_path = ValidationRequest(
        input_path=malformed,
        output_path=malformed,
        field_name="CertumDocumentSignature",
        expected_signer_sha256="a" * 64,
        expected_input_sha256=hashlib.sha256(malformed.read_bytes()).hexdigest(),
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
        trust_roots=(trust_path,),
        require_trust=True,
    )
    assert validate_signed_pdf(same_path) == {
        "ok": False,
        "failureCode": "invalid_validation_request",
    }


def test_validation_maps_real_output_symlink_loop_to_invalid_request(tmp_path: Path) -> None:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(b"%PDF-input")
    first = tmp_path / "loop-first.part"
    second = tmp_path / "loop-second.part"
    try:
        first.symlink_to(second.name)
        second.symlink_to(first.name)
    except OSError as exc:
        pytest.skip(f"symlink loop unavailable: {exc}")
    request = ValidationRequest(
        input_path=input_path,
        output_path=first,
        field_name="CertumDocumentSignature",
        expected_signer_sha256="a" * 64,
        expected_input_sha256=hashlib.sha256(input_path.read_bytes()).hexdigest(),
        page_index=1,
        box=(200.0, 642.0, 548.0, 680.0),
    )

    assert validate_signed_pdf(request) == {
        "ok": False,
        "failureCode": "invalid_validation_request",
    }


def test_spawn_validator_runs_the_independent_entry_path(signed_document) -> None:
    _, validation_request, _ = signed_document

    result, worker_pid = _spawn_validate_with_pid(validation_request, timeout_seconds=20)
    assert worker_pid != os.getpid()
    assert result == {
        "ok": True,
        "failureCode": None,
    }
    assert spawn_validate(validation_request, timeout_seconds=20) == result


@pytest.mark.softhsm
def test_combined_real_pkcs11_pades_with_softhsm_is_pending_when_unavailable() -> None:
    if shutil.which("softhsm2-util") is None:
        pytest.xfail("PENDING: SoftHSM is unavailable on this host")
    pytest.xfail("PENDING: configured SoftHSM token fixture is required")
