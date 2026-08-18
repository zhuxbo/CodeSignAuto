from __future__ import annotations

import hashlib
import logging
import math
import multiprocessing
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext


@dataclass(frozen=True)
class ValidationRequest:
    input_path: Path
    output_path: Path
    field_name: str
    expected_signer_sha256: str
    expected_input_sha256: str
    page_index: int
    box: tuple[float, float, float, float]
    trust_roots: tuple[Path, ...] = ()
    intermediate_certificates: tuple[Path, ...] = ()
    require_trust: bool = False


@dataclass(frozen=True)
class ValidationFacts:
    signature_count: int
    intact: bool
    valid: bool
    whole_file: bool
    signer_sha256: str
    timestamp_present: bool
    timestamp_intact: bool
    timestamp_valid: bool
    trusted: bool
    timestamp_trusted: bool
    timestamp_signer_sha256: str
    timestamp_utc: str
    digest_algorithm: str
    subfilter: str
    field_name: str
    certificate_not_after_utc: str
    widget_page_index: int
    widget_box: tuple[float, float, float, float]
    input_sha256: str

    def with_changes(self, **changes: object) -> ValidationFacts:
        return replace(self, **changes)


def _failure(code: str) -> dict[str, object]:
    return {"ok": False, "failureCode": code}


def evaluate_validation_facts(
    request: ValidationRequest, facts: ValidationFacts
) -> dict[str, object]:
    if facts.signature_count == 0:
        return _failure("signature_missing")
    if facts.signature_count != 1:
        return _failure("unexpected_signature_count")
    if not facts.intact or not facts.valid:
        return _failure("signature_integrity_invalid")
    if not facts.whole_file:
        return _failure("partial_signature_coverage")
    if facts.signer_sha256 != request.expected_signer_sha256:
        return _failure("signer_mismatch")
    if facts.input_sha256 != request.expected_input_sha256:
        return _failure("input_hash_mismatch")
    if not facts.timestamp_present:
        return _failure("timestamp_missing")
    if not facts.timestamp_intact or not facts.timestamp_valid:
        return _failure("timestamp_invalid")
    if request.require_trust and not facts.trusted:
        return _failure("signer_untrusted")
    if request.require_trust and not facts.timestamp_trusted:
        return _failure("timestamp_untrusted")
    if (
        re.fullmatch(r"[0-9a-f]{64}", facts.timestamp_signer_sha256) is None
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            facts.timestamp_utc,
        )
        is None
    ):
        return _failure("timestamp_metadata_invalid")
    if facts.digest_algorithm != "sha256":
        return _failure("digest_algorithm_mismatch")
    if facts.subfilter != "/ETSI.CAdES.detached":
        return _failure("pades_subfilter_missing")
    if facts.field_name != request.field_name:
        return _failure("signature_field_mismatch")
    if facts.widget_page_index != request.page_index:
        return _failure("signature_page_mismatch")
    if len(facts.widget_box) != 4 or any(
        abs(actual - expected) > 0.001
        for actual, expected in zip(facts.widget_box, request.box, strict=True)
    ):
        return _failure("signature_box_mismatch")
    if (
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\r\n]{1,32}Z",
            facts.certificate_not_after_utc,
        )
        is None
    ):
        return _failure("certificate_metadata_invalid")
    return {"ok": True, "failureCode": None}


def _empty_facts(signature_count: int) -> ValidationFacts:
    return ValidationFacts(
        signature_count=signature_count,
        intact=False,
        valid=False,
        whole_file=False,
        signer_sha256="",
        timestamp_present=False,
        timestamp_intact=False,
        timestamp_valid=False,
        trusted=False,
        timestamp_trusted=False,
        timestamp_signer_sha256="",
        timestamp_utc="",
        digest_algorithm="",
        subfilter="",
        field_name="",
        certificate_not_after_utc="",
        widget_page_index=-1,
        widget_box=(),
        input_sha256="",
    )


def _inspect_pdf(request: ValidationRequest) -> ValidationFacts:
    with request.output_path.open("rb") as stream:
        reader = PdfFileReader(stream, strict=True)
        all_signatures = reader.embedded_signatures
        signatures = reader.embedded_regular_signatures
        if len(all_signatures) != 1 or len(signatures) != 1:
            count = 0 if not all_signatures else max(2, len(all_signatures))
            return _empty_facts(count)
        signature = signatures[0]
        offline_context = ValidationContext(
            trust_roots=[_load_public_certificate(path) for path in request.trust_roots],
            other_certs=[
                _load_public_certificate(path) for path in request.intermediate_certificates
            ],
            allow_fetching=False,
        )
        status = validate_pdf_signature(
            signature,
            signer_validation_context=offline_context,
            ts_validation_context=offline_context,
        )
        timestamp_status = status.timestamp_validity
        timestamp_signer_der = (
            timestamp_status.signing_cert.dump() if timestamp_status is not None else b""
        )
        timestamp_utc = (
            timestamp_status.timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")
            if timestamp_status is not None
            else ""
        )
        signer_certificate = signature.signer_cert
        signer_der = signer_certificate.dump()
        selected_certificate = x509.load_der_x509_certificate(signer_der)
        certificate_not_after_utc = selected_certificate.not_valid_after_utc.isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        fields = list(enumerate_sig_fields(reader, with_name=signature.field_name))
        if len(fields) != 1:
            return _empty_facts(2)
        field = fields[0][2].get_object()
        widget_box = tuple(float(value) for value in field["/Rect"])
        if len(widget_box) != 4:
            return _empty_facts(2)
        page_reference = field.raw_get("/P").reference
        page_count = int(reader.root["/Pages"]["/Count"])
        widget_page_index = next(
            (
                page_index
                for page_index in range(page_count)
                if reader.find_page_for_modification(page_index)[0].reference == page_reference
            ),
            -1,
        )
        return ValidationFacts(
            signature_count=1,
            intact=status.intact,
            valid=status.valid,
            whole_file=status.coverage == SignatureCoverageLevel.ENTIRE_FILE,
            signer_sha256=hashlib.sha256(signer_der).hexdigest(),
            timestamp_present=timestamp_status is not None,
            timestamp_intact=timestamp_status is not None and timestamp_status.intact,
            timestamp_valid=timestamp_status is not None and timestamp_status.valid,
            trusted=status.trusted,
            timestamp_trusted=timestamp_status is not None and timestamp_status.trusted,
            timestamp_signer_sha256=hashlib.sha256(timestamp_signer_der).hexdigest()
            if timestamp_signer_der
            else "",
            timestamp_utc=timestamp_utc,
            digest_algorithm=status.md_algorithm,
            subfilter=str(signature.sig_object["/SubFilter"]),
            field_name=signature.field_name,
            certificate_not_after_utc=certificate_not_after_utc,
            widget_page_index=widget_page_index,
            widget_box=widget_box,
            input_sha256=_sha256_file(request.input_path),
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_public_certificate(path: Path) -> asn1_x509.Certificate:
    raw = path.read_bytes()
    try:
        certificate = (
            x509.load_pem_x509_certificate(raw)
            if raw.startswith(b"-----BEGIN CERTIFICATE-----")
            else x509.load_der_x509_certificate(raw)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid public certificate") from exc
    return asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


def _certificate_paths_are_valid(request: ValidationRequest) -> bool:
    all_paths = request.trust_roots + request.intermediate_certificates
    if not isinstance(request.require_trust, bool):
        return False
    if not request.require_trust:
        return not all_paths
    if not 1 <= len(request.trust_roots) <= 16:
        return False
    if len(request.intermediate_certificates) > 32 or len(set(all_paths)) != len(all_paths):
        return False
    for path in all_paths:
        if (
            not path.is_absolute()
            or not path.is_file()
            or path.is_symlink()
            or path.suffix.lower() not in {".cer", ".crt", ".pem"}
            or not 1 <= path.stat().st_size <= 1024 * 1024
        ):
            return False
        _load_public_certificate(path)
    return True


def _request_is_valid(request: ValidationRequest) -> bool:
    try:
        return (
            request.input_path.is_absolute()
            and request.input_path.is_file()
            and request.output_path.is_absolute()
            and request.input_path.resolve(strict=False)
            != request.output_path.resolve(strict=False)
            and request.output_path.name.endswith((".pdf", ".pdf.part"))
            and request.output_path.is_file()
            and not request.input_path.is_symlink()
            and not request.output_path.is_symlink()
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", request.field_name) is not None
            and re.fullmatch(r"[0-9a-f]{64}", request.expected_signer_sha256) is not None
            and re.fullmatch(r"[0-9a-f]{64}", request.expected_input_sha256) is not None
            and 0 <= request.page_index < 10_000
            and len(request.box) == 4
            and all(
                not isinstance(value, bool)
                and isinstance(value, (int, float))
                and math.isfinite(value)
                for value in request.box
            )
            and request.box[0] < request.box[2]
            and request.box[1] < request.box[3]
            and _certificate_paths_are_valid(request)
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def validate_signed_pdf(request: ValidationRequest) -> dict[str, object]:
    if not _request_is_valid(request):
        return _failure("invalid_validation_request")
    try:
        facts = _inspect_pdf(request)
    except Exception:
        return _failure("invalid_pdf")
    return evaluate_validation_facts(request, facts)


def validate_with_evidence(request: ValidationRequest) -> dict[str, object]:
    if not _request_is_valid(request):
        return _evidence_failure("invalid_validation_request")
    try:
        facts = _inspect_pdf(request)
    except Exception:
        return _evidence_failure("invalid_pdf")
    result = evaluate_validation_facts(request, facts)
    if result != {"ok": True, "failureCode": None}:
        return _evidence_failure(str(result["failureCode"]))
    return {
        "ok": True,
        "failureCode": None,
        "signatureCount": facts.signature_count,
        "wholeFile": facts.whole_file,
        "timestampPresent": facts.timestamp_present,
        "signerTrusted": facts.trusted,
        "timestampTrusted": facts.timestamp_trusted,
        "timestampSignerSha256": facts.timestamp_signer_sha256,
        "timestampUtc": facts.timestamp_utc,
        "signerSuffix": facts.signer_sha256[-8:].upper(),
        "certificateNotAfterUtc": facts.certificate_not_after_utc,
        "page": facts.widget_page_index + 1,
        "box": list(facts.widget_box),
        "fieldName": facts.field_name,
        "inputUnchanged": facts.input_sha256 == request.expected_input_sha256,
    }


def _evidence_failure(code: str) -> dict[str, object]:
    return {
        "ok": False,
        "failureCode": code,
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


def _validation_worker(request: ValidationRequest, result_queue: object) -> None:
    logging.disable(logging.CRITICAL)
    try:
        result = validate_signed_pdf(request)
    except Exception:
        result = _failure("validation_process_failed")
    result_queue.put((os.getpid(), result))


def _spawn_validate_with_pid(
    request: ValidationRequest,
    timeout_seconds: float = 30,
    context_factory: Callable[[str], Any] = multiprocessing.get_context,
) -> tuple[dict[str, object], int]:
    result_queue = None
    process = None
    started = False
    worker_pid = -1
    try:
        context = context_factory("spawn")
        result_queue = context.Queue(maxsize=1)
        process = context.Process(target=_validation_worker, args=(request, result_queue))
        process.start()
        started = True
        worker_pid = process.pid or -1
        process.join(timeout=max(0.1, min(timeout_seconds, 30)))
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
            return _failure("validation_process_timeout"), worker_pid
        reported_pid, result = result_queue.get(timeout=2)
        valid_result = isinstance(result, dict) and set(result) == {"ok", "failureCode"}
        if (
            reported_pid != worker_pid
            or process.exitcode != 0
            or not valid_result
            or not isinstance(result.get("ok"), bool)
            or result.get("failureCode") is not None
            and not isinstance(result.get("failureCode"), str)
        ):
            return _failure("validation_process_failed"), worker_pid
        return result, worker_pid
    except Exception:
        return _failure("validation_process_failed"), worker_pid
    finally:
        if process is not None and started:
            try:
                if not process.is_alive():
                    process.close()
            except (OSError, ValueError):
                pass
        if result_queue is not None:
            try:
                result_queue.close()
            except (OSError, ValueError):
                pass
            try:
                result_queue.join_thread()
            except (OSError, ValueError):
                pass


def spawn_validate(request: ValidationRequest, timeout_seconds: float = 30) -> dict[str, object]:
    result, _ = _spawn_validate_with_pid(request, timeout_seconds)
    return result
