from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import math
import multiprocessing
import os
import re
import sys
import traceback
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pkcs11
from cryptography import x509
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import (
    AttributeSensitive,
    AttributeTypeInvalid,
    DeviceRemoved,
    PKCS11Error,
    SessionClosed,
    SessionHandleInvalid,
    TokenNotPresent,
    UserNotLoggedIn,
)
from pyhanko.stamp import TextStampStyle

VERSION = "0.1.3"
MAX_REQUEST_BYTES = 64 * 1024
MAX_IDENTIFIER_BYTES = 128
MAX_CERTIFICATE_DER_BYTES = 64 * 1024
MAX_CATALOG_SLOTS = 32
MAX_CATALOG_CERTIFICATES = 256
FIELD_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
HEX_IDENTIFIER_PATTERN = re.compile(r"^[0-9a-f]+$")
SESSION_LOSS_EXCEPTIONS = (
    SessionClosed,
    SessionHandleInvalid,
    UserNotLoggedIn,
    DeviceRemoved,
    TokenNotPresent,
)
WINDOWS_APPEARANCE_FONTS = (
    "NotoSansSC-VF.ttf",
    "Deng.ttf",
    "simhei.ttf",
    "simfang.ttf",
    "simkai.ttf",
    "simsunb.ttf",
)


class RequestError(ValueError):
    """Raised when a controlled helper request does not match its schema."""


class SignatureTextStampStyle(TextStampStyle):
    def create_stamp(self, writer: Any, box: Any, text_params: dict) -> Any:
        normalized = dict(text_params)
        timestamp = normalized.get("ts")
        if isinstance(timestamp, str):
            normalized["ts"] = re.sub(
                r"UTC([+-]\d{2})(\d{2})$",
                r"UTC\1:\2",
                timestamp,
            )
        return super().create_stamp(writer, box, normalized)


@dataclass(frozen=True)
class ProbeRequest:
    module_path: Path
    slot_id: int
    token_serial: str
    certificate_id: bytes
    private_key_id: bytes


@dataclass(frozen=True)
class CatalogRequest:
    module_path: Path


@dataclass(frozen=True)
class SignRequest(ProbeRequest):
    input_path: Path
    output_path: Path
    page_index: int
    box: tuple[float, float, float, float]
    field_name: str
    reason: str | None
    location: str | None
    tsa_url: str


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("duplicate_property")
        result[key] = value
    return result


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        if not path.is_absolute() or not path.is_file():
            raise RequestError("invalid_request_path")
        if path.stat().st_size > MAX_REQUEST_BYTES:
            raise RequestError("request_too_large")
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise RequestError("invalid_encoding")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except RequestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RequestError("invalid_json") from exc
    if not isinstance(value, dict):
        raise RequestError("invalid_schema")
    return value


def _required_string(values: dict[str, Any], name: str, max_length: int) -> str:
    value = values.get(name)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RequestError("invalid_schema")
    return value


def _hex_identifier(values: dict[str, Any], name: str) -> bytes:
    value = _required_string(values, name, MAX_IDENTIFIER_BYTES * 2)
    if len(value) % 2 or HEX_IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise RequestError("invalid_hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise RequestError("invalid_hex") from exc
    if not decoded or len(decoded) > MAX_IDENTIFIER_BYTES:
        raise RequestError("invalid_hex")
    return decoded


def load_probe_request(path: Path) -> ProbeRequest:
    values = _load_json_object(path)
    expected = {
        "modulePath",
        "slotId",
        "tokenSerial",
        "certificateIdHex",
        "privateKeyIdHex",
    }
    if set(values) != expected:
        raise RequestError("invalid_schema")

    module_path = Path(_required_string(values, "modulePath", 1024))
    if not module_path.is_absolute():
        raise RequestError("invalid_module_path")
    slot_id = values["slotId"]
    if isinstance(slot_id, bool) or not isinstance(slot_id, int) or not 0 <= slot_id < 2**64:
        raise RequestError("invalid_slot")

    return ProbeRequest(
        module_path=module_path,
        slot_id=slot_id,
        token_serial=_required_string(values, "tokenSerial", 128),
        certificate_id=_hex_identifier(values, "certificateIdHex"),
        private_key_id=_hex_identifier(values, "privateKeyIdHex"),
    )


def load_catalog_request(path: Path) -> CatalogRequest:
    values = _load_json_object(path)
    if set(values) != {"modulePath"}:
        raise RequestError("invalid_schema")
    module_path = Path(_required_string(values, "modulePath", 1024))
    if not module_path.is_absolute():
        raise RequestError("invalid_module_path")
    return CatalogRequest(module_path=module_path)


def _parse_common(values: dict[str, Any]) -> tuple[Path, int, str, bytes, bytes]:
    module_path = Path(_required_string(values, "modulePath", 1024))
    if not module_path.is_absolute():
        raise RequestError("invalid_module_path")
    slot_id = values.get("slotId")
    if isinstance(slot_id, bool) or not isinstance(slot_id, int) or not 0 <= slot_id < 2**64:
        raise RequestError("invalid_slot")
    return (
        module_path,
        slot_id,
        _required_string(values, "tokenSerial", 128),
        _hex_identifier(values, "certificateIdHex"),
        _hex_identifier(values, "privateKeyIdHex"),
    )


def _optional_string(values: dict[str, Any], name: str, max_length: int) -> str | None:
    value = values.get(name)
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > max_length
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RequestError("invalid_schema")
    return value or None


def _parse_box(values: dict[str, Any]) -> tuple[float, float, float, float]:
    raw = values.get("box")
    if not isinstance(raw, list) or len(raw) != 4:
        raise RequestError("invalid_box")
    coordinates: list[float] = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RequestError("invalid_box")
        coordinate = float(value)
        if not math.isfinite(coordinate):
            raise RequestError("invalid_box")
        coordinates.append(coordinate)
    left, bottom, right, top = coordinates
    if left >= right or bottom >= top:
        raise RequestError("invalid_box")
    return left, bottom, right, top


def _validate_tsa_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RequestError("invalid_tsa") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise RequestError("invalid_tsa")
    return value


def load_sign_request(path: Path) -> SignRequest:
    values = _load_json_object(path)
    required = {
        "modulePath",
        "slotId",
        "tokenSerial",
        "certificateIdHex",
        "privateKeyIdHex",
        "inputPath",
        "outputPath",
        "page",
        "box",
        "fieldName",
        "tsaUrl",
    }
    optional = {"reason", "location"}
    if not required.issubset(values) or set(values) - required - optional:
        raise RequestError("invalid_schema")

    module_path, slot_id, token_serial, certificate_id, private_key_id = _parse_common(values)
    input_path = Path(_required_string(values, "inputPath", 1024))
    output_path = Path(_required_string(values, "outputPath", 1024))
    if not input_path.is_absolute() or not input_path.is_file() or not output_path.is_absolute():
        raise RequestError("invalid_file_path")
    if not output_path.name.endswith((".part", ".part.pdf")):
        raise RequestError("invalid_output_path")
    try:
        if input_path.resolve(strict=True) == output_path.resolve(strict=False):
            raise RequestError("invalid_output_path")
        if output_path.exists() and os.path.samefile(input_path, output_path):
            raise RequestError("invalid_output_path")
    except RequestError:
        raise
    except (OSError, RuntimeError) as exc:
        raise RequestError("invalid_output_path") from exc
    page = values.get("page")
    if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 10_000:
        raise RequestError("invalid_page")
    field_name = _required_string(values, "fieldName", 64)
    if FIELD_NAME_PATTERN.fullmatch(field_name) is None:
        raise RequestError("invalid_field_name")
    tsa_url = _validate_tsa_url(_required_string(values, "tsaUrl", 2048))
    return SignRequest(
        module_path=module_path,
        slot_id=slot_id,
        token_serial=token_serial,
        certificate_id=certificate_id,
        private_key_id=private_key_id,
        input_path=input_path,
        output_path=output_path,
        page_index=page - 1,
        box=_parse_box(values),
        field_name=field_name,
        reason=_optional_string(values, "reason", 128),
        location=_optional_string(values, "location", 128),
        tsa_url=tsa_url,
    )


def load_validate_request(path: Path):
    from CodeSignAuto_pdf_validator import ValidationRequest

    values = _load_json_object(path)
    expected = {
        "inputPath",
        "outputPath",
        "fieldName",
        "expectedInputSha256",
        "expectedSignerSha256",
        "page",
        "box",
        "trustRoots",
        "intermediateCertificates",
    }
    if set(values) != expected:
        raise RequestError("invalid_schema")

    input_path = Path(_required_string(values, "inputPath", 1024))
    output_path = Path(_required_string(values, "outputPath", 1024))
    if (
        not input_path.is_absolute()
        or not output_path.is_absolute()
        or not input_path.is_file()
        or not output_path.is_file()
        or input_path.is_symlink()
        or output_path.is_symlink()
        or not output_path.name.endswith((".pdf", ".pdf.part"))
    ):
        raise RequestError("invalid_file_path")
    try:
        if input_path.resolve(strict=True) == output_path.resolve(strict=True) or os.path.samefile(
            input_path, output_path
        ):
            raise RequestError("invalid_file_path")
    except RequestError:
        raise
    except (OSError, RuntimeError) as exc:
        raise RequestError("invalid_file_path") from exc

    field_name = _required_string(values, "fieldName", 64)
    if FIELD_NAME_PATTERN.fullmatch(field_name) is None:
        raise RequestError("invalid_field_name")
    expected_input_sha256 = _required_string(values, "expectedInputSha256", 64)
    expected_signer_sha256 = _required_string(values, "expectedSignerSha256", 64)
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_input_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", expected_signer_sha256) is None
    ):
        raise RequestError("invalid_hash")
    page = values.get("page")
    if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 10_000:
        raise RequestError("invalid_page")

    trust_roots = _public_certificate_paths(values, "trustRoots", minimum=1, maximum=16)
    intermediate_certificates = _public_certificate_paths(
        values, "intermediateCertificates", minimum=0, maximum=32
    )
    if len(set(trust_roots + intermediate_certificates)) != len(
        trust_roots + intermediate_certificates
    ):
        raise RequestError("invalid_certificate_path")

    return ValidationRequest(
        input_path=input_path,
        output_path=output_path,
        field_name=field_name,
        expected_signer_sha256=expected_signer_sha256,
        expected_input_sha256=expected_input_sha256,
        page_index=page - 1,
        box=_parse_box(values),
        trust_roots=trust_roots,
        intermediate_certificates=intermediate_certificates,
        require_trust=True,
    )


def _public_certificate_paths(
    values: dict[str, Any], name: str, *, minimum: int, maximum: int
) -> tuple[Path, ...]:
    raw = values.get(name)
    if not isinstance(raw, list) or not minimum <= len(raw) <= maximum:
        raise RequestError("invalid_schema")
    result: list[Path] = []
    for value in raw:
        if not isinstance(value, str) or not value or len(value) > 1024:
            raise RequestError("invalid_certificate_path")
        certificate_path = Path(value)
        try:
            if (
                not certificate_path.is_absolute()
                or not certificate_path.is_file()
                or certificate_path.is_symlink()
                or certificate_path.suffix.lower() not in {".cer", ".crt", ".pem"}
                or not 1 <= certificate_path.stat().st_size <= 1024 * 1024
            ):
                raise RequestError("invalid_certificate_path")
            raw_certificate = certificate_path.read_bytes()
            if raw_certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
                x509.load_pem_x509_certificate(raw_certificate)
            else:
                x509.load_der_x509_certificate(raw_certificate)
        except RequestError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise RequestError("invalid_certificate_path") from exc
        result.append(certificate_path)
    if len(set(result)) != len(result):
        raise RequestError("invalid_certificate_path")
    return tuple(result)


def _probe_result(
    *,
    token: bool,
    certificate: bool,
    private_key: bool,
    failure_code: str | None,
    certificate_not_after_utc: str | None = None,
    certificate_thumbprint_suffix: str | None = None,
) -> dict[str, bool | str | None]:
    return {
        "ok": failure_code is None,
        "tokenPresent": token,
        "certificatePresent": certificate,
        "privateKeyPresent": private_key,
        "failureCode": failure_code,
        "certificateNotAfterUtc": certificate_not_after_utc,
        "certificateThumbprintSuffix": certificate_thumbprint_suffix,
    }


def _normalized_token_serial(value: object) -> str | None:
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    normalized = value.rstrip(" \0")
    if (
        not normalized
        or len(normalized) > 128
        or not normalized.isascii()
        or not normalized.isprintable()
    ):
        return None
    return normalized


def probe_token(
    request: ProbeRequest,
    library_loader: Callable[[str], Any] = pkcs11.lib,
) -> dict[str, bool | str | None]:
    token_present = False
    certificate_present = False
    try:
        library = library_loader(str(request.module_path))
        slot = next(
            (
                candidate
                for candidate in library.get_slots(token_present=True)
                if candidate.slot_id == request.slot_id
            ),
            None,
        )
        if slot is None:
            return _probe_result(
                token=False,
                certificate=False,
                private_key=False,
                failure_code="token_missing",
            )
        token = slot.get_token()
        if _normalized_token_serial(token.serial) != request.token_serial:
            return _probe_result(
                token=False,
                certificate=False,
                private_key=False,
                failure_code="token_identifier_mismatch",
            )
        token_present = True
        with token.open() as session:
            certificate_object = next(
                iter(
                    session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.ID: request.certificate_id,
                        }
                    )
                ),
                None,
            )
            certificate_present = certificate_object is not None
            if not certificate_present:
                result = _probe_result(
                    token=True,
                    certificate=False,
                    private_key=False,
                    failure_code="certificate_missing",
                )
            else:
                certificate_der = certificate_object[Attribute.VALUE]
                if not isinstance(certificate_der, bytes) or not certificate_der:
                    return _probe_result(
                        token=True,
                        certificate=True,
                        private_key=False,
                        failure_code="certificate_invalid",
                    )
                try:
                    selected_certificate = x509.load_der_x509_certificate(certificate_der)
                    not_after_utc = selected_certificate.not_valid_after_utc.isoformat(
                        timespec="seconds"
                    ).replace("+00:00", "Z")
                    thumbprint_suffix = hashlib.sha256(certificate_der).hexdigest()[-8:].upper()
                except (TypeError, ValueError):
                    return _probe_result(
                        token=True,
                        certificate=True,
                        private_key=False,
                        failure_code="certificate_invalid",
                    )
                private_key_present = (
                    next(
                        iter(
                            session.get_objects(
                                {
                                    Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                                    Attribute.ID: request.private_key_id,
                                }
                            )
                        ),
                        None,
                    )
                    is not None
                )
                result = _probe_result(
                    token=True,
                    certificate=True,
                    private_key=private_key_present,
                    failure_code=None if private_key_present else "private_key_missing",
                    certificate_not_after_utc=not_after_utc,
                    certificate_thumbprint_suffix=thumbprint_suffix,
                )
        return result
    except Exception:
        return _probe_result(
            token=token_present,
            certificate=certificate_present,
            private_key=False,
            failure_code="pkcs11_unavailable",
        )


def _catalog_result(
    failure_code: str | None, certificates: list[dict[str, int | str | None]] | None = None
) -> dict[str, object]:
    return {
        "ok": failure_code is None,
        "failureCode": failure_code,
        "certificates": certificates or [],
    }


def _catalog_invalid() -> dict[str, object]:
    return _catalog_result("certificate_catalog_invalid")


def _catalog_observations(values: Any, maximum: int):
    iterator = iter(values)
    for _ in range(maximum):
        try:
            yield next(iterator)
        except StopIteration:
            return


def _catalog_private_key_match(session: Any, certificate_id: bytes) -> tuple[str, str | None]:
    private_keys = _catalog_observations(
        session.get_objects(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.ID: certificate_id,
            }
        ),
        2,
    )
    observed: list[Any] = []
    try:
        for private_key in private_keys:
            private_key_id = private_key[Attribute.ID]
            if not isinstance(private_key_id, bytes) or private_key_id != certificate_id:
                raise RequestError("certificate_catalog_invalid")
            observed.append(private_key)
    except (KeyError, AttributeSensitive, AttributeTypeInvalid) as exc:
        raise RequestError("certificate_catalog_invalid") from exc
    if not observed:
        return "missing", None
    if len(observed) == 2:
        return "ambiguous", None
    return "unique", certificate_id.hex()


def catalog_certificates(
    request: CatalogRequest,
    library_loader: Callable[[str], Any] = pkcs11.lib,
) -> dict[str, object]:
    try:
        records: list[dict[str, int | str | None]] = []
        identities: set[tuple[int, bytes, bytes]] = set()
        slots_seen = False
        certificate_count = 0
        slots = _catalog_observations(
            library_loader(str(request.module_path)).get_slots(token_present=True),
            MAX_CATALOG_SLOTS + 1,
        )
        for slot_index, slot in enumerate(slots):
            slots_seen = True
            if slot_index == MAX_CATALOG_SLOTS:
                return _catalog_invalid()
            slot_id = getattr(slot, "slot_id", None)
            if (
                isinstance(slot_id, bool)
                or not isinstance(slot_id, int)
                or not 0 <= slot_id < 2**64
            ):
                return _catalog_invalid()
            token = slot.get_token()
            token_serial = _normalized_token_serial(token.serial)
            if token_serial is None:
                return _catalog_invalid()
            with token.open() as session:
                observed_certificates: list[tuple[bytes, bytes]] = []
                certificates = _catalog_observations(
                    session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}),
                    MAX_CATALOG_CERTIFICATES + 1,
                )
                for certificate_index, certificate in enumerate(certificates):
                    if certificate_index == MAX_CATALOG_CERTIFICATES:
                        return _catalog_invalid()
                    certificate_count += 1
                    if certificate_count > MAX_CATALOG_CERTIFICATES:
                        return _catalog_invalid()
                    try:
                        certificate_id = certificate[Attribute.ID]
                        certificate_der = certificate[Attribute.VALUE]
                    except (KeyError, AttributeSensitive, AttributeTypeInvalid):
                        return _catalog_invalid()
                    if (
                        not isinstance(certificate_id, bytes)
                        or not certificate_id
                        or len(certificate_id) > MAX_IDENTIFIER_BYTES
                        or not isinstance(certificate_der, bytes)
                        or not certificate_der
                        or len(certificate_der) > MAX_CERTIFICATE_DER_BYTES
                    ):
                        return _catalog_invalid()
                    try:
                        x509.load_der_x509_certificate(certificate_der)
                    except (TypeError, ValueError):
                        return _catalog_invalid()
                    identity = (slot_id, certificate_id, certificate_der)
                    if identity in identities:
                        return _catalog_invalid()
                    identities.add(identity)
                    observed_certificates.append((certificate_id, certificate_der))
                for certificate_id, certificate_der in observed_certificates:
                    private_key_match, private_key_id_hex = _catalog_private_key_match(
                        session, certificate_id
                    )
                    records.append(
                        {
                            "slotId": slot_id,
                            "tokenSerial": token_serial,
                            "certificateIdHex": certificate_id.hex(),
                            "privateKeyMatch": private_key_match,
                            "privateKeyIdHex": private_key_id_hex,
                            "certificateDerBase64": b64encode(certificate_der).decode("ascii"),
                        }
                    )
        if not slots_seen:
            return _catalog_result("token_missing")
        return _catalog_result(None, records)
    except RequestError:
        return _catalog_invalid()
    except TokenNotPresent:
        return _catalog_result("token_missing")
    except SESSION_LOSS_EXCEPTIONS:
        return _catalog_result("pkcs11_session_lost")
    except PKCS11Error:
        return _catalog_result("pkcs11_unavailable")
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return _catalog_result("catalog_unexpected_error")


def _find_slot_and_token(request: ProbeRequest, library_loader: Callable[[str], Any]) -> Any:
    library = library_loader(str(request.module_path))
    slot = next(
        (
            candidate
            for candidate in library.get_slots(token_present=True)
            if candidate.slot_id == request.slot_id
        ),
        None,
    )
    if slot is None:
        raise RequestError("token_missing")
    token = slot.get_token()
    if _normalized_token_serial(token.serial) != request.token_serial:
        raise RequestError("token_identifier_mismatch")
    return token


def _first_exact_object(session: Any, object_class: ObjectClass, object_id: bytes) -> Any:
    return next(
        iter(session.get_objects({Attribute.CLASS: object_class, Attribute.ID: object_id})),
        None,
    )


def _default_sign_backend(request: SignRequest, session: Any) -> None:
    from pyhanko.sign import pkcs11 as pyhanko_pkcs11
    from pyhanko.sign import timestamps

    signer = pyhanko_pkcs11.PKCS11Signer(
        pkcs11_session=session,
        cert_id=request.certificate_id,
        key_id=request.private_key_id,
        prefer_pss=False,
    )
    sign_pdf_with_signer(
        request,
        signer,
        timestamps.HTTPTimeStamper(request.tsa_url),
    )


def _certificate_display_organization(signer: Any) -> str:
    certificate = getattr(signer, "signing_cert", None)
    subject = getattr(certificate, "subject", None)
    native = getattr(subject, "native", {})
    if not isinstance(native, dict):
        native = {}
    value = native.get("organization_name") or native.get("common_name")
    if isinstance(value, (list, tuple)):
        value = next((item for item in value if isinstance(item, str) and item.strip()), None)
    if not isinstance(value, str) or not value.strip():
        value = "Digital signature"
    return " ".join(value.split())[:128]


def _font_supports_text(font_path: Path, text: str) -> bool:
    from fontTools.ttLib import TTFont, TTLibError

    try:
        with TTFont(str(font_path), lazy=True) as font:
            cmap = font.getBestCmap() or {}
            return all(character.isspace() or ord(character) in cmap for character in text)
    except (OSError, KeyError, TTLibError):
        return False


def _windows_fonts_directory() -> Path | None:
    if os.name != "nt":
        return Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        return None
    windows_root = Path(buffer.value)
    if not windows_root.is_absolute():
        return None
    return windows_root / "Fonts"


def _appearance_font_candidates() -> tuple[Path, ...]:
    fonts_directory = _windows_fonts_directory()
    if fonts_directory is None:
        return ()
    return tuple(fonts_directory / name for name in WINDOWS_APPEARANCE_FONTS)


def _signature_stamp_style(required_text: str) -> SignatureTextStampStyle:
    from pyhanko.pdf_utils.text import TextBoxStyle

    text_box_style = TextBoxStyle(font_size=10)
    if os.name == "nt":
        font_path = next(
            (
                candidate
                for candidate in _appearance_font_candidates()
                if (
                    candidate.is_file()
                    and not candidate.is_symlink()
                    and _font_supports_text(candidate, required_text)
                )
            ),
            None,
        )
        if font_path is None:
            raise RuntimeError("pdf_appearance_font_missing")
        from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory

        text_box_style = TextBoxStyle(
            font=GlyphAccumulatorFactory(str(font_path)),
            font_size=10,
        )

    return SignatureTextStampStyle(
        border_width=0,
        background=None,
        text_box_style=text_box_style,
        stamp_text="%(organization)s\n%(ts)s",
        timestamp_format="%Y-%m-%d %H:%M:%S UTC%z",
    )


def sign_pdf_with_signer(request: SignRequest, signer: Any, timestamper: Any) -> None:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter

    organization = _certificate_display_organization(signer)
    metadata = signers.PdfSignatureMetadata(
        field_name=request.field_name,
        md_algorithm="sha256",
        reason=request.reason,
        location=request.location,
        subfilter=SigSeedSubFilter.PADES,
    )
    field_spec = SigFieldSpec(
        sig_field_name=request.field_name,
        on_page=request.page_index,
        box=request.box,
    )
    with (
        request.input_path.open("rb") as input_stream,
        request.output_path.open("wb") as output_stream,
    ):
        writer = IncrementalPdfFileWriter(input_stream)
        signers.PdfSigner(
            metadata,
            signer=signer,
            timestamper=timestamper,
            stamp_style=_signature_stamp_style(organization),
            new_field_spec=field_spec,
        ).sign_pdf(
            writer,
            output=output_stream,
            appearance_text_params={
                "organization": organization,
            },
        )


def _default_validation_runner(validation_request: Any) -> dict[str, object]:
    from CodeSignAuto_pdf_validator import spawn_validate

    return spawn_validate(validation_request)


def _sha256_file(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.digest()


def _safe_unlink(path: Path) -> bool:
    try:
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def sign_document(
    request: SignRequest,
    library_loader: Callable[[str], Any] = pkcs11.lib,
    sign_backend: Callable[[SignRequest, Any], None] = _default_sign_backend,
    validation_runner: Callable[[Any], dict[str, object]] = _default_validation_runner,
) -> dict[str, object]:
    from CodeSignAuto_pdf_validator import ValidationRequest

    if not _safe_unlink(request.output_path):
        return {"ok": False, "failureCode": "pdf_sign_failed"}
    try:
        before_hash = _sha256_file(request.input_path)
    except OSError:
        return {"ok": False, "failureCode": "pdf_sign_failed"}

    try:
        token = _find_slot_and_token(request, library_loader)
    except RequestError as exc:
        return {"ok": False, "failureCode": str(exc)}
    except SESSION_LOSS_EXCEPTIONS:
        return {"ok": False, "failureCode": "pkcs11_session_lost"}
    except Exception:
        return {"ok": False, "failureCode": "pkcs11_unavailable"}

    signing_started = False
    try:
        with token.open() as session:
            certificate = _first_exact_object(
                session, ObjectClass.CERTIFICATE, request.certificate_id
            )
            if certificate is None:
                return {"ok": False, "failureCode": "certificate_missing"}
            private_key = _first_exact_object(
                session, ObjectClass.PRIVATE_KEY, request.private_key_id
            )
            if private_key is None:
                return {"ok": False, "failureCode": "private_key_missing"}
            certificate_der = certificate[Attribute.VALUE]
            if not isinstance(certificate_der, bytes) or not certificate_der:
                return {"ok": False, "failureCode": "certificate_invalid"}
            signing_started = True
            sign_backend(request, session)
    except SESSION_LOSS_EXCEPTIONS:
        _safe_unlink(request.output_path)
        return {"ok": False, "failureCode": "pkcs11_session_lost"}
    except PKCS11Error:
        _safe_unlink(request.output_path)
        return {"ok": False, "failureCode": "pkcs11_unavailable"}
    except RuntimeError as exc:
        _safe_unlink(request.output_path)
        if str(exc) == "pdf_appearance_font_missing":
            return {"ok": False, "failureCode": "pdf_appearance_font_missing"}
        return {
            "ok": False,
            "failureCode": "pdf_sign_failed" if signing_started else "pkcs11_unavailable",
        }
    except Exception:
        _safe_unlink(request.output_path)
        return {
            "ok": False,
            "failureCode": "pdf_sign_failed" if signing_started else "pkcs11_unavailable",
        }

    try:
        after_hash = _sha256_file(request.input_path)
    except OSError:
        _safe_unlink(request.output_path)
        return {"ok": False, "failureCode": "pdf_sign_failed"}
    if after_hash != before_hash:
        _safe_unlink(request.output_path)
        return {"ok": False, "failureCode": "input_modified"}
    if not request.output_path.is_file():
        return {"ok": False, "failureCode": "pdf_sign_failed"}

    validation_request = ValidationRequest(
        input_path=request.input_path,
        output_path=request.output_path,
        field_name=request.field_name,
        expected_signer_sha256=hashlib.sha256(certificate_der).hexdigest(),
        expected_input_sha256=before_hash.hex(),
        page_index=request.page_index,
        box=request.box,
    )
    try:
        result = validation_runner(validation_request)
    except Exception:
        _safe_unlink(request.output_path)
        return {"ok": False, "failureCode": "pdf_validation_failed"}
    if result == {"ok": True, "failureCode": None}:
        return result
    _safe_unlink(request.output_path)
    return {"ok": False, "failureCode": "pdf_validation_failed"}


def _write_json_line(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n")


def _failure_exit_code(failure_code: object, command: str) -> int:
    if failure_code is None:
        return 0
    if command == "probe":
        return 10 if failure_code == "pkcs11_unavailable" else 0
    if command == "catalog":
        return (
            10
            if failure_code
            in {"pkcs11_unavailable", "pkcs11_session_lost", "catalog_unexpected_error"}
            else 0
        )
    if command == "validate":
        return 20
    if failure_code in {
        "token_missing",
        "token_identifier_mismatch",
        "certificate_missing",
        "private_key_missing",
        "certificate_invalid",
        "pkcs11_unavailable",
        "pkcs11_session_lost",
    }:
        return 10
    if failure_code == "pdf_validation_failed":
        return 30
    return 20


def main(argv: list[str] | None = None) -> int:
    logging.disable(logging.CRITICAL)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--version"]:
        sys.stdout.write(VERSION + "\n")
        return 0
    if (
        len(arguments) != 3
        or arguments[0] not in {"probe", "sign", "validate", "catalog"}
        or arguments[1] != "--request"
    ):
        _write_json_line({"ok": False, "failureCode": "invalid_request"})
        return 2
    command = arguments[0]
    try:
        request_path = Path(arguments[2])
        if command == "probe":
            result = probe_token(load_probe_request(request_path))
        elif command == "catalog":
            result = catalog_certificates(load_catalog_request(request_path))
        elif command == "validate":
            from CodeSignAuto_pdf_validator import validate_with_evidence

            result = validate_with_evidence(load_validate_request(request_path))
        else:
            result = sign_document(load_sign_request(request_path))
    except RequestError:
        _write_json_line({"ok": False, "failureCode": "invalid_request"})
        return 2
    except Exception:
        if command == "catalog":
            traceback.print_exc(file=sys.stderr)
            result = _catalog_result("catalog_unexpected_error")
        elif command == "validate":
            from CodeSignAuto_pdf_validator import _evidence_failure

            result = _evidence_failure("validation_process_failed")
        else:
            result = {
                "ok": False,
                "failureCode": (
                    "pkcs11_unavailable" if command in {"probe", "catalog"} else "pdf_sign_failed"
                ),
            }
    _write_json_line(result)
    return _failure_exit_code(result.get("failureCode"), command)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
