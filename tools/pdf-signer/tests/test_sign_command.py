from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import (
    DeviceRemoved,
    GeneralError,
    SessionClosed,
    SessionHandleInvalid,
    TokenNotPresent,
    UserNotLoggedIn,
)

import CodeSignAuto_pdf_signer
from CodeSignAuto_pdf_signer import (
    RequestError,
    SignRequest,
    _failure_exit_code,
    load_sign_request,
    sign_document,
)

SCRIPT = Path(__file__).parents[1] / "CodeSignAuto_pdf_signer.py"
CERTIFICATE_ID = bytes.fromhex("c0ffee01")
PRIVATE_KEY_ID = bytes.fromhex("decafbad")


def test_frozen_production_dependency_surface_is_pdf_pades_only() -> None:
    project_root = Path(__file__).parents[1]
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["dependencies"] == [
        "cryptography>=48,<49",
        "pyHanko[opentype,pkcs11]==0.36.2",
    ]

    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
    locked_names = {package["name"] for package in lock["package"]}
    assert {
        "pyhanko",
        "pyhanko-certvalidator",
        "python-pkcs11",
        "cryptography",
        "fonttools",
        "uharfbuzz",
    } <= locked_names
    assert locked_names.isdisjoint(
        {"click", "pillow", "pyhanko-cli", "python-barcode", "pyyaml"}
    )
    project_locks = [
        package for package in lock["package"] if package.get("source") == {"virtual": "."}
    ]
    assert len(project_locks) == 1
    assert project_locks[0]["metadata"]["requires-dist"] == [
        {"name": "cryptography", "specifier": ">=48,<49"},
        {
            "name": "pyhanko",
            "extras": ["opentype", "pkcs11"],
            "specifier": "==0.36.2",
        },
    ]


def valid_sign_mapping(tmp_path: Path) -> dict[str, object]:
    input_path = tmp_path / "input.pdf"
    input_path.write_bytes(b"%PDF-controlled-input")
    return {
        "modulePath": str(tmp_path / "pkcs11.dll"),
        "slotId": 42,
        "tokenSerial": "TEST-TOKEN-SERIAL-0001",
        "certificateIdHex": CERTIFICATE_ID.hex(),
        "privateKeyIdHex": PRIVATE_KEY_ID.hex(),
        "inputPath": str(input_path),
        "outputPath": str(tmp_path / "result.pdf.part"),
        "page": 2,
        "box": [200, 642, 548, 680],
        "fieldName": "CertumDocumentSignature",
        "reason": "Document approval",
        "location": "CN",
        "tsaUrl": "http://time.certum.pl",
    }


def write_request(tmp_path: Path, values: dict[str, object], name: str = "request.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(values), encoding="utf-8")
    return path


def test_sign_request_accepts_only_the_controlled_schema(tmp_path: Path) -> None:
    values = valid_sign_mapping(tmp_path)
    request = load_sign_request(write_request(tmp_path, values))

    assert request.page_index == 1
    assert request.box == (200.0, 642.0, 548.0, 680.0)
    assert request.certificate_id == CERTIFICATE_ID
    assert request.private_key_id == PRIVATE_KEY_ID
    assert request.output_path.name.endswith(".part")


def test_sign_request_accepts_the_service_pdf_spool_part_name(tmp_path: Path) -> None:
    values = valid_sign_mapping(tmp_path)
    values["outputPath"] = str(tmp_path / "result.part.pdf")

    request = load_sign_request(write_request(tmp_path, values, "service-spool.json"))

    assert request.output_path.name == "result.part.pdf"


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("extra", True),
        ("page", 0),
        ("page", True),
        ("box", [200, 642, 200, 680]),
        ("box", [200, 642, 548]),
        ("box", [200, 642, float("inf"), 680]),
        ("fieldName", "not allowed spaces"),
        ("fieldName", "x" * 65),
        ("reason", "x" * 129),
        ("location", "x" * 129),
        ("appearance", {"text": "unsupported"}),
        ("tsaUrl", "file:///controlled/tsa"),
        ("tsaUrl", "http://user:secret@time.example"),
    ],
)
def test_sign_request_rejects_unknown_wrong_type_and_unsupported_values(
    tmp_path: Path, change: str, value: object
) -> None:
    values = valid_sign_mapping(tmp_path)
    values[change] = value

    with pytest.raises(RequestError):
        load_sign_request(write_request(tmp_path, values, f"bad-{change}.json"))


def test_sign_request_rejects_duplicate_property_and_input_as_output(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"modulePath":"/controlled/a","modulePath":"/controlled/b"}',
        encoding="utf-8",
    )
    with pytest.raises(RequestError):
        load_sign_request(duplicate)

    values = valid_sign_mapping(tmp_path)
    values["outputPath"] = values["inputPath"]
    with pytest.raises(RequestError):
        load_sign_request(write_request(tmp_path, values, "same.json"))


def test_sign_request_rejects_directory_symlink_alias_before_unlinking_input(
    tmp_path: Path,
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    alias_directory = tmp_path / "alias"
    try:
        alias_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    input_path = real_directory / "same.pdf.part"
    input_path.write_bytes(b"must-survive")
    values = valid_sign_mapping(tmp_path)
    values["inputPath"] = str(input_path)
    values["outputPath"] = str(alias_directory / input_path.name)
    rejected = False

    try:
        request = load_sign_request(write_request(tmp_path, values, "alias.json"))
    except RequestError:
        rejected = True
    else:
        sign_document(request, library_loader=lambda path: FakeLibrary(FakeToken(FakeSession([]))))

    assert input_path.exists(), "the old implementation unlinked the input through its alias"
    assert rejected is True


def test_sign_request_rejects_existing_hardlink_to_input(tmp_path: Path) -> None:
    values = valid_sign_mapping(tmp_path)
    input_path = Path(values["inputPath"])
    output_path = Path(values["outputPath"])
    os.link(input_path, output_path)

    with pytest.raises(RequestError):
        load_sign_request(write_request(tmp_path, values, "hardlink.json"))
    assert input_path.read_bytes() == b"%PDF-controlled-input"


def test_sign_request_maps_path_resolution_error_to_request_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = valid_sign_mapping(tmp_path)
    output_path = Path(values["outputPath"])
    real_resolve = Path.resolve

    def fail_output_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        if path == output_path:
            raise OSError("simulated path resolution failure")
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_output_resolution)

    with pytest.raises(RequestError):
        load_sign_request(write_request(tmp_path, values, "resolve-error.json"))


def make_symlink_loop(tmp_path: Path) -> Path:
    first = tmp_path / "loop-first.part"
    second = tmp_path / "loop-second.part"
    try:
        first.symlink_to(second.name)
        second.symlink_to(first.name)
    except OSError as exc:
        pytest.skip(f"symlink loop unavailable: {exc}")
    return first


def test_sign_request_maps_real_output_symlink_loop_to_request_error(tmp_path: Path) -> None:
    values = valid_sign_mapping(tmp_path)
    values["outputPath"] = str(make_symlink_loop(tmp_path))
    request_path = write_request(tmp_path, values, "symlink-loop.json")

    with pytest.raises(RequestError):
        load_sign_request(request_path)
    assert Path(values["inputPath"]).is_file()


def test_cli_maps_real_output_symlink_loop_to_exit_2_without_deleting_input(
    tmp_path: Path,
) -> None:
    values = valid_sign_mapping(tmp_path)
    values["outputPath"] = str(make_symlink_loop(tmp_path))
    request_path = write_request(tmp_path, values, "symlink-loop-cli.json")

    result = run_cli("sign", "--request", str(request_path))

    assert result.returncode == 2
    assert result.stdout == '{"ok":false,"failureCode":"invalid_request"}\n'
    assert result.stderr == ""
    assert Path(values["inputPath"]).is_file()


@pytest.mark.parametrize("identifier", ["c0 ff 01", "c0\tff\t01", "C0FF", "abc", ""])
def test_sign_request_rejects_noncanonical_hex_identifiers(tmp_path: Path, identifier: str) -> None:
    values = valid_sign_mapping(tmp_path)
    values["certificateIdHex"] = identifier

    with pytest.raises(RequestError):
        load_sign_request(write_request(tmp_path, values, "bad-hex.json"))


class FakeObject:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def __getitem__(self, attribute: Attribute) -> bytes:
        if attribute == Attribute.VALUE:
            return self.value
        raise KeyError(attribute)


class FakeSession:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.closed = False
        self.queries: list[dict[Attribute, object]] = []

    def __enter__(self) -> FakeSession:
        self.events.append("session-open")
        return self

    def __exit__(self, *_: object) -> None:
        self.closed = True
        self.events.append("session-close")

    def get_objects(self, attrs: dict[Attribute, object]):
        self.queries.append(attrs)
        object_class = attrs[Attribute.CLASS]
        object_id = attrs[Attribute.ID]
        if object_class == ObjectClass.CERTIFICATE and object_id == CERTIFICATE_ID:
            return iter([FakeObject(b"expected-certificate-der")])
        if object_class == ObjectClass.PRIVATE_KEY and object_id == PRIVATE_KEY_ID:
            return iter([FakeObject(b"private-key")])
        return iter(())


class FakeToken:
    serial = b"TEST-TOKEN-SERIAL-0001"

    def __init__(self, session: FakeSession) -> None:
        self.session = session

    def open(self) -> FakeSession:
        return self.session


class FakeSlot:
    slot_id = 42

    def __init__(self, token: FakeToken) -> None:
        self.token = token

    def get_token(self) -> FakeToken:
        return self.token


class FakeLibrary:
    def __init__(self, token: FakeToken) -> None:
        self.slot = FakeSlot(token)

    def get_slots(self, token_present: bool = False) -> list[FakeSlot]:
        assert token_present is True
        return [self.slot]


def test_sign_closes_session_before_independent_validation_and_preserves_input(
    tmp_path: Path,
) -> None:
    request_path = write_request(tmp_path, valid_sign_mapping(tmp_path))
    request = load_sign_request(request_path)
    original_hash = hashlib.sha256(request.input_path.read_bytes()).hexdigest()
    events: list[str] = []
    session = FakeSession(events)

    def sign_backend(sign_request: SignRequest, active_session: FakeSession) -> None:
        assert active_session is session
        assert active_session.closed is False
        events.append("sign")
        sign_request.output_path.write_bytes(b"signed-pdf")

    def validator(validation_request: object) -> dict[str, object]:
        assert session.closed is True
        assert (
            getattr(validation_request, "expected_signer_sha256")
            == hashlib.sha256(b"expected-certificate-der").hexdigest()
        )
        assert getattr(validation_request, "require_trust") is False
        assert getattr(validation_request, "trust_roots") == ()
        assert getattr(validation_request, "intermediate_certificates") == ()
        events.append("validate")
        return {"ok": True, "failureCode": None}

    result = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=sign_backend,
        validation_runner=validator,
    )

    assert result == {"ok": True, "failureCode": None}
    assert events == ["session-open", "sign", "session-close", "validate"]
    assert session.queries == [
        {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.ID: CERTIFICATE_ID},
        {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: PRIVATE_KEY_ID},
    ]
    assert hashlib.sha256(request.input_path.read_bytes()).hexdigest() == original_hash
    assert request.output_path.read_bytes() == b"signed-pdf"


def test_sign_streams_input_hash_instead_of_reading_the_whole_pdf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    session = FakeSession([])

    def forbid_read_bytes(self: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not be used for a bounded 512 MiB input")

    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)

    result = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=lambda sign_request, active_session: sign_request.output_path.write_bytes(
            b"signed-pdf"
        ),
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )

    assert result == {"ok": True, "failureCode": None}


def test_sign_cleans_part_when_backend_removes_input_before_post_sign_hash(
    tmp_path: Path,
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    session = FakeSession([])

    def remove_input_after_writing_part(
        sign_request: SignRequest, active_session: FakeSession
    ) -> None:
        sign_request.output_path.write_bytes(b"signed-but-input-gone")
        sign_request.input_path.unlink()

    result = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=remove_input_after_writing_part,
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )

    assert result == {"ok": False, "failureCode": "pdf_sign_failed"}
    assert _failure_exit_code(result["failureCode"], "sign") == 20
    assert request.output_path.exists() is False


def test_cleanup_unlink_error_never_masks_pkcs11_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    session = FakeSession([])
    real_unlink = Path.unlink

    def locked_part_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == request.output_path and path.exists():
            raise PermissionError("simulated locked part")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", locked_part_unlink)

    def write_then_lose_session(sign_request: SignRequest, active_session: FakeSession) -> None:
        sign_request.output_path.write_bytes(b"partial")
        raise SessionClosed()

    result = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=write_then_lose_session,
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )

    assert result == {"ok": False, "failureCode": "pkcs11_session_lost"}
    assert _failure_exit_code(result["failureCode"], "sign") == 10


def test_exit_mapping_preserves_probe_diagnostics_and_stable_sign_categories() -> None:
    assert _failure_exit_code("token_missing", "probe") == 0
    assert _failure_exit_code("certificate_missing", "probe") == 0
    assert _failure_exit_code("private_key_missing", "probe") == 0
    assert _failure_exit_code("token_identifier_mismatch", "probe") == 0
    assert _failure_exit_code("pkcs11_unavailable", "probe") == 10
    assert _failure_exit_code("token_missing", "sign") == 10
    assert _failure_exit_code("pdf_sign_failed", "sign") == 20
    assert _failure_exit_code("pdf_validation_failed", "sign") == 30


@pytest.mark.parametrize("failure_stage", ["library", "open", "lookup"])
def test_sign_maps_native_token_and_session_failures_to_exit_10_and_removes_part(
    tmp_path: Path, failure_stage: str
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    request.output_path.write_bytes(b"stale-part-must-not-survive")
    session = FakeSession([])
    token = FakeToken(session)

    if failure_stage == "library":

        def library_loader(path: str):
            raise RuntimeError("native module path")
    else:

        def library_loader(path: str):
            return FakeLibrary(token)

    if failure_stage == "open":
        token.open = lambda: (_ for _ in ()).throw(RuntimeError("native open"))  # type: ignore[method-assign]
    if failure_stage == "lookup":
        session.get_objects = lambda attrs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError("native lookup")
        )

    def sign_backend(sign_request: SignRequest, active_session: FakeSession) -> None:
        sign_request.output_path.write_bytes(b"new-part")

    result = sign_document(
        request,
        library_loader=library_loader,
        sign_backend=sign_backend,
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )

    assert result == {"ok": False, "failureCode": "pkcs11_unavailable"}
    assert _failure_exit_code(result["failureCode"], "sign") == 10
    assert request.output_path.exists() is False


@pytest.mark.parametrize(
    "exception_type",
    [SessionClosed, SessionHandleInvalid, UserNotLoggedIn, DeviceRemoved, TokenNotPresent],
)
def test_exact_session_loss_is_retryable_and_other_pkcs11_errors_are_not(
    tmp_path: Path, exception_type: type[Exception]
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    session = FakeSession([])

    def lose_session(sign_request: SignRequest, active_session: FakeSession) -> None:
        sign_request.output_path.write_bytes(b"partial")
        raise exception_type()

    lost = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=lose_session,
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )

    assert lost == {"ok": False, "failureCode": "pkcs11_session_lost"}
    assert _failure_exit_code(lost["failureCode"], "sign") == 10
    assert request.output_path.exists() is False

    def generic_pkcs11(sign_request: SignRequest, active_session: FakeSession) -> None:
        raise GeneralError()

    unavailable = sign_document(
        request,
        library_loader=lambda path: FakeLibrary(FakeToken(session)),
        sign_backend=generic_pkcs11,
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )
    assert unavailable == {"ok": False, "failureCode": "pkcs11_unavailable"}


def test_sign_and_validation_failures_use_20_and_30_and_never_reuse_part(
    tmp_path: Path,
) -> None:
    request = load_sign_request(write_request(tmp_path, valid_sign_mapping(tmp_path)))
    session = FakeSession([])

    def library_loader(path: str):
        return FakeLibrary(FakeToken(session))

    request.output_path.write_bytes(b"stale")

    sign_failed = sign_document(
        request,
        library_loader=library_loader,
        sign_backend=lambda sign_request, active_session: (_ for _ in ()).throw(
            RuntimeError("tsa/signing failure with secret")
        ),
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )
    assert sign_failed == {"ok": False, "failureCode": "pdf_sign_failed"}
    assert _failure_exit_code(sign_failed["failureCode"], "sign") == 20
    assert request.output_path.exists() is False

    appearance_font_missing = sign_document(
        request,
        library_loader=library_loader,
        sign_backend=lambda sign_request, active_session: (_ for _ in ()).throw(
            RuntimeError("pdf_appearance_font_missing")
        ),
        validation_runner=lambda validation_request: {"ok": True, "failureCode": None},
    )
    assert appearance_font_missing == {
        "ok": False,
        "failureCode": "pdf_appearance_font_missing",
    }
    assert _failure_exit_code(appearance_font_missing["failureCode"], "sign") == 20
    assert request.output_path.exists() is False

    validation_failed = sign_document(
        request,
        library_loader=library_loader,
        sign_backend=lambda sign_request, active_session: sign_request.output_path.write_bytes(
            b"newly-signed"
        ),
        validation_runner=lambda validation_request: {
            "ok": False,
            "failureCode": "signature_integrity_invalid",
        },
    )
    assert validation_failed == {"ok": False, "failureCode": "pdf_validation_failed"}
    assert _failure_exit_code(validation_failed["failureCode"], "sign") == 30
    assert request.output_path.exists() is False


def test_pyinstaller_spec_collects_only_required_runtime_graph_without_secrets() -> None:
    spec = (SCRIPT.parent / "pdf-signer.spec").read_text(encoding="utf-8")

    assert 'name="CodeSignAutoPdfSigner"' in spec
    assert "collect_all" not in spec
    assert "collect_dynamic_libs" in spec
    assert "optimize=2" in spec
    for module in (
        "CodeSignAuto_pdf_validator",
        "pyhanko.sign.pkcs11",
        "pyhanko.sign.signers",
        "pyhanko.sign.validation",
        "pkcs11",
        "cryptography",
    ):
        assert module in spec
    for forbidden in (
        "agent.json",
        "time.certum.pl",
        "otpauth://",
        "collect_data_files",
    ):
        assert forbidden not in spec


def test_frozen_helper_uses_only_trusted_windows_appearance_fonts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_root = tmp_path / "Windows"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)
    monkeypatch.setattr(
        CodeSignAuto_pdf_signer,
        "_windows_fonts_directory",
        lambda: windows_root / "Fonts",
    )

    assert CodeSignAuto_pdf_signer._appearance_font_candidates() == tuple(
        windows_root / "Fonts" / name
        for name in CodeSignAuto_pdf_signer.WINDOWS_APPEARANCE_FONTS
    )


def test_windows_signature_stamp_rejects_missing_appearance_font(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(CodeSignAuto_pdf_signer.os, "name", "nt")
    monkeypatch.setattr(
        CodeSignAuto_pdf_signer,
        "_windows_fonts_directory",
        lambda: tmp_path / "Windows" / "Fonts",
    )

    with pytest.raises(RuntimeError, match="^pdf_appearance_font_missing$"):
        CodeSignAuto_pdf_signer._signature_stamp_style("组织名称")


def test_pyinstaller_spec_excludes_cli_and_image_surfaces_and_keeps_text_and_native_crypto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_path = SCRIPT.parent / "pdf-signer.spec"
    captured: dict[str, object] = {}

    def fake_collect_dynamic_libs(package: str) -> list[tuple[str, str]]:
        return [(f"controlled/{package}.pyd", package)]

    def fake_analysis(*arguments: object, **options: object) -> SimpleNamespace:
        captured["options"] = options
        result = SimpleNamespace(
            pure=[(module, "controlled-source", "PYMODULE") for module in options["hiddenimports"]],
            scripts=[],
            binaries=[],
            datas=list(options["datas"]),
        )
        captured["analysis"] = result
        return result

    monkeypatch.setattr("PyInstaller.utils.hooks.collect_dynamic_libs", fake_collect_dynamic_libs)
    namespace = {
        "Analysis": fake_analysis,
        "PYZ": lambda *arguments, **options: object(),
        "EXE": lambda *arguments, **options: object(),
    }
    runpy.run_path(str(spec_path), init_globals=namespace)

    options = captured["options"]
    assert options["optimize"] == 2
    assert options["datas"] == []
    assert options["binaries"] == [
        ("controlled/pkcs11.pyd", "pkcs11"),
        ("controlled/cryptography.pyd", "cryptography"),
    ]
    forbidden_prefixes = (
        "pyhanko.__main__",
        "pyhanko.cli",
        "click",
        "platformdirs",
        "yaml",
        "PIL",
        "barcode",
    )
    assert tuple(options["excludes"]) == forbidden_prefixes
    assert {
        "pyhanko.pdf_utils.font.opentype",
        "fontTools",
        "uharfbuzz",
    } <= set(options["hiddenimports"])
    assert all(
        not any(
            module == prefix or module.startswith(f"{prefix}.")
            for prefix in forbidden_prefixes
        )
        for module, *_ in captured["analysis"].pure
    )


def test_frozen_executable_validates_real_pades_and_probe_surface(tmp_path: Path) -> None:
    frozen_helper_value = os.environ.get("SIMPLYSIGN_FROZEN_HELPER_PATH")
    if frozen_helper_value is None:
        pytest.skip("release build supplies the frozen helper path")
    frozen_helper = Path(frozen_helper_value)
    assert frozen_helper.is_absolute()
    assert frozen_helper.is_file()
    assert not frozen_helper.is_symlink()

    validation_test = runpy.run_path(str(SCRIPT.parent / "tests" / "test_validate.py"))
    signed_document = validation_test["signed_document"].__wrapped__(tmp_path)
    validation_values = validation_test["validation_mapping"](signed_document)
    validation_request = validation_test["write_validation_request"](
        tmp_path,
        validation_values,
        "frozen-validate.json",
    )

    validation = subprocess.run(
        [str(frozen_helper), "validate", "--request", str(validation_request)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert validation.returncode == 0
    assert validation.stderr == ""
    assert len(validation.stdout.splitlines()) == 1
    validation_payload = json.loads(validation.stdout)
    assert validation_payload["ok"] is True
    assert validation_payload["failureCode"] is None
    assert validation_payload["signatureCount"] == 1
    assert validation_payload["wholeFile"] is True
    assert validation_payload["timestampPresent"] is True
    assert validation_payload["inputUnchanged"] is True

    probe_request = write_request(
        tmp_path,
        {
            "modulePath": str(tmp_path / "missing-pkcs11.dll"),
            "slotId": 42,
            "tokenSerial": "TEST-TOKEN-SERIAL-0001",
            "certificateIdHex": CERTIFICATE_ID.hex(),
            "privateKeyIdHex": PRIVATE_KEY_ID.hex(),
        },
        "frozen-probe.json",
    )
    probe = subprocess.run(
        [str(frozen_helper), "probe", "--request", str(probe_request)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert probe.returncode == 10
    assert probe.stderr == ""
    assert len(probe.stdout.splitlines()) == 1
    assert json.loads(probe.stdout) == {
        "ok": False,
        "tokenPresent": False,
        "certificatePresent": False,
        "privateKeyPresent": False,
        "failureCode": "pkcs11_unavailable",
        "certificateNotAfterUtc": None,
        "certificateThumbprintSuffix": None,
    }


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_cli_version_is_exact_and_other_shapes_are_rejected(tmp_path: Path) -> None:
    version = run_cli("--version")
    assert (version.returncode, version.stdout, version.stderr) == (0, "0.1.3\n", "")

    for arguments in [(), ("validate",), ("probe",), ("catalog",), ("sign", "--request")]:
        result = run_cli(*arguments)
        assert result.returncode == 2
        assert result.stderr == ""
        assert len(result.stdout.splitlines()) == 1
        assert json.loads(result.stdout) == {"ok": False, "failureCode": "invalid_request"}


def test_cli_probe_has_one_bounded_seven_field_json_line_and_never_leaks_request(
    tmp_path: Path,
) -> None:
    secret = "TEST-TOKEN-SERIAL-0001"
    values = valid_sign_mapping(tmp_path)
    probe_values = {
        name: values[name]
        for name in (
            "modulePath",
            "slotId",
            "tokenSerial",
            "certificateIdHex",
            "privateKeyIdHex",
        )
    }
    request_path = write_request(tmp_path, probe_values, "secret-probe.json")

    result = run_cli("probe", "--request", str(request_path))

    assert result.returncode == 10
    assert result.stderr == ""
    assert len(result.stdout.encode("utf-8")) < 4096
    assert len(result.stdout.splitlines()) == 1
    payload = json.loads(result.stdout)
    assert set(payload) == {
        "ok",
        "tokenPresent",
        "certificatePresent",
        "privateKeyPresent",
        "failureCode",
        "certificateNotAfterUtc",
        "certificateThumbprintSuffix",
    }
    assert payload["certificateNotAfterUtc"] is None
    assert payload["certificateThumbprintSuffix"] is None
    assert secret not in result.stdout
    assert str(request_path) not in result.stdout
    assert str(values["modulePath"]) not in result.stdout


def test_cli_invalid_json_never_echoes_secret_path_or_exception(tmp_path: Path) -> None:
    request_path = tmp_path / "token-TEST-TOKEN-SERIAL-0001.json"
    request_path.write_text('{"tokenSerial":"TEST-TOKEN-SERIAL-0001", bad}', encoding="utf-8")

    result = run_cli("probe", "--request", str(request_path))

    assert result.returncode == 2
    assert result.stderr == ""
    assert result.stdout == '{"ok":false,"failureCode":"invalid_request"}\n'
    assert "TEST-TOKEN-SERIAL-0001" not in result.stdout
    assert str(request_path) not in result.stdout


def test_cli_catalog_has_one_bounded_three_field_json_line_without_private_material(
    tmp_path: Path,
) -> None:
    secret_path = tmp_path / "catalog-private-key-material.json"
    secret_path.write_text(
        json.dumps({"modulePath": str(tmp_path / "private-key-material-pkcs11.dll")}),
        encoding="utf-8",
    )

    result = run_cli("catalog", "--request", str(secret_path))

    assert result.returncode == 10
    assert result.stderr == ""
    assert len(result.stdout.encode("utf-8")) < 4096
    assert len(result.stdout.splitlines()) == 1
    assert json.loads(result.stdout) == {
        "ok": False,
        "failureCode": "pkcs11_unavailable",
        "certificates": [],
    }
    assert "private-key-material" not in result.stdout
    assert str(secret_path) not in result.stdout


@pytest.mark.parametrize("failure_point", ["loader", "catalog"])
def test_main_catalog_unknown_dispatch_errors_keep_catalog_envelope_and_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_point: str,
) -> None:
    def raise_unknown(*_: object) -> object:
        raise RuntimeError(f"catalog {failure_point} diagnostic /module/path 42")

    if failure_point == "loader":
        monkeypatch.setattr(CodeSignAuto_pdf_signer, "load_catalog_request", raise_unknown)
    else:
        monkeypatch.setattr(
            CodeSignAuto_pdf_signer,
            "load_catalog_request",
            lambda path: CodeSignAuto_pdf_signer.CatalogRequest(
                module_path=Path("/controlled/pkcs11.dll")
            ),
        )
        monkeypatch.setattr(CodeSignAuto_pdf_signer, "catalog_certificates", raise_unknown)

    exit_code = CodeSignAuto_pdf_signer.main(["catalog", "--request", "/unused-request.json"])
    captured = capsys.readouterr()

    assert exit_code == 10
    assert json.loads(captured.out) == {
        "ok": False,
        "failureCode": "catalog_unexpected_error",
        "certificates": [],
    }
    assert "Traceback" in captured.err
    assert f"RuntimeError: catalog {failure_point} diagnostic /module/path 42" in captured.err
