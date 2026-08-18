from __future__ import annotations

import hashlib
import json
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import AttributeSensitive, AttributeTypeInvalid, FunctionFailed

from simplysign_pdf_signer import (
    CatalogRequest,
    ProbeRequest,
    RequestError,
    catalog_certificates,
    load_catalog_request,
    load_probe_request,
    probe_token,
)

CERTIFICATE_ID = bytes.fromhex("c0ffee01")
PRIVATE_KEY_ID = bytes.fromhex("decafbad")


def certificate_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SimplySign Test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 8, 9, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


CERTIFICATE_DER = certificate_der()
CERTIFICATE_THUMBPRINT_SUFFIX = hashlib.sha256(CERTIFICATE_DER).hexdigest()[-8:].upper()


class FakeObject:
    def __init__(self, value: object = b"certificate", object_id: object = CERTIFICATE_ID) -> None:
        self.value = value
        self.object_id = object_id

    def __getitem__(self, attribute: Attribute) -> object:
        if attribute is Attribute.VALUE:
            return self.value
        if attribute is Attribute.ID:
            return self.object_id
        raise KeyError(attribute)


class AttributeFailingObject(FakeObject):
    def __init__(self, failure: Exception, attribute: Attribute) -> None:
        super().__init__(CERTIFICATE_DER)
        self.failure = failure
        self.attribute = attribute

    def __getitem__(self, attribute: Attribute) -> object:
        if attribute is self.attribute:
            raise self.failure
        return super().__getitem__(attribute)


class FakeSession:
    def __init__(
        self,
        objects: dict[tuple[ObjectClass, bytes], list[FakeObject]],
        query_results: dict[tuple[ObjectClass, bytes | None], object] | None = None,
    ) -> None:
        self.objects = objects
        self.query_results = query_results or {}
        self.queries: list[dict[Attribute, object]] = []
        self.closed = False

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.closed = True

    def get_objects(self, attrs: dict[Attribute, object]):
        self.queries.append(attrs)
        object_class = attrs[Attribute.CLASS]
        object_id = attrs.get(Attribute.ID)
        override = self.query_results.get((object_class, object_id))
        if override is not None:
            return iter(override)
        return iter(
            object
            for (candidate_class, _), objects in self.objects.items()
            if candidate_class is object_class
            for object in objects
            if object_id is None or object[Attribute.ID] == object_id
        )


class SingleActiveSearchSession(FakeSession):
    def __init__(self, objects: dict[tuple[ObjectClass, bytes], list[FakeObject]]) -> None:
        super().__init__(objects)
        self.search_active = False

    def get_objects(self, attrs: dict[Attribute, object]):
        if self.search_active:
            raise FunctionFailed
        iterator = super().get_objects(attrs)
        self.search_active = True

        def guarded():
            try:
                yield from iterator
            finally:
                self.search_active = False

        return guarded()


class FakeToken:
    def __init__(
        self,
        serial: str | bytes,
        objects: dict[tuple[ObjectClass, bytes], list[FakeObject]] | None = None,
    ) -> None:
        self.serial = serial
        self.session = FakeSession(objects or {})

    def open(self) -> FakeSession:
        return self.session


class FakeSlot:
    def __init__(self, slot_id: int, token: FakeToken) -> None:
        self.slot_id = slot_id
        self.token = token

    def get_token(self) -> FakeToken:
        return self.token


class FakeLibrary:
    def __init__(self, slots: list[FakeSlot]) -> None:
        self.slots = slots
        self.token_present_argument: bool | None = None

    def get_slots(self, token_present: bool = False):
        self.token_present_argument = token_present
        return iter(self.slots)


class ObservationBoundedIterator:
    def __init__(self, values: list[object], maximum_observations: int) -> None:
        self.values = values
        self.maximum_observations = maximum_observations
        self.observations = 0

    def __iter__(self) -> ObservationBoundedIterator:
        return self

    def __next__(self) -> object:
        if self.observations >= self.maximum_observations:
            raise AssertionError("catalog materialized an untrusted iterator past its bound")
        if self.observations >= len(self.values):
            raise StopIteration
        value = self.values[self.observations]
        self.observations += 1
        return value


def request() -> ProbeRequest:
    return ProbeRequest(
        module_path=Path("/controlled/pkcs11.dll"),
        slot_id=42,
        token_serial="TEST-TOKEN-SERIAL-0001",
        certificate_id=CERTIFICATE_ID,
        private_key_id=PRIVATE_KEY_ID,
    )


def catalog_request() -> CatalogRequest:
    return CatalogRequest(module_path=Path("/controlled/pkcs11.dll"))


def catalog_record(
    slot_id: int,
    token_serial: str,
    certificate_id: bytes,
    der: bytes,
    private_key_match: str = "unique",
    private_key_id: bytes | None = None,
) -> dict[str, object]:
    return {
        "slotId": slot_id,
        "tokenSerial": token_serial,
        "certificateIdHex": certificate_id.hex(),
        "privateKeyMatch": private_key_match,
        "privateKeyIdHex": (
            (certificate_id if private_key_id is None else private_key_id).hex()
            if private_key_match == "unique"
            else None
        ),
        "certificateDerBase64": b64encode(der).decode("ascii"),
    }


def matching_objects() -> dict[tuple[ObjectClass, bytes], list[FakeObject]]:
    return {
        (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)],
        (ObjectClass.PRIVATE_KEY, PRIVATE_KEY_ID): [FakeObject(b"private", PRIVATE_KEY_ID)],
    }


def test_probe_selects_exact_slot_serial_certificate_and_private_key() -> None:
    wrong_slot = FakeSlot(41, FakeToken("TEST-TOKEN-SERIAL-0001", matching_objects()))
    selected = FakeToken(b"TEST-TOKEN-SERIAL-0001", matching_objects())
    library = FakeLibrary([wrong_slot, FakeSlot(42, selected)])

    result = probe_token(request(), lambda path: library)

    assert result == {
        "ok": True,
        "tokenPresent": True,
        "certificatePresent": True,
        "privateKeyPresent": True,
        "failureCode": None,
        "certificateNotAfterUtc": "2027-08-09T00:00:00Z",
        "certificateThumbprintSuffix": CERTIFICATE_THUMBPRINT_SUFFIX,
    }
    assert library.token_present_argument is True
    assert selected.session.queries == [
        {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.ID: CERTIFICATE_ID},
        {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: PRIVATE_KEY_ID},
    ]
    assert selected.session.closed is True
    assert wrong_slot.token.session.queries == []


@pytest.mark.parametrize(
    ("library", "failure_code"),
    [
        (FakeLibrary([]), "token_missing"),
        (
            FakeLibrary([FakeSlot(42, FakeToken("different", matching_objects()))]),
            "token_identifier_mismatch",
        ),
    ],
)
def test_probe_rejects_missing_or_wrong_token(library: FakeLibrary, failure_code: str) -> None:
    result = probe_token(request(), lambda path: library)

    assert result == {
        "ok": False,
        "tokenPresent": False,
        "certificatePresent": False,
        "privateKeyPresent": False,
        "failureCode": failure_code,
        "certificateNotAfterUtc": None,
        "certificateThumbprintSuffix": None,
    }


def test_probe_requires_matching_certificate_and_private_key() -> None:
    only_certificate = {
        (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)],
    }
    token = FakeToken("TEST-TOKEN-SERIAL-0001", only_certificate)

    result = probe_token(request(), lambda path: FakeLibrary([FakeSlot(42, token)]))

    assert result == {
        "ok": False,
        "tokenPresent": True,
        "certificatePresent": True,
        "privateKeyPresent": False,
        "failureCode": "private_key_missing",
        "certificateNotAfterUtc": "2027-08-09T00:00:00Z",
        "certificateThumbprintSuffix": CERTIFICATE_THUMBPRINT_SUFFIX,
    }
    assert token.session.closed is True


def test_probe_reports_missing_certificate_without_querying_private_key() -> None:
    token = FakeToken("TEST-TOKEN-SERIAL-0001", matching_objects())
    token.session.objects.pop((ObjectClass.CERTIFICATE, CERTIFICATE_ID))

    result = probe_token(request(), lambda path: FakeLibrary([FakeSlot(42, token)]))

    assert result["failureCode"] == "certificate_missing"
    assert result["tokenPresent"] is True
    assert result["certificatePresent"] is False
    assert result["privateKeyPresent"] is False
    assert token.session.queries == [
        {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.ID: CERTIFICATE_ID}
    ]
    assert token.session.closed is True


def test_probe_sanitizes_native_exception_and_closes_session() -> None:
    secret = "TEST-TOKEN-SERIAL-0001"
    token = FakeToken(secret, matching_objects())

    def fail(_: dict[Attribute, object]):
        raise RuntimeError(f"native failure /secret/module.dll {secret} c0ffee01")

    token.session.get_objects = fail  # type: ignore[method-assign]

    result = probe_token(request(), lambda path: FakeLibrary([FakeSlot(42, token)]))

    encoded = json.dumps(result)
    assert result["failureCode"] == "pkcs11_unavailable"
    assert token.session.closed is True
    assert secret not in encoded
    assert "c0ffee01" not in encoded
    assert "/secret" not in encoded


def test_probe_request_schema_rejects_duplicate_unknown_and_invalid_fields(
    tmp_path: Path,
) -> None:
    valid = {
        "modulePath": str(tmp_path / "pkcs11.dll"),
        "slotId": 42,
        "tokenSerial": "TEST-TOKEN-SERIAL-0001",
        "certificateIdHex": "c0ffee01",
        "privateKeyIdHex": "decafbad",
    }
    cases = [
        json.dumps({**valid, "label": "fallback-forbidden"}),
        json.dumps({**valid, "slotId": True}),
        json.dumps({**valid, "certificateIdHex": "xyz"}),
        json.dumps({**valid, "tokenSerial": "x" * 129}),
        '{"modulePath":"/a","modulePath":"/b","slotId":42,'
        '"tokenSerial":"serial","certificateIdHex":"aa","privateKeyIdHex":"bb"}',
    ]

    for index, content in enumerate(cases):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(RequestError):
            load_probe_request(path)


def test_catalog_returns_every_certificate_with_one_exact_private_key() -> None:
    second_certificate_id = bytes.fromhex("c0ffee02")
    second_der = certificate_der()
    first = FakeToken(
        b"CATALOG-ONE   ",
        {
            (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)],
            (ObjectClass.PRIVATE_KEY, CERTIFICATE_ID): [FakeObject(b"private-key-material")],
            (ObjectClass.CERTIFICATE, second_certificate_id): [
                FakeObject(second_der, second_certificate_id)
            ],
            (ObjectClass.PRIVATE_KEY, second_certificate_id): [
                FakeObject(b"other-private-key-material", second_certificate_id)
            ],
        },
    )
    third_certificate_id = bytes.fromhex("c0ffee03")
    third_der = certificate_der()
    second = FakeToken(
        "CATALOG-TWO\0\0",
        {
            (ObjectClass.CERTIFICATE, third_certificate_id): [
                FakeObject(third_der, third_certificate_id)
            ],
            (ObjectClass.PRIVATE_KEY, third_certificate_id): [
                FakeObject(b"third-private-key-material", third_certificate_id)
            ],
        },
    )

    result = catalog_certificates(
        catalog_request(),
        lambda path: FakeLibrary([FakeSlot(7, first), FakeSlot(8, second)]),
    )

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(7, "CATALOG-ONE", CERTIFICATE_ID, CERTIFICATE_DER),
            catalog_record(7, "CATALOG-ONE", second_certificate_id, second_der),
            catalog_record(8, "CATALOG-TWO", third_certificate_id, third_der),
        ],
    }
    assert "private-key-material" not in json.dumps(result)
    assert first.session.closed is True
    assert second.session.closed is True


def test_catalog_finishes_certificate_search_before_private_key_search() -> None:
    objects = matching_objects()
    objects[(ObjectClass.PRIVATE_KEY, CERTIFICATE_ID)] = [
        FakeObject(b"private-key-material", CERTIFICATE_ID)
    ]
    token = FakeToken("CATALOG-SINGLE-ACTIVE-SEARCH", objects)
    token.session = SingleActiveSearchSession(token.session.objects)

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(7, token)])
    )

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(7, "CATALOG-SINGLE-ACTIVE-SEARCH", CERTIFICATE_ID, CERTIFICATE_DER)
        ],
    }


def test_catalog_preserves_duplicate_x509_serial_certificates_as_distinct_records() -> None:
    first_certificate_id = bytes.fromhex("c0ffee04")
    second_certificate_id = bytes.fromhex("c0ffee05")
    first_der = certificate_der()
    second_der = certificate_der()
    token = FakeToken(
        "CATALOG-DUPLICATE-SERIAL",
        {
            (ObjectClass.CERTIFICATE, first_certificate_id): [
                FakeObject(first_der, first_certificate_id)
            ],
            (ObjectClass.PRIVATE_KEY, first_certificate_id): [
                FakeObject(b"private-one", first_certificate_id)
            ],
            (ObjectClass.CERTIFICATE, second_certificate_id): [
                FakeObject(second_der, second_certificate_id)
            ],
            (ObjectClass.PRIVATE_KEY, second_certificate_id): [
                FakeObject(b"private-two", second_certificate_id)
            ],
        },
    )

    result = catalog_certificates(catalog_request(), lambda path: FakeLibrary([FakeSlot(9, token)]))

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(9, "CATALOG-DUPLICATE-SERIAL", first_certificate_id, first_der),
            catalog_record(9, "CATALOG-DUPLICATE-SERIAL", second_certificate_id, second_der),
        ],
    }


def test_catalog_preserves_duplicate_private_keys_as_an_ambiguous_certificate_record() -> None:
    token = FakeToken(
        "CATALOG-DUPLICATE-KEY",
        {
            (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)],
            (ObjectClass.PRIVATE_KEY, CERTIFICATE_ID): [
                FakeObject(b"private-one"),
                FakeObject(b"private-two"),
            ],
        },
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(10, token)])
    )

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(
                10,
                "CATALOG-DUPLICATE-KEY",
                CERTIFICATE_ID,
                CERTIFICATE_DER,
                private_key_match="ambiguous",
            )
        ],
    }


def test_catalog_preserves_a_certificate_without_a_private_key() -> None:
    token = FakeToken(
        "CATALOG-MISSING-KEY",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)]},
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(11, token)])
    )

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(
                11,
                "CATALOG-MISSING-KEY",
                CERTIFICATE_ID,
                CERTIFICATE_DER,
                private_key_match="missing",
            )
        ],
    }


def test_catalog_skips_no_objects_only_by_returning_an_empty_valid_catalog() -> None:
    token = FakeToken("CATALOG-EMPTY")

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(12, token)])
    )

    assert result == {"ok": True, "failureCode": None, "certificates": []}
    assert token.session.closed is True


@pytest.mark.parametrize(
    "object",
    [FakeObject(b"not a certificate"), FakeObject(CERTIFICATE_DER, "not-bytes")],
)
def test_catalog_rejects_invalid_der_and_non_byte_object_ids(object: FakeObject) -> None:
    token = FakeToken(
        "CATALOG-INVALID",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [object]},
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(13, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_rejects_a_valid_certificate_larger_than_the_der_contract() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oversized")])
    oversized_der = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 8, 9, tzinfo=UTC))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"x" * 65536), False
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    assert len(oversized_der) > 65536
    token = FakeToken(
        "CATALOG-OVERSIZED-DER",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(oversized_der)]},
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(13, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


@pytest.mark.parametrize("kind", ["slots", "certificates"])
def test_catalog_rejects_unbounded_slots_or_certificates_without_full_materialization(
    kind: str,
) -> None:
    if kind == "slots":
        library = FakeLibrary([])
        library.slots = ObservationBoundedIterator(
            [FakeSlot(index, FakeToken(f"CATALOG-SLOT-{index}")) for index in range(33)],
            maximum_observations=33,
        )
    else:
        token = FakeToken("CATALOG-MANY-CERTIFICATES")
        token.session.query_results[(ObjectClass.CERTIFICATE, None)] = ObservationBoundedIterator(
            [FakeObject(CERTIFICATE_DER, index.to_bytes(2)) for index in range(257)],
            maximum_observations=257,
        )
        library = FakeLibrary([FakeSlot(14, token)])

    result = catalog_certificates(catalog_request(), lambda path: library)

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_rejects_global_certificate_cap_across_multiple_slots() -> None:
    first = FakeToken(
        "CATALOG-FIRST-SLOT",
        {
            (ObjectClass.CERTIFICATE, index.to_bytes(2)): [
                FakeObject(CERTIFICATE_DER, index.to_bytes(2))
            ]
            for index in range(256)
        },
    )
    second_certificate_id = (256).to_bytes(2)
    second = FakeToken(
        "CATALOG-SECOND-SLOT",
        {
            (ObjectClass.CERTIFICATE, second_certificate_id): [
                FakeObject(CERTIFICATE_DER, second_certificate_id)
            ]
        },
    )

    result = catalog_certificates(
        catalog_request(),
        lambda path: FakeLibrary([FakeSlot(18, first), FakeSlot(19, second)]),
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


@pytest.mark.parametrize(
    "attribute_error",
    [AttributeSensitive(), AttributeTypeInvalid()],
)
def test_catalog_maps_real_pkcs11_attribute_read_errors_to_invalid(
    attribute_error: Exception,
) -> None:
    certificate = AttributeFailingObject(attribute_error, Attribute.ID)
    token = FakeToken(
        "CATALOG-ATTRIBUTE-ERROR",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [certificate]},
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(20, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_maps_private_key_attribute_read_error_to_invalid() -> None:
    key = AttributeFailingObject(AttributeSensitive(), Attribute.ID)
    token = FakeToken(
        "CATALOG-PRIVATE-ATTRIBUTE-ERROR",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)]},
    )
    token.session.query_results[(ObjectClass.PRIVATE_KEY, CERTIFICATE_ID)] = [key]

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(22, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_keeps_non_attribute_pkcs11_errors_as_environment_failures() -> None:
    certificate = AttributeFailingObject(FunctionFailed(), Attribute.ID)
    token = FakeToken(
        "CATALOG-FUNCTION-FAILED",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [certificate]},
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(21, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "pkcs11_unavailable",
        "certificates": [],
    }


def test_catalog_returns_token_missing_without_raising_when_no_token_is_present() -> None:
    result = catalog_certificates(catalog_request(), lambda path: FakeLibrary([]))

    assert result == {"ok": False, "failureCode": "token_missing", "certificates": []}


def test_catalog_rejects_duplicate_identical_certificate_identity() -> None:
    token = FakeToken(
        "CATALOG-DUPLICATE-CERTIFICATE",
        {
            (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [
                FakeObject(CERTIFICATE_DER),
                FakeObject(CERTIFICATE_DER),
            ],
            (ObjectClass.PRIVATE_KEY, CERTIFICATE_ID): [FakeObject(b"private")],
        },
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(15, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_reads_the_actual_private_key_id_and_rejects_mismatched_query_results() -> None:
    key_id = bytes.fromhex("decafbad")
    token = FakeToken(
        "CATALOG-KEY-ID",
        {
            (ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)],
            (ObjectClass.PRIVATE_KEY, CERTIFICATE_ID): [FakeObject(b"private", key_id)],
        },
    )

    token.session.query_results[(ObjectClass.PRIVATE_KEY, CERTIFICATE_ID)] = [
        FakeObject(b"private", key_id)
    ]
    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(16, token)])
    )

    assert result == {
        "ok": False,
        "failureCode": "certificate_catalog_invalid",
        "certificates": [],
    }


def test_catalog_stops_after_two_private_key_observations_and_marks_ambiguous() -> None:
    token = FakeToken(
        "CATALOG-TWO-KEYS",
        {(ObjectClass.CERTIFICATE, CERTIFICATE_ID): [FakeObject(CERTIFICATE_DER)]},
    )
    private_key_query = (ObjectClass.PRIVATE_KEY, CERTIFICATE_ID)
    token.session.query_results[private_key_query] = ObservationBoundedIterator(
        [FakeObject(b"private-one"), FakeObject(b"private-two"), FakeObject(b"private-three")],
        maximum_observations=2,
    )

    result = catalog_certificates(
        catalog_request(), lambda path: FakeLibrary([FakeSlot(17, token)])
    )

    assert result == {
        "ok": True,
        "failureCode": None,
        "certificates": [
            catalog_record(
                17,
                "CATALOG-TWO-KEYS",
                CERTIFICATE_ID,
                CERTIFICATE_DER,
                private_key_match="ambiguous",
            )
        ],
    }


def test_catalog_unknown_exception_has_stable_code_and_full_stderr_diagnostics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def raise_unknown(_: str) -> object:
        raise RuntimeError("catalog native diagnostic /module/path 42")

    result = catalog_certificates(catalog_request(), raise_unknown)
    captured = capsys.readouterr()

    assert result == {
        "ok": False,
        "failureCode": "catalog_unexpected_error",
        "certificates": [],
    }
    assert "Traceback" in captured.err
    assert "RuntimeError: catalog native diagnostic /module/path 42" in captured.err


def test_catalog_request_accepts_only_an_absolute_module_path(tmp_path: Path) -> None:
    valid = {"modulePath": str(tmp_path / "pkcs11.dll")}
    request_path = tmp_path / "catalog.json"
    request_path.write_text(json.dumps(valid), encoding="utf-8")

    assert load_catalog_request(request_path) == CatalogRequest(
        module_path=Path(valid["modulePath"])
    )

    for index, values in enumerate(
        [
            {"modulePath": "relative.dll"},
            {"modulePath": str(tmp_path / "pkcs11.dll"), "slotId": 1},
            {"modulePath": ""},
        ]
    ):
        path = tmp_path / f"invalid-catalog-{index}.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        with pytest.raises(RequestError):
            load_catalog_request(path)
