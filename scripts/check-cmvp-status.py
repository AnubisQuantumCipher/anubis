#!/usr/bin/env python3
"""Reject unsupported or internally inconsistent assurance claims.

The current schema records a non-certified engineering program. A future CAVP
or CMVP certificate must cause a reviewed schema and verifier change; flipping
a JSON boolean can never turn this repository into a validated module.
"""

from __future__ import annotations

import copy
import datetime
import html
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


class StatusError(ValueError):
    """The status document violates the non-certified assurance contract."""


ENGINE_FALSE_CLAIMS = (
    '"approved_only_mode": false,',
    '"fips_140_3_validated": false,',
    '"fips_140_3_certificate": null,',
)

RUNTIME_SUITE_EXPECTED: dict[str, Any] = {
    "kem": "X25519+ML-KEM-1024",
    "sig": "ML-DSA-87",
    "aead": "ChaCha20-Poly1305",
    "kdf": "HKDF-SHA512",
    "pq_security_category": 5,
    "fips": ["203", "204"],
    "nist_standards": ["FIPS 203", "FIPS 204"],
    "algorithm_profile": "portable-v3",
    "approved_only_mode": False,
    "fips_140_3_validated": False,
    "fips_140_3_certificate": None,
    "pure_rust": True,
    "format": "anubis-encryption.org/v3",
}

RUNTIME_ROOT_KEYS = {
    "kind",
    "status_schema",
    "suite",
    "version",
    "identities",
    "recipients",
    "recent",
    "counts",
    "generated",
}

RUNTIME_ASSURANCE_LINE = (
    "assurance:   Category 5 PQ parameters; not FIPS 140-3 validated"
)

VERSION_PATTERN = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)

CLAIM_TOKEN = re.compile(
    r"\b(?:FIPS|CMVP|CAVP|validated|certified|certificate|compliant)\b",
    re.IGNORECASE,
)

RUNTIME_HUMAN_PATTERNS = (
    re.compile(r"ANUBIS " + VERSION_PATTERN.pattern),
    re.compile(
        r"suite:\s+X25519\+ML-KEM-1024 / ML-DSA-87 / ChaCha20-Poly1305"
    ),
    re.compile(r"format:\s+anubis-encryption\.org/v3"),
    re.compile(re.escape(RUNTIME_ASSURANCE_LINE)),
    re.compile(r"identities:\s+[0-9]+"),
    re.compile(r"recipients:\s+[0-9]+"),
    re.compile(
        r"operations:\s+[0-9]+ encrypted, [0-9]+ decrypted, [0-9]+ failed"
    ),
)

PUBLIC_TEXT_SUFFIXES = {
    ".adoc",
    ".c",
    ".cc",
    ".conf",
    ".cpp",
    ".desktop",
    ".h",
    ".hh",
    ".htm",
    ".html",
    ".hpp",
    ".ini",
    ".install",
    ".js",
    ".json",
    ".jsx",
    ".lock",
    ".md",
    ".mmd",
    ".py",
    ".qml",
    ".rs",
    ".rst",
    ".service",
    ".sh",
    ".svg",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

PUBLIC_TEXT_NAMES = {
    "CHANGELOG",
    "LICENSE",
    "NOTICE",
    "PKGBUILD",
    "README",
    "SECURITY",
}

PROSE_SUFFIXES = {
    ".adoc",
    ".desktop",
    ".htm",
    ".html",
    ".json",
    ".md",
    ".mmd",
    ".py",
    ".rst",
    ".toml",
    ".txt",
    ".xml",
    ".svg",
    ".install",
    ".yaml",
    ".yml",
}

SOURCE_LITERAL_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hh",
    ".hpp",
    ".js",
    ".jsx",
    ".py",
    ".qml",
    ".rs",
    ".sh",
    ".ts",
    ".tsx",
}

CURRENT_NEXT_ENGINEERING_GATE = (
    "Freeze the v4 restricted profile and implement its production provider, "
    "cryptographic module self-tests, service and data-output gates, SSP "
    "lifecycle, deterministic test adapter, and independent vectors."
)

ANUBIS_SUBJECT = (
    r"(?:the\s+)?ANUBIS(?:\s+Vault)?(?:/v[0-9]+|\s+v[0-9]+)?"
    r"(?:\s+cryptographic\s+module)?"
)

ASSURANCE_PROGRAM = r"(?:FIPS(?:\s+140-3)?|CMVP|CAVP)"
SOURCE_LITERAL_START = r"(?:(?:u8|[rubf]{0,2})\#*[\"'`])"

SOURCE_LITERAL_JOIN = re.compile(
    r"(?<!\\)[\"'`]\#*\s*(?:\+\s*)?"
    r"(?:u8|[rubf]{0,2})\#*[\"'`]",
    re.IGNORECASE,
)

SOURCE_ESCAPED_SPACE = re.compile(
    r"\\(?:[tnrfv]|x(?:09|0[a-d]|20)|u(?:0009|000[a-d]|0020)|"
    r"u\{0*(?:9|[a-d]|20)\}|\r?\n)",
    re.IGNORECASE,
)

PROHIBITED_CLAIM_PREFIX = re.compile(
    r"(?:(?:do|must|should)\s+not|never)\s+"
    r"(?:claim|say|state|write|describe|market|label|call|present|represent)"
    r"(?:\s+(?:that|it\s+as))?\s*[:\-]?\s*[\"'\N{LEFT DOUBLE QUOTATION MARK}"
    r"\N{LEFT SINGLE QUOTATION MARK}]?\s*$",
    re.IGNORECASE,
)

POSITIVE_SUBJECT_CLAIMS = (
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        rf"(?:a\s+)?{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:validated|approved)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:certified|validated)\s+(?:under|to)\s+"
        rf"{ASSURANCE_PROGRAM}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:has\s+)?(?:successfully\s+)?"
        r"(?:achieved|completed|obtained|received)\s+(?:an?\s+)?"
        rf"(?:{ASSURANCE_PROGRAM}\s+)?"
        r"(?:module\s+)?(?:validation|certification|certificate)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:now\s+)?(?:has|holds)\s+"
        rf"(?:an?\s+)?{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:certificate|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        rf"{ASSURANCE_PROGRAM}(?:\s+module)?\s+certified\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:has\s+)?(?:successfully\s+)?passed\s+"
        rf"(?:the\s+)?{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:validation|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        rf"(?:{ASSURANCE_PROGRAM}[-\s]+compliant|"
        rf"compliant\s+with\s+{ASSURANCE_PROGRAM})\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:validated|approved)\s*:\s*"
        rf"{ANUBIS_SUBJECT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s*(?::|[-\N{{EM DASH}}\N{{EN DASH}}])\s*"
        rf"{ASSURANCE_PROGRAM}(?:\s+module)?\s+(?:validated|approved)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:now\s+)?has\s+(?:an?\s+)?"
        rf"{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:validation|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is|has\s+been)\s+validated\s+by\s+"
        rf"(?:the\s+)?{ASSURANCE_PROGRAM}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is|was|has\s+been)\s+"
        r"(?:independently|third[-\s]+party(?:\s+cryptographically)?)\s+audited\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:has\s+)?(?:successfully\s+)?"
        r"(?:undergone|completed|passed|received)\s+(?:an?\s+)?"
        r"(?:independent|third[-\s]+party)"
        r"(?:\s+(?:cryptographic|security|source[-\s]+code))?\s+audit\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:independently\s+audited|(?:independent|third[-\s]+party)"
        r"(?:\s+(?:cryptographic|security|source[-\s]+code))?\s+audit\s+"
        r"(?:passed|completed))\s*:\s*"
        rf"{ANUBIS_SUBJECT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:FIPS(?:\s+140-3)?[-\s]+(?:aligned|conformant)|"
        r"validation[-\s]+ready)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:meets|conforms\s+to|complies\s+with)\s+"
        r"FIPS(?:\s+140-3)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is|has\s+been)\s+aligned\s+with\s+"
        r"FIPS(?:\s+140-3)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:now\s+)?has\s+"
        r"FIPS(?:\s+140-3)?[-\s]+alignment\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:provides|has|operates\s+in|supports|offers)\s+"
        r"(?:an?\s+)?approved[-\s]+(?:only[-\s]+)?(?:mode|operation)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+approved[-\s]+(?:only[-\s]+)?"
        r"(?:mode|operation)\s+(?:is\s+)?(?:available|supported|enabled)\b",
        re.IGNORECASE,
    ),
)

POSITIVE_STANDALONE_CLAIMS = (
    re.compile(
        rf"^\s*(?:status:\s*)?{ASSURANCE_PROGRAM}(?:\s+module)?\s+"
        r"(?:validated|certified|approved)"
        r"(?:\s+cryptographic\s+module)?[.!]?\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:status:\s*)?independently\s+audited[.!]?\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*approved[-\s]+(?:only[-\s]+)?(?:mode|operation)\s*:\s*"
        r"(?:available|supported|enabled)[.!]?\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
)

POSITIVE_SOURCE_LITERAL_CLAIMS = (
    re.compile(
        rf"{SOURCE_LITERAL_START}\s*(?:status:\s*)?{ASSURANCE_PROGRAM}"
        r"(?:\s+module)?\s+(?:validated|certified|approved|compliant)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"{SOURCE_LITERAL_START}\s*(?:status:\s*)?independently\s+audited\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"{SOURCE_LITERAL_START}\s*approved[-\s]+(?:only[-\s]+)?"
        r"(?:mode|operation)\s*:?\s*(?:is\s+)?(?:available|supported|enabled)\b",
        re.IGNORECASE,
    ),
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StatusError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_status(text: str) -> object:
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def _exact_keys(value: object, expected: set[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StatusError(f"{location} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise StatusError(f"{location} keys differ: missing={missing}, extra={extra}")
    return value


def validate(data: object) -> None:
    root = _exact_keys(
        data,
        {
            "schema",
            "as_of",
            "candidate",
            "engineering",
            "certification",
            "claims",
            "next_engineering_gate",
        },
        "root",
    )
    if root["schema"] != "anubis.assurance-status.v2":
        raise StatusError("unsupported assurance status schema")
    if not isinstance(root["as_of"], str) or not root["as_of"]:
        raise StatusError("as_of must be a non-empty date string")
    try:
        parsed_date = datetime.date.fromisoformat(root["as_of"])
    except ValueError as error:
        raise StatusError("as_of must be an ISO calendar date") from error
    if parsed_date.isoformat() != root["as_of"]:
        raise StatusError("as_of must use canonical YYYY-MM-DD form")
    if root["next_engineering_gate"] != CURRENT_NEXT_ENGINEERING_GATE:
        raise StatusError("next_engineering_gate changed without a status-schema review")

    candidate = _exact_keys(
        root["candidate"],
        {"name", "version", "type", "source_boundary", "design_reference"},
        "candidate",
    )
    if candidate["name"] != "ANUBIS v4 Cryptographic Core":
        raise StatusError("candidate.name changed without a status-schema review")
    if candidate["version"] is not None:
        raise StatusError("the candidate module version is not frozen")
    if candidate["type"] != "software":
        raise StatusError("the current candidate must remain software")
    if candidate["source_boundary"] != "crates/anubis-v4-core":
        raise StatusError("candidate source boundary changed without a status-schema review")
    if candidate["design_reference"] != (
        "selected software-module controls drawn from FIPS 140-3 Security Level 1 requirements"
    ):
        raise StatusError("candidate design reference changed without a status-schema review")

    engineering = _exact_keys(
        root["engineering"],
        {"phase", "profile", "restricted_profile_available", "self_assessment"},
        "engineering",
    )
    if engineering["phase"] != "implementation":
        raise StatusError("this schema records only the current implementation phase")
    if engineering["profile"] != "restricted-nist-standard-v4":
        raise StatusError("engineering profile changed without a status-schema review")
    if engineering["restricted_profile_available"] is not False:
        raise StatusError("the restricted v4 profile is not available")
    if engineering["self_assessment"] != "partial":
        raise StatusError("the current self-assessment remains partial")

    certification = _exact_keys(
        root["certification"],
        {"status", "cstl", "test_id", "cavp_certificates", "cmvp_certificate"},
        "certification",
    )
    if certification["status"] != "sponsor-deferred":
        raise StatusError(
            "external certification must remain sponsor-deferred until a reviewed transition"
        )
    if certification["cstl"] is not None or certification["test_id"] is not None:
        raise StatusError("non-certified status cannot name a CSTL or test ID")
    if certification["cavp_certificates"] != []:
        raise StatusError("non-certified status cannot claim CAVP certificates")
    if certification["cmvp_certificate"] is not None:
        raise StatusError("a CMVP certificate requires a new certificate-aware schema")

    claims = _exact_keys(
        root["claims"],
        {
            "fips_140_3_compliant",
            "cavp_validated",
            "approved_mode_available",
            "fips_140_3_validated",
            "independently_audited",
        },
        "claims",
    )
    for field in (
        "fips_140_3_compliant",
        "cavp_validated",
        "approved_mode_available",
        "fips_140_3_validated",
        "independently_audited",
    ):
        if claims[field] is not False:
            raise StatusError(f"the non-certified schema requires claims.{field}=false")


def validate_engine_claim_surface(source: str) -> None:
    claim_fields = (
        "approved_only_mode",
        "fips_140_3_validated",
        "fips_140_3_certificate",
    )
    for field in claim_fields:
        if source.count(field) != 1:
            raise StatusError(f"engine claim field must occur exactly once: {field}")
    for required in ENGINE_FALSE_CLAIMS:
        if source.count(required) != 1:
            raise StatusError(
                f"engine non-certified claim must occur exactly once: {required}"
            )
    for forbidden in (
        '"approved_only_mode": true',
        '"fips_140_3_validated": true',
    ):
        if forbidden in source:
            raise StatusError(f"engine contains a forbidden non-certified claim: {forbidden}")


def _positive_claim(
    text: str, *, include_standalone: bool
) -> re.Match[str] | None:
    normalized = html.unescape(text).replace("\N{NO-BREAK SPACE}", " ")
    normalized = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", normalized)
    normalized = re.sub(r"!?\[([^\]]+)\]\[[^\]]*\]", r"\1", normalized)
    normalized = re.sub(r"<[^>\n]+>", "", normalized)
    normalized = re.sub(r"[*_`]+", "", normalized)
    patterns = POSITIVE_SUBJECT_CLAIMS
    if include_standalone:
        patterns += POSITIVE_STANDALONE_CLAIMS
    for pattern in patterns:
        for match in pattern.finditer(normalized):
            line_start = normalized.rfind("\n", 0, match.start()) + 1
            prefix = normalized[line_start : match.start()]
            if PROHIBITED_CLAIM_PREFIX.search(prefix) is not None:
                continue
            return match
    return None


def _positive_source_literal_claim(text: str) -> re.Match[str] | None:
    normalized = html.unescape(text).replace("\N{NO-BREAK SPACE}", " ")
    normalized = SOURCE_ESCAPED_SPACE.sub(" ", normalized)
    while True:
        joined = SOURCE_LITERAL_JOIN.sub("", normalized)
        if joined == normalized:
            break
        normalized = joined
    for pattern in POSITIVE_SOURCE_LITERAL_CLAIMS:
        match = pattern.search(normalized)
        if match is not None:
            return match
    return None


def validate_prose_claim_surface(repo_root: pathlib.Path) -> None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise StatusError(f"cannot inventory repository prose: {error}") from error

    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            relative = pathlib.Path(raw_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise StatusError("repository contains a non-UTF-8 path") from error
        suffix = relative.suffix.lower()
        if suffix not in PUBLIC_TEXT_SUFFIXES and relative.name not in PUBLIC_TEXT_NAMES:
            continue
        if relative == pathlib.Path("scripts/check-cmvp-status.py"):
            continue
        path = repo_root / relative
        if path.is_symlink():
            raise StatusError(f"refusing symlinked claim prose: {relative}")
        try:
            prose = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise StatusError(f"cannot inspect claim prose {relative}: {error}") from error
        match = _positive_claim(
            prose,
            include_standalone=suffix in PROSE_SUFFIXES
            or relative.name in PUBLIC_TEXT_NAMES,
        )
        if match is None and suffix in SOURCE_LITERAL_SUFFIXES:
            match = _positive_source_literal_claim(prose)
        if match is not None:
            raise StatusError(
                f"unsupported positive assurance prose is forbidden before verified evidence: "
                f"{relative}: {match.group(0)!r}"
            )


def validate_repository_claim_surface(repo_root: pathlib.Path) -> None:
    engine_path = repo_root / "crates/anubis-cli/src/main.rs"
    try:
        engine = engine_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise StatusError(f"cannot inspect engine claim surface: {error}") from error
    validate_engine_claim_surface(engine)
    validate_prose_claim_surface(repo_root)


def validate_runtime_status(data: object) -> None:
    root = _exact_keys(data, RUNTIME_ROOT_KEYS, "runtime root")
    if root["kind"] != "status":
        raise StatusError("runtime output is not an ANUBIS status record")
    if root["status_schema"] != "anubis-status/assurance-v1":
        raise StatusError("runtime assurance schema changed without review")
    if not isinstance(root["version"], str) or VERSION_PATTERN.fullmatch(
        root["version"]
    ) is None:
        raise StatusError("runtime version must be a canonical semantic version")
    if CLAIM_TOKEN.search(root["version"]) is not None:
        raise StatusError("runtime version contains a certificate-claim token")
    suite = _exact_keys(root["suite"], set(RUNTIME_SUITE_EXPECTED), "runtime suite")
    for field, value in RUNTIME_SUITE_EXPECTED.items():
        if suite[field] != value or type(suite[field]) is not type(value):
            raise StatusError(f"runtime non-certified field differs: suite.{field}")


def validate_runtime_human(text: str) -> None:
    lines = text.splitlines()
    if len(lines) != len(RUNTIME_HUMAN_PATTERNS):
        raise StatusError("runtime human output has an unexpected line count")
    for line, pattern in zip(lines, RUNTIME_HUMAN_PATTERNS, strict=True):
        if pattern.fullmatch(line) is None:
            raise StatusError("runtime human output changed without review")
    if CLAIM_TOKEN.search(lines[0]) is not None:
        raise StatusError("runtime human version contains a certificate-claim token")
    match = _positive_claim(text, include_standalone=True)
    if match is not None:
        raise StatusError(f"runtime human output contains a positive claim: {match.group(0)!r}")


def self_test() -> None:
    valid: dict[str, Any] = {
        "schema": "anubis.assurance-status.v2",
        "as_of": "2026-09-01",
        "candidate": {
            "name": "ANUBIS v4 Cryptographic Core",
            "version": None,
            "type": "software",
            "source_boundary": "crates/anubis-v4-core",
            "design_reference": (
                "selected software-module controls drawn from FIPS 140-3 "
                "Security Level 1 requirements"
            ),
        },
        "engineering": {
            "phase": "implementation",
            "profile": "restricted-nist-standard-v4",
            "restricted_profile_available": False,
            "self_assessment": "partial",
        },
        "certification": {
            "status": "sponsor-deferred",
            "cstl": None,
            "test_id": None,
            "cavp_certificates": [],
            "cmvp_certificate": None,
        },
        "claims": {
            "fips_140_3_compliant": False,
            "cavp_validated": False,
            "approved_mode_available": False,
            "fips_140_3_validated": False,
            "independently_audited": False,
        },
        "next_engineering_gate": CURRENT_NEXT_ENGINEERING_GATE,
    }
    validate(valid)

    mutations = []
    for field in valid["claims"]:
        claimed = copy.deepcopy(valid)
        claimed["claims"][field] = True
        mutations.append(claimed)
    certificate = copy.deepcopy(valid)
    certificate["certification"]["cmvp_certificate"] = "unverified"
    mutations.append(certificate)
    hidden_field = copy.deepcopy(valid)
    hidden_field["claims"]["marketing_override"] = True
    mutations.append(hidden_field)
    enabled_profile = copy.deepcopy(valid)
    enabled_profile["engineering"]["restricted_profile_available"] = True
    mutations.append(enabled_profile)
    completed_assessment = copy.deepcopy(valid)
    completed_assessment["engineering"]["self_assessment"] = "complete"
    mutations.append(completed_assessment)
    pursuing_certification = copy.deepcopy(valid)
    pursuing_certification["certification"]["status"] = "pursued"
    mutations.append(pursuing_certification)
    permanently_abandoned = copy.deepcopy(valid)
    permanently_abandoned["certification"]["status"] = "not-pursued"
    mutations.append(permanently_abandoned)
    noncanonical_date = copy.deepcopy(valid)
    noncanonical_date["as_of"] = "20260901"
    mutations.append(noncanonical_date)

    for mutation in mutations:
        try:
            validate(mutation)
        except StatusError:
            continue
        raise AssertionError("claim gate accepted a forbidden mutation")

    valid_engine = "\n".join(ENGINE_FALSE_CLAIMS)
    validate_engine_claim_surface(valid_engine)
    for forbidden in (
        '"approved_only_mode": true,',
        '"fips_140_3_validated": true,',
    ):
        try:
            validate_engine_claim_surface(valid_engine + "\n" + forbidden)
        except StatusError:
            continue
        raise AssertionError("engine claim gate accepted a forbidden claim")

    for prose in (
        "ANUBIS is FIPS 140-3 validated.",
        "ANUBIS is **CMVP validated**.",
        "ANUBIS now has a CMVP certificate.",
        "ANUBIS achieved FIPS 140-3 validation.",
        "ANUBIS is validated under FIPS 140-3.",
        "The ANUBIS v4 Cryptographic Module is FIPS 140-3 validated.",
        "ANUBIS successfully completed CMVP validation.",
        "ANUBIS has FIPS 140-3 certification.",
        "ANUBIS passed FIPS 140-3 validation.",
        "ANUBIS is FIPS 140-3 compliant.",
        "ANUBIS Vault is FIPS 140-3 validated.",
        "FIPS 140-3 validated: ANUBIS",
        "ANUBIS is [FIPS 140-3 validated](https://example.invalid).",
        "ANUBIS is <strong>FIPS 140-3 validated</strong>.",
        "ANUBIS: FIPS 140-3 validated",
        "ANUBIS — FIPS 140-3 validated",
        "ANUBIS has CMVP validation.",
        "ANUBIS has been validated by CMVP.",
        "ANUBIS is FIPS-compliant.",
        "ANUBIS is FIPS 140-3 aligned.",
        "ANUBIS is FIPS conformant.",
        "ANUBIS is validation-ready.",
        "ANUBIS meets FIPS 140-3.",
        "ANUBIS conforms to FIPS 140-3.",
        "ANUBIS complies with FIPS 140-3.",
        "ANUBIS operates in an approved-only mode.",
        "ANUBIS is CAVP validated.",
        "ANUBIS is CAVP approved.",
        "Status: CAVP approved.",
        "ANUBIS has CAVP validation.",
        "ANUBIS holds a CAVP certificate.",
        "CAVP validated: ANUBIS",
        "ANUBIS has been independently audited.",
        "ANUBIS passed an independent audit.",
        "ANUBIS completed a third-party security audit.",
        "Independently audited: ANUBIS",
        "ANUBIS is aligned with FIPS 140-3.",
        "ANUBIS has FIPS 140-3 alignment.",
        "ANUBIS supports approved-only operation.",
        "ANUBIS approved-only mode is available.",
        "Approved-only mode: supported.",
        "![FIPS 140-3 validated](badge.svg)",
        "**FIPS 140-3 VALIDATED**",
    ):
        if _positive_claim(prose, include_standalone=True) is None:
            raise AssertionError("prose claim gate missed a positive validation claim")

    for prose in (
        "ANUBIS is not FIPS 140-3 validated.",
        "ANUBIS has no CMVP certificate.",
        "ANUBIS implements selected software-module controls drawn from FIPS 140-3.",
        "ANUBIS is a non-validated restricted cryptographic profile.",
        "Do not write: FIPS 140-3 validated.",
        "Do not claim \N{LEFT DOUBLE QUOTATION MARK}ANUBIS is CAVP validated."
        "\N{RIGHT DOUBLE QUOTATION MARK}",
        "Never state that 'ANUBIS is CAVP approved.'",
        "ANUBIS has not been independently audited.",
        "ANUBIS has no CAVP validation or certificate.",
    ):
        if _positive_claim(prose, include_standalone=True) is not None:
            raise AssertionError("prose claim gate rejected an explicit non-claim")

    for source in (
        'const STATUS: &str = "FIPS 140-3 validated";',
        'text: qsTr("CMVP validated")',
        "const label = 'CAVP validated';",
        "const label = `CAVP validated`;",
        'text: "CMVP " + "validated"',
        'const char *label = "CAVP " "validated";',
        'text: "FIPS 140-3\\x20validated"',
        'const label = "CAVP\\tvalidated";',
        'const AUDIT: &str = r#"Independently audited"#;',
        'text: "Approved-only mode: available"',
    ):
        if _positive_source_literal_claim(source) is None:
            raise AssertionError("source claim gate missed a wrapped positive claim")

    for source in (
        'const STATUS: &str = "not FIPS 140-3 validated";',
        'text: qsTr("FIPS 140-3 STATUS NOT STATED")',
        "const label = 'CAVP status unavailable';",
        'const AUDIT: &str = r#"Not independently audited"#;',
    ):
        if _positive_source_literal_claim(source) is not None:
            raise AssertionError("source claim gate rejected an explicit non-claim")

    duplicate_claim = (
        '{"claims":{"fips_140_3_validated":true,'
        '"fips_140_3_validated":false}}'
    )
    try:
        load_status(duplicate_claim)
    except StatusError:
        pass
    else:
        raise AssertionError("status parser accepted a duplicate claim key")

    valid_runtime: dict[str, Any] = {
        "kind": "status",
        "status_schema": "anubis-status/assurance-v1",
        "suite": copy.deepcopy(RUNTIME_SUITE_EXPECTED),
        "identities": [],
        "recipients": [],
        "recent": [],
        "counts": {"encrypt": 0, "decrypt": 0, "failed": 0},
        "generated": "2026-09-01T00:00:00Z",
        "version": "2.1.0-test",
    }
    validate_runtime_status(valid_runtime)
    false_runtime = copy.deepcopy(valid_runtime)
    false_runtime["suite"]["fips_140_3_validated"] = True
    try:
        validate_runtime_status(false_runtime)
    except StatusError:
        pass
    else:
        raise AssertionError("runtime gate accepted a false validation claim")

    missing_runtime = copy.deepcopy(valid_runtime)
    del missing_runtime["suite"]["fips_140_3_certificate"]
    try:
        validate_runtime_status(missing_runtime)
    except StatusError:
        pass
    else:
        raise AssertionError("runtime gate accepted a missing certificate field")

    alias_runtime = copy.deepcopy(valid_runtime)
    alias_runtime["suite"]["cmvp_validated"] = True
    try:
        validate_runtime_status(alias_runtime)
    except StatusError:
        pass
    else:
        raise AssertionError("runtime gate accepted an extra validation alias")

    claimed_version = copy.deepcopy(valid_runtime)
    claimed_version["version"] = "2.1.0-FIPS-140-3-validated"
    try:
        validate_runtime_status(claimed_version)
    except StatusError:
        pass
    else:
        raise AssertionError("runtime gate accepted a claim-bearing version")

    validate_runtime_human(
        "ANUBIS 2.1.0\n"
        "suite:       X25519+ML-KEM-1024 / ML-DSA-87 / ChaCha20-Poly1305\n"
        "format:      anubis-encryption.org/v3\n"
        f"{RUNTIME_ASSURANCE_LINE}\n"
        "identities:  0\n"
        "recipients:  0\n"
        "operations:  0 encrypted, 0 decrypted, 0 failed\n"
    )
    try:
        validate_runtime_human(
            "ANUBIS 3.0.0\nassurance:   FIPS 140-3 validated\n"
        )
    except StatusError:
        pass
    else:
        raise AssertionError("runtime human gate accepted a false validation claim")

    try:
        validate_runtime_human(
            "ANUBIS 2.1.0\n"
            "suite:       X25519+ML-KEM-1024 / ML-DSA-87 / ChaCha20-Poly1305\n"
            "format:      anubis-encryption.org/v3\n"
            f"{RUNTIME_ASSURANCE_LINE}\n"
            "certification: FIPS 140-3 validated\n"
            "identities:  0\n"
            "recipients:  0\n"
            "operations:  0 encrypted, 0 decrypted, 0 failed\n"
        )
    except StatusError:
        pass
    else:
        raise AssertionError("runtime human gate accepted a contradictory claim")


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        self_test()
        print("Assurance claim-gate self-test: ok")
        return 0
    if len(argv) == 2 and argv[0] in {"--runtime-status", "--runtime-human"}:
        try:
            text = sys.stdin.read() if argv[1] == "-" else pathlib.Path(argv[1]).read_text(
                encoding="utf-8"
            )
            if argv[0] == "--runtime-status":
                validate_runtime_status(load_status(text))
            else:
                validate_runtime_human(text)
        except (OSError, json.JSONDecodeError, StatusError) as error:
            print(f"Assurance runtime status refused: {error}", file=sys.stderr)
            return 1
        print("Assurance runtime claim surface accepted")
        return 0
    if len(argv) != 1:
        print(
            f"usage: {pathlib.Path(sys.argv[0]).name} STATUS.json | "
            "--runtime-status STATUS.json|- | --runtime-human STATUS.txt|- | "
            "--self-test",
            file=sys.stderr,
        )
        return 2

    path = pathlib.Path(argv[0])
    try:
        data = load_status(path.read_text(encoding="utf-8"))
        validate(data)
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        validate_repository_claim_surface(repo_root)
    except (OSError, json.JSONDecodeError, StatusError) as error:
        print(f"Assurance status refused: {error}", file=sys.stderr)
        return 1

    print(f"Assurance status accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
