#!/usr/bin/env python3
"""Reject premature or internally inconsistent CMVP claims.

The current schema is intentionally pre-certificate-only. A future CMVP
certificate must cause a reviewed schema and verifier change; flipping a JSON
boolean can never turn this repository into a validated module.
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
    """The status document violates the pre-certificate contract."""


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

CURRENT_NEXT_EXTERNAL_GATE = (
    "Execute a statement of work with an NVLAP-accredited CST laboratory for "
    "architecture review, ACVTS testing, and a FIPS 140-3 Full Submission."
)

ANUBIS_SUBJECT = (
    r"(?:the\s+)?ANUBIS(?:\s+Vault)?(?:/v[0-9]+|\s+v[0-9]+)?"
    r"(?:\s+cryptographic\s+module)?"
)

POSITIVE_SUBJECT_CLAIMS = (
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:a\s+)?(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+validated\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:certified|validated)\s+(?:under|to)\s+"
        r"(?:FIPS(?:\s+140-3)?|CMVP)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:has\s+)?(?:successfully\s+)?"
        r"(?:achieved|completed|obtained|received)\s+(?:an?\s+)?"
        r"(?:(?:FIPS(?:\s+140-3)?|CMVP)\s+)?"
        r"(?:module\s+)?(?:validation|certification|certificate)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:now\s+)?(?:has|holds)\s+"
        r"(?:an?\s+)?(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+"
        r"(?:certificate|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+certified\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:has\s+)?(?:successfully\s+)?passed\s+"
        r"(?:the\s+)?(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+"
        r"(?:validation|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is(?:\s+now)?|has\s+been)\s+"
        r"(?:(?:FIPS(?:\s+140-3)?|CMVP)[-\s]+compliant|"
        r"compliant\s+with\s+(?:FIPS(?:\s+140-3)?|CMVP))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+validated\s*:\s*"
        rf"{ANUBIS_SUBJECT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s*(?::|[-\N{{EM DASH}}\N{{EN DASH}}])\s*"
        r"(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+validated\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:now\s+)?has\s+(?:an?\s+)?"
        r"(?:FIPS(?:\s+140-3)?|CMVP)(?:\s+module)?\s+"
        r"(?:validation|certification)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{ANUBIS_SUBJECT}\s+(?:is|has\s+been)\s+validated\s+by\s+"
        r"(?:the\s+)?(?:FIPS(?:\s+140-3)?|CMVP)\b",
        re.IGNORECASE,
    ),
)

POSITIVE_STANDALONE_CLAIMS = (
    re.compile(
        r"^\s*(?:status:\s*)?FIPS\s+140-3\s+validated"
        r"(?:\s+cryptographic\s+module)?[.!]?\s*$",
        re.IGNORECASE | re.MULTILINE,
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
            "module",
            "program",
            "claims",
            "next_external_gate",
        },
        "root",
    )
    if root["schema"] != "anubis.cmvp-precertificate-status.v1":
        raise StatusError("unsupported CMVP status schema")
    if not isinstance(root["as_of"], str) or not root["as_of"]:
        raise StatusError("as_of must be a non-empty date string")
    try:
        parsed_date = datetime.date.fromisoformat(root["as_of"])
    except ValueError as error:
        raise StatusError("as_of must be an ISO calendar date") from error
    if parsed_date.isoformat() != root["as_of"]:
        raise StatusError("as_of must use canonical YYYY-MM-DD form")
    if root["next_external_gate"] != CURRENT_NEXT_EXTERNAL_GATE:
        raise StatusError("next_external_gate changed without a status-schema review")

    module = _exact_keys(
        root["module"],
        {"name", "version", "type", "target_security_level", "source_boundary"},
        "module",
    )
    if module["name"] != "ANUBIS v4 Cryptographic Module":
        raise StatusError("module.name changed without a status-schema review")
    if module["version"] is not None:
        raise StatusError("the candidate module version is not frozen")
    if module["type"] != "software":
        raise StatusError("the current validation target must remain a software module")
    if type(module["target_security_level"]) is not int or module["target_security_level"] != 1:
        raise StatusError("the current validation target is Security Level 1")
    if module["source_boundary"] != "crates/anubis-v4-core":
        raise StatusError("module source boundary changed without a status-schema review")

    program = _exact_keys(
        root["program"],
        {"phase", "cstl", "test_id", "cavp_certificates", "cmvp_certificate"},
        "program",
    )
    if program["phase"] != "pre-submission":
        raise StatusError("this schema records only the current pre-submission phase")
    if program["cstl"] is not None or program["test_id"] is not None:
        raise StatusError("pre-submission status cannot name a CSTL or test ID")
    if program["cavp_certificates"] != []:
        raise StatusError("pre-submission status cannot claim CAVP certificates")
    if program["cmvp_certificate"] is not None:
        raise StatusError("a CMVP certificate requires a new certificate-aware schema")

    claims = _exact_keys(
        root["claims"],
        {"approved_mode_available", "fips_140_3_validated"},
        "claims",
    )
    if claims["approved_mode_available"] is not False:
        raise StatusError("the inert v4 core does not provide an approved mode")
    if claims["fips_140_3_validated"] is not False:
        raise StatusError("the pre-certificate schema can never claim FIPS 140-3 validation")


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
                f"engine pre-certificate claim must occur exactly once: {required}"
            )
    for forbidden in (
        '"approved_only_mode": true',
        '"fips_140_3_validated": true',
    ):
        if forbidden in source:
            raise StatusError(f"engine contains a forbidden pre-certificate claim: {forbidden}")


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
        if match is not None:
            raise StatusError(
                f"positive FIPS validation prose is forbidden before a certificate: "
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
            raise StatusError(f"runtime pre-certificate field differs: suite.{field}")


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
        "schema": "anubis.cmvp-precertificate-status.v1",
        "as_of": "2026-09-01",
        "module": {
            "name": "ANUBIS v4 Cryptographic Module",
            "version": None,
            "type": "software",
            "target_security_level": 1,
            "source_boundary": "crates/anubis-v4-core",
        },
        "program": {
            "phase": "pre-submission",
            "cstl": None,
            "test_id": None,
            "cavp_certificates": [],
            "cmvp_certificate": None,
        },
        "claims": {
            "approved_mode_available": False,
            "fips_140_3_validated": False,
        },
        "next_external_gate": CURRENT_NEXT_EXTERNAL_GATE,
    }
    validate(valid)

    mutations = []
    claimed = copy.deepcopy(valid)
    claimed["claims"]["fips_140_3_validated"] = True
    mutations.append(claimed)
    approved = copy.deepcopy(valid)
    approved["claims"]["approved_mode_available"] = True
    mutations.append(approved)
    certificate = copy.deepcopy(valid)
    certificate["program"]["cmvp_certificate"] = "unverified"
    mutations.append(certificate)
    wrong_level = copy.deepcopy(valid)
    wrong_level["module"]["target_security_level"] = 4
    mutations.append(wrong_level)
    hidden_field = copy.deepcopy(valid)
    hidden_field["claims"]["marketing_override"] = True
    mutations.append(hidden_field)
    premature_lab = copy.deepcopy(valid)
    premature_lab["program"]["phase"] = "module-testing"
    mutations.append(premature_lab)
    boolean_level = copy.deepcopy(valid)
    boolean_level["module"]["target_security_level"] = True
    mutations.append(boolean_level)
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
        "![FIPS 140-3 validated](badge.svg)",
        "**FIPS 140-3 VALIDATED**",
    ):
        if _positive_claim(prose, include_standalone=True) is None:
            raise AssertionError("prose claim gate missed a positive validation claim")

    for prose in (
        "ANUBIS is not FIPS 140-3 validated.",
        "ANUBIS has no CMVP certificate.",
        "Do not write: FIPS 140-3 validated.",
    ):
        if _positive_claim(prose, include_standalone=True) is not None:
            raise AssertionError("prose claim gate rejected an explicit non-claim")

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
        print("CMVP status claim-gate self-test: ok")
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
            print(f"CMVP runtime status refused: {error}", file=sys.stderr)
            return 1
        print("CMVP runtime claim surface accepted")
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
        print(f"CMVP status refused: {error}", file=sys.stderr)
        return 1

    print(f"CMVP status accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
