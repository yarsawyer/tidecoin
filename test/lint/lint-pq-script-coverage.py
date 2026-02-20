#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check PQ script fixture/corpus scorecard and hard-cutover invariants."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_FIXTURE = ROOT / "src/test/data/script_tests_pq.json"
SCRIPT_ASSETS = ROOT / "src/test/data/script_assets_test.json"

FLAG_ORDER = (
    "P2SH",
    "NULLDUMMY",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "PQ_STRICT",
)

REQUIRED_SCRIPT_CATEGORIES = (
    ("P2PK/P2PKH", r"^PQ P2PKH?\b|^PQ P2PK\b", True, True),
    ("P2SH semantics", r"^PQ P2SH", True, True),
    ("Multisig", r"1-of-2|2-of-3", True, True),
    ("Sighash modes", r"sighash", True, True),
    ("NULLDUMMY", r"NULLDUMMY", True, True),
    ("SIGPUSHONLY", r"SIGPUSHONLY|non-push scriptSig", True, True),
    ("CLEANSTACK", r"CLEANSTACK", True, True),
    ("MINIMALDATA", r"MINIMALDATA", True, True),
    ("MINIMALIF", r"MINIMALIF", True, True),
    ("NULLFAIL", r"NULLFAIL", True, True),
    ("CLTV", r"\bCLTV\b", True, True),
    ("CSV", r"\bCSV\b", True, True),
    ("Interpreter surface", r"^PQ interpreter ", True, True),
    ("CONST_SCRIPTCODE", r"CONST_SCRIPTCODE", True, True),
    ("OP_SHA512", r"OP_SHA512", True, True),
    ("witness v1_512", r"v1_512", True, True),
    ("PQ_STRICT", r"^PQ strict|^PQ non-strict", True, True),
)

REQUIRED_ASSET_FLAG_SETS = {
    "PQ_STRICT",
    "NULLDUMMY,PQ_STRICT",
    "CHECKLOCKTIMEVERIFY,PQ_STRICT",
    "CHECKSEQUENCEVERIFY,PQ_STRICT",
    "CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,PQ_STRICT",
    "NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,PQ_STRICT",
    "P2SH,WITNESS,PQ_STRICT",
    "P2SH,NULLDUMMY,WITNESS,PQ_STRICT",
    "P2SH,CHECKLOCKTIMEVERIFY,WITNESS,PQ_STRICT",
    "P2SH,CHECKSEQUENCEVERIFY,WITNESS,PQ_STRICT",
    "P2SH,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,PQ_STRICT",
    "P2SH,NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,PQ_STRICT",
    "P2SH,CHECKLOCKTIMEVERIFY,PQ_STRICT",
    "P2SH,CHECKSEQUENCEVERIFY,PQ_STRICT",
    "P2SH,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,PQ_STRICT",
}

REQUIRED_ASSET_COMMENT_TAGS = (
    "PQ legacy spend",
    "PQ witness spend",
    "PQ p2sh-witness spend",
    "PQ static CLTV spend",
    "PQ static CLTV time-lock spend",
    "PQ static CSV spend",
    "PQ static CSV time-lock spend",
    "PQ static CLTV+CSV spend",
    "PQ static P2SH CLTV spend",
    "PQ static P2SH CSV spend",
    "PQ static P2SH CLTV+CSV spend",
    "PQ static P2WSH CLTV spend",
    "PQ static P2WSH CSV spend",
    "PQ static P2WSH CLTV+CSV spend",
)

LEGACY_FORBIDDEN_PATTERNS = (
    r"\bBIP66\b",
    r"\bDERSIG\b",
    r"\bLOW_S\b",
    r"\bSTRICTENC\b",
    r"\bECDSA\b",
    r"\bsecp(?:256k1)?\b",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def check_legacy_invariants(errors: list[str]) -> None:
    if (ROOT / "src/test/data/script_tests.json").exists():
        fail(errors, "legacy fixture present: src/test/data/script_tests.json")

    test_tree_files = [p for p in (ROOT / "src/test").rglob("*") if p.is_file() and p.suffix in {".cpp", ".h", ".json", ".cmake", ".txt"}]
    bad_refs = []
    pattern = re.compile(r"script_tests\.json\b")
    for path in test_tree_files:
        if pattern.search(read_text(path)):
            bad_refs.append(path.relative_to(ROOT).as_posix())
    if bad_refs:
        fail(errors, "legacy script_tests.json references found under src/test: " + ", ".join(sorted(bad_refs)))

    script_tests_cpp = read_text(ROOT / "src/test/script_tests.cpp")
    transaction_tests_cpp = read_text(ROOT / "src/test/transaction_tests.cpp")
    cmake_tests = read_text(ROOT / "src/test/CMakeLists.txt")
    script_assets_tests_cpp = read_text(ROOT / "src/test/script_assets_tests.cpp")

    if "#include <test/data/script_tests_pq.json.h>" not in script_tests_cpp:
        fail(errors, "missing include: <test/data/script_tests_pq.json.h> in src/test/script_tests.cpp")

    if "#include <test/data/tx_valid_pq.json.h>" not in transaction_tests_cpp:
        fail(errors, "missing include: <test/data/tx_valid_pq.json.h> in src/test/transaction_tests.cpp")
    if "#include <test/data/tx_invalid_pq.json.h>" not in transaction_tests_cpp:
        fail(errors, "missing include: <test/data/tx_invalid_pq.json.h> in src/test/transaction_tests.cpp")

    if "data/script_tests.json" in cmake_tests:
        fail(errors, "legacy data/script_tests.json still listed in src/test/CMakeLists.txt")

    for forbidden in LEGACY_FORBIDDEN_PATTERNS:
        matcher = re.compile(forbidden)
        if matcher.search(script_tests_cpp):
            fail(errors, f"legacy term found in src/test/script_tests.cpp: /{forbidden}/")
        if matcher.search(transaction_tests_cpp):
            fail(errors, f"legacy term found in src/test/transaction_tests.cpp: /{forbidden}/")

    legacy_size_gate = "CKey::SIZE != 32"
    if legacy_size_gate in script_tests_cpp or legacy_size_gate in transaction_tests_cpp:
        fail(errors, "legacy CKey::SIZE != 32 gate still present in script/transaction tests")

    if "skipping script_assets_test" in cmake_tests or "skipping script_assets_test" in script_assets_tests_cpp:
        fail(errors, "script_assets_test skip path detected in required test path")


def parse_script_fixture_rows() -> list[dict[str, str]]:
    data = json.loads(read_text(SCRIPT_FIXTURE))
    if not isinstance(data, list):
        raise ValueError(f"{SCRIPT_FIXTURE.relative_to(ROOT)} must be a JSON array")
    parsed = []
    for idx, row in enumerate(data):
        if not isinstance(row, list):
            continue
        pos = 1 if row and isinstance(row[0], list) else 0
        if len(row) < pos + 4:
            continue
        expected = row[pos + 3]
        comment = row[pos + 4] if len(row) > pos + 4 and isinstance(row[pos + 4], str) else ""
        parsed.append(
            {
                "index": str(idx),
                "expected": str(expected),
                "comment": comment,
            }
        )
    return parsed


def check_script_fixture_scorecard(errors: list[str]) -> tuple[int, int]:
    rows = parse_script_fixture_rows()
    if not rows:
        fail(errors, "script fixture scorecard has no parsed rows")
        return (0, 0)

    for category_name, regex, require_ok, require_fail in REQUIRED_SCRIPT_CATEGORIES:
        matcher = re.compile(regex)
        matched = [row for row in rows if matcher.search(row["comment"])]
        if not matched:
            fail(errors, f"script category missing: {category_name}")
            continue

        ok_count = sum(1 for row in matched if row["expected"] == "OK")
        fail_count = len(matched) - ok_count
        if require_ok and ok_count == 0:
            fail(errors, f"script category lacks positive coverage: {category_name}")
        if require_fail and fail_count == 0:
            fail(errors, f"script category lacks negative coverage: {category_name}")

    return (len(rows), len(REQUIRED_SCRIPT_CATEGORIES))


def check_script_assets_scorecard(errors: list[str]) -> tuple[int, int]:
    data = json.loads(read_text(SCRIPT_ASSETS))
    if not isinstance(data, list):
        fail(errors, "script-assets corpus must be a JSON array")
        return (0, 0)

    flag_order_index = {name: idx for idx, name in enumerate(FLAG_ORDER)}
    present_flag_sets = set()
    comments = []

    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            fail(errors, f"script-assets entry #{idx} must be an object")
            continue

        for required_key in ("tx", "prevouts", "index", "flags", "comment", "success", "failure"):
            if required_key not in entry:
                fail(errors, f"script-assets entry #{idx} missing key: {required_key}")

        flags = str(entry.get("flags", ""))
        present_flag_sets.add(flags)
        split_flags = [flag for flag in flags.split(",") if flag]
        unknown_flags = [flag for flag in split_flags if flag not in flag_order_index]
        if unknown_flags:
            fail(errors, f"script-assets entry #{idx} has unknown flag(s): {unknown_flags}")
            continue
        canonical = sorted(split_flags, key=lambda flag: flag_order_index[flag])
        if split_flags != canonical:
            fail(errors, f"script-assets entry #{idx} has non-canonical flag order: {flags}")

        comments.append(str(entry.get("comment", "")))

    missing_flag_sets = sorted(REQUIRED_ASSET_FLAG_SETS - present_flag_sets)
    if missing_flag_sets:
        fail(errors, "missing required script-assets flag set(s): " + ", ".join(missing_flag_sets))

    missing_comment_tags = []
    for tag in REQUIRED_ASSET_COMMENT_TAGS:
        if not any(comment.startswith(tag) for comment in comments):
            missing_comment_tags.append(tag)
    if missing_comment_tags:
        fail(errors, "missing required script-assets comment tag(s): " + ", ".join(missing_comment_tags))

    return (len(data), len(present_flag_sets))


def main() -> int:
    errors: list[str] = []

    check_legacy_invariants(errors)
    script_rows, script_categories = check_script_fixture_scorecard(errors)
    assets_entries, assets_flag_sets = check_script_assets_scorecard(errors)

    if errors:
        print("PQ script coverage scorecard failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("PQ script coverage scorecard OK")
    print(f"- script fixture rows: {script_rows}")
    print(f"- required script categories checked: {script_categories}")
    print(f"- script-assets entries: {assets_entries}")
    print(f"- script-assets distinct flag sets: {assets_flag_sets}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
