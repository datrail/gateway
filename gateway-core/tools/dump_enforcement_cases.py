"""Write `ENFORCEMENT_CASES` as a JSON array, readable without post-processing.

Usage: make dump-enforcement-cases, or
uv run python gateway-core/tools/dump_enforcement_cases.py [OUT]
(default: enforcement-cases.json)
"""

import base64
import binascii
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import core_support
from core_support import ENFORCEMENT_CASES, REASONS

# Past this, a string is shown by its start and its length.
MAX_SHOWN = 120

# The policies `core_support` names, by identity, so a row shows the name.
POLICY_NAMES = {
    id(value): name
    for name, value in vars(core_support).items()
    if name.isupper() and isinstance(value, dict) and "condition" in value
}


def shorten(text: str) -> str:
    """`text`, with control characters escaped and a long one cut short."""
    text = "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode() for c in text
    )
    if len(text) <= MAX_SHOWN:
        return text
    return f"{text[:60]}… ({len(text)} chars)"


def format_condition(c: dict) -> str:
    return " ".join(str(c[k]) for k in ("field", "operator", "value") if k in c)


def format_policy(p: dict) -> dict:
    return {
        "label": POLICY_NAMES.get(id(p), p["name"]),
        "id": p["id"],
        "priority": p["priority"],
        "action": p["action"],
        "condition": format_condition(p["condition"]),
    }


def format_bundle(case) -> dict:
    """The held bundle's fields, each prefixed `bun_`."""
    if case.enforcement is None:
        return dict.fromkeys(
            ("bun_posture", "bun_fallback", "bun_policies", "bun_bindings")
        )
    return {
        "bun_posture": case.enforcement,
        "bun_fallback": case.fallback,
        "bun_policies": [format_policy(p) for p in case.policies],
        "bun_bindings": [
            {
                "endpoint_key": b["endpoint_key"],
                "mode": b["mode"],
                "policy_ids": b["policy_ids"],
            }
            for b in case.bindings
        ],
    }


def decode_ticket(header: str) -> str:
    """The claims a ticket carries, as the JSON it decodes to."""
    try:
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return shorten(raw.decode())
    except (binascii.Error, UnicodeDecodeError):
        return f"not base64: {shorten(header)}"


def format_body(raw: bytes) -> str:
    return shorten(raw.decode("utf-8", errors="backslashreplace"))


def format_outcome(status: int | None) -> str:
    return "forwarded" if status is None else f"{status} {REASONS[status]}"


def format_report(expected) -> dict | str:
    if expected is None:
        return None
    return json.loads(
        json.dumps(expected),
        object_hook=lambda d: {
            k: shorten(v) if isinstance(v, str) else v for k, v in d.items()
        },
    )


def set_empty_to_none(value):
    """`value` with every empty string, list or dict in it replaced by None."""
    if isinstance(value, dict):
        value = {k: set_empty_to_none(v) for k, v in value.items()}
    elif isinstance(value, list):
        value = [set_empty_to_none(v) for v in value]
    return None if value in ("", [], {}) else value


def format_case(case) -> dict:
    return {
        "name": case.name,
        **format_bundle(case),
        "rqs_method": case.method,
        "rqs_path": case.path,
        "rqs_body": format_body(case.body),
        "rqs_x_rail": [decode_ticket(t) for t in case.x_rail],
        "rqs_x_rail_status": [shorten(s) for s in case.x_rail_status],
        "exp_outcome": format_outcome(case.status),
        "exp_report": format_report(case.report),
        "skipped_for": dict(case.not_for),
    }


def write_cases() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "enforcement-cases.json")
    rows = [set_empty_to_none(format_case(case)) for case in ENFORCEMENT_CASES]
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(rows)} cases written to {out}")


if __name__ == "__main__":
    write_cases()
