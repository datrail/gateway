"""What Rail Center's signed vectors cannot say.

The vectors hold tickets Rail Center's harness signed. Every one carries `iss`,
and only one goes without `aud`, so a ticket naming no issuer is a case they
never reach. The rules below are about tickets like that, which Rail Center
never issues, or about the order the checks run in, and both are where a reader
goes wrong without any vector noticing. The tickets here are signed with the
vectors' own test key, whose seed that file publishes.
"""

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.core.ticket import TicketVerifier, parse_rail_header, usable_keys

SIGNING = json.loads(
    (Path(__file__).parent / "vectors" / "signed_tickets.json").read_text(
        encoding="utf-8"
    )
)["signing"]
KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SIGNING["test_key_seed_hex"]))
KID = SIGNING["jwks"]["keys"][0]["kid"]

NOW = 1_785_240_000
ISSUER = "https://rail-center.example/tenants/00000000-0000-4000-8000-0000000000aa"
AUDIENCE = "00000000-0000-4000-8000-0000000000aa"

READER = TicketVerifier(
    keys=usable_keys(SIGNING["jwks"]), issuer=ISSUER, audience=AUDIENCE
)


def _part(value: Any) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _signed(claims: Any, header: dict[str, Any] | None = None) -> str:
    """`claims` as a ticket signed with the test key, over the parts as sent."""
    signing_input = (
        f"{_part(header or {'alg': 'EdDSA', 'typ': 'JWT', 'kid': KID})}.{_part(claims)}"
    )
    return f"{signing_input}.{_part(KEY.sign(signing_input.encode()))}"


def _claims(**overrides: Any) -> dict[str, Any]:
    claims = {
        "id": "5c8f1e42-0000-4000-8000-0000000000c1",
        "exp": NOW + 900,
        "nbf": NOW,
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def test_a_genuine_ticket_for_this_reader_is_valid_and_carries_its_claims() -> None:
    """The baseline every case below departs from by one thing."""
    result = parse_rail_header(_signed(_claims()), NOW, READER)

    assert result.state == "valid"
    assert result.token == _claims()


def test_a_reader_with_no_issuer_refuses_a_ticket_naming_none() -> None:
    """No configured issuer accepts **nothing**, not merely nothing that names
    one.

    Compared value to value, an unset issuer and a ticket with no `iss` are
    both absent and agree, so a reader letting the comparison stand in for the
    rule would admit that ticket on its audience alone. (The audience cannot
    fail the same way: one that is not a string is refused before it is
    compared.) Rail Center never issues a ticket without `iss`, so only a
    forger holding a key would — which is the case this exists for.
    """
    no_issuer = TicketVerifier(keys=READER.keys, audience=AUDIENCE)
    ticket = _signed(_claims(iss=None))

    assert parse_rail_header(ticket, NOW, no_issuer).state == "wrong_audience"


def test_a_ticket_naming_no_issuer_is_not_for_a_reader_that_has_one() -> None:
    assert parse_rail_header(_signed(_claims(iss=None)), NOW, READER).state == (
        "wrong_audience"
    )


def test_a_payload_that_fails_its_signature_is_never_decoded() -> None:
    """The signature is checked before the payload is read, so a payload that
    is not even JSON is `bad_signature` and not `undecodable`.

    Read the other way round, the state would tell a forger how far a crafted
    payload got, and the claims of one that parsed would be in hand before
    anything said whether to trust them.
    """
    good = _signed(_claims())
    header, _, signature = good.split(".")
    forged = f"{header}.{_part(b'not json')}.{signature}"

    assert parse_rail_header(forged, NOW, READER).state == "bad_signature"


def test_a_signature_is_checked_over_the_parts_as_they_arrived() -> None:
    """Padding the payload part changes nothing it decodes to and everything
    the signature covers, so the padded ticket no longer verifies."""
    header, payload, signature = _signed(_claims()).split(".")
    padded = f"{header}.{payload}{'=' * (-len(payload) % 4) or '=='}.{signature}"

    assert parse_rail_header(padded, NOW, READER).state == "bad_signature"


def test_no_verifier_reads_every_signed_ticket_as_bad_signature() -> None:
    """A caller that passes none holds no key set, which the contract reads as
    `bad_signature` for every signed ticket — never as a pass."""
    assert parse_rail_header(_signed(_claims()), NOW).state == "bad_signature"


def test_an_unsigned_ticket_is_read_as_before_with_no_verifier() -> None:
    """Every caller today passes none, and must see no change."""
    unsigned = _part({"agent_id": "a", "exp": NOW + 900})

    assert parse_rail_header(unsigned, NOW).state == "valid"


def test_the_header_names_no_key_this_reader_uses() -> None:
    """A `jwk` carrying another key, and a `kid` this reader does not hold, is
    refused: the key comes from the reader's set and never from the ticket."""
    other = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(SIGNING["other_key_seed_hex"])
    )
    x = _part(other.public_key().public_bytes_raw())
    header = {
        "alg": "EdDSA",
        "kid": "attacker",
        "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
    }
    signing_input = f"{_part(header)}.{_part(_claims())}"
    ticket = f"{signing_input}.{_part(other.sign(signing_input.encode()))}"

    assert parse_rail_header(ticket, NOW, READER).state == "bad_signature"


def test_a_key_set_with_a_repeated_kid_is_not_a_key_set() -> None:
    entry = SIGNING["jwks"]["keys"][0]

    assert usable_keys({"keys": [entry, dict(entry)]}) is None


def test_a_key_set_skips_what_is_not_for_verifying() -> None:
    """Entries for other purposes are passed over rather than refusing the set,
    and a set left with nothing usable counts as a failed fetch."""
    entry = SIGNING["jwks"]["keys"][0]
    not_ours = [
        {**entry, "kid": "enc", "use": "enc"},
        {**entry, "kid": "sign-only", "key_ops": ["sign"]},
        {**entry, "kid": "rs", "alg": "RS256"},
        {**entry, "kid": "short", "x": _part(b"\x00" * 31)},
        {"kty": "RSA", "kid": "rsa", "n": "AQAB", "e": "AQAB"},
    ]

    assert set(usable_keys({"keys": [entry, *not_ours]}) or {}) == {entry["kid"]}
    assert usable_keys({"keys": not_ours}) is None
    assert usable_keys({"keys": []}) is None
    assert usable_keys([entry]) is None
