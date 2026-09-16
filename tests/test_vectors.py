"""Run the conformance vectors.

The vectors are the specification of what this gateway reads, written as data
so a reimplementation in another language is answerable to the same cases. That
only holds while something runs them: a vector file nothing executes states a
rule without enforcing it, which is worse than no file, because the rule looks
covered.

Each case is its own test, named after itself, so a failure names the rule that
broke rather than the file that holds it.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from gateway.bundle.conditions import ConditionInput, UninterpretableCondition
from gateway.bundle.decide import decide, refuses_unbound
from gateway.bundle.validate import (
    _SCHEMA_VERSION,
    SUPPORTED_SCHEMA_MAJOR,
    Binding,
    UnusableBundle,
    validate_bundle,
)
from gateway.key_safety import has_unsafe_key_characters
from gateway.mode import ENFORCEMENTS, FALLBACKS, blocks
from gateway.ticket import parse_rail_header

VECTORS = Path(__file__).parent / "vectors"
SCHEMAS = Path(__file__).parent.parent / "schemas"

#: "this key is not in the document", which `None` cannot say.
_ABSENT = object()


def _load(name: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))["cases"]


def _header(case: dict[str, Any]) -> Any:
    """A JSON list becomes a Python list; everything else passes through.

    `parse_rail_header` accepts a list or a tuple for the repeated-header case,
    and JSON can only spell the list. The tuple half is covered in
    `test_ticket.py`.
    """
    return case["header"]


TICKET_CASES = _load("ticket.json")


@pytest.mark.parametrize(
    "case", TICKET_CASES, ids=[case["name"] for case in TICKET_CASES]
)
def test_ticket_vector(case: dict[str, Any]) -> None:
    result = parse_rail_header(_header(case), case["now"])

    assert result.state == case["state"]

    # `token` is asserted only where the case carries the key. Its absence
    # means the case does not assert one — either because JSON cannot express
    # it, as for a token carrying infinity, or because the state alone is the
    # point. Asserting `None` on every case that omits it would quietly demand
    # the opposite of what the file documents.
    if "token" in case:
        assert result.token == case["token"]


def test_every_unusable_state_surrenders_its_claims() -> None:
    """The rule the vectors state case by case, stated once over all of them.

    A case asserting `token: null` pins that one payload. This pins the rule:
    nothing but `valid` ever comes back carrying claims, whatever the payload
    said and however readable it was.
    """
    for case in TICKET_CASES:
        result = parse_rail_header(_header(case), case["now"])
        if result.state != "valid":
            assert result.token is None, case["name"]


def test_the_file_is_worth_running() -> None:
    """A guard against the failure mode this file exists to close.

    An empty or truncated vector file makes every test above pass by having
    nothing to run, and a parametrised suite reports that as success. The count
    is deliberately a floor rather than an equality: adding a case should not
    fail the suite, and losing most of them should.
    """
    assert len(TICKET_CASES) >= 70
    assert len({case["name"] for case in TICKET_CASES}) == len(TICKET_CASES)


BUNDLE_CASES = _load("bundle.json")


@pytest.mark.parametrize(
    "case", BUNDLE_CASES, ids=[case["name"] for case in BUNDLE_CASES]
)
def test_bundle_vector(case: dict[str, Any]) -> None:
    if not case["usable"]:
        with pytest.raises(UnusableBundle):
            validate_bundle(case["bundle"])
        return

    bundle = validate_bundle(case["bundle"])

    # The chain as canonical ids in evaluation order. Comparing the whole list
    # rather than a set is the point: ordering is what the priority and
    # tiebreak rules are about, and a set assertion would pass on a chain
    # ordered however the bundle happened to list it.
    assert [policy.id for policy in bundle.chain] == case["chain"]

    # What an operator reads. A policy whose name is unreadable is named by its
    # id rather than refused, and that substitution is behaviour an operator
    # sees rather than an implementation detail. A denial report carries neither
    # — it names the policy id, and Rail Center resolves the rest.
    assert [policy.name for policy in bundle.chain] == case["chain_names"]

    # Priorities as well as order. A chain can come out in the right order with
    # the wrong values in it — a whole float left unnarrowed, say — and only
    # comparing the values catches that.
    assert [policy.priority for policy in bundle.chain] == case["chain_priorities"]
    assert all(type(p.priority) is int for p in bundle.chain)

    # The two the walk decides on. They travel unread through this module, and
    # a reader that dropped them would leave a chain that still looks right —
    # right ids, right order, right names — while every verdict came out the
    # same, because the contract's rule is that any action but `alert` denies.
    assert [policy.condition for policy in bundle.chain] == case["chain_conditions"]
    assert [policy.action for policy in bundle.chain] == case["chain_actions"]

    assert {
        key: {"mode": binding.mode, "policy_ids": sorted(binding.policy_ids)}
        for key, binding in bundle.bindings.items()
    } == case["bindings"]

    # Carried exactly. A reader re-fetches on a timer and re-parses only when
    # this changes, so a content hash normalised on the way through would
    # either re-parse forever or never.
    assert bundle.content_hash == case["bundle"]["content_hash"]
    assert bundle.schema_version == case["bundle"]["schema_version"]


def test_an_unusable_bundle_names_what_was_wrong() -> None:
    """Every refusal carries a reason, and no reason carries a raw wire value.

    The names in a refusal come off the wire and reach an operator's log, so a
    control plane that has been tampered with could otherwise forge a log line
    through one. This asserts the property over every unusable case at once
    rather than pinning any single message, which is an operator's text and not
    a contract.
    """
    for case in BUNDLE_CASES:
        if case["usable"]:
            continue
        try:
            validate_bundle(case["bundle"])
        except UnusableBundle as refusal:
            assert refusal.reason, case["name"]
            # Asked of the same predicate the code guards with, rather than of a
            # list of characters written out here. A hand-written list is a
            # second rule to keep in step with the first, and the one this
            # started as missed the escape sequence and the null byte.
            assert not has_unsafe_key_characters(refusal.reason), case["name"]
            # What a traceback prints, which is not the same string a caller
            # reads. Its safety follows from the line above, so what is asserted
            # here is that it carries the reason at all.
            assert str(refusal) == f"unusable policy bundle: {refusal.reason}"
            # Bounded as well as clean. A wire value that is not a string is
            # reported by its kind, so no refusal grows with what it is
            # refusing — a bundle naming a thousand-element endpoint_key would
            # otherwise put all of it in the log.
            # Tight enough to catch an unbounded number, and written as the
            # arithmetic rather than as a round number so that it tracks the
            # code: `safe_for_log` cuts at 255 and adds a 12-character mark,
            # `_q` puts two backticks round the result, and the longest message
            # taking two of those has an 86-character frame. The longest frame
            # in the file is 141 and takes one value, which is smaller.
            assert len(refusal.reason) <= 2 * (255 + 12 + 2) + 86, case["name"]
        else:  # pragma: no cover - the parametrised test above catches this first
            raise AssertionError(f"not refused: {case['name']}")


def test_a_validated_bundle_cannot_be_edited_in_place() -> None:
    """The three results are frozen, and that is load-bearing.

    A bundle is fetched once and evaluated against for every request until the
    next refresh replaces it. A caller that could reorder the chain or retarget
    a binding would change what every subsequent request is judged against,
    from inside the request that did it. What it does not close is reaching
    *into* a condition or an action, which are the wire's own objects — see the
    comment below.
    """
    bundle = validate_bundle(
        {
            "schema_version": "1.0",
            "content_hash": "v1",
            "policies": [{"id": "5c8f1e42-0000-4000-8000-0000000000a1", "priority": 1}],
            "bindings": [
                {"endpoint_key": "e", "mode": "open", "policy_ids": []},
            ],
        }
    )

    for target, field, value in (
        (bundle, "content_hash", "v2"),
        (bundle.chain[0], "action", "block"),
        (bundle.chain[0], "priority", 0),
        (bundle.bindings["e"], "mode", "gated"),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(target, field, value)

    # The chain is a tuple and a binding's ids a frozenset, so neither can be
    # appended to, and the bindings are a read-only view rather than a dict.
    # What freezing does not reach is the wire's own objects: a `condition` or
    # an `action` is carried by reference, and a caller that reaches into one
    # edits the rule. That is deliberate and stated on `Policy` — copying an
    # arbitrary JSON value on every fetch is a real cost against a threat that
    # is a caller misusing its own held bundle.
    assert isinstance(bundle.chain, tuple)
    assert isinstance(bundle.bindings["e"].policy_ids, frozenset)
    with pytest.raises(TypeError):
        bundle.bindings["e"] = Binding(mode="gated", policy_ids=frozenset({"x"}))
    with pytest.raises(AttributeError):
        bundle.bindings.clear()


def test_a_refusal_names_the_value_it_refused() -> None:
    """The other half of what `_q` does.

    Every escaping assertion above still passes if `_q` returns nothing at all
    and every message reads `(None)` — which is a safe message and a useless
    one. A refusal an operator cannot act on is the outcome this whole module's
    care about log lines exists to avoid, so every place a wire value is
    interpolated is checked to actually carry it.
    """
    one = "5c8f1e42-0000-4000-8000-0000000000a1"

    def body(**over: Any) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "content_hash": "v",
            "policies": [],
            "bindings": [],
            **over,
        }

    def binding(**over: Any) -> dict[str, Any]:
        return {"endpoint_key": "e", "mode": "gated", "policy_ids": [one], **over}

    refusals = [
        (body(content_hash="a\nb"), "unprintable"),
        # And a refused content hash an operator can actually read, so the only
        # case is not the one that renders as a placeholder.
        (body(content_hash="v" * 256), "v" * 255),
        # The same two rules on the schema version, which is held and re-echoed
        # for exactly as long as the hash beside it is.
        (body(schema_version="a\nb"), "unprintable"),
        (body(schema_version="v" * 256), "v" * 255),
        # And the two refusals the version check itself raises. For the first,
        # the message is all an operator has to tell a third part from a suffix
        # from a pair of digits that are digits everywhere but in ASCII, since
        # all three arrive as one refusal.
        (body(schema_version="1.0.0"), "1.0.0"),
        (body(schema_version="1.0-rc1"), "1.0-rc1"),
        (body(schema_version="\u0661.\u0660"), "\u0661.\u0660"),
        # The second raise, where the version parses and the major is one this
        # reader has no rules for.
        (body(schema_version="2.0"), "2.0"),
        (body(policies=["not a policy"]), "not a policy"),
        # The binding half of the same message, which round 8's docstring
        # described away as naming nothing rather than noticing it was silent.
        (body(bindings=["not a binding"]), "not a binding"),
        (body(policies=[{"id": "not-a-uuid"}]), "not-a-uuid"),
        # Twice: the unreadable priority, and the policy it belongs to. The
        # second is what tells an operator which rule to go and fix.
        (body(policies=[{"id": one, "priority": "not-a-number"}]), "not-a-number"),
        (body(policies=[{"id": one, "priority": "not-a-number"}]), one),
        # And the kind, which is what separates a priority of "1" from one of 1
        # — both render as `1` once quoted.
        (body(policies=[{"id": one, "priority": "1"}]), "str `1`"),
        (body(policies=[{"id": one, "priority": [1]}]), "list `<array>`"),
        (body(policies=[{"id": one, "priority": 1}, {"id": one, "priority": 2}]), one),
        (body(bindings=[binding(endpoint_key=17)]), "17"),
        (body(bindings=[binding(endpoint_key="k1"), binding(endpoint_key="k1")]), "k1"),
        (body(bindings=[binding(endpoint_key="k2", mode="closed")]), "k2"),
        (body(bindings=[binding(endpoint_key="k3", mode="closed")]), "closed"),
        (body(bindings=[binding(endpoint_key="k4", policy_ids="abc")]), "k4"),
        (body(bindings=[binding(endpoint_key="k5", mode="open")]), "k5"),
        (body(bindings=[binding(endpoint_key="k6", policy_ids=[])]), "k6"),
        (body(bindings=[binding(endpoint_key="k7", policy_ids=["nope"])]), "k7"),
        (body(bindings=[binding(endpoint_key="k8", policy_ids=["nope"])]), "nope"),
    ]
    for payload, expected in refusals:
        with pytest.raises(UnusableBundle) as caught:
            validate_bundle(payload)
        assert expected in caught.value.reason, (expected, caught.value.reason)


def test_an_unreadable_shape_is_refused_before_anything_beneath_it() -> None:
    """Which of two refusals an operator is sent to act on.

    `schema_version` is read and acted on before anything else because it
    describes the shape of everything under it, so every refusal after it is a
    claim about a `1.x` document — the only kind this reader can make a claim
    about. A bundle declaring a major it does not know *and* carrying a second
    fault is therefore refused for its shape: naming the field below would send
    an operator to fix a document whose shape is the actual fault, against a
    rule this reader has just said it cannot apply.

    The vectors cannot hold this. An unusable case asserts the refusal and not
    its reason, the message being an operator's text rather than a contract, so
    all three bodies below are unusable there whichever refusal answers. What is
    pinned here is the narrowest thing that tells the two apart — the supported
    major the message offers — and not its wording.
    """
    for beneath in ({"policies": "nope"}, {"bindings": "nope"}, {"content_hash": ""}):
        body = {
            "schema_version": "2.0",
            "content_hash": "h",
            "policies": [],
            "bindings": [],
            **beneath,
        }
        with pytest.raises(UnusableBundle) as caught:
            validate_bundle(body)
        assert f"{SUPPORTED_SCHEMA_MAJOR}.x" in caught.value.reason, (
            beneath,
            caught.value.reason,
        )


def test_a_version_too_long_to_convert_is_refused_rather_than_converted() -> None:
    """The order of the two guards `schema_version` passes through.

    The major is compared as an integer, and CPython refuses `int()` on a
    decimal string past 4,300 digits. What keeps that unreachable is the
    recordability guard above the grammar: `schema_version` is bounded at
    `MAX_ENDPOINT_KEY_LENGTH` before either the grammar or the conversion sees
    it, so the conversion only ever runs on a string far shorter than the limit.
    The two guards sit a few lines apart in one function and neither names the
    other, which is what this case is here to say instead.

    The refusal path is what the order protects. `_refresh_once` catches
    `UnusableBundle`, keeps the bundle already held and logs a line naming the
    fault; a `ValueError` out of `validate_bundle` is caught by neither, so it
    reaches `_loop` as a traceback and anything awaiting `refresh()` as itself
    — telling an operator that a control plane it disagrees with is a gateway
    that crashed.

    Only the exception is pinned. Which of the two refusals answers is the
    guards' own business, and both name a `schema_version` an operator can go
    and look at.
    """
    body = {
        "schema_version": "9" * 5000 + ".0",
        "content_hash": "a3f1c09e7b2d4485",
        "policies": [],
        "bindings": [],
    }
    with pytest.raises(UnusableBundle):
        validate_bundle(body)


def _postured(
    enforcement: Any = _ABSENT, binding_fallback: Any = _ABSENT
) -> dict[str, Any]:
    """A minimal usable bundle, carrying the given posture and fallback or none.

    **They are two root fields and not one object**, which is the shape this
    helper exists to keep honest: the posture says how much of a verdict is
    acted on, the fallback says what the verdict is where no binding matched.

    `_ABSENT` rather than `None`, because a bundle carrying `"enforcement":
    null` and one carrying no such key are the same claim here and a default
    argument cannot tell them apart.
    """
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "content_hash": "v-posture",
        "policies": [],
        "bindings": [],
    }
    if enforcement is not _ABSENT:
        body["enforcement"] = enforcement
    if binding_fallback is not _ABSENT:
        body["binding_fallback"] = binding_fallback
    return body


def test_a_bundle_naming_no_enforcement_judges_nothing_and_blocks_the_unbound() -> None:
    """The reading of a bundle from a Rail Center older than RC-312.

    Both halves are a decision rather than an absence, and the dangerous
    direction is the first: an untold posture of `enforce` would have every
    pre-RC-312 bundle start refusing traffic on a posture no operator set.
    """
    resolved = validate_bundle(_postured())

    assert resolved.enforcement == "none"
    assert resolved.fallback == "block"


def test_a_bundle_naming_a_mode_and_no_fallback_blocks_the_unbound() -> None:
    """The fallback defaults on its own, under a posture that consults it.

    `block` is the conservative half of a pair whose other half admits every
    endpoint no binding matches, so a default of `pass` would quietly widen
    what an `enforce` bundle allows.
    """
    resolved = validate_bundle(_postured({"mode": "enforce"}))

    assert resolved.enforcement == "enforce"
    assert resolved.fallback == "block"


def test_a_fallback_inside_enforcement_is_warned_about_and_decides_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A fallback stated where nothing reads it is reported, not obeyed.

    The direction is what makes silence unacceptable: the responder said `pass`
    and the reader holds `block`, so at `enforce` every call no binding matches
    is refused with a 403 while the control plane's own document says it should
    be forwarded. The warning is the only place those two claims are put beside
    each other.
    """
    body = _postured({"mode": "enforce", "fallback": "pass"})

    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        resolved = validate_bundle(body)

    assert resolved.fallback == "block"
    said = "\n".join(record.getMessage() for record in caplog.records)
    assert "`pass`" in said
    assert "`block`" in said
    assert "binding_fallback" in said


@pytest.mark.parametrize(
    "enforcement, binding_fallback",
    [
        ({"mode": "enforce"}, "pass"),
        ({"mode": "enforce"}, _ABSENT),
        ({"mode": "observe"}, "block"),
        (_ABSENT, "pass"),
    ],
    ids=["enforce-and-pass", "enforce-alone", "observe-and-block", "fallback-alone"],
)
def test_a_correctly_shaped_bundle_says_nothing_about_its_fallback(
    caplog: pytest.LogCaptureFixture, enforcement: Any, binding_fallback: Any
) -> None:
    """The report of a misplaced fallback is confined to a misplaced fallback.

    A warning that also fires on every bundle an operator has got right is one
    they learn to skip, which costs the case it exists to make visible its only
    audience. Silence on the correct shape is half of what that warning is,
    rather than an absence of behaviour.
    """
    body = _postured(enforcement, binding_fallback)

    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        validate_bundle(body)

    assert caplog.records == []


@pytest.mark.parametrize(
    "refused, named",
    [
        (
            {"policies": [{"id": "not-a-uuid", "enabled": True, "priority": 1}]},
            "not-a-uuid",
        ),
        (
            {
                "bindings": [
                    {"endpoint_key": "delivery.x", "mode": "gated", "policy_ids": []}
                ]
            },
            "delivery.x",
        ),
    ],
    ids=["a-policy-id-that-cannot-be-compared", "a-gated-binding-naming-no-policy"],
)
def test_a_refused_bundle_says_nothing_about_which_fallback_applies(
    caplog: pytest.LogCaptureFixture, refused: dict[str, Any], named: str
) -> None:
    """Nothing in a refused bundle applies, so nothing in it is reported.

    The audience is an operator mid-reshape, whose responder has moved the root
    and not the fallback. A line naming the fallback that "applies" off a bundle
    this reader then throws away names neither this bundle's — it applies none —
    nor the held one still deciding traffic, and it repeats every poll for as
    long as the drift lasts, since a refused bundle never reaches the
    content-hash short-circuit that quiets the accepted case after one line.

    Both the chain and the bindings, because either one left below the warning
    reopens the case for every bundle the other accepts, and the two refusals
    are reached from different fields of the same body.
    """
    body = _postured({"mode": "enforce", "fallback": "pass"}) | refused

    with (
        caplog.at_level(logging.WARNING, logger="gateway.bundle"),
        pytest.raises(UnusableBundle) as caught,
    ):
        validate_bundle(body)

    assert named in caught.value.reason
    assert caplog.records == []


#: Every `mode` a bundle can carry, paired with how a refusal must name it, or
#: `None` where the value is in the vocabulary and is accepted. `_ABSENT` is the
#: object with no `mode` key, which reads as a null one.
#:
#: The rendering is `validate.py`'s: a value off the wire is quoted and made
#: safe before it reaches a log line. Pairing each candidate with it pins that a
#: refusal names *what* was wrong and not merely that something was.
_MODES: list[tuple[Any, str | None]] = [
    (_ABSENT, "`<null>`"),
    (None, "`<null>`"),
    ("none", None),
    ("observe", None),
    ("enforce", None),
    ("halt", "`halt`"),
    ("", "``"),
    # Not folded. `RAIL_PLUGIN_ENABLED` is folded because a proxy reading the same
    # variable folds it; a bundle is a document from one producer, and a
    # producer shouting the value disagrees about the vocabulary like any other.
    ("NONE", "`NONE`"),
    (17, "`17`"),
    (True, "`true`"),
    ([], "`<array>`"),
    ({}, "`<object>`"),
]

#: The same for `fallback`, where `None` covers two accepted classes rather than
#: one: in the vocabulary, or absent and therefore defaulted.
_FALLBACKS: list[tuple[Any, str | None]] = [
    (_ABSENT, None),
    (None, None),
    ("pass", None),
    ("block", None),
    ("allow", "`allow`"),
    ("", "``"),
    ("PASS", "`PASS`"),
    (17, "`17`"),
    (True, "`true`"),
    ([], "`<array>`"),
]


def test_the_posture_tables_hold_every_value_the_contract_names() -> None:
    """The product below is a branch space only while these cover the vocabulary.

    A value dropped from either table narrows the product silently, and a value
    added to `ENFORCEMENTS` or `FALLBACKS` without a row here would never be
    driven at all.
    """
    assert {mode for mode, named in _MODES if named is None} == set(ENFORCEMENTS)
    accepted = {
        fallback
        for fallback, named in _FALLBACKS
        if named is None and fallback is not _ABSENT and fallback is not None
    }
    assert accepted == set(FALLBACKS)


def test_the_published_posture_enums_are_the_vocabulary_this_reader_holds() -> None:
    """`schemas/policy-bundle.schema.json`'s enums, against `mode.py`'s tuples.

    The posture vocabulary is written twice on this branch — as those enums and
    as `ENFORCEMENTS`/`FALLBACKS`, which is what the hand-rolled `_posture`
    reads — and neither copy is generated from the other. The test above pins
    the product tables against the module constants, so the code half cannot
    narrow without failing; this one pins the published half against the same
    constants, in both directions, because nothing else did.

    **Narrowing the schema was the loose direction.** `tests/test_schemas.py`
    asserts what these enums must *reject*, so a value added to either fails
    there while a value removed passes. `mode: "none"` is what that costs. The
    contract makes it the kill switch — "A component that stops polling at
    `none` cannot be told it has been moved off `none`, so the kill switch only
    turns one way, which is the whole of what the value is for" — so a
    reimplementer building against a schema that had lost it would have no valid
    way to spell the one posture an operator reaches for during an incident,
    while `validate_bundle` went on accepting what that schema called invalid.

    Compared as sets: order carries no meaning in a JSON Schema enum, and a
    duplicate is already refused by `test_the_schema_is_valid_json_schema`.
    """
    published = json.loads(
        (SCHEMAS / "policy-bundle.schema.json").read_text(encoding="utf-8")
    )
    enforcement = published["properties"]["enforcement"]["properties"]
    assert set(enforcement["mode"]["enum"]) == set(ENFORCEMENTS)
    assert set(published["properties"]["binding_fallback"]["enum"]) == set(FALLBACKS)


def test_the_published_version_grammar_is_the_language_this_reader_parses() -> None:
    """`schemas/policy-bundle.schema.json`'s `pattern`, against `_SCHEMA_VERSION`.

    The version grammar is written twice — as the pattern a reimplementation
    builds against and as the regex this reader matches with — and neither copy
    is generated from the other. What holds them to one language is that every
    candidate below is driven through *both* and the two verdicts compared,
    rather than each being checked against a list of expected answers. A list
    beside each copy is a third copy of the rule: it agrees with both on the day
    it is written and says nothing on the day one of them moves.

    **Well-formed is a different claim from read**, and the vectors own the
    second: `2.0` and `0.9` are well-formed and refused. A published pattern
    that hard-coded the supported major would be a wire contract that expired
    the first time a reader moved on, so nothing here asserts one.

    The candidates are the versions the vectors already carry, so a case added
    there is asserted here too, plus the shapes no vector carries.

    **What they are compared over is every candidate that reaches the grammar.**
    A `schema_version` carrying a character no log line can hold is refused
    before it, and that class is one the published schema states in prose
    because `pattern` cannot express it. `1.0\\n` is where the two look like they
    differ and do not: `jsonschema` compiles patterns with `re`, where `$` also
    matches before a trailing newline, so the published grammar admits a string
    this reader refuses a step earlier. Spelling that anchor past `re` is what
    costs more than it closes — `\\Z`, `\\z` and a `(?![\\s\\S])` lookahead are
    each unavailable to one of `re`, ECMA-262 and RE2, and RE2 is the engine a
    Go reimplementation validates with, where an unsupported lookahead fails
    the whole document rather than one field.
    """
    published = json.loads(
        (SCHEMAS / "policy-bundle.schema.json").read_text(encoding="utf-8")
    )
    grammar = re.compile(published["properties"]["schema_version"]["pattern"])

    candidates = {
        case["bundle"]["schema_version"]
        for case in BUNDLE_CASES
        if isinstance(case["bundle"], dict)
        and isinstance(case["bundle"].get("schema_version"), str)
    } | {
        # Shapes no vector carries, each standing for a way one copy of the
        # grammar can narrow or widen without the other: a major longer than
        # any vector's, a minor likewise, four ways a run of digits can be
        # bounded by something other than the end of the string, and either
        # part alone made of something that is not a digit. The two runs carry
        # a character class each, so one widens without the other; the case
        # where both do is `x.y`, which the vectors carry because the reader
        # refusing it is what leaves `int` only digits to convert.
        "0001.0",
        "123456789.0",
        "1.000000000",
        "x.0",
        "1.y",
        "1.0\n",
        "\n1.0",
        "1.0 ",
        " 1.0",
        "1.0\n2.0",
        "",
    }

    compared = [c for c in sorted(candidates) if not has_unsafe_key_characters(c)]
    for candidate in compared:
        # `search`, not `match`: a JSON Schema `pattern` is unanchored and
        # `jsonschema` applies it as a search, so where the published grammar
        # ends is the pattern's own business and not this test's.
        published_reads = bool(grammar.search(candidate))
        assert published_reads == bool(_SCHEMA_VERSION.match(candidate)), candidate

    # The excluded case, asserted rather than described: `1.0\n` is refused for
    # the character it carries and never reaches either grammar.
    assert has_unsafe_key_characters("1.0\n")

    # Agreement over a corpus that had stopped exercising both answers would be
    # agreement about nothing, which is the same hazard the case-count floors
    # above exist for.
    assert any(grammar.search(candidate) for candidate in compared)
    assert any(not grammar.search(candidate) for candidate in compared)


def test_every_enforcement_object_resolves_or_is_refused() -> None:
    """The posture guard driven over its branch space rather than over samples.

    Present-but-wrong is refused where absent is read as `none`/`block`, and the
    two are not the same claim: an absent field is a control plane that has said
    nothing, while a value outside the vocabulary is one that disagrees with the
    contract about what these words are, and guessing which of two opposite
    readings it meant is the choice the contract refuses to make.

    `schemas/policy-bundle.schema.json` asserts the same vocabulary, but nothing
    under `gateway/` applies that schema at runtime — `validate_bundle` is
    hand-rolled — so those assertions pin the published document rather than this
    reader.

    **Driven as a product because an enumeration of examples kept moving.** Two
    rounds of review each closed on a list of cases and the next found cells
    beside them: a malformed fallback at `none`, a list where a string had been
    pinned, an object carrying no `mode`. A branch added to `_posture` now has to
    be given a rule here, or some cell disagrees with it.

    `{"enforcement": {}}` is the cell carrying the danger. The schema marks
    `mode` required and this reader refuses present-but-wrong, so a producer that
    emits the object and omits the mode is refused rather than read as
    `none`/`block` — which would be a gateway judging nothing, reached by the one
    path the refusal exists to close.
    """
    for mode, mode_named in _MODES:
        for fallback, fallback_named in _FALLBACKS:
            enforcement: dict[str, Any] = {}
            if mode is not _ABSENT:
                enforcement["mode"] = mode
            cell = f"mode={mode!r}, binding_fallback={fallback!r}"

            # The mode is read first, so a bundle wrong in both is refused for
            # the mode. Naming one fault per refusal is the contract's shape.
            expected = (
                ("an enforcement mode outside the contract", mode_named)
                if mode_named is not None
                else ("a fallback outside the contract", fallback_named)
                if fallback_named is not None
                else None
            )
            if expected is not None:
                prefix, named = expected
                with pytest.raises(UnusableBundle) as refused:
                    validate_bundle(_postured(enforcement, fallback))
                reason = refused.value.reason
                assert reason.startswith(prefix), (cell, reason)
                assert named in reason, (cell, reason)
                continue

            resolved = validate_bundle(_postured(enforcement, fallback))
            # Literals, not `UNTOLD_ENFORCEMENT`/`DEFAULT_FALLBACK`: expectations
            # read off the constants would move with a mutation of them.
            assert resolved.enforcement == mode, cell
            defaulted = fallback is _ABSENT or fallback is None
            assert resolved.fallback == ("block" if defaulted else fallback), cell
            # However little of it was stated, it was stated. Only a bundle
            # carrying no `enforcement` at all is untold.
            assert resolved.posture_told is True, cell


def test_an_enforcement_that_is_not_an_object_is_refused() -> None:
    """Every shape that is neither a mapping nor absent.

    A list is what widened this past the string a previous round pinned:
    `["enforce"]` is what a producer emits having read the field as a set of
    postures, and reading it as untold would leave a gateway judging nothing.
    """
    for value in ["enforce", "", ["enforce"], [], 17, 0, 1.5, True, False]:
        with pytest.raises(UnusableBundle) as refused:
            validate_bundle(_postured(value))

        assert refused.value.reason == "`enforcement` is not an object", value


def test_a_bundle_that_said_nothing_is_not_a_bundle_that_said_none() -> None:
    """The one distinction the resolved posture cannot carry.

    Both resolve to `none`/`block`, deliberately, so `posture_told` is the only
    thing that separates a Rail Center older than RC-312 from one that chose to
    judge nothing — and the contract refuses to name a safe universal reading of
    the first, which makes reporting it as the second a claim about a control
    plane that said nothing at all.

    An explicit `null` sits with absence rather than with a stated posture: it
    is the same claim, and a producer that serialises unset fields writes it.
    """
    for untold in (_postured(), _postured(None)):
        resolved = validate_bundle(untold)
        assert (resolved.enforcement, resolved.fallback) == ("none", "block")
        assert resolved.posture_told is False

    stated = validate_bundle(_postured({"mode": "none"}))
    assert (stated.enforcement, stated.fallback) == ("none", "block")
    assert stated.posture_told is True


def test_the_bundle_file_is_worth_running() -> None:
    """The same guard the ticket vectors carry, for the same reason."""
    assert len(BUNDLE_CASES) >= 70
    assert len({case["name"] for case in BUNDLE_CASES}) == len(BUNDLE_CASES)
    # Both halves are load-bearing. A file of only refusals would pass while
    # `validate_bundle` refused everything, and a file of only acceptances
    # would pass while it accepted everything.
    assert sum(1 for c in BUNDLE_CASES if c["usable"]) >= 20
    assert sum(1 for c in BUNDLE_CASES if not c["usable"]) >= 45


DECIDE_CASES = _load("decide.json")

#: The policy a *condition* case is walked behind: one enabled `block` rule at
#: priority 1, so the decision reads straight back as whether the condition
#: held. Walking it rather than calling `holds` is what makes these vectors
#: rather than unit tests of a private function — a reimplementation answerable
#: to this file need not have a function of that name at all.
CONDITION_POLICY_ID = "5c8f1e42-0000-4000-8000-0000000c04de"

CONDITION_BUNDLE_VERSION = "v-decide-condition"


def _encoded(claims: dict[str, Any]) -> str:
    """`claims` as the mint emits them: base64url(JSON), unpadded."""
    raw = json.dumps(claims, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decide_request(case: dict[str, Any]) -> ConditionInput:
    """The request a case describes.

    `header` is passed through unchanged and `claims` is encoded here, which is
    the split the contract draws: a case that lets the harness encode its own
    payload cannot detect a disagreement about decoding, so anything about the
    header's own bytes has to be a literal.
    """
    header = case["header"] if "header" in case else _encoded(case["claims"])
    return ConditionInput(
        ticket=parse_rail_header(header, case["now"]),
        endpoint_key=case["endpoint_key"],
    )


def _decide_bundle(case: dict[str, Any]) -> dict[str, Any]:
    if "bundle" in case:
        return case["bundle"]
    return {
        "schema_version": "1.0",
        "content_hash": CONDITION_BUNDLE_VERSION,
        "policies": [
            {
                "id": CONDITION_POLICY_ID,
                "name": "the condition under test",
                "priority": 1,
                "condition": case["condition"],
                "action": "block",
                "enabled": True,
            }
        ],
        "bindings": [],
        "rejected": [],
    }


@pytest.mark.parametrize(
    "case", DECIDE_CASES, ids=[case["name"] for case in DECIDE_CASES]
)
def test_decide_vector(case: dict[str, Any]) -> None:
    bundle = validate_bundle(_decide_bundle(case))
    request = _decide_request(case)

    # Where a case says what the header must classify as, that is checked before
    # the decision. A case whose ticket read differently from what it describes
    # would still reach the right verdict for the wrong reason.
    if "ticket_state" in case:
        assert request.ticket.state == case["ticket_state"]

    if "refusal" in case:
        # **The kind is asserted, not merely that something was raised.** A
        # runner asking only "did it throw?" scores a crash as conformant, and a
        # crash is the one outcome the contract rules out everywhere: an
        # exception where a decision belongs is neither an allow nor a deny.
        assert case["refusal"] == "uninterpretable_condition"
        with pytest.raises(UninterpretableCondition):
            decide(bundle, request)
        return

    verdict = decide(bundle, request)
    denied_by = verdict.denied_by.id if verdict.denied_by else None

    if "holds" in case:
        assert verdict.allowed is not case["holds"]
        assert denied_by == (CONDITION_POLICY_ID if case["holds"] else None)
        # The one policy in the chain blocks, so a condition case that produced
        # an alert would be a decision reached some other way than the one the
        # case describes.
        assert verdict.alerts == ()
        return

    expect = case["expect"]
    assert verdict.allowed == expect["allowed"]
    assert denied_by == expect["denied_by"]
    # Compared as an ordered list. Alerts accumulate in evaluation order —
    # priority ascending, ties by canonical id — not in the order the bundle
    # listed them, and a set assertion cannot see the difference.
    assert [policy.id for policy in verdict.alerts] == expect["alerts"]


def test_the_decide_file_is_worth_running() -> None:
    """The same guard the other two vector files carry, and one more.

    Every group here can pass by being empty, and the ways that happens are not
    symmetrical: a file of only refusals passes while the walk refuses
    everything, a file of only allows passes while nothing is ever denied, and
    a file with no `holds: true` case passes while every condition answers
    false — which is precisely the shape the contract's most emphasised rule
    forbids.
    """
    assert len(DECIDE_CASES) >= 140
    # The contract models `endpoint_key` as an argument that is always present,
    # so it takes no position on a call naming none. This gateway's answer to
    # that is `tests/test_decide.py`, and a case for it here would be this
    # implementation writing its own contract.
    assert all(case["endpoint_key"] is not None for case in DECIDE_CASES)
    assert len({case["name"] for case in DECIDE_CASES}) == len(DECIDE_CASES)

    refusals = [case for case in DECIDE_CASES if "refusal" in case]
    conditions = [case for case in DECIDE_CASES if "holds" in case]
    walks = [case for case in DECIDE_CASES if "expect" in case]
    assert len(refusals) >= 25
    assert sum(1 for case in conditions if case["holds"]) >= 25
    assert sum(1 for case in conditions if not case["holds"]) >= 25
    assert sum(1 for case in walks if case["expect"]["allowed"]) >= 5
    assert sum(1 for case in walks if not case["expect"]["allowed"]) >= 10
    assert sum(1 for case in walks if case["expect"]["alerts"]) >= 3

    # Every case is one of the three shapes, so a case carrying neither `holds`,
    # `expect` nor `refusal` cannot sit in the file being counted and never
    # asserted on.
    assert len(refusals) + len(conditions) + len(walks) == len(DECIDE_CASES)
    for case in DECIDE_CASES:
        assert ("bundle" in case) ^ ("condition" in case), case["name"]
        assert ("header" in case) ^ ("claims" in case), case["name"]


FALLBACK_CASES = _load("fallback.json")

#: The one policy a `gated` binding in these cases names. What it says is
#: irrelevant — the fallback looks for a binding *entry*, and which policies the
#: entry names is the chain's business — but a binding naming an id no policy
#: carries would be a bundle about nothing.
FALLBACK_POLICY_ID = "5c8f1e42-0000-4000-8000-0000000000d1"


#: The chain a case gets when it names none: one `alert` rule, which cannot deny
#: and so cannot reach a verdict a fallback case was not asking about.
INERT_CHAIN = [
    {
        "id": FALLBACK_POLICY_ID,
        "name": "something for a binding to name",
        "priority": 1,
        "condition": {"field": "agent_id", "operator": "present"},
        "action": "alert",
        "enabled": True,
    }
]


def _fallback_bundle(case: dict[str, Any]):
    return validate_bundle(
        {
            "schema_version": "1.0",
            # The content hash moves with the posture and the fallback because
            # Rail Center hashes both into it, and a file whose cases shared one
            # hash across four postures would describe a control plane whose
            # kill switch cannot arrive.
            "content_hash": f"v-fallback-{case['enforcement']['mode']}"
            f"-{case['binding_fallback']}",
            "policies": case.get("policies", INERT_CHAIN),
            "bindings": case["bindings"],
            "enforcement": case["enforcement"],
            "binding_fallback": case["binding_fallback"],
        }
    )


@pytest.mark.parametrize(
    "case", FALLBACK_CASES, ids=[case["name"] for case in FALLBACK_CASES]
)
def test_fallback_vector(case: dict[str, Any]) -> None:
    """**The composition is asserted, not `refuses_unbound` alone.**

    `fallback` is read at `enforce` and at no other mode, and that half of the
    rule lives in the caller rather than in the predicate — so a case run
    against the predicate by itself would score a gateway that refuses at
    `observe` as conformant on precisely the mode an operator uses to be sure
    nothing is blocked. `blocks` and `refuses_unbound` are composed here the
    same way `_Enforcement` composes them, which is what the vector is about.
    """
    bundle = _fallback_bundle(case)

    refused = blocks(bundle.enforcement) and refuses_unbound(
        bundle, case["endpoint_key"], keyless=case["keyless"]
    )

    assert refused == case["refused"]

    # **A case carrying `expect` asserts what the walk concluded**, and that is
    # what stops `pass` being implemented as *unjudged*. Every `refused` in this
    # file is answered correctly by a reader that forwards an unbound endpoint
    # without walking it at all; only these cases can tell that reader apart
    # from one that hands the call to the chain.
    if "expect" not in case:
        return
    assert not refused, "a refused call reached no walk, so there is nothing to expect"
    verdict = decide(
        bundle,
        ConditionInput(
            ticket=parse_rail_header(_encoded(case["claims"]), case["now"]),
            endpoint_key=case["endpoint_key"],
        ),
        keyless=case["keyless"],
    )
    assert verdict.allowed == case["expect"]["allowed"]
    assert (verdict.denied_by.id if verdict.denied_by else None) == case["expect"][
        "denied_by"
    ]


def test_the_fallback_file_is_worth_running() -> None:
    """Every group can pass by being empty, and here the empty file is a real
    hazard: a file of only `refused: false` cases passes against a reader that
    has not implemented the fallback at all.
    """
    assert len(FALLBACK_CASES) >= 12
    assert len({case["name"] for case in FALLBACK_CASES}) == len(FALLBACK_CASES)
    assert sum(1 for case in FALLBACK_CASES if case["refused"]) >= 3
    assert sum(1 for case in FALLBACK_CASES if not case["refused"]) >= 6

    modes = {case["enforcement"]["mode"] for case in FALLBACK_CASES}
    fallbacks = {case["binding_fallback"] for case in FALLBACK_CASES}
    # Both halves of the composition are exercised over both of their values. A
    # file covering only `enforce` would say nothing about the rule that makes
    # `observe` safe to switch on.
    assert modes == {"none", "observe", "enforce"}
    assert fallbacks == {"pass", "block"}

    # A case with a key and one without are different rules, and the second is
    # this gateway's own — the contract models `endpoint_key` as always present.
    assert any(case["endpoint_key"] is None for case in FALLBACK_CASES)
    assert any(case["endpoint_key"] is not None for case in FALLBACK_CASES)
    assert {case["keyless"] for case in FALLBACK_CASES} == {True, False}

    # **`pass` with a chain that matches and one that does not**, which is the
    # pair PTH.G1 names. Without both, a reader that forwards an unbound
    # endpoint unjudged passes this file: the matching case is what denies it,
    # and the non-matching one is what stops the fix being `block` in disguise.
    walked = [case for case in FALLBACK_CASES if "expect" in case]
    assert sum(1 for case in walked if case["expect"]["allowed"]) >= 1
    assert sum(1 for case in walked if not case["expect"]["allowed"]) >= 1
    assert all(
        case["binding_fallback"] == "pass" and not case["refused"] for case in walked
    )
