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
from pathlib import Path
from typing import Any

import pytest

from gateway.bundle.conditions import ConditionInput, UninterpretableCondition
from gateway.bundle.decide import decide, refuses_unbound
from gateway.bundle.validate import Binding, UnusableBundle, validate_bundle
from gateway.key_safety import has_unsafe_key_characters
from gateway.mode import ENFORCEMENTS, FALLBACKS, blocks
from gateway.ticket import parse_rail_header

VECTORS = Path(__file__).parent / "vectors"

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

    assert len(bundle.rejected) == case["rejected_count"]

    # Carried exactly. A reader re-fetches on a timer and re-parses only when
    # this changes, so a version normalised on the way through would either
    # re-parse forever or never.
    assert bundle.version == case["bundle"]["version"]


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
            "version": "v1",
            "policies": [{"id": "5c8f1e42-0000-4000-8000-0000000000a1", "priority": 1}],
            "bindings": [
                {"endpoint_key": "e", "mode": "open", "policy_ids": []},
            ],
            "rejected": [],
        }
    )

    for target, field, value in (
        (bundle, "version", "v2"),
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
    assert isinstance(bundle.rejected, tuple)
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
            "version": "v",
            "policies": [],
            "bindings": [],
            "rejected": [],
            **over,
        }

    def binding(**over: Any) -> dict[str, Any]:
        return {"endpoint_key": "e", "mode": "gated", "policy_ids": [one], **over}

    refusals = [
        (body(version="a\nb"), "unprintable"),
        # And a refused version an operator can actually read, so the only
        # case is not the one that renders as a placeholder.
        (body(version="v" * 256), "v" * 255),
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


def _postured(enforcement: Any = _ABSENT) -> dict[str, Any]:
    """A minimal usable bundle, carrying the given `enforcement` or none at all.

    `_ABSENT` rather than `None`, because a bundle carrying `"enforcement":
    null` and one carrying no such key are the same claim here and a default
    argument cannot tell them apart.
    """
    body: dict[str, Any] = {
        "version": "v-posture",
        "policies": [],
        "bindings": [],
        "rejected": [],
    }
    if enforcement is not _ABSENT:
        body["enforcement"] = enforcement
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
    # Not folded. `RAIL_TICKET_MODE` is folded because a proxy reading the same
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
            if fallback is not _ABSENT:
                enforcement["fallback"] = fallback
            cell = f"mode={mode!r}, fallback={fallback!r}"

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
                    validate_bundle(_postured(enforcement))
                reason = refused.value.reason
                assert reason.startswith(prefix), (cell, reason)
                assert named in reason, (cell, reason)
                continue

            resolved = validate_bundle(_postured(enforcement))
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
        "version": CONDITION_BUNDLE_VERSION,
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


def _fallback_bundle(case: dict[str, Any]):
    return validate_bundle(
        {
            # The version moves with the posture because Rail Center hashes
            # `enforcement` into it, and a file whose cases shared one version
            # across four postures would describe a control plane whose kill
            # switch cannot arrive.
            "version": f"v-fallback-{case['enforcement']['mode']}"
            f"-{case['enforcement']['fallback']}",
            "policies": [
                {
                    "id": FALLBACK_POLICY_ID,
                    "name": "something for a binding to name",
                    "priority": 1,
                    "condition": {"field": "agent_id", "operator": "present"},
                    "action": "alert",
                    "enabled": True,
                }
            ],
            "bindings": case["bindings"],
            "rejected": [],
            "enforcement": case["enforcement"],
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
    fallbacks = {case["enforcement"]["fallback"] for case in FALLBACK_CASES}
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
