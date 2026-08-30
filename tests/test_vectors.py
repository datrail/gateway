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
from gateway.bundle.decide import decide
from gateway.bundle.validate import Binding, UnusableBundle, validate_bundle
from gateway.key_safety import has_unsafe_key_characters
from gateway.ticket import parse_rail_header

VECTORS = Path(__file__).parent / "vectors"


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
