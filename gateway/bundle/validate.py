"""Turning a fetched bundle into one that can be walked, or refusing it whole.

Two kinds of refusal live in this component and they differ in *when*, which
rail-center's `docs/policy-evaluation-contract.md` calls the easiest thing in it
to get backwards:

* **A bundle that cannot be ordered, or whose bindings cannot be applied, is
  refused eagerly — here, before the walk**, whatever the walk would have
  answered. A bad ``priority`` at position 9 refuses the bundle even though a
  ``block`` at priority 1 would have denied first.
* **A condition that cannot be interpreted is refused lazily**, where the walk
  reaches it, so an earlier policy that already denied still gives that request
  a clean answer.

The ordering inside this file is specified too, and one step is load-bearing in
a way that reads like a detail: **``enabled`` is settled before anything is
validated.** The situation this whole module exists for — a bundle carrying
something this gateway cannot read — has one obvious remedy for whoever is
paged: switch the offending policy off. That remedy only works if disabling
happens before interpreting.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from gateway.bundle.uuid import canonical_uuid
from gateway.json_wire import MAX_SAFE_INTEGER
from gateway.key_safety import MAX_ENDPOINT_KEY_LENGTH, has_unsafe_key_characters
from gateway.key_safety import safe_for_log as _safe
from gateway.mode import (
    DEFAULT_FALLBACK,
    ENFORCEMENTS,
    FALLBACKS,
    UNTOLD_ENFORCEMENT,
    Enforcement,
    Fallback,
)

#: The holder's logger, shared so that everything an operator reads about one
#: bundle — the fetch, the refusal, the posture, and the warnings below —
#: arrives under one name.
logger = logging.getLogger("gateway.bundle")


def _q(value: object) -> str:
    """Bundle content, quoted and made safe to put in a refusal message.

    Most messages below name the thing that was wrong, and every name they use
    comes off the wire. The ones that name nothing are about a whole field
    being the wrong shape — `policies` is not a list, the response is not an
    object — where the field is the answer and there is nothing to quote. Names
    reach an operator's log, so an unescaped interpolation here is a forged log
    line from a control plane that has been tampered with.
    """
    return f"`{_safe(value)}`"


class UnusableBundle(Exception):
    """A bundle that cannot be evaluated at all.

    The caller answers 503 and reports no denial: no policy decided the
    request, and naming one in a denial report is the only thing that would
    make it so.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"unusable policy bundle: {reason}")
        self.reason = reason


@dataclass(frozen=True)
class Policy:
    """A policy that survived validation.

    ``id`` is canonical; the walk and the denial report both use this spelling.
    A report names the policy by its id and by nothing else — it carries the
    resolved endpoint key too, but no policy name — so the name below never
    leaves this process.
    ``condition`` and ``action`` are carried unread — a condition is interpreted
    where the walk reaches it, which is what lets an earlier policy answer a
    request the later one could not. They are also the wire's own objects rather
    than copies, so a caller that reaches into one edits the rule every later
    request is judged by. Freezing the dataclass does not reach them, and
    nothing here copies them: a deep copy of an arbitrary JSON value on every
    fetch is a real cost for a threat that is a caller misusing its own held
    bundle, not anything the wire can do.
    """

    id: str
    name: str
    priority: int
    condition: Any
    action: Any


@dataclass(frozen=True)
class Binding:
    """One endpoint's narrowing. ``policy_ids`` holds canonical ids."""

    mode: Literal["gated", "open"]
    policy_ids: frozenset[str]


@dataclass(frozen=True)
class UsableBundle:
    """A bundle that can be walked."""

    #: The bundle's shape, as the responder declares it. Read but not yet acted
    #: on: refusing an unsupported one is its own change, and a reader that
    #: refused before anything else in this component understood the new root
    #: would refuse the only bundles it can read.
    schema_version: str
    #: A sha256 over the fields that change behaviour, truncated. **A content
    #: hash and not a version**: two builds of the same inputs produce the same
    #: value, nothing stores it, and it orders nothing. It is what a poller
    #: compares to decide whether anything changed, and what `If-None-Match`
    #: will carry when a conditional fetch lands.
    content_hash: str
    #: Enabled policies, ordered: ``priority`` ascending, ties by canonical id.
    chain: tuple[Policy, ...]
    #: Resolved endpoint key to its narrowing. **A key with no entry here is
    #: subject to the whole chain** — the absence is not "no policies".
    #:
    #: A read-only view rather than a dict. Freezing the dataclass stops the
    #: field being replaced and does nothing about the mapping it points at, so
    #: without this a caller could retarget an endpoint or clear the lot —
    #: changing what every later request is judged against, from inside the one
    #: that did it.
    #:
    #: It costs `asdict`, `deepcopy` and `pickle`, none of which work on a
    #: mappingproxy. A caller wanting any of those wants a snapshot of what is
    #: held, and `dict(bundle.bindings)` is the line that gives it one.
    bindings: Mapping[str, Binding]
    #: What Rail Center says to do with a call (RC-312). Read from the bundle on
    #: every poll rather than from the environment at start-up, which is what
    #: lets an operator move a gateway's posture and have it take effect on the
    #: next refresh.
    #:
    #: A bundle naming no `enforcement` is one from a Rail Center older than
    #: RC-312, and is read as `none` — judge nothing. That is the safe reading
    #: here and not the timid one: the alternative is enforcing a posture the
    #: control plane never stated.
    enforcement: Enforcement
    #: What happens to a call no binding matches. **A property of the binding
    #: set, not of the posture**, which is why it sits beside `bindings` at the
    #: bundle root rather than inside `enforcement`: a posture says how much of a
    #: verdict is acted on, a fallback says what the verdict *is* for a call
    #: nothing matched.
    fallback: Fallback
    #: Whether the bundle *said* so. False only for a bundle naming no
    #: `enforcement` at all, which resolves to the same `none` a bundle naming
    #: `none` resolves to — so the posture alone cannot tell a control plane
    #: that chose to judge nothing from one that has said nothing. The fallback
    #: is no help either way: it is read from the root and resolves whatever the
    #: posture says, so the two fields say nothing about each other.
    #:
    #: Nothing decides traffic on this. It exists because the two states are
    #: not equal in consequence to the operator being told about them: silence
    #: means a Rail Center older than RC-312, and the contract refuses to name
    #: a safe universal reading of it, so a line reporting that silence as a
    #: decision attributes to Rail Center a posture it never stated.
    posture_told: bool


def _usable_priority(value: object) -> bool:
    """Whether `value` is a priority both implementations can order by.

    ``bool`` is excluded explicitly because ``isinstance(True, int)`` is true in
    Python and ``typeof true === "boolean"`` in TypeScript. Without saying so,
    the two sides would disagree about ``priority: true``.

    ``1.0`` passes: JSON has no integer type, so it is the integer 1 and a
    reader on doubles cannot tell them apart. ``1.5`` is not a priority.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    # No narrowing before the comparison: Python compares a float against an
    # int exactly, so 1.0 and 1 answer alike. `_order` narrows separately,
    # where the value is kept rather than tested.
    return abs(value) <= MAX_SAFE_INTEGER


def _is_enabled(policy: dict[str, Any]) -> bool:
    """Whether a policy is in force.

    Skipped when ``enabled`` is **exactly** ``False``, never merely falsy — the
    falsy sets do not agree across languages, and ``[]`` is falsy in Python and
    truthy in JavaScript. A policy carrying no ``enabled`` key is enabled: a
    rule nobody switched off is one an operator expects to be running.
    """
    return policy.get("enabled") is not False


def _order(policies: list[Any]) -> tuple[Policy, ...]:
    """The enabled policies, ordered, with every id canonical.

    Raises `UnusableBundle` when the chain cannot be ordered. That refusal
    propagates: there is no partial chain to walk, and skipping the offending
    policy would enforce part of a ruleset with no way to tell.
    """
    seen: set[str] = set()
    chain: list[Policy] = []

    for entry in policies:
        if not isinstance(entry, dict):
            raise UnusableBundle(f"a policy that is not an object ({_q(entry)})")
        if not _is_enabled(entry):
            continue

        policy_id = canonical_uuid(entry.get("id"))
        if policy_id is None:
            raise UnusableBundle(
                f"a policy id that cannot be compared ({_q(entry.get('id'))})"
            )
        # A duplicate id is refused at any priorities, not only equal ones. An
        # id identifies a policy: two entries sharing one are two claims about
        # the same rule, and nothing in a bundle says which is current.
        if policy_id in seen:
            raise UnusableBundle(f"policy {_q(policy_id)} appears twice")
        seen.add(policy_id)

        priority = entry.get("priority")
        if not _usable_priority(priority):
            # The kind as well as the value. `safe_for_log` reports a string
            # by its content and everything else by its kind, so a priority of
            # `"1"` and one of `1` render identically — and a string is the one
            # case where an operator most needs to know which they are looking
            # at, since the message says the value cannot be ordered.
            raise UnusableBundle(
                f"policy {_q(policy_id)} has a priority that cannot be "
                f"ordered ({type(priority).__name__} {_q(priority)})"
            )

        name = entry.get("name")
        chain.append(
            Policy(
                id=policy_id,
                # A policy with no readable name is named by its id rather than
                # refused: a name is what an operator reads in a log line, not
                # something a decision turns on and not something a denial
                # report carries, so refusing the bundle over one would take
                # enforcement down for a cosmetic fault.
                name=name if isinstance(name, str) else policy_id,
                priority=int(priority),
                condition=entry.get("condition"),
                action=entry.get("action"),
            )
        )

    # Ties break by canonical id ascending, so two policies at one priority are
    # never ordered by however the bundle happened to list them.
    return tuple(sorted(chain, key=lambda p: (p.priority, p.id)))


def _index(bindings: list[Any]) -> dict[str, Binding]:
    """The binding index, or a refusal.

    **The whole set is checked, not only the entry a request needs.** A lazy
    check surfaces the fault on whichever endpoint happens to be called first,
    which is not a property anyone can reason about.

    Eight shapes are refused. Seven are the contract's, whose sixth bullet names
    two — a `policy_ids` that is not a list, and an id the canonical form cannot
    parse — and the eighth is an entry that is not an object at all. Each
    removes a choice two implementations would make differently. The one about a
    *silent* fault rather than an ambiguous
    one is ``gated`` naming no policy: read literally it disarms the endpoint
    completely — no threshold, and not even the rule denying a request that
    presents no ticket — without anyone having written ``open``.
    """
    out: dict[str, Binding] = {}

    for entry in bindings:
        if not isinstance(entry, dict):
            raise UnusableBundle(f"a binding that is not an object ({_q(entry)})")

        key = entry.get("endpoint_key")
        # Not coerced. A language that turns `123` into a lookup narrows a
        # request whose resolved key is the string "123".
        if not isinstance(key, str):
            raise UnusableBundle(
                f"a binding whose endpoint_key is not a string ({_q(key)})"
            )
        if key in out:
            raise UnusableBundle(f"two bindings for endpoint {_q(key)}")

        mode = entry.get("mode")
        if mode not in ("gated", "open"):
            raise UnusableBundle(
                f"binding for {_q(key)} has mode {_q(mode)} — the two guesses "
                'are "the listed policies apply" and "none do"'
            )

        ids = entry.get("policy_ids")
        # A string iterates as its characters — binding nothing while looking
        # like it bound something.
        if not isinstance(ids, list):
            raise UnusableBundle(
                f"binding for {_q(key)} has policy_ids that are not a list"
            )

        if mode == "open" and ids:
            raise UnusableBundle(
                f"binding for {_q(key)} is open and still names policies"
            )
        if mode == "gated" and not ids:
            raise UnusableBundle(
                f"binding for {_q(key)} is gated and names no policy — "
                '"subject to nothing" is spelled open, and "subject to '
                'everything" is spelled by carrying no entry'
            )

        # Normalised here, so a non-canonically spelled id still matches its
        # policy rather than nothing. Missing this fails in the dangerous
        # direction: an endpoint that matches no policy is gated by nothing.
        canonical: set[str] = set()
        for bound in ids:
            resolved = canonical_uuid(bound)
            if resolved is None:
                raise UnusableBundle(
                    f"binding for {_q(key)} names an id that cannot be "
                    f"compared ({_q(bound)})"
                )
            canonical.add(resolved)

        out[key] = Binding(mode=mode, policy_ids=frozenset(canonical))

    return out


def _posture(value: object) -> tuple[Enforcement, bool]:
    """The enforcement value this bundle carries, or what an older one means.

    Returns the posture and whether the bundle stated it. The second value is
    the only thing that keeps the two apart downstream, since absent and an
    explicit `none` resolve identically and deliberately so.

    **Absent is `none`, and present-but-wrong is refused.** The two are not the
    same claim and must not collapse into one. An absent field is a Rail
    Center that predates RC-312 and has said nothing about posture, which this
    component reads as "judge nothing" — the alternative, inventing a posture,
    enforces a decision no operator made. A field that is present and outside
    the vocabulary is a responder disagreeing with the contract about what these
    values are, and the contract's own rule for that is to refuse the bundle
    rather than guess which of two opposite readings was meant.

    Refusing costs an *update* rather than enforcement, because a reader keeps
    serving the bundle it already holds — except on a first fetch, where there
    is nothing to fall back to and the gateway reports itself unready.
    """
    if value is None:
        return UNTOLD_ENFORCEMENT, False
    if not isinstance(value, dict):
        raise UnusableBundle("`enforcement` is not an object")
    mode = value.get("mode")
    if mode not in ENFORCEMENTS:
        raise UnusableBundle(f"an enforcement mode outside the contract ({_q(mode)})")
    return mode, True  # type: ignore[return-value]


def _fallback(value: object) -> Fallback:
    """What a call no binding matches is judged to be.

    **Read from the bundle root, beside `bindings`, and not from
    `enforcement`.** It is a property of the binding set rather than of the
    posture: a posture says how much of a verdict is acted on, a fallback says
    what the verdict *is* where nothing matched. It cannot sit inside a binding
    for the same reason — it is precisely what applies when there is no binding.

    Absent is `block`, the conservative half of a pair whose other half admits
    unbound endpoints. Present and outside the vocabulary is refused, for the
    reason `_posture` gives: a responder disagreeing with the contract about
    what these values are is one whose chain should not be enforced.

    Read whatever the posture says. It is acted on only at `enforce`, but a
    bundle carrying a malformed one at `observe` is a responder that disagrees
    about the vocabulary — and the posture it disagrees about is one poll away
    from being the one that decides.
    """
    if value is None:
        return DEFAULT_FALLBACK
    if value not in FALLBACKS:
        raise UnusableBundle(f"a fallback outside the contract ({_q(value)})")
    return value  # type: ignore[return-value]


def validate_bundle(body: object) -> UsableBundle:
    """Validate a fetched bundle and return one that can be walked.

    Raises `UnusableBundle` for anything that cannot be ordered or applied.

    Note what is **not** checked here: whether a bound id names a policy that
    exists or is enabled. A bound id resolving to nothing binds nothing and is
    not an error — the same rule seen from the other side, since a policy that
    is absent or switched off enforces nothing whether or not an endpoint was
    narrowed to it. A binding whose every id resolves to nothing therefore
    leaves an empty chain, and an empty chain allows. Falling back to the whole
    chain when narrowing empties it is the tempting mistake, and it makes the
    two sides disagree on a bundle Rail Center did not produce.
    """
    if not isinstance(body, dict):
        raise UnusableBundle("the response is not an object")

    # Read first, because it describes the shape of everything read after it —
    # a reader that parsed the document and then asked what shape it was in has
    # already made the assumption the field exists to check. **Not acted on
    # here**: refusing an unsupported version is its own change, and this one
    # only teaches the component where to find it.
    schema_version = body.get("schema_version")
    if not isinstance(schema_version, str) or schema_version == "":
        raise UnusableBundle("no schema_version to read the bundle against")
    if (
        has_unsafe_key_characters(schema_version)
        or len(schema_version) > MAX_ENDPOINT_KEY_LENGTH
    ):
        raise UnusableBundle(
            f"a schema_version that cannot be recorded ({_q(schema_version)})"
        )

    content_hash = body.get("content_hash")
    if not isinstance(content_hash, str) or content_hash == "":
        raise UnusableBundle("no content_hash to cache on")
    # A content hash is a short token of ordinary characters. Refusing anything
    # else closes this off at the source rather than at each place it is
    # printed: it is held for as long as the bundle is, and re-echoed on every
    # failed refresh after that, so one accepted once keeps arriving in an
    # operator's log every refresh interval.
    if (
        has_unsafe_key_characters(content_hash)
        or len(content_hash) > MAX_ENDPOINT_KEY_LENGTH
    ):
        raise UnusableBundle(
            f"a content_hash that cannot be recorded ({_q(content_hash)})"
        )

    policies = body.get("policies")
    if not isinstance(policies, list):
        raise UnusableBundle("`policies` is not a list")
    # Always present, so a reader can tell "no endpoint is narrowed" from "this
    # bundle does not describe bindings" without a special case.
    bindings = body.get("bindings")
    if not isinstance(bindings, list):
        raise UnusableBundle("`bindings` is not a list")
    # `rejected` is not read. It carried the policies Rail Center could not
    # compile, for an operator to see; nothing in this component ever narrowed
    # anything with it, and it is gone from the root rather than carried
    # unused. A bundle that still sends one is not refused for it — an unknown
    # root field is a newer or older responder, not a broken one.

    told_enforcement = body.get("enforcement")
    enforcement, posture_told = _posture(told_enforcement)
    fallback = _fallback(body.get("binding_fallback"))

    # Last, because the two of them are what can still refuse the bundle whole.
    chain = _order(policies)
    indexed = MappingProxyType(_index(bindings))

    # The fallback is read from `binding_fallback` at the root and from nowhere
    # else, so a `fallback` inside `enforcement` is a value the responder states
    # and this reader does not consult — a stated `pass` held as `block` refuses
    # every unmatched call at `enforce`, with nothing saying why.
    #
    # Warned and not refused. The bundle is well-formed and the chain in it is
    # enforceable; refusing would take enforcement down over a field that
    # decides nothing, which is a worse outcome than the one being reported.
    # That both hold is why the warning sits below the two calls above rather
    # than beside the read: a bundle those refuse applies nothing, and a line
    # naming the fallback that "applies" would name neither this bundle's nor
    # the held one still deciding traffic.
    if isinstance(told_enforcement, Mapping) and "fallback" in told_enforcement:
        logger.warning(
            "policy bundle states %s inside `enforcement`; the fallback is read "
            "from `binding_fallback` at the bundle root, so %s applies and the "
            "stated one decides nothing",
            _q(told_enforcement.get("fallback")),
            _q(fallback),
        )

    return UsableBundle(
        schema_version=schema_version,
        content_hash=content_hash,
        chain=chain,
        bindings=indexed,
        enforcement=enforcement,
        fallback=fallback,
        posture_told=posture_told,
    )
