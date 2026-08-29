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

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from gateway.bundle.uuid import canonical_uuid
from gateway.json_wire import MAX_SAFE_INTEGER
from gateway.key_safety import MAX_ENDPOINT_KEY_LENGTH, has_unsafe_key_characters
from gateway.key_safety import safe_for_log as _safe


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

    version: str
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
    #: Policies Rail Center could not compile. Not an error channel to drop: it
    #: is how an operator sees a rule is not in force rather than inferring it
    #: from an absence.
    rejected: tuple[Any, ...]


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

    version = body.get("version")
    if not isinstance(version, str) or version == "":
        raise UnusableBundle("no version to cache on")
    # A version is a content hash, so it is a short token of ordinary
    # characters. Refusing anything else closes this off at the source rather
    # than at each place it is printed: it is held for as long as the bundle
    # is, and re-echoed on every failed refresh after that, so one accepted
    # once keeps arriving in an operator's log every refresh interval.
    if has_unsafe_key_characters(version) or len(version) > MAX_ENDPOINT_KEY_LENGTH:
        raise UnusableBundle(f"a version that cannot be recorded ({_q(version)})")

    policies = body.get("policies")
    if not isinstance(policies, list):
        raise UnusableBundle("`policies` is not a list")
    # Always present, so a reader can tell "no endpoint is narrowed" from "this
    # bundle does not describe bindings" without a special case.
    bindings = body.get("bindings")
    if not isinstance(bindings, list):
        raise UnusableBundle("`bindings` is not a list")
    # Refused rather than coerced to empty, like the two above — and this one
    # is strictness the contract does not ask for, so it is worth saying what
    # it buys and what it costs. Nothing here reads `rejected`; it is carried
    # for an operator, and a wrong-shaped one narrows nothing. What it does say
    # is that the responder is not Rail Center, and the cheapest moment to
    # notice that is before a chain assembled by something else is enforced.
    # The cost is bounded by the contract's own rule that a reader keeps
    # serving the last bundle it holds, so this refuses an update rather than
    # enforcement — except on a first fetch, where there is nothing to fall
    # back to and the gateway refuses traffic.
    rejected = body.get("rejected")
    if not isinstance(rejected, list):
        raise UnusableBundle("`rejected` is not a list")

    return UsableBundle(
        version=version,
        chain=_order(policies),
        bindings=MappingProxyType(_index(bindings)),
        rejected=tuple(rejected),
    )
