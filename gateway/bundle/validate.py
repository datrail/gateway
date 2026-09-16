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
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from gateway.bundle.uuid import canonical_uuid
from gateway.endpoint import strip_slug
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

#: The bundle shape this reader understands, as a major version. A bundle
#: declaring the same major is read; one declaring any other is refused whole.
#:
#: **The minor is deliberately not compared.** This reader already treats a root
#: field it does not recognise as a responder of a different age rather than a
#: broken one — see `validate_bundle`, where a bundle still carrying `rejected`
#: is read rather than refused — and a minor bump is exactly that case given a
#: number. Refusing one would make adding an optional field a breaking change
#: after all, which would leave that tolerance unreachable and put every
#: component on a lockstep upgrade with its control plane.
#:
#: **The major is compared because a major bump means the opposite**: a field
#: this reader relies on has moved or changed meaning, so reading the document
#: at all would be guessing. Refusing it costs an *update* rather than
#: enforcement — the caller keeps the bundle it already holds — except on a
#: first fetch, where there is nothing to fall back to and the gateway reports
#: itself unready.
SUPPORTED_SCHEMA_MAJOR: Final[int] = 1

#: `MAJOR.MINOR` in ASCII digits, anchored at both ends.
#:
#: **Written as a pattern rather than as `str.isdigit()` and `int()`, because
#: those accept digits this contract does not.** `isdigit` is true of the
#: Arabic-Indic `١`, the fullwidth `１` and the superscript `¹`, and `int`
#: parses the first two — so a bundle declaring `١.٠` would be read as major 1
#: here and refused by a reimplementation in a language whose integer parser is
#: ASCII-only. The vectors beside this file are answerable to both, so the
#: grammar has to be the narrow one.
_SCHEMA_VERSION = re.compile(r"\A[0-9]+\.[0-9]+\Z")

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
    #: The key exactly as Rail Center published it, slug and all.
    #:
    #: **Kept because a denial reports it, not because anything matches on it.**
    #: The index is keyed on the stripped form — that is what this gateway can
    #: compose — but a refusal on a matched binding can name the whole key
    #: rather than the part this gateway happens to hold, and a key that
    #: originated in Rail Center is one Rail Center can resolve without
    #: re-deriving. Where nothing matched there is no full key to name, and the
    #: report carries the stripped form instead.
    full_key: str


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
    #: The full key each stripped one came from, so a collision can name both.
    first_seen: dict[str, str] = {}

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
        comparable = strip_slug(key)
        if not comparable:
            # **Logged and skipped, where a collision refuses the whole bundle**,
            # and the difference is what each one costs to act on. A key this
            # gateway cannot reduce to anything narrows one endpoint and says
            # nothing about the others; refusing the bundle over it would take
            # every other binding down with it, and the endpoint it names goes
            # to the whole chain — which is the strict reading, not the lax one.
            # A collision is not like that: it is two bindings an operator has
            # to choose between, and serving either would be this gateway
            # choosing for them.
            logger.warning(
                "policy bundle carries a binding this gateway cannot read as a "
                "key (%s); it narrows nothing and every other binding stands",
                _safe(key),
            )
            continue
        if comparable in out:
            # **Both full keys, because neither alone identifies the fault.**
            # The stripped form is what collided and the slugs are what an
            # operator has to change, so a message naming only one of the three
            # sends them to a file that looks correct.
            #
            # **This compares bindings against each other, and that is the whole
            # reach it has.** The cost is written down rather than designed
            # around, as the widening at `conditions.strip_slug` for a ticket's
            # skills is: a collision only one side of which is bound is not
            # visible here, so a binding published for one data source narrows
            # the identically-named tool on every other upstream behind this
            # gateway, and an `open` one opens it. Closing that would need a
            # route-to-data-source relationship the routes file deliberately
            # does not carry, or a discriminator in the key — which is why the
            # constraint is stated to the operator in the README rather than
            # enforced in full here.
            raise UnusableBundle(
                f"two bindings reach this gateway as {_q(comparable)} — "
                f"{_q(first_seen[comparable])} and {_q(key)}. Endpoint keys "
                f"must be unique within a gateway once the data source slug is "
                f"stripped, because this gateway composes no slug of its own"
            )
        first_seen[comparable] = key

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

        out[comparable] = Binding(
            mode=mode, policy_ids=frozenset(canonical), full_key=key
        )

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


def _refuse_an_unsupported_schema(declared: str) -> None:
    """Refuse a bundle whose shape this reader cannot claim to understand.

    **`MAJOR.MINOR`, and only the major is compared.** A matching major with any
    minor is read; a different major is refused; anything that is not two
    non-negative integers separated by a single dot is refused, because a
    version this reader cannot parse is one it cannot say it supports — and
    guessing at it is the half-read the field exists to prevent.

    A trailing suffix is not tolerated. `1.0-rc1` and `1.0.0` are refused rather
    than read as `1.0`: both are a producer saying something this reader has no
    rule for, and accepting them would mean accepting whatever the next
    responder invents in that position.
    """
    if not _SCHEMA_VERSION.match(declared):
        raise UnusableBundle(
            f"a schema_version that is not MAJOR.MINOR ({_q(declared)})"
        )
    major = declared.partition(".")[0]
    if int(major) != SUPPORTED_SCHEMA_MAJOR:
        raise UnusableBundle(
            f"schema_version {_q(declared)} is a bundle shape this gateway does "
            f"not read; it understands {SUPPORTED_SCHEMA_MAJOR}.x"
        )


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

    # Read first, and acted on before anything else is, because it describes the
    # shape of everything below it — a reader that parsed the document and then
    # asked what shape it was in has already made the assumption this field
    # exists to check. Every refusal after this one is a claim about a `1.x`
    # document, which is the only kind this reader can make a claim about.
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
    _refuse_an_unsupported_schema(schema_version)

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
