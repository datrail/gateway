"""The walk: which policy, if any, denies this request.

Transcribed from the pseudocode in rail-center's
``docs/policy-evaluation-contract.md`` under *The decision*, and the word is
deliberate — this is a transcription rather than a reinterpretation, because a
Python implementation that gets any of its marked rules subtly wrong disagrees
with Rail Center on exactly the tickets that matter, and does so in the
flattering direction.

Most of the contract's decision section is already satisfied before this module
runs. `validate_bundle` drops disabled policies, orders the chain by
``priority`` ascending with ties broken on the canonical id, canonicalises every
bound id, and refuses a bundle it cannot order or whose bindings it cannot
apply. That is what leaves this file as short as it is, and it is also why the
eager half of the contract's two refusal kinds does not appear here: a bundle
that cannot be read never reaches the walk.

What remains are the four rules the pseudocode carries in its comments, each of
which has a natural wrong shape:

  * **Narrow after ordering, never before.** `UsableBundle.chain` arrives
    ordered, so narrowing here is narrowing after — but the ordering is what
    refuses an unreadable chain, and a bundle is unusable whether or not a
    binding happens to exclude the offending policy. Filtering first, or
    short-circuiting ``open`` before the chain was ever ordered, allows requests
    where this refuses them.

  * **`open` allows at the end of the walk, not before it.** It narrows to an
    empty chain and the loop finds nothing to deny. An ``if mode == open:
    return allow`` that returns early is the natural misreading, and it is
    wrong for the same reason: it skips the ordering that refuses a bad bundle.

  * **Any action that is not `alert` denies.** The database constrains
    ``action`` to ``block`` or ``alert``; this gateway builds policies from wire
    JSON where no such constraint reaches. A matched policy whose action cannot
    be read is still a matched policy, and treating an unrecognised one as
    inert is how a rule quietly stops enforcing.

  * **A condition outside the grammar refuses the request where the walk
    reaches it** — not as a condition that did not hold, and not as a refusal of
    the whole bundle up front. Lazily, because the walk stops at the first
    match: a rule at priority 9 is never reached once priority 1 has denied, and
    that request has a clean answer. `holds` raising rather than returning False
    is what makes the placement possible.

Alerts accumulated before a refusal are **discarded** with the decision. They
were the first half of a verdict that was never reached, and reporting them
would put half a decision in the alert log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gateway.bundle.conditions import ConditionInput, holds
from gateway.bundle.validate import Policy, UsableBundle


@dataclass(frozen=True)
class Decision:
    """What the walk concluded, and what an operator is owed about it.

    A refusal is not one of these. `holds` raises `UninterpretableCondition`
    and this module lets it through, because a refusal is the absence of a
    decision rather than a third value of one — folding it in here would give
    every caller a state it could forget to check.
    """

    #: True when no policy denied. An empty chain allows, which is why a
    #: narrowing that resolves to nothing is not the same as no narrowing.
    allowed: bool
    #: The policy that denied, or None. **The one that actually matched** — an
    #: implementation reporting the first rule in its chain, or a rule it was
    #: configured with rather than one it evaluated, produces a record that is
    #: wrong and that nothing downstream will contradict.
    denied_by: Policy | None = None
    #: Every `alert` policy that matched, **in evaluation order** — priority
    #: ascending, ties by canonical id — not in the order the bundle listed
    #: them. They accumulate whether or not the request is ultimately allowed:
    #: an alert that matched on a request a later denial stopped is still
    #: something an operator asked to be told about.
    alerts: tuple[Policy, ...] = field(default_factory=tuple)


def chain_for(bundle: UsableBundle, endpoint_key: str | None) -> tuple[Policy, ...]:
    """The policies this endpoint is judged by, in evaluation order.

    **An endpoint with no binding entry is subject to every policy**, so the
    absence of a narrowing is not the absence of rules. Read the other way
    round it is a total loss of enforcement, which is why the contract states it
    twice and pins it with a vector.

    A binding whose every id resolves to nothing leaves an empty chain, and an
    empty chain allows. Do **not** fall back to the whole chain when narrowing
    empties it. Rail Center has a fallback of exactly that shape and it belongs
    to the publishing side alone: it drops a binding entry whose policies are
    all absent or disabled, so the endpoint returns to the whole chain before
    the bundle is written. Copying that here makes the two sides disagree —
    deny there, allow here — on a bundle Rail Center did not produce.

    A call naming no endpoint is judged by the whole chain too. There is no key
    to look up, so nothing narrows; the rules that key on `endpoint_key` decline
    to hold against an absence, and the rest apply as they would anywhere.
    """
    if endpoint_key is None:
        return bundle.chain
    binding = bundle.bindings.get(endpoint_key)
    if binding is None:
        return bundle.chain
    # `policy_ids` is empty for mode `open`, which narrows to nothing and lets
    # the loop below allow at the end of the walk rather than before it.
    return tuple(p for p in bundle.chain if p.id in binding.policy_ids)


def decide(
    bundle: UsableBundle,
    request: ConditionInput,
) -> Decision:
    """Walk this endpoint's chain and return the first denial, if any.

    Raises `UninterpretableCondition` where the walk reaches a rule outside the
    grammar. The caller answers 503 and reports no denial — no policy decided
    this request, so naming one would attribute a verdict nobody reached.
    """
    alerts: list[Policy] = []

    for policy in chain_for(bundle, request.endpoint_key):
        if not holds(policy.condition, request):
            continue

        # **Any action that is not `alert` denies**, and the comparison is
        # against `alert` rather than for `block` precisely so that an action
        # this gateway cannot read still denies.
        if policy.action == "alert":
            alerts.append(policy)
            continue

        # **The first matching denying policy wins and stops the walk**, which
        # is what makes a lower priority number genuinely higher precedence
        # rather than merely earlier in a list that keeps being read.
        return Decision(allowed=False, denied_by=policy, alerts=tuple(alerts))

    return Decision(allowed=True, denied_by=None, alerts=tuple(alerts))
