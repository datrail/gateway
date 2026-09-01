"""`RAIL_TICKET_MODE` — how much of the decision this gateway acts on.

Platform-wide rather than this component's own, so the proxy in front reads the
same variable and one value configures a whole customer zone.

The three values map onto two components, which two separate switches could not:

===========  ==========================  ==========================================
Value        Proxy                       Gateway
===========  ==========================  ==========================================
``none``     does not fetch or inject    does not evaluate; forwards what arrives
``observe``  injects                     evaluates, logs every verdict, blocks none
``enforce``  injects                     evaluates and blocks
===========  ==========================  ==========================================

**`none` is a pass-through, not "ignore the ticket".** The alternative reading —
where only ticket-derived conditions stop matching — makes `none` deny
*everything*: a proxy in that mode injects no ticket, so ``x_rail_header``
resolves to absent on every request and the seeded P0 rule matches all of them.
A switch whose off position denies everything is not an off position. So the
three states are don't look, look and log, look and act.

Two consequences of that follow this component around, and both are `none`'s:
a gateway that does not evaluate must not need a policy bundle to report itself
ready, and must not poll Rail Center for one it will never read. Both are
implemented where they belong — in the readiness route and the holder's
lifecycle — rather than being re-derived from the mode at each site.

**`enforce` is the default, and it blocks.** A deployment that has never set
this variable evaluates every call and refuses the ones the walk denies, because
a component whose default is not to enforce stops protecting anything the day an
operator forgets a line. The startup line `describe` returns is what keeps that
visible: an operator reading the log is told what this mode does to traffic
rather than discovering it from a request that was refused.
"""

from __future__ import annotations

import os
from typing import Final, Literal

TicketMode = Literal["none", "observe", "enforce"]

#: The modes this component implements. Ordered as the rollout runs.
TICKET_MODES: Final[tuple[TicketMode, ...]] = ("none", "observe", "enforce")

#: What an unset variable means. `enforce`, because a component whose default
#: is not to enforce is one that silently stops protecting anything the day a
#: deployment forgets a line.
DEFAULT_TICKET_MODE: Final[TicketMode] = "enforce"


class TicketModeError(RuntimeError):
    """The configured mode cannot be honoured. Fatal at startup, by design."""


def ticket_mode() -> TicketMode:
    """`RAIL_TICKET_MODE`, or the default.

    Refused loudly rather than defaulted when it is set to something outside
    the three. A typo that fell back to `enforce` would be a deployment
    enforcing when its operator wrote `none`, and one that fell back to `none`
    would be a deployment enforcing nothing while its operator believed it was.
    Neither is a guess worth making on an operator's behalf.

    **Case is folded, and that is what makes the variable platform-wide.** One
    value configures a zone, and the proxy in front reads it through
    ``.strip().lower()``. A gateway that matched exactly would refuse to start
    on the ``NONE`` or ``Enforce`` its proxy resolved happily — one variable,
    two vocabularies, and the disagreement surfaces as a component that will not
    boot. The message names what the operator wrote rather than the folded form,
    so a value refused for a reason other than its case still reads back to
    them.
    """
    raw = (os.environ.get("RAIL_TICKET_MODE") or "").strip()
    if not raw:
        return DEFAULT_TICKET_MODE
    folded = raw.lower()
    if folded not in TICKET_MODES:
        raise TicketModeError(
            f"RAIL_TICKET_MODE must be one of {', '.join(TICKET_MODES)}, got: {raw}"
        )
    return folded  # type: ignore[return-value]


def evaluates(mode: TicketMode) -> bool:
    """Whether this mode consults the policy bundle at all.

    False only for `none`, and it is the single question the rest of the
    component asks — readiness, the holder's lifecycle and the walk all turn on
    it. Asking it here rather than comparing against the string at four sites is
    what stops one of them being missed when a fourth mode is added.
    """
    return mode != "none"


def describe(mode: TicketMode) -> str:
    """The startup line for this mode, naming what it does and does not do.

    Each line says what traffic will experience, because that is what an
    operator is checking this against: `enforce` names both refusals and the
    report, and `observe` says plainly that nothing is blocked, so a deployment
    reading its own log learns which of the two it is before a request tells it.
    """
    if mode == "none":
        return (
            "RAIL_TICKET_MODE=none — this gateway evaluates no policy and "
            "forwards every request; no policy bundle is fetched"
        )
    if mode == "observe":
        return (
            "RAIL_TICKET_MODE=observe — every request is evaluated and every "
            "verdict logged; nothing is blocked"
        )
    return (
        "RAIL_TICKET_MODE=enforce — every request is evaluated and every verdict "
        "logged; a denied request is refused with 403 and reported to Rail "
        "Center, and one that cannot be judged is refused with 503"
    )
