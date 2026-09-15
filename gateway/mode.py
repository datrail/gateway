"""Whether this gateway has a control plane, and what that control plane tells it to do.

Two questions. They were one variable until RC-312, and separating them is the
whole of this module's job.

**`RAIL_TICKET_MODE` answers the first and nothing else.** ``plugin`` means a
Rail Center exists to poll; ``none`` means one does not. It is deploy-time
configuration because it describes the estate rather than a policy decision: a
component with no control plane to reach cannot be told to acquire one.

**The bundle answers the second.** ``enforcement.mode`` — ``none``, ``observe``
or ``enforce`` — arrives on every poll and may change between two of them, which
is the point. Posture is an operator's decision and belongs where operators
work, not in a variable that needs a redeploy to move.

==============  ===================================  ==========================
State           Reached by                           Traffic
==============  ===================================  ==========================
no data path    ``RAIL_TICKET_MODE=none``            forwarded; never polls
holding none    ``plugin``, nothing fetched yet      forwarded; polling
no posture      ``plugin`` + bundle says nothing     forwarded; polling
``none``        ``plugin`` + bundle says ``none``    forwarded; polling
``observe``     ``plugin`` + bundle says ``observe`` evaluated, logged, allowed
``enforce``     ``plugin`` + bundle says ``enforce`` evaluated, acted on
==============  ===================================  ==========================

**Four of those six pass every request, and they are not each other.** The
first was never given a control plane. The second has one and has not heard
from it. The third has heard, and was told nothing about posture — a Rail
Center predating RC-312, whose silence this gateway reads as judging nothing
rather than as a posture anyone chose. The fourth has heard, and was told to
judge nothing. Reporting any of them as another is the misreading design §5.2
exists to prevent: an operator looking at a gateway that forwards everything
needs to know which of the four they have, because the remedy differs in each.

**A `plugin` component polls at every enforcement value, including `none`.** That
is the inversion RC-312 makes, and it is the one rule here worth stating twice.
A component that stopped polling at ``none`` could never be told it had been
moved off ``none``, so the kill switch would turn one way only — the operator
who disabled enforcement during an incident could not re-enable it without a
redeploy. ``none`` is a posture held by a gateway in touch with its control
plane, not a gateway that has stopped listening.

**`enforce` is no longer the default, because there is no longer a default
posture at all.** A component holding no bundle judges nothing — it has been
told nothing, and inventing `enforce` there would refuse traffic on a ruleset it
does not have. What protects a deployment during that window is ``/ready``,
which reports 503 until a bundle is held; what protects it afterwards is the
bundle. The default that remains is enrolment's: an unset ``RAIL_TICKET_MODE``
is ``plugin``, so a deployment that forgets the line still asks Rail Center what
to do rather than silently opting out of having a control plane.
"""

from __future__ import annotations

import os
from typing import Final, Literal

#: Whether a Rail Center exists for this component to poll. Deploy-time.
Enrolment = Literal["none", "plugin"]

ENROLMENTS: Final[tuple[Enrolment, ...]] = ("none", "plugin")

#: What an unset `RAIL_TICKET_MODE` means. `plugin`, so a deployment that
#: forgets the line asks its control plane what to do rather than deciding for
#: itself to have none.
DEFAULT_ENROLMENT: Final[Enrolment] = "plugin"

#: What the control plane says to do with a call. Read from the bundle, never
#: from the environment.
Enforcement = Literal["none", "observe", "enforce"]

ENFORCEMENTS: Final[tuple[Enforcement, ...]] = ("none", "observe", "enforce")

#: What a `plugin` component runs at before its first successful poll. It has
#: been told nothing, so it judges nothing; `/ready` is what keeps traffic off
#: it in that window wherever an orchestrator honours readiness.
UNTOLD_ENFORCEMENT: Final[Enforcement] = "none"

#: What happens to a call no binding matches, at `enforce` and nowhere else.
Fallback = Literal["pass", "block"]

FALLBACKS: Final[tuple[Fallback, ...]] = ("pass", "block")

#: The fallback a bundle is read as carrying when it names none. `block` is the
#: conservative half of a pair whose other half admits unbound endpoints, and a
#: bundle without the field is one from a Rail Center older than RC-312.
DEFAULT_FALLBACK: Final[Fallback] = "block"


class TicketModeError(RuntimeError):
    """`RAIL_TICKET_MODE` cannot be honoured. Fatal at startup, by design."""


def enrolment() -> Enrolment:
    """`RAIL_TICKET_MODE`, or the default.

    **The three old values are refused rather than translated**, and that is a
    deliberate break: a deployment carrying `RAIL_TICKET_MODE=enforce` today
    stops starting until the line is changed. The alternative — reading
    `observe` and `enforce` as `plugin` — would let a deployment go on declaring
    a posture in a variable nothing reads any more, with the bundle quietly
    overruling it and nobody told. A component that will not boot is the cheaper
    of the two, because it is the one an operator sees.

    Case is folded for the reason it always was: the proxy in front reads the
    same variable through `.strip().lower()`, and a gateway matching exactly
    would refuse to start on the `NONE` its proxy resolved happily.
    """
    raw = (os.environ.get("RAIL_TICKET_MODE") or "").strip()
    if not raw:
        return DEFAULT_ENROLMENT
    folded = raw.lower()
    if folded not in ENROLMENTS:
        retired = (
            " RC-312 replaced the posture values: it now arrives in the policy bundle."
            if folded in ENFORCEMENTS
            else ""
        )
        raise TicketModeError(
            f"RAIL_TICKET_MODE must be one of {', '.join(ENROLMENTS)}, got: {raw}.{retired}"
        )
    return folded  # type: ignore[return-value]


def polls(enrolled: Enrolment) -> bool:
    """Whether this component reaches a control plane at all.

    False only for `none`, and it is the single question the rest of the
    component asks of enrolment — the holder's lifecycle and readiness both turn
    on it. **It is not a question about posture**: a `plugin` component polls at
    every enforcement value, `none` included.
    """
    return enrolled != "none"


def judges(enforcement: Enforcement) -> bool:
    """Whether this enforcement value walks the chain.

    False only for `none`. `observe` judges and acts on nothing, which is not
    the same thing: a component that skipped the walk at `observe` would have
    nothing to report and would have silently become `none`.
    """
    return enforcement != "none"


def blocks(enforcement: Enforcement) -> bool:
    """Whether a denied call is refused rather than logged and forwarded."""
    return enforcement == "enforce"


def describe_enrolment(enrolled: Enrolment) -> str:
    """The startup line, naming what this deployment is rather than what it does.

    What it *does* is the bundle's to say and is not known at startup, so this
    line deliberately promises nothing about traffic — an operator reading it
    learns whether a control plane is in play, and looks at the gateway's posture
    for the rest.
    """
    if enrolled == "none":
        return (
            "RAIL_TICKET_MODE=none — this gateway has no control plane: it "
            "fetches no policy bundle, evaluates nothing, and forwards every "
            "request"
        )
    return (
        "RAIL_TICKET_MODE=plugin — this gateway polls Rail Center for its policy "
        "bundle and takes its enforcement posture from it; until the first "
        "bundle arrives it judges nothing and reports itself unready"
    )


def describe_enforcement(
    enforcement: Enforcement, fallback: Fallback, *, told: bool
) -> str:
    """The line logged when a poll changes the posture.

    Says what traffic will experience, because that is what an operator is
    checking it against — and names the fallback only where it is consulted, so
    a line mentioning it is a line where it decides something.

    **`told` is not a default, and that is the point of it.** A bundle naming no
    `enforcement` resolves to the same `none`/`block` as one naming them, so the
    posture alone cannot say whether Rail Center chose to judge nothing or said
    nothing at all — and the line that reports the second as the first credits a
    control plane with a decision it never made. Every caller has the answer to
    hand; requiring it is what stops a fourth state being rendered as a third.
    """
    if not told:
        return (
            "enforcement=none — this bundle carries no posture at all, so Rail "
            "Center predates RC-312 and has said nothing about one; every "
            "request is forwarded. Judging nothing is this gateway's reading of "
            "that silence and not a decision an operator made, so a deployment "
            "that means to enforce needs a Rail Center that sends the field. "
            "This gateway keeps polling and reports a posture as soon as it is "
            "told one"
        )
    if enforcement == "none":
        return (
            "enforcement=none — Rail Center says judge nothing; every request is "
            "forwarded, and this gateway keeps polling so it is told when that "
            "changes"
        )
    if enforcement == "observe":
        return (
            "enforcement=observe — every request is evaluated and every verdict "
            "logged; nothing is blocked"
        )
    unbound = (
        "an endpoint no binding matches is refused without consulting the chain"
        if fallback == "block"
        else "an endpoint no binding matches is judged by the whole chain rather than refused"
    )
    return (
        "enforcement=enforce — every request is evaluated and every verdict "
        "logged; a denied request is refused with 403 and reported to Rail "
        f"Center, and one that cannot be judged is refused with 503. "
        f"fallback={fallback}: {unbound}"
    )
