"""Whether this gateway has a control plane, and what that control plane tells it to do.

Two questions. They were one variable until RC-312, and separating them is the
whole of this module's job.

**`RAIL_PLUGIN_ENABLED` answers the first and nothing else.** True means RailXia
is installed on this deployment and a Rail Center exists to poll; false means
this is a plain gateway that never contacts one. It is deploy-time configuration
because it describes the estate rather than a policy decision — reaching a
control plane is a RailXia feature, not a gateway feature, and a component with
no control plane to reach cannot be told to acquire one.

**The bundle answers the second.** ``enforcement.mode`` — ``none``, ``observe``
or ``enforce`` — arrives on every poll and may change between two of them, which
is the point. Posture is an operator's decision and belongs where operators
work, not in a variable that needs a redeploy to move.

==============  =====================================  ==========================
State           Reached by                             Traffic
==============  =====================================  ==========================
no data path    ``RAIL_PLUGIN_ENABLED=false``          forwarded; never polls
holding none    enabled, nothing fetched yet           forwarded; polling
no posture      enabled, bundle says nothing           forwarded; polling
``none``        enabled, bundle says ``none``          forwarded; polling
``observe``     enabled, bundle says ``observe``       evaluated, logged, allowed
``enforce``     enabled, bundle says ``enforce``       evaluated, acted on
==============  =====================================  ==========================

**Four of those six pass every request, and they are not each other.** The
first was never given a control plane. The second has one and has not heard
from it. The third has heard, and was told nothing about posture — a Rail
Center predating RC-312, whose silence this gateway reads as judging nothing
rather than as a posture anyone chose. The fourth has heard, and was told to
judge nothing. Reporting any of them as another is the misreading design §5.2
exists to prevent: an operator looking at a gateway that forwards everything
needs to know which of the four they have, because the remedy differs in each.

**A plugged-in component polls at every enforcement value, including `none`.**
That is the inversion RC-312 makes, and it is the one rule here worth stating
twice. A component that stopped polling at ``none`` could never be told it had
been moved off ``none``, so the kill switch would turn one way only — the
operator who disabled enforcement during an incident could not re-enable it
without a redeploy. ``none`` is a posture held by a gateway in touch with its
control plane, not a gateway that has stopped listening.

**`enforce` is no longer the default, because there is no longer a default
posture at all.** A component holding no bundle judges nothing — it has been
told nothing, and inventing `enforce` there would refuse traffic on a ruleset it
does not have. What protects a deployment during that window is ``/ready``,
which reports 503 until a bundle is held; what protects it afterwards is the
bundle.

**Enrolment's default is `false`, and the contradiction check is what makes that
safe.** The danger in defaulting off is that a dropped line silently unenrols a
gateway that was enforcing an hour ago; the danger in defaulting on is that a
plain gateway with no RailXia anywhere near it refuses to start, because
``RAIL_CENTER_URL`` is required once the plugin is on. Neither default escapes
both. So the answer is not the default: a deployment carrying Rail Center
configuration with the flag off is **refused at startup**, naming both. The
dangerous case is exactly the case that has ``RAIL_CENTER_URL`` set, so it stops
the component rather than unenrolling it, while the harmless case — nothing to
point at, nothing configured — boots as the plain gateway it is.
"""

from __future__ import annotations

import os
from typing import Final, Literal

#: The variable that says whether RailXia is installed on this deployment.
PLUGIN_FLAG: Final[str] = "RAIL_PLUGIN_ENABLED"

#: The variable this one replaces, named so that an operator still setting it is
#: told rather than ignored.
RETIRED_FLAG: Final[str] = "RAIL_TICKET_MODE"

#: The two spellings accepted, case folded. Anything else is refused rather
#: than read as false: a component that read `ture` as off would unenrol on a
#: typo, which is the direction that loses enforcement silently.
PLUGIN_VALUES: Final[tuple[str, str]] = ("true", "false")

#: What an unset `RAIL_PLUGIN_ENABLED` means. False, so a gateway nobody has
#: given RailXia configuration needs no variable at all — and the contradiction
#: refusal below is what stops that default unenrolling one that has it.
DEFAULT_PLUGIN_ENABLED: Final[bool] = False

#: Rail Center configuration, whose presence contradicts a plugin that is off.
#: `RAIL_CENTER_URL` is the decisive one, being what an enabled plugin requires;
#: the other two are named because setting them to a value that asserts anything
#: is something only an operator who meant to enrol does. What counts as
#: asserting is `_asserts_enrolment`'s, not mere presence.
RAIL_CENTER_VARIABLES: Final[tuple[str, ...]] = (
    "RAIL_CENTER_URL",
    "RAIL_AUTH_MODE",
    "RAIL_AUTH_TOKEN",
)

#: The one value among those variables that asserts no enrolment. `none` is
#: `RAIL_AUTH_MODE`'s own default and names *no credential*, which is exactly
#: what a gateway with no control plane has — so a platform template that spells
#: the default out, or a zone that sets one auth mode across every component,
#: says nothing about whether RailXia is installed here.
#:
#: `RAIL_AUTH_TOKEN` has no counterpart: a token is only ever set to be sent.
UNENROLLING_AUTH_MODE: Final[str] = "none"

#: What the control plane says to do with a call. Read from the bundle, never
#: from the environment.
Enforcement = Literal["none", "observe", "enforce"]

ENFORCEMENTS: Final[tuple[Enforcement, ...]] = ("none", "observe", "enforce")

#: What a `plugin` component runs at before its first successful poll. It has
#: been told nothing, so it judges nothing; `/ready` is what keeps traffic off
#: it in that window wherever an orchestrator honours readiness.
UNTOLD_ENFORCEMENT: Final[Enforcement] = "none"

#: What happens to a call no binding matches. **Evaluated wherever the chain
#: is walked and acted on only at `enforce`**: at `observe` the would-be
#: refusal is logged and the walk still runs, so an operator sees what
#: `block` would refuse before it refuses anything — which is what makes
#: `observe` a preview of enforcement rather than of everything but this.
Fallback = Literal["pass", "block"]

FALLBACKS: Final[tuple[Fallback, ...]] = ("pass", "block")

#: The fallback a bundle is read as carrying when it names none. `block` is the
#: conservative half of a pair whose other half admits unbound endpoints, and a
#: bundle without the field is one from a Rail Center older than RC-312.
DEFAULT_FALLBACK: Final[Fallback] = "block"


class PluginConfigError(RuntimeError):
    """`RAIL_PLUGIN_ENABLED` cannot be honoured. Fatal at startup, by design."""


def _asserts_enrolment(name: str) -> bool:
    """Whether this variable, as it is set, says an operator meant to enrol.

    Blank and unset say nothing, and so does `RAIL_AUTH_MODE=none` — the value
    means *no credential*, which is the state of every gateway that reaches no
    control plane at all. Admitting it costs no protection: `RAIL_CENTER_URL` is
    the decisive variable and every deployment that really polls a Rail Center
    has it, so the dangerous case — a dropped flag on a gateway that was
    enforcing an hour ago — is still refused.

    Lower-cased to match `auth_headers`, which reads the same variable through
    `.lower()`. A gateway that took `NONE` for an enrolment would refuse to
    start on a value its own auth layer resolves happily.
    """
    value = (os.environ.get(name) or "").strip()
    if not value:
        return False
    if name == "RAIL_AUTH_MODE":
        return value.lower() != UNENROLLING_AUTH_MODE
    return True


def plugin_enabled() -> bool:
    """Whether RailXia is installed here, from `RAIL_PLUGIN_ENABLED`.

    **It is not a question about posture.** An enabled component polls at every
    enforcement value, `none` included; this answers only whether there is a
    control plane to poll at all.

    Two refusals rather than a lenient read, and they cover the two ways an
    operator's intent and this variable come apart:

    **A leftover `RAIL_TICKET_MODE` stops the component**, naming what replaced
    it. That variable carried a posture, then carried enrolment, and now carries
    nothing — so a deployment still setting it believes it is configuring
    something that is no longer read. Refusing is the cheaper failure because it
    is the one an operator sees.

    **Rail Center configuration beside a plugin that is off stops it too**,
    naming both. This is what makes the `false` default safe: the case that
    would be dangerous — a dropped flag on a gateway that was enforcing an hour
    ago — is exactly the case with `RAIL_CENTER_URL` set, so it is refused
    rather than silently unenrolled. A deployment with no Rail Center
    configuration is a plain gateway and boots without the variable, and
    `RAIL_AUTH_MODE=none` is none of it: see `_asserts_enrolment`.

    Case is folded for the reason it always was: the proxy in front reads its
    own flag through `.strip().lower()`, and a gateway matching exactly would
    refuse to start on the `TRUE` its proxy resolved happily.
    """
    if (os.environ.get(RETIRED_FLAG) or "").strip():
        raise PluginConfigError(
            f"{RETIRED_FLAG} is no longer read. Whether this gateway has a "
            f"control plane is {PLUGIN_FLAG}=true|false; what it does with a "
            f"call arrives in the policy bundle as `enforcement.mode`. Remove "
            f"{RETIRED_FLAG}."
        )

    raw = (os.environ.get(PLUGIN_FLAG) or "").strip()
    if not raw:
        enabled = DEFAULT_PLUGIN_ENABLED
    else:
        folded = raw.lower()
        if folded not in PLUGIN_VALUES:
            raise PluginConfigError(
                f"{PLUGIN_FLAG} must be one of {', '.join(PLUGIN_VALUES)}, got: {raw}"
            )
        enabled = folded == "true"

    if not enabled:
        configured = [
            name for name in RAIL_CENTER_VARIABLES if _asserts_enrolment(name)
        ]
        if configured:
            raise PluginConfigError(
                f"{PLUGIN_FLAG} is {raw or 'unset, which is false'} and this "
                f"gateway would reach no control plane, but "
                f"{', '.join(configured)} "
                f"{'is' if len(configured) == 1 else 'are'} set. Set "
                f"{PLUGIN_FLAG}=true to use that configuration, or remove it."
            )
    return enabled


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


def describe_plugin(enabled: bool) -> str:
    """The startup line, naming what this deployment is rather than what it does.

    What it *does* is the bundle's to say and is not known at startup, so this
    line deliberately promises nothing about traffic — an operator reading it
    learns whether a control plane is in play, and looks at the gateway's posture
    for the rest.
    """
    if not enabled:
        return (
            "RAIL_PLUGIN_ENABLED=false — RailXia is not installed on this "
            "gateway: it fetches no policy bundle, evaluates nothing, and "
            "forwards every request"
        )
    return (
        "RAIL_PLUGIN_ENABLED=true — this gateway polls Rail Center for its policy "
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
    `enforcement` resolves to the same `none` as one naming `none`, so the
    posture alone cannot say whether Rail Center chose to judge nothing or said
    nothing at all — and the line that reports the second as the first credits a
    control plane with a decision it never made. Every caller has the answer to
    hand; requiring it is what stops a fourth state being rendered as a third.
    The fallback settles none of this, for the reason `UsableBundle.posture_told`
    gives.
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
