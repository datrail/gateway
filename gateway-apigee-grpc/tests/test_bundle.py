"""The reference bundle and the code it copies from agree."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from core_support import REASONS
from gateway.apigee_grpc.servicer import BODY, DECISION, STATUS
from gateway.core.enforcement import refusal_body

_BUNDLE = Path(__file__).parents[1] / "apigee" / "apiproxy"


def test_the_bundle_agrees_with_the_servicer_and_core():
    text = "\n".join(path.read_text() for path in sorted(_BUNDLE.rglob("*.xml")))
    assert set(re.findall(r"rail\.[a-z_]+", text)) == {DECISION, STATUS, BODY}

    # The callout isn't there to supply the body, so the bundle holds a copy.
    failed = ET.parse(_BUNDLE / "policies" / "RF-CalloutFailed.xml").getroot()
    payload = failed.findtext("FaultResponse/Set/Payload")
    assert payload.encode() == refusal_body(REASONS[503])


def test_only_the_callouts_own_fault_or_no_decision_fails_closed():
    callout = ET.parse(_BUNDLE / "policies" / "EC-Rail.xml").getroot().get("name")
    proxy = ET.parse(_BUNDLE / "proxies" / "default.xml").getroot()

    # The policy's own flag, so another policy's fault keeps its own error.
    rule = proxy.find("FaultRules/FaultRule")
    assert rule.findtext("Step/Name") == "RF-CalloutFailed"
    assert rule.findtext("Condition") == f"externalcallout.{callout}.failed = true"

    steps = [
        (step.findtext("Name"), step.findtext("Condition"))
        for step in proxy.findall("PreFlow/Request/Step")
    ]
    assert steps == [
        (callout, None),
        ("RF-CalloutFailed", f"{DECISION} = null"),
        ("RF-Refuse", f'{DECISION} = "refuse"'),
    ]
