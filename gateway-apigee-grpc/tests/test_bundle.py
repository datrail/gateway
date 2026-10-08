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
