"""The enforcement contract, against `judge` and the reporter alone."""

import json

import httpx
import pytest

from core_support import REASONS, Holder, enforcement_params
from gateway.core.enforcement import DenialReporter, judge


async def _sent(verdict) -> list[dict]:
    """The report bodies the verdict sends, as Rail Center receives them."""
    bodies: list[dict] = []

    def receive(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(202)

    if verdict.report is not None:
        reporter = DenialReporter(
            "http://rail-center.test", {}, transport=httpx.MockTransport(receive)
        )
        reporter.send(verdict.report)
        for task in list(reporter._reports):
            await task
    return bodies


@pytest.mark.asyncio
@pytest.mark.parametrize("case", enforcement_params("core"))
async def test_the_verdict_matches_every_row_of_the_contract(case):
    verdict = judge(
        Holder(case.bundle()),
        case.path,
        case.body,
        list(case.x_rail) or None,
        list(case.x_rail_status) or None,
    )

    assert verdict.status == case.status
    assert verdict.reason == (REASONS[case.status] if case.status else "")
    sent = await _sent(verdict)
    if case.report is None:
        assert sent == []
    else:
        (body,) = sent
        body.pop("denied_at")
        assert body == case.report
