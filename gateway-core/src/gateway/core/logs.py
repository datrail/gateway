"""How every interface logs: one handler, on `gateway`, at the configured level."""

import logging
import os

#: Checked against by name rather than through `logging.getLevelName`, whose
#: return type is the contract: an integer for a known name and the string
#: "Level <n>" for anything else, so a typo would set a level nobody chose.
LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"})


def configure_logging() -> None:
    """Give this component's logger a handler, and nothing else one.

    uvicorn configures only `uvicorn*`, and `logging.lastResort` drops anything
    below WARNING — so without a handler here the line naming the upstream is
    discarded. `basicConfig` would do it by configuring the *root* logger, which
    also turns on INFO for httpx and every mcp module and buys around thirty
    lines per forwarded call.
    """
    raw = (os.environ.get("RAIL_GATEWAY_LOG_LEVEL") or "").strip() or "INFO"
    level = raw.upper()
    if level not in LOG_LEVELS:
        raise RuntimeError(
            f"RAIL_GATEWAY_LOG_LEVEL must be one of "
            f"{', '.join(sorted(LOG_LEVELS))}, got: {raw}"
        )
    # On `gateway`, the parent of every module's logger, core's included.
    component = logging.getLogger("gateway")
    component.setLevel(level)
    if component.handlers:
        # Called twice — by `main()` and by a test — this would otherwise add a
        # second handler and print every line twice.
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    component.addHandler(handler)
