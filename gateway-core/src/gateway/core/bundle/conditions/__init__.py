"""Whether one policy condition holds for one request, in the grammar the
bundle's ``schema_version`` names.

Only the reading of a condition is versioned. `v1` is ``{field, operator,
value}`` over a fixed field table; `v2` is ``{path, op, value}`` over the
``ticket`` and ``request`` sources. Both resolve a value and hand it to the
same operators, and everything around them — the walk, the fallbacks, the
report — is one implementation whichever grammar a bundle carries.
"""

from types import ModuleType

from gateway.core.bundle.conditions import v1, v2
from gateway.core.bundle.conditions._shared import (
    ConditionInput,
    UninterpretableCondition,
    request_headers,
)

__all__ = [
    "ConditionInput",
    "UninterpretableCondition",
    "grammar",
    "request_headers",
    "v1",
    "v2",
]

_BY_MAJOR: dict[int, ModuleType] = {1: v1, 2: v2}


def grammar(major: int) -> ModuleType:
    """The grammar a bundle of this `schema_version` major is read in: a module
    with `holds(condition, request)` and `drops_when_keyless(condition)`."""
    return _BY_MAJOR[major]
