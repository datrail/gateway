"""What JSON's number type costs a contract, stated once.

JSON has no integer type. Every number on the wire is a double, so two values a
double cannot separate are one value to any conformant reader — and a language
with arbitrary-precision integers will separate them anyway unless it is told
not to. That is one fact, and this component turns on it twice: a ticket's
``exp`` and a policy's ``priority`` are both bounded by it, for the same reason
and with the same consequence when it is missed.

Two copies of a constant are two chances to change one and not the other, and
the rationale is longer than the value.
"""

from __future__ import annotations

#: The largest N for which every integer in ``[-N, N]`` survives a round trip
#: through an IEEE-754 double — ``Number.MAX_SAFE_INTEGER``. Past it the
#: representable values thin out, so two implementations read different numbers
#: from the same bytes: a pair of priorities one side orders and the other ties,
#: or two expiries that name different instants.
MAX_SAFE_INTEGER = 2**53 - 1
