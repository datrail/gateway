"""The credential this gateway presents to Rail Center.

A deployment lists what its control plane accepts and each component takes one
of those, so one variable and one token configure a whole customer zone. This
component reads `RAIL_AUTH_MODE` and, where the mode needs one, `RAIL_AUTH_TOKEN`.

**Resolved once, at startup, and refused loudly.** A gateway that cannot produce
the credential it was configured for must stop rather than fall back to calling
anonymously: against a control plane that has stopped accepting unauthenticated
reads, the degradation shows up only as a bundle that never arrives, long after
the deployment that caused it and with nothing naming the cause.
"""

from __future__ import annotations

import os
import re

#: The modes this component implements. `gcp` is named and refused under its own
#: name rather than falling into the "unknown mode" branch: the platform's
#: contract lists it, so an operator who sets it has configured something real
#: and deserves to be told it is not built here, not that it does not exist.
AUTH_MODES = ("none", "bearer")

#: A mode the platform defines and this component does not implement.
UNIMPLEMENTED_MODES = ("gcp",)

#: What may appear in a credential once it is trimmed.
#:
#: The token goes into an `Authorization` header value, so it has to be legal in
#: one: RFC 7230 allows %x21–7E there, and a bearer token has no reason to carry
#: anything else. A secret written with an interior newline — a mount that
#: appends a metadata line, a copy-paste that took the trailing return — is the
#: ordinary way an illegal character arrives.
#:
#: Refusing it here is what keeps it out of the logs. `httpx` refuses such a
#: value too, but the error it raises quotes the header, so the secret would be
#: printed on every refresh that failed on it. Checking the character makes that
#: one startup error instead, phrased so the token never appears.
_HEADER_UNSAFE = re.compile(r"[^\x21-\x7E]")


class AuthConfigurationError(RuntimeError):
    """The configured mode cannot be honoured. Fatal at startup, by design."""


def _trimmed(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _bearer_credential(raw: str, name: str) -> str:
    """`raw` as a header value, or a refusal naming the variable and not the value.

    Trailing whitespace is stripped rather than refused, because every ordinary
    way of writing a secret into a file leaves a newline behind and that is not
    an operator error. Anything illegal *inside* the value is, and the offset
    and code point are what locate it — the token itself never reaches the
    message.
    """
    value = raw.strip()
    if not value:
        raise AuthConfigurationError(
            f"{name} is required when RAIL_AUTH_MODE is bearer"
        )
    found = _HEADER_UNSAFE.search(value)
    if found is not None:
        offset = found.start()
        code_point = ord(value[offset])
        raise AuthConfigurationError(
            f"{name} holds U+{code_point:04X} at offset {offset}, "
            "which cannot go in a header value"
        )
    return value


def auth_headers() -> dict[str, str]:
    """The headers every Rail Center call carries, resolved from the environment.

    A plain dict rather than a callable: this component's only credential source
    is an environment variable, which a running process cannot change. A mode
    whose credential can rotate under a live process — a file that is re-read, a
    token that is minted — needs resolving per call instead, and that is the
    shape to reach for when one lands rather than now.

    Raises `AuthConfigurationError` for anything it cannot honour.
    """
    mode = _trimmed("RAIL_AUTH_MODE").lower() or "none"

    if mode in UNIMPLEMENTED_MODES:
        raise AuthConfigurationError(
            f"RAIL_AUTH_MODE={mode} is a mode this platform defines and this "
            f"gateway does not implement; it accepts {', '.join(AUTH_MODES)}"
        )
    if mode not in AUTH_MODES:
        raise AuthConfigurationError(
            f"RAIL_AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {mode}"
        )

    if mode == "none":
        return {}
    return {
        "Authorization": f"Bearer {_bearer_credential(os.environ.get('RAIL_AUTH_TOKEN') or '', 'RAIL_AUTH_TOKEN')}"
    }
