"""The credential the gateway presents to Rail Center.

Every case here is a configuration mistake and what an operator is told about
it, because that is the whole of what this module does. The one thing asserted
about every refusal is that the token is not in it.
"""

from __future__ import annotations

import pytest

from gateway.auth import AUTH_MODES, AuthConfigurationError, auth_headers

SECRET = "s3cr3t-token-nobody-should-see"


def test_an_unset_mode_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """The platform's default, and the one a fresh deployment starts on."""
    monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    assert auth_headers() == {}


@pytest.mark.parametrize("value", ["none", "NONE", " none ", "None"])
def test_none_is_read_whatever_its_case(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("RAIL_AUTH_MODE", value)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    assert auth_headers() == {}


def test_bearer_carries_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", SECRET)
    assert auth_headers() == {"Authorization": f"Bearer {SECRET}"}


def test_a_token_written_to_a_file_keeps_its_meaning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Surrounding whitespace is stripped, not refused.

    Every ordinary way of writing a secret into a file or a secret manager
    leaves a trailing newline. That is not an operator error and must not be
    one: the alternative is a gateway that refuses to start over a character
    nobody typed.
    """
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", f"  {SECRET}\n")
    assert auth_headers() == {"Authorization": f"Bearer {SECRET}"}


def test_gcp_is_refused_under_its_own_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mode the platform defines and this component does not implement.

    Falling into the generic "unknown mode" branch would tell an operator who
    configured something real that it does not exist, and send them looking for
    a typo instead of for the component that has not built it yet.
    """
    monkeypatch.setenv("RAIL_AUTH_MODE", "gcp")
    with pytest.raises(AuthConfigurationError) as caught:
        auth_headers()
    assert "does not implement" in str(caught.value)
    assert "none, bearer" in str(caught.value)


def test_an_unknown_mode_names_what_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RAIL_AUTH_MODE", "mtls")
    with pytest.raises(AuthConfigurationError) as caught:
        auth_headers()
    assert "must be one of" in str(caught.value)
    for mode in AUTH_MODES:
        assert mode in str(caught.value)


@pytest.mark.parametrize("token", ["", "   ", "\n"])
def test_bearer_without_a_token_stops_the_process(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    """Refused rather than downgraded to an anonymous call.

    Against a control plane that has stopped accepting unauthenticated reads,
    a silent downgrade shows up only as a bundle that never arrives — long
    after the deployment that caused it, and with nothing naming the cause.
    """
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", token)
    with pytest.raises(AuthConfigurationError) as caught:
        auth_headers()
    assert "RAIL_AUTH_TOKEN is required" in str(caught.value)


@pytest.mark.parametrize(
    ("token", "code_point", "offset"),
    [
        (f"tok{chr(10)}en", "U+000A", 3),
        (f"tok{chr(13)}en", "U+000D", 3),
        (f"tok{chr(9)}en", "U+0009", 3),
        ("tok en", "U+0020", 3),
        # No NUL case: `os.environ` cannot carry one — `setenv` raises — so a
        # token containing it is unreachable through the only source this
        # module reads. The check still covers it, and would matter if a file
        # or a secret manager ever became a source.
        ("tøken", "U+00F8", 1),
        (f"tok{chr(0x7F)}en", "U+007F", 3),
    ],
)
def test_a_token_illegal_in_a_header_is_refused_by_location(
    monkeypatch: pytest.MonkeyPatch, token: str, code_point: str, offset: int
) -> None:
    """Located precisely, and never quoted.

    `httpx` refuses such a value too, but the error it raises quotes the whole
    header — so the secret would be printed on every refresh that failed on it.
    Checking the character here makes that one startup error instead, and the
    message carries the offset and the code point rather than the token.
    """
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", token)
    with pytest.raises(AuthConfigurationError) as caught:
        auth_headers()
    message = str(caught.value)
    assert code_point in message
    assert f"offset {offset}" in message
    assert token not in message
    assert "tok" not in message


def test_no_refusal_ever_carries_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """The property, over every way of getting the token wrong at once."""
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    for token in (f"{SECRET}\n{SECRET}", f"\t{SECRET}\t{SECRET}", f"{SECRET}\x7f"):
        monkeypatch.setenv("RAIL_AUTH_TOKEN", token)
        with pytest.raises(AuthConfigurationError) as caught:
            auth_headers()
        assert SECRET not in str(caught.value)


@pytest.mark.parametrize("mode", ["none", None])
def test_a_token_beside_none_stops_the_process(
    monkeypatch: pytest.MonkeyPatch, mode: str | None
) -> None:
    """The one door the unknown-mode branch does not cover.

    A misspelled `RAIL_AUTH_MODE` resolves to `none` like an unset one, and a
    `none` that ignores the token calls anonymously a control plane the operator
    plainly meant to authenticate to. Both halves of the mistake are visible
    here — the credential is set, the mode is not — and the message says which
    of the two to change.
    """
    if mode is None:
        monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    else:
        monkeypatch.setenv("RAIL_AUTH_MODE", mode)
    monkeypatch.setenv("RAIL_AUTH_TOKEN", SECRET)

    with pytest.raises(AuthConfigurationError) as caught:
        auth_headers()

    message = str(caught.value)
    assert "sends no credential" in message
    assert "RAIL_AUTH_MODE=bearer" in message
    assert SECRET not in message


@pytest.mark.parametrize("token", ["", "   ", "\n"])
def test_an_empty_token_beside_none_is_the_ordinary_shape(
    monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    """Empty is not set.

    A deployment writing `RAIL_AUTH_TOKEN=${TOKEN:-}` passes an empty value
    whenever the mode is `none`, so refusing on the variable's presence rather
    than its content would refuse the compose file that runs the demo.
    """
    monkeypatch.setenv("RAIL_AUTH_MODE", "none")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", token)
    assert auth_headers() == {}
