.PHONY: init fmt lint test

# CI runs these same targets.

# Every member, editable, plus the pinned dev tools. Run once, and after pulling.
init:
	uv sync

# Format, and fix what ruff can.
fmt:
	uv run ruff format .
	uv run ruff check --fix .

# Check only. Ruff honours git's global excludes, which CI does not have.
lint:
	uv run ruff check .
	uv run ruff format --check .

# Runs a real gateway and upstream on ephemeral ports.
test:
	uv run pytest -q
