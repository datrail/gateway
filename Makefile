.PHONY: fmt lint test

# Every target runs through `uv run`, in the workspace's one environment: `uv sync`
# first, and it holds every member and the pinned dev tools.

# Formats, and fixes what ruff can. `lint` below only checks.
fmt:
	uv run ruff format .
	uv run ruff check --fix .

# The gate is defined here rather than in .github/workflows/ci.yml, so the command
# CI runs is the one you can run before opening a pull request.
#
# The two halves cover different files. `ruff check` reads Python; `ruff format`
# also reads Python fenced in Markdown. And ruff honours git's global excludes
# file, which a runner does not have: a path you exclude globally is linted in
# CI and skipped locally.
lint:
	uv run ruff check .
	uv run ruff format --check .

# The suite stands up a real upstream and a real gateway on ephemeral ports:
# the gateway reaches its upstream as an MCP client, so an in-process transport
# would exercise a shape no deployment has.
test:
	uv run pytest -q
