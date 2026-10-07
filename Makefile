.PHONY: init fmt lint test dump-enforcement-cases e2e e2e-standalone e2e-down

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

# The enforcement contract table as JSON, for review.
dump-enforcement-cases:
	uv run python gateway-core/tools/dump_enforcement_cases.py

# Every e2e stack in turn. Leaves the containers up; `make e2e-down` removes them.
e2e: e2e-standalone

e2e-standalone:
	docker compose -f e2e/standalone/compose.yml up --build --force-recreate \
		--abort-on-container-exit --exit-code-from driver

# Removes every stack's containers and volumes.
e2e-down:
	docker compose -f e2e/standalone/compose.yml down -v --remove-orphans
