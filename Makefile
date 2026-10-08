.PHONY: init fmt lint test dump-enforcement-cases proto proto-check e2e e2e-standalone \
	e2e-apigee-grpc e2e-down e2e-apigee-live-up e2e-apigee-live \
	e2e-apigee-live-down

# CI runs these same targets, apart from e2e-apigee-live-*.

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

# The callout's proto and its generated code: see gateway-apigee-grpc/Makefile.
proto proto-check:
	$(MAKE) -C gateway-apigee-grpc $@

# Every e2e stack in turn. Leaves the containers up; `make e2e-down` removes them.
e2e: e2e-standalone e2e-apigee-grpc

e2e-standalone:
	docker compose -f e2e/standalone/compose.yml up --build --force-recreate \
		--abort-on-container-exit --exit-code-from driver

e2e-apigee-grpc:
	docker compose -f e2e/apigee-grpc/compose.yml up --build --force-recreate \
		--abort-on-container-exit --exit-code-from driver

# Removes every stack's containers and volumes.
e2e-down:
	docker compose -f e2e/standalone/compose.yml down -v --remove-orphans
	docker compose -f e2e/apigee-grpc/compose.yml down -v --remove-orphans

# A paid session on real Apigee: see e2e/apigee-grpc/live/README.md. Never in CI.
e2e-apigee-live-up e2e-apigee-live-down:
	e2e/apigee-grpc/live/session.sh $(subst e2e-apigee-live-,,$@)

# The driver against the session; the result is its exit code.
e2e-apigee-live:
	e2e/apigee-grpc/live/session.sh test
