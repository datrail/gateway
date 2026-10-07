.PHONY: proto proto-check proto-check-vendored proto-check-generated

# Paths are relative to this folder; the root Makefile runs these with -C.
PROTO_ROOT := proto
PROTO := $(PROTO_ROOT)/gateway/apigee_grpc/_proto/external_callout.proto
PROTO_CODE := src/gateway/apigee_grpc/_proto
# SHA-256 of the upstream file: everything below the proto's vendoring line.
PROTO_UPSTREAM_SHA256 := 70e78ff48b1970a5de668c6816d0ec295dcf640f50aacb746697b38d2cdf6be9
# protoc on the vendored proto, writing under $(1). One command for `proto` and
# its check, so the two can't differ.
protoc = uv run python -m grpc_tools.protoc -I $(PROTO_ROOT) \
	--python_out=$(1) --pyi_out=$(1) --grpc_python_out=$(1) $(PROTO)

# Regenerates the committed code from the vendored proto.
proto:
	$(call protoc,src)

# The checks CI runs as their own job.
proto-check: proto-check-vendored proto-check-generated

# Fails if the vendored proto is no longer the upstream file.
proto-check-vendored:
	@sed '1,/^\/\/ Vendored unchanged below this line\.$$/d' $(PROTO) | sha256sum \
		| grep -q '^$(PROTO_UPSTREAM_SHA256) ' \
		|| { echo "$(PROTO) differs from the upstream file. If on purpose," \
			"update its header's commit and PROTO_UPSTREAM_SHA256 together."; exit 1; }

# Fails if the committed code isn't what `make proto` would write.
proto-check-generated:
	@out=$$(mktemp -d) && trap 'rm -rf "$$out"' EXIT \
		&& $(call protoc,$$out) \
		&& diff -r -x __init__.py -x __pycache__ $$out/gateway/apigee_grpc/_proto $(PROTO_CODE) \
		|| { echo "The code in $(PROTO_CODE) is out of date: run make proto."; exit 1; }
