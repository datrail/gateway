.PHONY: proto proto-check

# Paths are relative to this folder; the root Makefile runs these with -C.
PROTO_ROOT := proto
PROTO := $(PROTO_ROOT)/gateway/apigee_grpc/_proto/external_callout.proto
# SHA-256 of the upstream file: everything below the proto's vendoring line.
PROTO_UPSTREAM_SHA256 := 70e78ff48b1970a5de668c6816d0ec295dcf640f50aacb746697b38d2cdf6be9

# Regenerates the committed code from the vendored proto. CI runs it and fails
# if the tree then differs from what was committed.
proto:
	uv run python -m grpc_tools.protoc -I $(PROTO_ROOT) \
		--python_out=src --pyi_out=src --grpc_python_out=src $(PROTO)

# Fails if the vendored proto is no longer the upstream file.
proto-check:
	@sed '1,/^\/\/ Vendored unchanged below this line\.$$/d' $(PROTO) | sha256sum \
		| grep -q '^$(PROTO_UPSTREAM_SHA256) ' \
		|| { echo "$(PROTO) differs from the upstream file. If on purpose," \
			"update its header's commit and PROTO_UPSTREAM_SHA256 together."; exit 1; }
