#!/bin/bash
set -e
ROOT_DIR="/workspaces/sliver-nxc-module"
cd "$ROOT_DIR"

# Generate protobuf files if needed
if [ ! -d "src/sliver_client/pb/clientpb" ]; then
    poetry run python -c "from sliver_client import protobuf; protobuf.generate_protobuf_code()" 2>/dev/null || true
fi

# Copy protobuf files to mutants directory if it exists
if [ -d "mutants" ] && [ ! -d "mutants/src/sliver_client/pb" ]; then
    mkdir -p mutants/src/sliver_client
    cp -r src/sliver_client/pb mutants/src/sliver_client/
fi

# Run tests, skipping mutmut_skip marked tests
exec poetry run pytest tests/test_sliver_exec.py --tb=no -q -m "not mutmut_skip" "$@"
