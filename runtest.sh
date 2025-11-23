#!/bin/bash
set -e
cd /workspaces/sliver-nxc-module && python -m  pytest -q --disable-warnings --maxfail=1 --cov=sliver_exec --cov-report=term-missing
