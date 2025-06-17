#!/bin/sh
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
uv pip install -r ${SCRIPT_DIR}/requirements.txt