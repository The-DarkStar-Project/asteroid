#!/bin/sh
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

uv pip install -r ${SCRIPT_DIR}/requirements.txt