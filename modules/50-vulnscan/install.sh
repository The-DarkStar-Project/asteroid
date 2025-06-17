#!/bin/sh
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

apt install -y firefox-esr

uv tool install wappalyzer
uv pip install -r "$SCRIPT_DIR/requirements.txt"
