#!/bin/sh
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

apt install -y firefox-esr sudo git

uv tool install wappalyzer
uv pip install -r "$SCRIPT_DIR/requirements.txt"

cd "$SCRIPT_DIR/search_vulns/"
git submodule update --init --recursive
bash install.sh