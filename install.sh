#!/bin/bash

dashes() {
    COLS=$(tput cols)
    printf -- '-%0.s' $(seq 1 $COLS)
}

# General dependencies
dashes
echo "Installing general dependencies"
dashes
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"' >> $HOME/.bashrc

apt update && apt install -y python3 golang curl # python3-pip pypy3-venv
# UV
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
uv pip install -r requirements.txt

# Loop over other installation scripts
scripts=$(find modules -maxdepth 2 -mindepth 2 -name install.sh | sort)
num_scripts=$(echo "$scripts" | wc -l)
# Convert to array
IFS=$'\n' read -d '' -r -a scripts <<< "$scripts"

for i in $(seq 0 $(($num_scripts-1))); do
    script=${scripts[$i]}
    modulename=$(dirname "$script")
    dashes
    echo "[$(($i+1))/$num_scripts] Running $modulename install script: $script"
    dashes
    bash "$script"
done