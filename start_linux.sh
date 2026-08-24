#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
: "${UTAMO_HOST:=127.0.0.1}"
: "${UTAMO_PM3_MODE:=ANALYSIS_ONLY}"
export UTAMO_HOST UTAMO_PM3_MODE
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
