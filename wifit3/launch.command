#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
export PYTHONPATH="$PWD/../osint-vault-relay${PYTHONPATH:+:$PYTHONPATH}"
exec uv run --project "$PWD" --python 3.12 wifit3 "$@"
