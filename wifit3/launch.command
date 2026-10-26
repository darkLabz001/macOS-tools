#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
exec uv run --project "$PWD" --python 3.12 wifit3 "$@"
