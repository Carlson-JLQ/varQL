#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONDA_SH="/root/anaconda3/etc/profile.d/conda.sh"
ENV_NAME="varql"
NVD_API_KEY="bd2d6861-ecf3-4979-b22b-5cd33f1342e1"

if [[ ! -f "$CONDA_SH" ]]; then
  echo "Conda init script not found: $CONDA_SH" >&2
  exit 1
fi

source "$CONDA_SH"
conda activate "$ENV_NAME"

cd "$ROOT_DIR"

echo "[1/3] Running CodeQL docs fetcher..."
python3 scripts/codeql_docs_fetcher.py

echo "[2/3] Running CWE fetcher..."
python3 scripts/cwe_fetcher.py

echo "[3/3] Running CVE fetcher..."
python3 scripts/cves_fetcher.py --api-key="$NVD_API_KEY"

echo "Bootstrap completed."
