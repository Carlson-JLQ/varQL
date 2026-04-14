#!/bin/bash
# Usage: ./run_cve.sh <CVE-ID> [extra args]
# Example: ./run_cve.sh CVE-2025-27818 --max-iteration 10
# Example (ablation): ./run_cve.sh CVE-2025-27818 --ablation-mode no_tools
# Ablation modes: full, no_tools, no_lsp, no_docs, no_ast

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <CVE-ID> [extra args]"
  exit 1
fi

CVE=$1
shift

docker compose run --rm app python3 src/ql_agent.py \
  --cve-id "$CVE" \
  --vuln-db "cves/$CVE/${CVE}-vul" \
  --fixed-db "cves/$CVE/${CVE}-fix" \
  --diff "cves/$CVE/${CVE}.diff" \
  "$@"
