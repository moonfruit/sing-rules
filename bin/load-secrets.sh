#!/usr/bin/env bash
# Decrypt sops-encrypted dotenv file and emit KEY=VALUE lines on stdout.
# Skips blank lines and comments. Caller decides how to consume the output:
#   - GitHub Actions: pipe into a loop that masks values and appends to $GITHUB_ENV
#   - Local shell:    set -a; source <(./bin/load-secrets.sh); set +a
set -euo pipefail

FILE="${1:-config/secrets.env}"

sops -d "$FILE" | while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    printf '%s\n' "$line"
done
