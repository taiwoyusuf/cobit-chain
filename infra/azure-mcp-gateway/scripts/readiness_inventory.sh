#!/usr/bin/env bash
set -euo pipefail

# Gateway R1 deployment-readiness inventory only.
# This script performs read-only Azure CLI queries and deliberately avoids
# RBAC changes, secret/key retrieval, connection-string retrieval, and resource mutations.

command -v az >/dev/null 2>&1 || {
  echo "Azure CLI (az) is required." >&2
  exit 1
}

az account show --output json
az account list --output json
az group list --output json
az containerapp env list --output json
az containerapp list --output json

printf '%s\n' "Gateway R1 readiness inventory complete. No Azure mutations were requested."
