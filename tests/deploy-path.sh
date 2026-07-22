#!/usr/bin/env bash
set -Eeuo pipefail

declare -A observed=()
for _ in $(seq 1 32); do
  path="$(bash deploy.sh --generate-path)"
  [[ "$path" =~ ^/[abcdefghjkmnpqrstuvwyz][a-f0-9]{48}/$ ]]
  [[ "$path" != /x* && "$path" != /X* ]]
  [[ -z "${observed[$path]:-}" ]]
  observed[$path]=1
done

printf 'random management path tests passed\n'
