#!/bin/sh
set -eu

cd -- "$(dirname -- "$0")"

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' '需要 Node.js >= 22，請先安裝 Node.js。' >&2
  exit 1
fi

if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
  printf '%s\n' '需要 Node.js >= 22，請先更新 Node.js。' >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  printf '%s\n' '找不到 npm，請先安裝 npm。' >&2
  exit 1
fi

npm ci --include=dev
npm run build
exec node dist/main.js "$@"
