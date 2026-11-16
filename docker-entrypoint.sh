#!/bin/sh
# Fly volumes are mounted root-owned. Repair only the paths this app reads or writes.
set -eu

data_dir="${DATA_DIR:-/data}"
if [ "$data_dir" != "/data" ]; then
  echo "DATA_DIR must be /data in this container." >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  backup_dir="$data_dir/backups"
  mkdir -p "$backup_dir"
  chown node:node "$data_dir" "$backup_dir"

  find "$data_dir" -maxdepth 1 -type f \
    \( -name 'product-labels.sqlite' -o -name 'product-labels.sqlite-wal' -o -name 'product-labels.sqlite-shm' -o -name 'product-labels.sqlite-journal' \) \
    -exec chown node:node -- {} +
  find "$backup_dir" -maxdepth 1 -type f -exec chown node:node -- {} +

  exec setpriv --reuid=node --regid=node --init-groups "$@"
fi

exec "$@"
