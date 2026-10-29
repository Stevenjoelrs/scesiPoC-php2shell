#!/bin/sh
# php2shell lab entrypoint wrapper.
#
# The host bind-mounts runtime/out. On Linux this chown is enough to let the
# Apache worker (www-data) write proofs. Docker Desktop's VirtioFS ignores
# ownership changes on bind mounts, so the Makefile also makes the host
# directories world-writable for local labs.
set -eu

mkdir -p /out
chown -R www-data:www-data /out 2>/dev/null || true

exec docker-php-entrypoint "$@"
