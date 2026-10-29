#!/bin/sh
# php2shell lab entrypoint wrapper.
#
# The host bind-mounts runtime/out, which Docker creates as root. The Apache
# worker runs as www-data, so hand it ownership before starting the server.
# Everything else is delegated to the official image entrypoint, keeping the
# lab as close to a stock php:8.4.x-apache container as possible.
set -eu

mkdir -p /out
chown -R www-data:www-data /out 2>/dev/null || true

exec docker-php-entrypoint "$@"
