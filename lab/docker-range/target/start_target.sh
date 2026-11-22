#!/usr/bin/env bash
set -euo pipefail

mkdir -p /etc/nginx/certs /out
# Generate self-signed cert with O=ARTEX to test Suricata sid:9100013 and TLS SNI/sawtooth capture
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/nginx/certs/target.key \
  -out /etc/nginx/certs/target.crt \
  -days 365 \
  -subj "/CN=172.30.0.20/O=ARTEX" >/dev/null 2>&1

cp /target/nginx.conf /etc/nginx/nginx.conf
: > /out/nginx_access.log
chown www-data:www-data /out/nginx_access.log
chmod 644 /out/nginx_access.log

python3 /target/app.py &
exec nginx -g "daemon off;"
