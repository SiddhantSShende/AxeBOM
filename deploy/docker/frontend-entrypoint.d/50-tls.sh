#!/bin/sh
# Toggles the SSL placeholders nginx.conf ships with, based on whether a cert
# is actually mounted at /etc/nginx/tls — see the ⚠ comment on the `listen`
# directive in deploy/docker/nginx.conf for why this can't be done inside
# nginx's own config language. Runs automatically: this base image executes
# every executable *.sh under /docker-entrypoint.d/ before starting nginx.
set -eu

conf=/etc/nginx/conf.d/default.conf
crt=/etc/nginx/tls/frontend.crt
key=/etc/nginx/tls/frontend.key

if [ -f "$crt" ] && [ -f "$key" ]; then
	echo "50-tls.sh: $crt found, serving :8085 over TLS"
	sed -i "s#__SSL_LISTEN_SUFFIX__#ssl#" "$conf"
	# One line, deliberately: BusyBox sed's handling of an embedded newline in
	# a replacement is not reliably portable, and nginx directives only need a
	# terminating `;` each, not a line of their own.
	sed -i "s#__SSL_CERTIFICATE_DIRECTIVES__#ssl_certificate $crt; ssl_certificate_key $key;#" "$conf"
else
	echo "50-tls.sh: no cert at $crt, serving :8085 over plain HTTP"
	sed -i "s#__SSL_LISTEN_SUFFIX__##" "$conf"
	sed -i "/__SSL_CERTIFICATE_DIRECTIVES__/d" "$conf"
fi
