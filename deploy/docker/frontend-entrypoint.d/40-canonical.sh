#!/bin/sh
# Templates nginx.conf's __CANONICAL_REDIRECT__ placeholder from
# ZITADEL_PUBLIC_URL — see that placeholder's own comment in
# deploy/docker/nginx.conf for why a non-canonical origin has to be redirected
# rather than served. Runs automatically: this base image executes every
# executable *.sh under /docker-entrypoint.d/ before starting nginx.
#
# Numbered 40 so it runs before 50-tls.sh. The two are independent — they
# rewrite different placeholders — but keeping the origin decision ahead of the
# TLS decision matches the order they are read in.
set -eu

conf=/etc/nginx/conf.d/default.conf

# Unset or empty is the correct default, not an error: a deployment that has
# not been given a public URL has no canonical origin to redirect TO, and
# guessing one would be worse than serving whatever host was asked for.
url="${ZITADEL_PUBLIC_URL:-}"
if [ -z "$url" ]; then
	echo "40-canonical.sh: ZITADEL_PUBLIC_URL unset, serving every Host as-is"
	sed -i "/__CANONICAL_REDIRECT__/d" "$conf"
	exit 0
fi

# host:port, exactly as the browser sends it in the Host header — $http_host
# keeps the port, which is what makes the comparison below correct on a
# non-443 origin like :5173. Strip the scheme and anything from the first
# path slash on.
host="${url#*://}"
host="${host%%/*}"

echo "40-canonical.sh: canonical origin is $url, redirecting other hosts to it"

# ⚠ ONE LINE, for the same reason 50-tls.sh's replacement is one line: BusyBox
# sed's handling of an embedded newline in a replacement is not portable.
# nginx needs only a terminating `;` per directive, not a line of its own.
#
# `if` with `return` is one of the two uses of `if` that are safe in a server
# block (the other being `rewrite ... last`); this is not the "if is evil"
# case, which is about `if` wrapping other directives.
#
# error_page 497 covers the plain-HTTP-to-TLS-port case, which nginx answers
# before the rewrite phase this `if` runs in. Given an ABSOLUTE url nginx
# issues a 302 for it, matching the `if` above. Both arrive at the same place,
# so it does not matter which one fires.
sed -i "s#__CANONICAL_REDIRECT__#if (\$http_host != \"$host\") { return 302 $url\$request_uri; } error_page 497 $url\$request_uri;#" "$conf"
