#!/usr/bin/env bash
# Prove that common Apache/PHP and nginx/PHP-FPM origins execute PHP before
# PATH_INFO ending in an inert extension. Requires Docker and curl.
set -euo pipefail

cd "$(dirname "$0")/.."
fixture=$(mktemp -d "$PWD/ci/.static-pathinfo.XXXXXX")
name="wph-pathinfo-$(basename "$fixture" | tr '.' '-')"
chmod 755 "$fixture"
cleanup() {
	docker rm -f "$name-apache" "$name-nginx" "$name-fpm" >/dev/null 2>&1 || true
	docker network rm "$name-net" >/dev/null 2>&1 || true
	rm -rf "${fixture:?}"
}
trap cleanup EXIT

cat >"$fixture/wp-config.php" <<'PHP'
<?php header('Content-Type: text/plain'); echo 'SENSITIVE_' . 'EXECUTED';
PHP
mkdir "$fixture/wp-admin"
cp "$fixture/wp-config.php" "$fixture/wp-admin/install.php"
printf 'body { color: red; }\n' >"$fixture/style.css"
cat >"$fixture/nginx.conf" <<'NGINX'
events {}
http {
  server {
    listen 80;
    root /var/www/html;
    location ~ \.php(?:/|$) {
      fastcgi_split_path_info ^(.+?\.php)(/.*)$;
      try_files $fastcgi_script_name =404;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      fastcgi_param PATH_INFO $fastcgi_path_info;
      fastcgi_pass __FPM__:9000;
    }
    location / { try_files $uri =404; }
  }
}
NGINX
sed -i "s/__FPM__/$name-fpm/" "$fixture/nginx.conf"

docker network create "$name-net" >/dev/null
docker run -d --rm --name "$name-apache" -p 127.0.0.1::80 \
	-v "$fixture:/var/www/html:ro" php@sha256:c2c73159da2f7a19167a2849bd9785ca9ad4f5eeff01f85295ef861a5e9bcf4d >/dev/null
docker run -d --rm --name "$name-fpm" --network "$name-net" \
	-v "$fixture:/var/www/html:ro" php@sha256:e436b5b6ce4a4e632f97a66ea0ea14c5d001e229e2adc5c8ed2f7b5b5fe5c989 >/dev/null
docker run -d --rm --name "$name-nginx" --network "$name-net" \
	-p 127.0.0.1::80 -v "$fixture:/var/www/html:ro" \
	-v "$fixture/nginx.conf:/etc/nginx/nginx.conf:ro" nginx@sha256:62ff2089abf5a9ed33bd232895bef5e22f7bb4b200675cec49a5ebc48e3d4ac8 >/dev/null

probe() {
	local engine=$1 path=$2 expected_status=$3 expected_body=$4 port status
	port=$(docker port "$name-$engine" 80/tcp)
	port=${port##*:}
	for _ in $(seq 1 30); do
		status=$(curl --path-as-is -sS -o "$fixture/response" -w '%{http_code}' \
			"http://127.0.0.1:$port$path" 2>/dev/null) || status=000
		[ "$status" = "$expected_status" ] && break
		sleep 1
	done
	if [ "$status" != "$expected_status" ]; then
		printf '%s %s: expected HTTP %s, got %s\n' "$engine" "$path" "$expected_status" "$status" >&2
		exit 1
	fi
	if [ "$expected_body" = marker ] && ! marker_oracle "$fixture/response"; then
		printf '%s %s: PHP execution marker absent\n' "$engine" "$path" >&2
		exit 1
	fi
	if [ "$expected_body" = static ] && ! grep -q 'body { color: red; }' "$fixture/response"; then
		printf '%s %s: static asset body absent\n' "$engine" "$path" >&2
		exit 1
	fi
	printf '%s %s: HTTP %s %s\n' "$engine" "$path" "$status" "$expected_body"
}

marker_oracle() {
	[ "$(cat "$1")" = SENSITIVE_EXECUTED ]
}

# A raw PHP source response must never satisfy the execution oracle.
cp "$fixture/wp-config.php" "$fixture/response"
if marker_oracle "$fixture/response"; then
	echo 'Raw PHP source passed execution oracle' >&2
	exit 1
fi
echo 'Raw PHP source rejected by execution oracle'

for engine in apache nginx; do
	probe "$engine" /wp-config.php/extra.css 200 marker
	probe "$engine" /wp-config.php/extra.js 200 marker
	probe "$engine" /wp-admin/install.php/extra.js 200 marker
	probe "$engine" /style.css 200 static
	probe "$engine" /style.css/extra.js 404 none
	probe "$engine" /missing.php/extra.css 404 none
done
