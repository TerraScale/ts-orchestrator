#!/usr/bin/env bash
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=ts-e2e-ca -addext keyUsage=critical,keyCertSign,cRLSign \
	-keyout ca.key -out ca.pem 2>/dev/null
leaf() {
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
	openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -days 90 -extfile <(echo "subjectAltName=$2") -out "$1.pem" 2>/dev/null
}
