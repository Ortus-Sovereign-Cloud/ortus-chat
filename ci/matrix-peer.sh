#!/usr/bin/env bash
# An independent Matrix server for tests: Dendrite in a container on the
# host's network, named peer.test, federating with TLS on 127.0.0.2:8448
# and answering its client API on 127.0.0.2:8008. A throwaway CA signs a
# certificate for peer.test and one for the test's Ortus (ortus1.test and
# ortus2.test, one name per installation the test makes, federating on
# 127.0.0.1:8448); Dendrite trusts that CA and finds both at 127.0.0.1.
# Prints the settings for the test.
#
#   ci/matrix-peer.sh <directory> | stop
set -euo pipefail
name=ortus-matrix-peer
image=matrixdotorg/dendrite-monolith:v0.13.8
if [ "${1:-}" = stop ]; then
  docker rm -f "$name" >/dev/null 2>&1 || true
  exit 0
fi
dir=$(realpath -m "${1:?a directory for the certificates and the peer data}")
mkdir -p "$dir/dendrite"
cd "$dir"
# The CA and the two server certificates.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Ortus test CA" -keyout ca.key -out ca.pem 2>/dev/null
for host in peer.test ortus.test; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$host" -keyout "$host.key" -out "$host.csr" 2>/dev/null
  if [ "$host" = ortus.test ]; then san="DNS:ortus1.test,DNS:ortus2.test"; else san="DNS:$host"; fi
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" > "$host.ext"
  openssl x509 -req -in "$host.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile "$host.ext" -out "$host.pem" 2>/dev/null
done
cp peer.test.pem peer.test.key ca.pem dendrite/
chmod 644 dendrite/*
docker run --rm --entrypoint /usr/bin/generate-config "$image" -ci -server peer.test -dir /etc/dendrite \
  | sed "s/registration_disabled: false/registration_disabled: true/" > dendrite/dendrite.yaml
docker run --rm --entrypoint /usr/bin/generate-keys -v "$dir/dendrite:/etc/dendrite" "$image" --private-key /etc/dendrite/matrix_key.pem >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network host --add-host ortus1.test:127.0.0.1 --add-host ortus2.test:127.0.0.1 \
  -e SSL_CERT_FILE=/etc/dendrite/ca.pem -v "$dir/dendrite:/etc/dendrite" "$image" \
  --config /etc/dendrite/dendrite.yaml --http-bind-address 127.0.0.2:8008 --https-bind-address 127.0.0.2:8448 \
  --tls-cert /etc/dendrite/peer.test.pem --tls-key /etc/dendrite/peer.test.key >/dev/null
for _ in $(seq 1 60); do
  curl -sf http://127.0.0.2:8008/_matrix/client/versions >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.2:8008/_matrix/client/versions >/dev/null || { docker logs "$name" | tail -40 >&2; exit 1; }
password=$(openssl rand -hex 12)
docker exec "$name" /usr/bin/create-account -config /etc/dendrite/dendrite.yaml -url http://127.0.0.2:8008 -username bob -password "$password" >/dev/null 2>&1
cat <<EOF
export ORTUS_TEST_MATRIX=http://127.0.0.2:8008
export ORTUS_TEST_MATRIX_SERVER=peer.test
export ORTUS_TEST_MATRIX_USER=bob
export ORTUS_TEST_MATRIX_PASSWORD=$password
export ORTUS_FEDERATION_LISTEN=127.0.0.1:8448
export ORTUS_FEDERATION_TLS_CERT=$dir/ortus.test.pem
export ORTUS_FEDERATION_TLS_KEY=$dir/ortus.test.key
export ORTUS_FEDERATION_CA=$dir/ca.pem
export ORTUS_FEDERATION_HOSTS=peer.test=127.0.0.2:8448
EOF
