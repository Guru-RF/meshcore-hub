#!/usr/bin/env bash
# Build, copy to the meshcore-hub VM over IAP SSH, and install.
#   deploy/deploy.sh            build + install
#   SKIP_BUILD=1 deploy/deploy.sh   install what is in dist/
#   RESTART=1 deploy/deploy.sh      also restart services whose files did not change
# Only services whose binary or unit changed are restarted; a hub.toml change
# alone reloads the allowlist without dropping repeater sessions.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT=${PROJECT:-customer-uba}
ZONE=${ZONE:-europe-west1-b}
VM=${VM:-meshcore-hub}
GC=(--project "$PROJECT" --zone "$ZONE" --tunnel-through-iap)

[ -n "${SKIP_BUILD:-}" ] || deploy/build.sh

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp dist/meshcore-hubd dist/meshcore-portal "$stage/"
cp deploy/hub.toml deploy/install.sh deploy/meshcore-hubd.service deploy/meshcore-portal.service deploy/Caddyfile "$stage/"
tar -C "$stage" -czf "$stage.tgz" .
trap 'rm -rf "$stage" "$stage.tgz"' EXIT

gcloud compute scp "${GC[@]}" "$stage.tgz" "$VM:/tmp/meshcore-hub-bundle.tgz"
gcloud compute ssh "${GC[@]}" "$VM" --command \
	'set -e; d=$(mktemp -d); tar -C "$d" -xzf /tmp/meshcore-hub-bundle.tgz; sudo RESTART='"${RESTART:-}"' "$d/install.sh"; rm -rf "$d" /tmp/meshcore-hub-bundle.tgz'
