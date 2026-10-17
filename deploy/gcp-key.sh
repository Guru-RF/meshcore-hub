#!/usr/bin/env bash
# Back up the hub's private key to Google Secret Manager, or restore it onto
# a (new) VM. The key travels VM <-> Secret Manager through a pipe: it is never
# written to disk or shown on the machine that runs this script.
#
#   deploy/gcp-key.sh backup    add the VM's key as a new secret version
#                               (creates the secret, pinned to the VM's region)
#   deploy/gcp-key.sh restore   write the latest secret version onto the VM;
#                               run it before the first deploy on a new VM
#   deploy/gcp-key.sh verify    check that the VM's key matches the secret
#
# Override PROJECT, ZONE, VM, SECRET (and REGION) for another installation.
set -euo pipefail

PROJECT=${PROJECT:-customer-uba}
ZONE=${ZONE:-europe-west1-b}
REGION=${REGION:-${ZONE%-*}}
VM=${VM:-meshcore-hub}
SECRET=${SECRET:-meshcore-hub-key}
KEY=/etc/meshcore-hub/hub.key
SSH=(gcloud compute ssh "$VM" --project "$PROJECT" --zone "$ZONE" --tunnel-through-iap --quiet --command)

vm_sum() { "${SSH[@]}" "sudo sha256sum $KEY 2>/dev/null" 2>/dev/null | cut -d' ' -f1; }
secret_sum() { gcloud secrets versions access latest --secret "$SECRET" --project "$PROJECT" | sha256sum | cut -d' ' -f1; }

case "${1:-}" in
backup)
	if ! gcloud secrets describe "$SECRET" --project "$PROJECT" >/dev/null 2>&1; then
		gcloud secrets create "$SECRET" --project "$PROJECT" \
			--replication-policy user-managed --locations "$REGION" \
			--labels app=meshcore-hub
	fi
	"${SSH[@]}" "sudo cat $KEY" 2>/dev/null |
		gcloud secrets versions add "$SECRET" --project "$PROJECT" --data-file=-
	;;
restore)
	gcloud secrets versions access latest --secret "$SECRET" --project "$PROJECT" |
		"${SSH[@]}" "sudo install -d -m 0755 /etc/meshcore-hub && sudo install -m 0600 -o root -g root /dev/stdin $KEY" 2>/dev/null
	;;
verify) ;;
*)
	echo "usage: $0 backup|restore|verify" >&2
	exit 2
	;;
esac

vm=$(vm_sum)
sec=$(secret_sum)
if [ -n "$vm" ] && [ "$vm" = "$sec" ]; then
	echo "ok: $VM:$KEY matches the latest version of secret $SECRET"
else
	echo "MISMATCH: $VM:$KEY ${vm:-<missing>} vs secret $SECRET $sec" >&2
	exit 1
fi
