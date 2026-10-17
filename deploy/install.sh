#!/usr/bin/env bash
# Install or upgrade meshcore-hub on the VM. Run as root from the unpacked
# bundle that deploy/deploy.sh copies over. Safe to run again.
set -euo pipefail
cd "$(dirname "$0")"

id meshcore-hub >/dev/null 2>&1 ||
	useradd --system --home-dir /var/lib/meshcore-hub --no-create-home --shell /usr/sbin/nologin meshcore-hub
id meshcore-portal >/dev/null 2>&1 ||
	useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin meshcore-portal
usermod -a -G meshcore-hub meshcore-portal

if ! command -v caddy >/dev/null; then
	apt-get update -q
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q caddy sqlite3
fi

# Work out what changed, so a portal-only update does not drop repeater sessions.
differs() { ! cmp -s "$1" "$2"; }
restart_hubd=0
restart_portal=0
reload_hubd=0
{ differs meshcore-hubd /usr/local/bin/meshcore-hubd || differs meshcore-hubd.service /etc/systemd/system/meshcore-hubd.service; } && restart_hubd=1
{ differs meshcore-portal /usr/local/bin/meshcore-portal || differs meshcore-portal.service /etc/systemd/system/meshcore-portal.service; } && restart_portal=1
differs hub.toml /etc/meshcore-hub/hub.toml && reload_hubd=1
[ -n "${RESTART:-}" ] && restart_hubd=1 && restart_portal=1

install -m 0755 meshcore-hubd meshcore-portal /usr/local/bin/
install -d -m 0750 -o root -g meshcore-hub /etc/meshcore-hub
install -m 0640 -o root -g meshcore-hub hub.toml /etc/meshcore-hub/hub.toml
if [ ! -f /etc/meshcore-hub/hub.key ]; then
	echo "generating the hub identity"
	meshcore-hubd genkey /etc/meshcore-hub/hub.key >/dev/null
fi
chown root:root /etc/meshcore-hub/hub.key
chmod 0600 /etc/meshcore-hub/hub.key
meshcore-hubd -c /etc/meshcore-hub/hub.toml check

install -m 0644 meshcore-hubd.service meshcore-portal.service /etc/systemd/system/
if ! cmp -s Caddyfile /etc/caddy/Caddyfile; then
	install -m 0644 Caddyfile /etc/caddy/Caddyfile
	caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
	systemctl reload-or-restart caddy
fi

systemctl daemon-reload
systemctl enable meshcore-hubd meshcore-portal caddy >/dev/null 2>&1
if [ $restart_hubd = 1 ] || ! systemctl is-active -q meshcore-hubd; then
	echo "restarting meshcore-hubd (repeaters reconnect on their own)"
	systemctl restart meshcore-hubd
elif [ $reload_hubd = 1 ]; then
	# SIGHUP re-reads the allowlist without dropping sessions. Other hub.toml
	# settings need a restart: RESTART=1 deploy/deploy.sh
	echo "reloading the allowlist"
	systemctl reload meshcore-hubd
else
	echo "meshcore-hubd unchanged, sessions kept"
fi
if [ $restart_portal = 1 ] || ! systemctl is-active -q meshcore-portal; then
	echo "restarting meshcore-portal"
	systemctl restart meshcore-portal
fi
sleep 1
systemctl --no-pager --lines=0 status meshcore-hubd meshcore-portal caddy | grep -E "●|Active:"
echo "hub public key (backbone_hub_key): $(meshcore-hubd -c /etc/meshcore-hub/hub.toml pubkey)"
