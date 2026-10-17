# Running a hub on Google Cloud

This guide sets up a meshcore-hub on Google Cloud the way `be.mesh73.net` runs.
Use it to start a hub for your own region or to rebuild this one: one small
VM, a static IP, a firewall rule, and the hub's private key backed up in
Secret Manager.

**Why a VM and not Cloud Run:** the backbone is UDP, repeaters keep long-lived
sessions from behind NAT, and the hub must be a single stateful process.
Cloud Run takes no inbound UDP, caps connections at 60 minutes, and briefly
runs two instances during a deploy.

## What you need

- **A Google Cloud project** with billing, and the `gcloud` CLI logged in.
  You need Compute and Secret Manager admin rights on the project.
- **Docker** on your machine. The binaries are built in a Debian 13
  container, so they match the VM.
- **A DNS name** for the portal, for example `xx.mesh73.net`.

The examples use the values of the Belgian hub. Replace them with your own:

```sh
export PROJECT=customer-uba
export REGION=europe-west1          # St. Ghislain, Belgium
export ZONE=europe-west1-b
export VM=meshcore-hub
export SECRET=meshcore-hub-key
```

`deploy/deploy.sh` and `deploy/gcp-key.sh` read `PROJECT`, `ZONE`, `VM` and
`SECRET` from the environment, with these values as defaults.

## 1. Static IP, VM and firewall

```sh
gcloud compute addresses create $VM --project $PROJECT --region $REGION --network-tier PREMIUM

gcloud compute instances create $VM --project $PROJECT --zone $ZONE \
  --machine-type e2-small \
  --image-family debian-13 --image-project debian-cloud \
  --boot-disk-size 20GB --boot-disk-type pd-balanced \
  --address $(gcloud compute addresses describe $VM --project $PROJECT --region $REGION --format 'value(address)') \
  --tags http-server,https-server,meshcore-hub \
  --labels app=meshcore-hub \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

# Repeaters connect from dynamic home and 4G addresses, so the port is open to all.
# Datagrams from keys that are not on the allowlist are dropped unanswered.
gcloud compute firewall-rules create meshcore-backbone --project $PROJECT \
  --network default --direction INGRESS --action ALLOW --rules udp:4405 \
  --source-ranges 0.0.0.0/0 --target-tags meshcore-hub
```

**Sizing:** an e2-small (2 shared vCPU, 2 GB) is plenty for a few dozen
repeaters. The hub uses a few MB of RAM. To resize later, stop the VM, run
`gcloud compute instances set-machine-type`, and start it again. The static
IP stays.

**Ports 80 and 443:** the `http-server` and `https-server` tags open them
for Caddy and Let's Encrypt. That assumes the project has the default
`default-allow-http` and `default-allow-https` rules. If it doesn't, create
equivalent rules.

**Cost:** roughly US$20 a month in europe-west1 (VM ~14, static IP ~3.65,
disk ~2). Secret Manager is effectively free at one secret.

## 2. DNS

Point an `A` record for your portal name at the static IP:

```sh
gcloud compute addresses describe $VM --project $PROJECT --region $REGION --format 'value(address)'
```

Wait until it resolves before the first deploy. Caddy requests the TLS
certificate as soon as it starts.

## 3. Configure

- **`deploy/hub.toml`** is the allowlist (`[[repeater]]` entries with callsign,
  `pub=` key and roles) and the public channels the portal decodes.
- **`deploy/Caddyfile`:** replace `be.mesh73.net` with your portal name.

## 4. Deploy

```sh
deploy/deploy.sh
```

This:

- builds the binaries in a container;
- copies them to the VM over IAP SSH (no port 22 needs to be open to the
  internet);
- runs `deploy/install.sh` on the VM.

On the first install, `install.sh` generates the hub's identity in
`/etc/meshcore-hub/hub.key` and prints its public key. Repeaters pin that
public key as `backbone_hub_key`.

## 5. Back up the hub key: do this right after the first deploy

Every repeater trusts exactly one hub key. If `hub.key` is lost with the VM,
each repeater operator has to change their config. Keep a copy in Secret
Manager:

```sh
deploy/gcp-key.sh backup
```

This:

- creates the secret `$SECRET` the first time, pinned to the VM's region so
  the key stays there;
- adds the VM's key as a new version;
- verifies it byte for byte with a checksum.

The key goes from the VM into Secret Manager through a pipe. It is never
written to disk or shown on your machine.

`deploy/gcp-key.sh verify` checks at any time that the VM and the backup
still match.

**Who can read it:** project owners and anyone you grant
`roles/secretmanager.secretAccessor` on the secret. The VM itself needs no
access: it keeps its own copy, root-only (mode 0600). The service reads it
through systemd `LoadCredential=`.

## Rebuilding or moving the VM

Restore the key **before** the first deploy. `install.sh` only generates a
key when none exists, so a deploy to an empty VM would create a new
identity.

```sh
# create the VM as in step 1, then:
deploy/gcp-key.sh restore     # writes /etc/meshcore-hub/hub.key (0600, root) and verifies it
deploy/deploy.sh
```

Check that the deploy prints the same `hub public key` as before. If it
does, repeaters reconnect on their own: they re-resolve the host name on
every attempt.

## If the key leaks

Anyone with the hub key can pose as the hub towards the repeaters. They are
still limited by each repeater's content policy and rate limit.

1. On the VM, as root, stop the hub, generate a new key and restart:

   ```sh
   systemctl stop meshcore-hubd
   rm /etc/meshcore-hub/hub.key
   meshcore-hubd genkey /etc/meshcore-hub/hub.key
   systemctl start meshcore-hubd
   ```

2. Run `deploy/gcp-key.sh backup` to store the new key, then disable the old
   version:

   ```sh
   gcloud secrets versions disable <n> --secret $SECRET --project $PROJECT
   ```

3. Give every repeater operator the new `backbone_hub_key`. The portal's Join
   tab shows it.

## Day to day

| Task | How |
|---|---|
| SSH | `gcloud compute ssh $VM --project $PROJECT --zone $ZONE --tunnel-through-iap` |
| Logs | `journalctl -u meshcore-hubd -u meshcore-portal -f` |
| Add or remove a repeater | Edit `deploy/hub.toml`, then run `deploy/deploy.sh`. |
| Hub public key | `sudo meshcore-hubd pubkey`, or the portal's Join tab. |
