# MeshCore MQTT broker runbook

This deployment uses Docker Compose, reads settings from the existing `.env`, persists the abuse-detection SQLite database in the repository's `data/` directory, restarts after failures, and starts after a host reboot when Docker is enabled.

## Prerequisites

- Docker Engine with the Compose plugin (`docker compose version`)
- A completed `.env` in the repository root
- A runtime ACL file copied from `config/access-control.example.yaml`
- Port `MQTT_WS_PORT` (normally `8883`) available on host loopback

The `.env` is passed to the container at runtime. It is excluded from the image build context and is not copied into the image.

## First deployment

From the repository root:

```bash
chmod 600 .env
cp -n config/access-control.example.yaml config/access-control.yaml
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=100 broker
```

`restart: unless-stopped` makes the broker restart after a crash or Docker daemon restart. Enable Docker itself at boot:

```bash
sudo systemctl enable --now docker
```

After deploying, stop the copy running in `screen` so only the container owns the listening port. If it is still running during `docker compose up -d`, Docker will report that the port is already allocated.

## Routine operations

Check status and health:

```bash
docker compose ps
docker inspect --format '{{.State.Health.Status}}' meshcore-mqtt-broker
```

Follow or inspect logs:

```bash
docker compose logs -f --tail=100 broker
docker compose logs --since=1h broker
```

Restart or stop the broker:

```bash
docker compose restart broker
docker compose stop broker
docker compose up -d broker
```

Stopping it explicitly prevents `unless-stopped` from restarting it until it is started again.

## Deploy an update

```bash
docker compose build --pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 broker
```

Compose replaces the container but retains the `broker-data` volume.

## Change configuration

Edit `.env`, validate the Compose file, then recreate the container:

```bash
docker compose config --quiet
docker compose up -d --force-recreate broker
docker compose logs --tail=100 broker
```

Edit `config/access-control.yaml` to change the accepted IATAs or blocked observer public keys. The IATA allowlist rejects publish attempts after MQTT login; the observer blacklist rejects login and disconnects observers already connected when they are added. ACL updates are checked every five seconds and take effect without recreating the container. The live file is intentionally excluded from Git and the Docker image; only the example is tracked. Keep the YAML valid: rejected updates are logged and the broker retains the last valid ACL. Add `test` to `acceptedIatas` if the test topic region is needed.

Compose overrides `MQTT_HOST` to `0.0.0.0` inside the container so Docker can forward traffic to it, but publishes that port only as `127.0.0.1` on the host. The broker is therefore reachable by the host-local Caddy TLS proxy and not directly on a public host interface. Compose also maps the existing host `data/` directory to `/data` while overriding `ABUSE_PERSISTENCE_PATH`, so existing host-oriented values in `.env` remain compatible. The optional raw TCP listener binds to loopback inside the container and is not published to the host.

## Log rotation

The container uses Docker's `json-file` driver with `max-size: 10m` and `max-file: 5`. Its retained logs are therefore limited to approximately 50 MB. To change the cap, edit `compose.yaml` and recreate the container:

```bash
docker compose up -d --force-recreate broker
```

Do not edit or delete Docker's JSON log files directly. Use `docker compose logs` to read them.

## Data backup

For a consistent backup, stop the broker and archive its data directory:

```bash
docker compose stop broker
tar czf broker-data.tgz data
docker compose up -d broker
```

To restore, stop the broker and extract a trusted backup over `data/`. Preserve the current directory before overwriting it.

## Troubleshooting

```bash
docker compose ps
docker compose logs --tail=200 broker
docker compose port broker "${MQTT_WS_PORT:-8883}"
curl -I "http://127.0.0.1:${MQTT_WS_PORT:-8883}/"
```

The HTTP request should return the broker's `301` redirect. Common startup failures are missing `.env` values, the old `screen` process occupying the port, or an `ABUSE_PERSISTENCE_PATH` outside writable `/data`.

`docker compose ps` should show a binding beginning with `127.0.0.1:`. If it shows `0.0.0.0:`, do not expose the service until the Compose port mapping is corrected; Caddy is responsible for public access and TLS termination.

## Removal

`docker compose down` removes the container and network but retains broker state in `data/`.
