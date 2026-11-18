# Self-hosting Airport

Airport is one Rust binary and one SQLite file. It needs no external database,
queue, or cloud account.

## Configuration location

| Deployment | File |
| --- | --- |
| Local / Docker Compose | `<repository>/.env` |
| systemd | `/etc/ekravo-airport/airport.env` |
| Any other path | `AIRPORT_ENV_FILE=/absolute/path/to/file` |
| Platform-as-a-service | Provider environment/secret settings |

Real environment variables take precedence over the file. Every setting is
documented in [`.env.example`](../.env.example). The only required value is
`AIRPORT_JWT_SECRET`.

```bash
cp .env.example .env
# dotenvy applies the first declaration, so replace the empty placeholder
# instead of appending a second AIRPORT_JWT_SECRET line.
sed -i "s|^AIRPORT_JWT_SECRET=.*|AIRPORT_JWT_SECRET=$(openssl rand -base64 48)|" .env
chmod 600 .env
```

Do not commit `.env`. It is already in `.gitignore`.

## Run from source

Rust 1.89 or newer is required; that floor is declared in `Cargo.toml` and tested
in CI.

```bash
cargo run --release --locked -p airport-server
```

Or build and install:

```bash
cargo build --release -p airport-server
sudo install -m 0755 target/release/airport /usr/local/bin/airport
```

Health checks:

```bash
curl -fsS http://127.0.0.1:8787/healthz
curl -fsS http://127.0.0.1:8787/readyz
```

## Docker

Build and run the image:

```bash
docker build -t ekravo-airport:0.1.0 .
docker run -d --name airport \
  --restart unless-stopped \
  -p 127.0.0.1:8787:8787 \
  -v airport-data:/var/lib/airport \
  --env-file .env \
  -e AIRPORT_DATABASE_URL=sqlite:///var/lib/airport/airport.db \
  ekravo-airport:0.1.0
```

The image runs as UID 10001, has a healthcheck, and stores SQLite in
`/var/lib/airport`. The image already defaults the database to that path; the
`-e` line makes it explicit and matches Compose. It also works without
`--env-file` if you pass `-e AIRPORT_JWT_SECRET=…` directly.

Confirm the container is actually serving:

```bash
docker inspect --format '{{.State.Health.Status}}' airport
curl -fsS http://127.0.0.1:8787/healthz
curl -fsS http://127.0.0.1:8787/readyz
docker logs --tail 5 airport
```

The health status is `healthy` only after `/healthz` answers inside the
container. The first check runs after the 10-second start period.

The image healthcheck defaults to `http://127.0.0.1:8787/healthz`. If Airport
serves TLS itself, point the probe at the encrypted listener and give it the CA
that signed the certificate. It verifies the certificate; it never uses `-k`:

```bash
-e AIRPORT_HEALTHCHECK_URL=https://127.0.0.1:8787/healthz \
-e AIRPORT_HEALTHCHECK_CA=/certs/ca.pem
```

Restart against the same named volume and confirm state survives:

```bash
docker stop airport      # SIGTERM; logs "shutdown requested" and exits cleanly
docker start airport
docker inspect --format '{{.State.Health.Status}}' airport
```

Paired devices, grants, and queued messages live in the volume. After a restart
a device reconnects with its existing credential and the server logs
`replaying the mailbox` for anything it had not acknowledged. No re-pairing is
needed.

A named volume inherits the ownership of `/var/lib/airport` from the image, so it
is writable by UID 10001 without extra steps. A bind mount does not: give it the
same owner first.

```bash
mkdir -p ./airport-data
sudo chown -R 10001:10001 ./airport-data
docker run -d --name airport \
  -p 127.0.0.1:8787:8787 \
  -v "$PWD/airport-data:/var/lib/airport" \
  --env-file .env \
  ekravo-airport:0.1.0
```

On Windows with Git Bash, MSYS rewrites Linux-looking arguments. Prefix commands
that pass container paths or `-e` values (`docker exec`, `AIRPORT_ENV_FILE=…`)
with `MSYS_NO_PATHCONV=1`, and pass host mount sources as Windows paths (for
example `$(cygpath -w "$PWD/tls")`). Without this, an env file appears to be
missing inside the container.

### Docker Compose (plaintext)

```bash
cp .env.example .env
sed -i "s|^AIRPORT_JWT_SECRET=.*|AIRPORT_JWT_SECRET=$(openssl rand -base64 48)|" .env
docker compose -p airport up -d --build
docker compose -p airport ps
docker inspect --format '{{.State.Health.Status}}' airport-airport-1
curl -fsS http://127.0.0.1:8787/healthz
curl -fsS http://127.0.0.1:8787/readyz
docker compose -p airport logs --tail 6
docker compose -p airport exec -T airport ls -ln /var/lib/airport
```

`docker-compose.yml` additionally makes the root filesystem read-only, drops all
capabilities, sets `no-new-privileges`, and mounts `/tmp` as tmpfs. The SQLite
volume stays writable; its files must be owned by UID `10001`.

Compose publishes the plaintext port on `127.0.0.1` only. Put a TLS proxy on the
same host, or change the mapping in `docker-compose.yml` to `"8787:8787"` if the
instance is meant to be reached directly. The TLS stack already binds only
`127.0.0.1:8443`.

```bash
docker compose -p airport down -v    # stop and delete the volume
```

## systemd

```bash
sudo useradd --system --home /var/lib/ekravo-airport --shell /usr/sbin/nologin airport
sudo install -d -o airport -g airport -m 0750 /var/lib/ekravo-airport
sudo install -d -m 0750 /etc/ekravo-airport
sudo install -m 0640 -o root -g airport .env.example /etc/ekravo-airport/airport.env
sudo editor /etc/ekravo-airport/airport.env     # set the secret and database URL
sudo install -m 0644 deploy/airport.service /etc/systemd/system/airport.service
sudo systemctl daemon-reload
sudo systemctl enable --now airport
sudo systemctl status airport
```

Use:

```
AIRPORT_DATABASE_URL=sqlite:///var/lib/ekravo-airport/airport.db
```

The unit is hardened (`ProtectSystem=strict`, no new privileges, no capabilities,
only the state directory writable).

## TLS

### In-process

```dotenv
AIRPORT_TLS_CERT=/etc/ekravo-airport/fullchain.pem
AIRPORT_TLS_KEY=/etc/ekravo-airport/privkey.pem
AIRPORT_PUBLIC_URL=https://airport.example.com
```

Airport then serves HTTPS and WSS directly on `AIRPORT_BIND_ADDR`. There is no
plaintext listener and no HTTP-to-HTTPS redirect: a plain `http://` request to
the TLS port fails the handshake, which is the intended behavior. HSTS is added
to every response.

`AIRPORT_PUBLIC_URL` must use `https://` so ticket responses contain `wss://`
URLs. When it is empty, clients join the ticket's relative path to their own
base URL, which is also correct for a TLS deployment.

#### Local certificates for testing

Generate a private CA and a server certificate for `localhost`. The CA is only
for your own machine; never distribute its key.

```bash
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout tls/ca-key.pem -out tls/ca.pem \
  -subj "/CN=Airport Local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout tls/server-key.pem -out tls/server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth"

openssl x509 -req -in tls/server.csr -CA tls/ca.pem -CAkey tls/ca-key.pem \
  -CAcreateserial -out tls/server.pem -days 365 -sha256 -copy_extensions copy

openssl verify -CAfile tls/ca.pem tls/server.pem
```

Start Airport with it:

```bash
AIRPORT_JWT_SECRET="$(openssl rand -base64 48)" \
AIRPORT_TLS_CERT=tls/server.pem \
AIRPORT_TLS_KEY=tls/server-key.pem \
AIRPORT_PUBLIC_URL=https://localhost:8787 \
AIRPORT_DATABASE_URL=sqlite://data/airport.db \
cargo run -p airport-server
```

Verify the listener and certificate chain:

```bash
curl --cacert tls/ca.pem https://localhost:8787/healthz
echo | openssl s_client -connect localhost:8787 -CAfile tls/ca.pem \
  -verify_return_error -brief
```

The handshake should report `Verification: OK` and TLS 1.3. On Windows, `curl`
is often built with Schannel, which may reject a private CA because it cannot
check revocation. Use the OpenSSL client above, Node, or `curl --ssl-no-revoke`
for local testing; do not disable verification in production clients.

Pair and run the reference device over the encrypted listener. Both the HTTP API
and the WebSocket honor the same CA:

```bash
airport-device pair \
  --server https://localhost:8787 \
  --ca-cert tls/ca.pem \
  --code airport_pair_… \
  --name "Laptop"

airport-device run --ca-cert tls/ca.pem
```

`AIRPORT_CA_CERT=/path/to/ca.pem` is equivalent to `--ca-cert`. The client adds
the CA to its trust store; it never disables certificate verification.

For the TypeScript SDK under Node, point Node at the same CA:

```bash
NODE_EXTRA_CA_CERTS="$PWD/tls/ca.pem" node examples/node-echo.mjs
```

A browser must trust the CA in the operating system or browser store before a
page can open `wss://localhost:8787`. For production, use a publicly trusted
certificate (for example from your ACME client) instead of a private CA.

#### Docker with in-process TLS

The container runs as UID 10001, so the mounted certificate, key, CA, and env
file must be readable by that user. This is the complete flow used for the
self-hosting check.

Generate a throwaway CA and a server certificate for `localhost` and
`127.0.0.1`, then build a full chain (leaf first) for the server:

```bash
mkdir -p tls
openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
  -keyout tls/ca-key.pem -out tls/ca.pem \
  -subj "/CN=Airport Container Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout tls/server-key.pem -out tls/server.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth"

openssl x509 -req -in tls/server.csr -CA tls/ca.pem -CAkey tls/ca-key.pem \
  -CAcreateserial -out tls/server.pem -days 2 -sha256 -copy_extensions copy

cat tls/server.pem tls/ca.pem > tls/server-fullchain.pem
openssl verify -CAfile tls/ca.pem tls/server.pem
```

Put the container configuration in a file and make everything readable by the
container user. `AIRPORT_ENV_FILE` is resolved inside the container, not on the
host, and an unreadable or missing explicit file now fails startup instead of
silently falling back to an empty environment.

```bash
JWT_SECRET="$(openssl rand -base64 48)"
cat > tls/airport.env <<EOF
AIRPORT_JWT_SECRET=$JWT_SECRET
AIRPORT_BIND_ADDR=0.0.0.0:8787
AIRPORT_DATABASE_URL=sqlite:///var/lib/airport/airport.db
AIRPORT_TLS_CERT=/certs/server-fullchain.pem
AIRPORT_TLS_KEY=/certs/server-key.pem
AIRPORT_PUBLIC_URL=https://localhost:8443
AIRPORT_TRUSTED_ORIGINS=https://app.example.test
AIRPORT_LOG_FORMAT=json
EOF

chmod 0644 tls/ca.pem tls/server-fullchain.pem tls/server-key.pem tls/airport.env
```

`AIRPORT_PUBLIC_URL` must be the origin a browser reaches, including the host
port (`8443` below). That is what produces `wss://localhost:8443/...` in ticket
responses; using the internal port would make clients dial the wrong port.

The server listens on `8787` inside the container and TLS terminates there. Map
`8443` on the host to it, mount `/certs` and the env file read-only, and point
the healthcheck at HTTPS with the CA:

```bash
docker build -t ekravo-airport:0.1.0 .
docker run -d --name airport-tls \
  --restart unless-stopped \
  -p 127.0.0.1:8443:8787 \
  -v airport-tls-data:/var/lib/airport \
  --mount type=bind,source="$PWD/tls",target=/certs,readonly \
  --mount type=bind,source="$PWD/tls/airport.env",target=/etc/airport/airport.env,readonly \
  -e AIRPORT_ENV_FILE=/etc/airport/airport.env \
  -e AIRPORT_HEALTHCHECK_URL=https://127.0.0.1:8787/healthz \
  -e AIRPORT_HEALTHCHECK_CA=/certs/ca.pem \
  ekravo-airport:0.1.0
```

On Windows with Git Bash, Docker Desktop needs host paths and `-e` values that
are not rewritten by MSYS. Use `MSYS_NO_PATHCONV=1` for the `docker run`, and
replace `$PWD/tls` with `$(cygpath -w "$PWD/tls")` (the same for the env-file
source). The check above ran on Docker Desktop this way with the certificate
paths inside the container still absolute Linux paths.

Confirm the encrypted listener and the probe:

```bash
docker inspect --format '{{.State.Health.Status}}' airport-tls
curl --cacert tls/ca.pem https://localhost:8443/healthz
curl --cacert tls/ca.pem https://localhost:8443/readyz
echo | openssl s_client -connect localhost:8443 -CAfile tls/ca.pem \
  -verify_return_error -brief
```

A plaintext request to the TLS port is refused by the handshake, not redirected
or downgraded. Pair and run the reference device against the mapped port:

```bash
airport-device pair \
  --server https://localhost:8443 \
  --ca-cert tls/ca.pem \
  --code airport_pair_… \
  --name "Laptop"

airport-device run --ca-cert tls/ca.pem
```

Persistence and shutdown, same as the plaintext container:

```bash
docker stop airport-tls
docker logs airport-tls | grep -E 'shutdown requested|Airport stopped'
docker start airport-tls
docker inspect --format '{{.State.Health.Status}}' airport-tls
docker exec airport-tls ls -ln /var/lib/airport
```

The `ls` output must show UID `10001` for `airport.db`, `airport.db-shm`, and
`airport.db-wal`. After a restart the same device reconnects with its original
credential, and a message queued while it was offline is replayed (the log says
`replaying the mailbox`).

The repository ships `docker-compose.tls.yml` for this stack. It mounts `./tls`
and `tls/airport.env`, sets `AIRPORT_ENV_FILE`, and points the inherited image
healthcheck at HTTPS with the CA. Start and check it with exactly:

```bash
docker compose -f docker-compose.tls.yml -p airport-tls up -d --build
docker compose -f docker-compose.tls.yml -p airport-tls ps
docker inspect --format '{{.State.Health.Status}}' airport-tls-airport-1
curl --cacert tls/ca.pem https://localhost:8443/healthz
curl --cacert tls/ca.pem https://localhost:8443/readyz
docker compose -f docker-compose.tls.yml -p airport-tls logs --tail 8
docker compose -f docker-compose.tls.yml -p airport-tls exec -T airport ls -ln /var/lib/airport
```

Remove it with:

```bash
docker compose -f docker-compose.tls.yml -p airport-tls down -v
```

#### Production certificates

Point the two settings at your existing files and restart:

```dotenv
AIRPORT_TLS_CERT=/etc/ekravo-airport/fullchain.pem
AIRPORT_TLS_KEY=/etc/ekravo-airport/privkey.pem
AIRPORT_PUBLIC_URL=https://airport.example.com
```

Airport reads both files at startup; renew the certificate and restart (or
reload the service) to pick up a new one. Keep the key readable only by the
`airport` user:

```bash
sudo chown root:airport /etc/ekravo-airport/privkey.pem
sudo chmod 0640 /etc/ekravo-airport/privkey.pem
```

### Reverse proxy (recommended)

Caddy:

```caddyfile
airport.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name airport.example.com;

    ssl_certificate     /etc/letsencrypt/live/airport.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/airport.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
    }
}
```

Behind a proxy:

```dotenv
AIRPORT_TRUST_PROXY=true
AIRPORT_PUBLIC_URL=https://airport.example.com
```

`X-Forwarded-For` is only honored when `AIRPORT_TRUST_PROXY=true`. Never enable
it on a directly exposed instance.

## Backups

SQLite runs in WAL mode. A plain file copy while the server is running can miss
the `-wal` contents.

Safe options:

```bash
# Consistent online backup (SQLite CLI).
sqlite3 /var/lib/ekravo-airport/airport.db ".backup '/backup/airport-$(date +%F).db'"

# Or stop the service and copy the database with its sidecars.
sudo systemctl stop airport
sudo cp /var/lib/ekravo-airport/airport.db* /backup/
sudo systemctl start airport
```

Test a restore on a spare instance. The schema is created automatically, so an
empty database plus a fresh start is also a valid recovery path — but it loses
accounts, devices, grants, and queued mail.

## Upgrades

1. Back up the database.
2. Replace the binary or image.
3. Restart. The schema step is idempotent and runs on every start.

The database records its schema revision in `PRAGMA user_version`. A binary
refuses to start against a database created by a newer revision with a clear
message, so downgrading an instance cannot silently corrupt data.

Sockets disconnect during a restart. Devices reconnect with backoff and receive
unacknowledged mail; clients reconnect with a fresh ticket. Nothing needs manual
re-pairing. The container path was verified by restarting against the same named
volume: the device kept its id and credential, and a message queued while it was
offline was replayed after the restart.

Rotating `AIRPORT_JWT_SECRET` invalidates all access tokens immediately. Clients
refresh normally, so the user impact is a single refresh round trip; refresh
tokens are unaffected unless you also revoke them.

## Monitoring

| Endpoint | Use |
| --- | --- |
| `GET /healthz` | Liveness; process is up. Includes uptime and live connection count |
| `GET /readyz` | Readiness; SQLite answers |
| `GET /version` | Version and protocol version |

Logs are JSON by default (`AIRPORT_LOG_FORMAT=json`) and include ids, codes, and
counts — never payloads or secrets.

Useful things to alert on:

- `/readyz` failing for more than a minute.
- A rising rate of `internal` errors.
- A device flapping between online and offline.
- Disk usage of the database and its WAL.

## Troubleshooting

**`missing required environment variable AIRPORT_JWT_SECRET`** — set it in `.env`
or the unit's `EnvironmentFile`. `.env` is read from the working directory; use
`AIRPORT_ENV_FILE` if the service starts elsewhere.

**WebSocket returns 401** — tickets are single-use and expire after 90 seconds.
Request a new one; do not reuse a ticket or a URL from a log.

**A device never receives messages** — check `GET /api/v1/devices` for `online`.
If it is offline, messages queue until the TTL. If it is online but silent, check
the device's own logs and that it sends `ack`, otherwise the same message replays
on every reconnect.

**`mailbox_full`** — the device has 500 unacknowledged messages. Bring it online
or revoke/re-pair it.

**`recipient_unavailable` for a connection target** — the browser/tab is gone.
Devices should either accept that or use a device target.

**`403 registration is closed`** — set `AIRPORT_ALLOW_REGISTRATION=true`
temporarily to create the account, then close it again. The first account on an
empty database is always allowed.

**Clock skew** — JWT validation allows five seconds of leeway. Larger skew will
reject access tokens; keep both hosts on NTP.
