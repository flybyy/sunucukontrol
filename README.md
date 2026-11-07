# SunucuKontrol

**Self-hosted server management dashboard** built with **FastAPI + Python 3.13**.

Manage the local Docker host, monitor resources, inspect container logs, manage Minecraft servers and deployment projects, and register remote SSH servers for monitoring. Includes session authentication, CSRF checks, optional TOTP, audit events, backup functions, and optional Cloudflare/notification integrations.

> **Security notice:** Mounting `/var/run/docker.sock` gives this service effectively root-level control of the Docker host. Use only on a trusted machine and **never expose it directly to the public internet**. Default Compose binds to `127.0.0.1` only. Use a VPN or SSH tunnel for remote access.

## Requirements

- Linux host with Docker Engine and Docker Compose v2
- Python 3.13 on your local machine **only for the setup helper** (or run the helper in a disposable Python container)
- Supported image architectures: amd64 / arm64

## Quick start

```bash
git clone https://github.com/flybyy/sunucukontrol.git
cd sunucukontrol
python3 -m pip install argon2-cffi
python3 scripts/setup.py
docker compose up -d --build
docker compose ps
```

Open `http://localhost:9090`. SSH tunnel from another computer:

```bash
ssh -L 9090:127.0.0.1:9090 user@your-server
```

`PANEL_ORIGIN` must match the browser origin (default `http://localhost:9090`). For a real HTTPS reverse proxy set `PANEL_ORIGIN=https://your-domain.example` and `PANEL_SECURE_COOKIES=true` in `.env`, and configure the proxy separately. Do not publish port 9090 publicly.

## Features

| Area | Current functionality |
| --- | --- |
| Host overview | Resource usage, alerts, audit events |
| Docker | List, inspect, start, stop, restart, view logs |
| Minecraft | Server lifecycle, commands, logs, backups |
| Deployments | Project uploads, deployment and rollback |
| Remote hosts | SSH registration and monitoring (key configuration required) |
| Security | Argon2, session + CSRF, optional TOTP, origin checks |
| Integrations | Optional Cloudflare, Telegram, ntfy, webhooks |

Some host-level actions such as OS reboot, host firewall changes and system updates are not supported inside the container without a separate privileged host agent. SSH monitoring is not an interactive terminal. Multi-user RBAC, automatic SSL provisioning and one-click app installation are **not implemented**.

## Useful commands

```bash
docker compose logs -f panel
docker compose restart panel
docker compose down                  # keeps named volume
docker compose down -v               # WARNING: deletes persistent data
curl -fsS http://127.0.0.1:9090/healthz
```

## Development

```bash
python3 -m pip install -r requirements-dev.txt
PANEL_ENV=test SESSION_SECRET=development-only-test-secret-01234567890123456789 python3 -m pytest -q
```

CI runs the Python tests and dependency audit, validates the Compose config, and builds the image and checks its health endpoint. Test the deployment on your host before using it in production.

## Configuration

See `.env.example`, `SECURITY.md`, `README-V4.md` and `PYTHON-SECURITY.md`. Never commit `.env`, SSH keys, databases, or backups. The Docker image includes the Docker CLI and a pinned Docker Compose v2 plugin to support existing deployment workflows.

## License

MIT — see `LICENSE`.
