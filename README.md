<div align="center">
  <img src="assets/app-icon.png" width="130" height="130" alt="Silkie" style="border-radius: 22px;" />
  <h1>Silkie</h1>
  <p><strong>Self-hosted zero-trust access layer</strong></p>
  <p>
    <a href="LICENSE">Apache 2.0</a> &nbsp;·&nbsp;
    <a href="https://www.wireguard.com/">Built on WireGuard</a> &nbsp;·&nbsp;
    Author: <a href="https://github.com/rafiki270">Ondrej Rafaj</a>
  </p>
</div>

---

Silkie is a self-hosted management and administration layer for a [WireGuard](https://www.wireguard.com/)-based zero-trust overlay network. It provides device enrollment, session brokering, STUN/TURN-assisted NAT traversal, and a clean admin UI — wrapping the underlying WireGuard peer-to-peer protocol, which is open source and maintained independently.

WireGuard is developed by Jason A. Donenfeld and released under the [GPLv2 license](https://www.wireguard.com/license/). Silkie links to WireGuard userspace implementations at runtime and does not distribute WireGuard source. See [wireguard.com](https://www.wireguard.com/) and the [WireGuard GitHub organisation](https://github.com/WireGuard) for the canonical project.

---

## What it does

- Enrolls devices (macOS, Linux, iOS, Android) into a shared WireGuard overlay network
- Issues short-lived session tokens and brokers peer-to-peer connections via ICE/STUN/TURN
- Exposes a service catalog — each device reports its listening ports; peers connect by overlay IP
- Provides a single-page admin UI for device management, session history, relay health, and system status
- Ships a Node.js CLI daemon (`silkie`) that runs as an OS service on each enrolled device
- Provides native mobile apps (iOS and Android) for connecting to enrolled servers

---

## Architecture

```
Admin UI (browser, static HTML + Tailwind)
        │ HTTPS (internal session JWT)
Control Server (Go 1.23+)
   Auth · Device registry · Session broker · Policy · Audit
   PostgreSQL (durable) · Redis (ephemeral)
        │ WireGuard overlay + STUN/TURN
Silkie CLI (Node.js, runs as OS service on each device)
   WireGuard peer · Heartbeat · Service manifest reporter
```

The control server coordinates identity and session establishment. It never carries application-layer traffic — once a connection is established, peers communicate directly over the WireGuard overlay (or via TURN relay when direct paths are blocked by NAT).

---

## Documentation

| Document | Description |
|---|---|
| [docs/brief.md](docs/brief.md) | Full system design, data models, API surface |
| [docs/frameworks.md](docs/frameworks.md) | Component architecture, SDK design, auth flows |
| [docs/cli.md](docs/cli.md) | CLI daemon reference |
| [docs/mobile.md](docs/mobile.md) | Native iOS and Android app specification |
| [docs/sso.md](docs/sso.md) | Authentication with UOA (UnlikeOtherAuthenticator) |
| [docs/techstack.md](docs/techstack.md) | Library and dependency choices |

---

## Quick start

```sh
# Copy and fill in your environment
cp .env.example .env

# Start with Docker Compose (server + postgres + redis + coturn)
docker compose up

# Enrol your first device (runs on the device being enrolled)
npm install -g silkie
silkie enroll
```

After enrollment, open the admin UI, complete SSO login — the first login becomes the super user account.

---

## License

Silkie is released under the [Apache License 2.0](LICENSE).

Copyright 2026 [UnlikeOtherAI Ltd](https://unlikeotherai.com)

**Author:** Ondrej Rafaj &lt;ondrej@unlikeotherai.com&gt;

WireGuard® is a registered trademark of Jason A. Donenfeld. Silkie is not affiliated with or endorsed by the WireGuard project.
