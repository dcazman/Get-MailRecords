# GMR — Get Mail Records

A DNS mail record inspector. Give it a domain, email address, or URL and it returns A, MX, SPF, DMARC, DKIM, and NS records in a clean web interface.

**Live demo:** https://gmr.thecasmas.com  
**Source:** https://github.com/dcazman/Get-MailRecords

---

## Quick start

```bash
docker run -d \
  --name gmr \
  --restart unless-stopped \
  -p 7777:7777 \
  dcazman/gmr:latest
```

Then open http://localhost:7777

---

## With docker-compose

### Standard setup — works on any machine

```yaml
services:
  gmr:
    image: dcazman/gmr:latest
    container_name: gmr
    restart: unless-stopped
    ports:
      - "7777:7777"
```

### Cloudflare Tunnel setup

If you're running a `cloudflared` container in `network_mode: host`, use host networking so cloudflared can reach GMR via localhost:

```yaml
services:
  gmr:
    image: dcazman/gmr:latest
    container_name: gmr
    restart: unless-stopped
    network_mode: host
```

Then point your Cloudflare Tunnel to `http://localhost:7777`.

---

## What's inside

| Layer | Technology |
|-------|-----------|
| Base image | Alpine 3.19 |
| Web server | Node.js / Express (port 7777) |
| DNS engine | PowerShell 7 + `dig` (bind-tools) |
| DNS resolver | 8.8.8.8 (Google) — overridable per query |

---

## Records returned

- **A** — confirms the domain resolves
- **MX** — mail exchange servers
- **SPF** — sender policy framework
- **DMARC** — domain-based message authentication
- **DKIM** — auto-discovers selector if not provided
- **NS** — first two nameservers

---

## Ports

| Port | Purpose |
|------|---------|
| 7777 | HTTP web interface |

No environment variables required. No volumes required.

---

## Troubleshooting

**Blank results page** — test directly inside the container:
```bash
docker exec -it gmr pwsh -NoProfile -NonInteractive -Command \
  ". /app/gmr.ps1; Get-MailRecords -Domain google.com | ConvertTo-Json -Depth 10"
```

**dig not found** — rebuild with `--no-cache`. The `bind-tools` package must be present in the Alpine layer.

**Port 7777 already in use:**
```bash
ss -tlnp | grep 7777
```

---

## Source & license

https://github.com/dcazman/Get-MailRecords

Built by Dan Casmas — March 2026.
