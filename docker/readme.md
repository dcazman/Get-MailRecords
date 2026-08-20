# GMR — Get Mail Records
### Web deployment for gmr.thecasmas.com

## Files
```
gmr-docker/
├── Dockerfile
├── docker-compose.yml
├── gmr.ps1              ← PowerShell DNS function (the core)
├── server.js            ← Node/Express web layer
├── package.json
├── start.sh
└── apache/
    └── httpd.conf
```

## Deploy

```bash
# 1. Copy this folder to your OMV server
scp -r gmr-docker/ user@yourserver:~/

# 2. SSH in and build
cd /srv/mergerfs/warehouse/gmr
docker compose build

# 3. Run it
docker compose up -d

# 4. Verify it's running
docker logs gmr
curl http://localhost:7777
```

## Cloudflare Tunnel

In the Cloudflare Zero Trust dashboard:
- Networks → Tunnels → your tunnel → Edit
- Add a Public Hostname:
  - Subdomain: `gmr`
  - Domain: `yourdomain.com`
  - Service: `http://localhost:7777`

That's it. gmr.thecasmas.com will be live.

## Update GMR function

```bash
# Copy updated gmr.ps1 into place, then rebuild
docker compose build
docker compose up -d
```

## Logs

```bash
docker logs gmr -f
```
