# Operational Runbook

## Health checks

```bash
curl -s https://phishchecker.onrender.com/health
# Expected: {"status":"ok"}
```

## Admin panel

- URL: https://phishchecker.onrender.com/admin/dashboard
- Lockout: 2 attempts → 5 minute lockout
- Session timeout: 30 minutes

## Rate limits

- Single scan: 10 requests/minute per IP
- Bulk scan: 5 requests/minute per IP
- History/export: 30 requests/minute per IP
- Default daily cap: 200 requests/day per IP

## Monitoring endpoints

- `GET /admin/monitoring/health` — uptime, version, service status
- `GET /admin/monitoring/scans` — 24h volume buckets
- `GET /admin/monitoring/errors` — risk breakdown
- `GET /admin/monitoring/system` — CPU/memory/disk (psutil if available)

## Logs

- Render dashboard: Logs tab
- `GET /admin/logs` — returns empty list (stub; extend if logging added)

## Backup

- `GET /admin/backup/export` — stub (extend to export scans + analytics JSON)

## Deploy

```bash
cd /home/irene/projects/phishchecker
git add -A && git commit -m "..." && git push origin main
/home/irene/.local/bin/render deploys create srv-da14gte1egvs739v6nh0 --confirm
```

## Rollback

```bash
git log --oneline -5
git revert --no-commit <bad-sha>..HEAD
git commit -m "rollback: revert bad deploy"
git push origin main
/home/irene/.local/bin/render deploys create srv-da14gte1egvs739v6nh0 --confirm
```
