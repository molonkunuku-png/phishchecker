# Offline behavior
- The app is a static SPA on Render; if the host is unreachable, browser caches the last loaded shell.
- No PWA/service worker is bundled yet. Last scan results are not persisted offline in this release.

# Recovering from bad deploys
- If a deploy fails on Render, use the last successful deploy ID from `render deploys list srv-da14gte1egvs739v6nh0`.
- Roll back in the Render dashboard by redeploying the prior commit if needed.

# Local development
- Frontend: `cd frontend && npm run dev`
- Backend: `source .venv/bin/activate && python -m pytest`
