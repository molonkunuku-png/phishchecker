# PhishChecker

Privacy-first URL phishing risk scanner for personal safety.

## Features

- Real-time URL analysis with live scan streaming (SSE)
- v2 REST API with history, export (JSON/CSV), bulk scan, and webhook reports
- CORS-enabled with credentials support and security headers
- API key auth + rate limiting on public POST endpoints
- React 19 + TypeScript + Vite + Tailwind v4 frontend
- i18n support: English, Japanese, Spanish

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

## Environment

- `SECRET_KEY` or `PHISHCHECKER_SECRET` — Flask session secret
- `PHISHCHECKER_ENV` — `production` or `development`

## License

MIT
