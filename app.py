from flask import Flask, jsonify, request, send_file, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import os
from scoring import score as run_scan

app = Flask(__name__)

# Security: session cookie flags
is_production = os.getenv('RENDER', 'false').lower() in ('1', 'true', 'yes')
app.config.update(
    SESSION_COOKIE_SECURE=is_production,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
)

# CORS: restrict to known origins
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'https://phishchecker.onrender.com').split(',')
CORS(app, origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()], supports_credentials=True)

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=['200 per day', '50 per hour'])

# Security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    # CSP: allow inline styles for admin dashboard, scripts from self only
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "font-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# Input validation helper
MAX_URL_LENGTH = 2048

def validate_url(url):
    if not url or not isinstance(url, str):
        return None, 'Invalid URL'
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return None, f'URL too long (max {MAX_URL_LENGTH} chars)'
    if not (url.startswith('http://') or url.startswith('https://')):
        return None, 'URL must start with http:// or https://'
    return url, None

app.secret_key = os.getenv('PHISHCHECKER_SECRET', 'change-me')

# Configuration from environment
DEBUG = os.getenv('PHISHCHECKER_DEBUG', 'false').lower() in ('1', 'true', 'yes')
PORT = int(os.getenv('PHISHCHECKER_PORT', '8080'))

# In-memory storage for demo
from data_store import scans

class ScanService:
    def run_scan(self, url, mode='standard', family_mode=False):
        return run_scan(url, mode=mode, family_mode=family_mode)

scan_service = ScanService()

@app.route('/health')
def health():
    return jsonify({
        "ok": True,
        "service": "phishchecker",
        "version": "2.1.0",
        "extension_compatible": True,
        "browser_targets": ["chrome", "firefox", "edge"]
    })

@app.route('/api/v2/status')
def status():
    return jsonify({
        "features": {
            "api_access": True,
            "bulk_scan": True,
            "export": True,
            "history": True,
            "public_scanning": True,
            "team_endpoints": True,
            "community_reporting": True,
            "browser_extension": True,
            "secured_by": "AES-256-GCM"
        },
        "service": "phishchecker",
        "version": "2.1.0"
    })

@app.route('/api/v2/scans', methods=['POST'])
@limiter.limit('10 per minute')
def api_scan():
    payload = request.get_json(force=True) or {}
    url = payload.get('url', '')
    ok, err = validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    family = bool(payload.get("family")) if isinstance(payload.get("family"), bool) else str(payload.get("family", "")).lower() in ("1", "true", "yes")
    mode = (payload.get('mode') or 'standard').lower()
    result = scan_service.run_scan(url, mode=mode, family_mode=family)
    scans.append(result)
    return jsonify(result), 202

@app.route('/api/v2/scans/history')
@limiter.limit('30 per minute')
def api_history():
    page = max(1, int(request.args.get("page", 1)))
    size = min(100, max(1, int(request.args.get("page_size", 20))))
    
    risk = (request.args.get("risk") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lower()
    
    items = scans
    if risk:
        items = [x for x in items if (x.get("risk") or "").lower() == risk]
    if q:
        items = [x for x in items if q in (x.get("domain") or "").lower() or q in (x.get("url") or "").lower()]
    
    return jsonify({
        "items": items,
        "total": len(items),
        "page": page,
        "page_size": size
    }), 200

@app.route('/api/v2/team/scan', methods=['POST'])
@limiter.limit('10 per minute')
def handle_team_scan():
    payload = request.get_json(force=True) or {}
    url = (payload.get('url') or '').strip()
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    result = scan_service.run_scan(url)
    scans.append(result)
    return jsonify(result), 202

@app.route('/api/v2/team/scan', methods=['GET'])
def team_scan_info():
    return jsonify({"endpoint": "/api/v2/team/scan", "methods": ["POST"], "usage": "POST JSON {\"url\": \"...\"}"})

@app.route('/api/v2/community/flag', methods=['POST'])
def handle_community_flag():
    payload = request.get_json(force=True) or {}
    url = (payload.get('url') or '').strip()
    category = (payload.get('category') or 'general').strip()
    notes = (payload.get('notes') or '').strip()
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    flag = {
        'url': url,
        'domain': url.split('/')[2] if '://' in url else url.split('/')[0],
        'category': category,
        'notes': notes,
        'id': str(len(scans) + 1),
        'created_at': __import__('datetime').datetime.now().isoformat(),
    }
    scans.append(flag)
    return jsonify({"ok": True, "status": "community_flag_endpoint", "flag": flag['id']}), 202

@app.route('/api/v2/community/flags')
def list_community_flags():
    flagged = [x for x in scans if 'category' in x]
    return jsonify({"flags": flagged}), 200

@app.route('/api/v2/community/scheduled', methods=['POST'])
def create_scheduled():
    return jsonify({"status": "scheduled_endpoint"}), 202

@app.route('/api/v2/community/scheduled')
def list_scheduled():
    return jsonify({"scheduled": []}), 200

@app.route('/api/v2/scans/bulk', methods=['POST'])
@limiter.limit('5 per minute')
def bulk_scan():
    payload = request.get_json(force=True) or {}
    urls = payload.get('urls') or []
    mode = (payload.get('mode') or 'quick').lower()
    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'Missing URLs list'}), 400
    results = []
    for url in urls[:50]:
        ok, err = validate_url(url)
        if not ok:
            results.append({'error': err, 'url': url})
            continue
        r = scan_service.run_scan(url, mode=mode)
        scans.append(r)
        results.append(r)
    return jsonify({'results': results, 'scanned': len(results)}), 202

@app.route('/api/v2/scans/export')
def export_public_scans():
    fmt = (request.args.get('format') or 'json').lower()
    items = scans
    if fmt == 'csv':
        lines = ['url,domain,risk,score,reasons']
        for x in items:
            lines.append(f"{x.get('url','')},{x.get('domain','')},{x.get('risk','')},{x.get('score','')},\"{(x.get('reasons') or [])}\"")
        payload = '\n'.join(lines)
        return jsonify({"csv": payload}), 200
    return jsonify({"results": items}), 200

@app.route('/api/v2/scan/screenshot', methods=['POST'])
def screenshot_scan():
    payload = request.get_json(force=True) or {}
    image = (payload.get('image') or '').strip()
    if not image:
        return jsonify({"error": "Missing image data"}), 400
    return jsonify({"error": "OCR extraction not yet implemented", "status": "stub"}), 501

@app.route('/api/v2/scan/qr', methods=['POST'])
def qr_scan():
    payload = request.get_json(force=True) or {}
    image = (payload.get('image') or '').strip()
    if not image:
        return jsonify({"error": "Missing image data"}), 400
    return jsonify({"error": "QR decoding not yet implemented", "status": "stub"}), 501

from admin import admin_bp
app.register_blueprint(admin_bp)

@app.route('/api/csrf', methods=['GET'])
def api_csrf():
    return jsonify({'csrf_token': 'public-no-csrf'})

ADMIN_DIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin', 'templates')

@app.route('/admin/manifest.json')
def admin_manifest():
    return send_file(os.path.join(ADMIN_DIST_DIR, 'manifest.json'), mimetype='application/json')

FRONTEND_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frontend', 'dist')
FRONTEND_ASSETS = os.path.join(FRONTEND_DIST, 'assets')

@app.route('/changelog')
def changelog_page():
    candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'changelog.html')
    if os.path.isfile(candidate):
        return send_file(candidate)
    return send_file(os.path.join(FRONTEND_DIST, 'index.html'))

@app.route('/privacy')
def privacy_page():
    candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'privacy.html')
    if os.path.isfile(candidate):
        return send_file(candidate)
    return send_file(os.path.join(FRONTEND_DIST, 'index.html'))

@app.route('/terms')
def terms_page():
    candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'terms.html')
    if os.path.isfile(candidate):
        return send_file(candidate)
    return send_file(os.path.join(FRONTEND_DIST, 'index.html'))

@app.route('/')
def index():
    return send_file(os.path.join(FRONTEND_DIST, 'index.html'))

@app.route('/<path:path>')
def frontend_files(path):
    if path.startswith('api/'):
        return abort(404)
    candidate = os.path.join(FRONTEND_DIST, path)
    if os.path.isfile(candidate):
        return send_file(candidate)
    candidate = os.path.join(FRONTEND_ASSETS, path)
    if path.startswith('assets/') and os.path.isfile(candidate):
        return send_file(candidate)
    return send_file(os.path.join(FRONTEND_DIST, 'index.html'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)

@app.route('/robots.txt')
def robots_txt():
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'robots.txt'), mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'sitemap.xml'), mimetype='application/xml')


# Privacy-first analytics: aggregate pageviews only, no PII
ANALYTICS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'analytics.json')

def _load_analytics():
    try:
        with open(ANALYTICS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'pageviews': [], 'counts': {}}

def _save_analytics(data):
    os.makedirs(os.path.dirname(ANALYTICS_FILE), exist_ok=True)
    with open(ANALYTICS_FILE, 'w') as f:
        json.dump(data, f)

@app.route('/api/v2/analytics/pageview', methods=['POST'])
@limiter.limit('60 per minute')
def analytics_pageview():
    payload = request.get_json(force=True) or {}
    path = (payload.get('path') or '/').strip()[:256]
    now = __import__('datetime').datetime.utcnow().isoformat() + 'Z'
    data = _load_analytics()
    data['pageviews'].append({'path': path, 'ts': now})
    data['counts'][path] = data['counts'].get(path, 0) + 1
    if len(data['pageviews']) > 1000:
        data['pageviews'] = data['pageviews'][-1000:]
    _save_analytics(data)
    return jsonify({'ok': True})
