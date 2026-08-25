from flask import Flask, jsonify, request, send_file, abort
from flask_cors import CORS
import time
import os
from scoring import score as run_scan

app = Flask(__name__)
CORS(app)
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
def api_scan():
    payload = request.get_json(force=True) or {}
    url = payload.get('url', '')
    if not url:
        return jsonify({"error": "Missing URL"}), 400
        
    family = bool(payload.get("family")) if isinstance(payload.get("family"), bool) else str(payload.get("family", "")).lower() in ("1", "true", "yes")
    
    mode = (payload.get('mode') or 'standard').lower()
    result = scan_service.run_scan(url, mode=mode, family_mode=family)
    scans.append(result)
    
    return jsonify(result), 202

@app.route('/api/v2/scans/history')
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
def bulk_scan():
    payload = request.get_json(force=True) or {}
    urls = payload.get('urls') or []
    mode = (payload.get('mode') or 'quick').lower()
    if not urls or not isinstance(urls, list):
        return jsonify({"error": "Missing URLs list"}), 400
    results = []
    for url in urls[:50]:
        r = scan_service.run_scan(url.strip(), mode=mode)
        scans.append(r)
        results.append(r)
    return jsonify({"results": results, "scanned": len(results)}), 202

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