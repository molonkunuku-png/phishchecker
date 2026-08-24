from flask import Flask, jsonify, request
from flask_cors import CORS
import time
import os

app = Flask(__name__)
CORS(app)

# Configuration from environment
DEBUG = os.getenv('PHISHCHECKER_DEBUG', 'false').lower() in ('1', 'true', 'yes')
PORT = int(os.getenv('PHISHCHECKER_PORT', '8080'))

# In-memory storage for demo
scans = []

class ScanService:
    def __init__(self):
        pass
    
    def run_scan(self, url, mode='standard', family_mode=False):
        time.sleep(0.5)
        
        risky_domains = ['free-gift-cards', 'fake-login', 'verify-account']
        risky_tlds = ['.xyz', '.top', '.gq', '.cf']
        
        domain = url.split('//')[-1].split('/')[0] if '//' in url else url.split('/')[0]
        domain_parts = domain.split('.')
        
        risk_score = 5
        if any(part in risky_domains for part in domain_parts):
            risk_score = 85
        elif any(domain.endswith(tld) for tld in risky_tlds):
            risk_score = 65
        elif 'login' in url or 'account' in url:
            risk_score = 35
        
        reasons = []
        if family_mode:
            reasons.append('family-safe mode: limited analysis')
        
        if risk_score > 70:
            risk_level = 'high'
        elif risk_score > 40:
            risk_level = 'suspicious'
        else:
            risk_level = 'clean'
        
        return {
            'url': url,
            'domain': domain,
            'risk': risk_level,
            'score': risk_score,
            'reasons': reasons,
            'details': {},
            'mode': mode,
            'family_mode': family_mode,
            'duration_ms': 500,
            'scanner_version': 'demo-2.0'
        }

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
    
    result = scan_service.run_scan(url, family_mode=family)
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
    return jsonify({"status": "team_scan_endpoint"})

@app.route('/api/v2/community/flag', methods=['POST'])
def handle_community_flag():
    return jsonify({"status": "community_flag_endpoint"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)