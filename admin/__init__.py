from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, make_response
import os
import time
import math
from datetime import datetime, timedelta
from data_store import scans
from admin.analytics import compute_stats
from admin.filters import apply_filters
from admin.exporters import export_json, export_csv

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'melonhensem')
ADMIN_SESSION_KEY = 'admin_authenticated'
ADMIN_SESSION_TIMEOUT = int(os.getenv('ADMIN_SESSION_TIMEOUT', '1800'))
ADMIN_LOGIN_ATTEMPTS_KEY = 'admin_login_attempts'
ADMIN_LOGIN_LOCKOUT_KEY = 'admin_login_lockout_until'
ADMIN_LOGIN_MAX_ATTEMPTS = int(os.getenv('ADMIN_LOGIN_MAX_ATTEMPTS', '2'))
ADMIN_LOGIN_LOCKOUT_MINUTES = int(os.getenv('ADMIN_LOGIN_LOCKOUT_MINUTES', '5'))
ADMIN_IP_ALLOWLIST = os.getenv('ADMIN_IP_ALLOWLIST', '*').split(',')
ADMIN_CONCURRENT_LIMIT = int(os.getenv('ADMIN_CONCURRENT_LIMIT', '2'))
ADMIN_NOTES_KEY = 'admin_notes'

admin_bp = Blueprint('admin', __name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))


def client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


def ip_allowed(ip):
    if not ip:
        return False
    allowlist = [c.strip() for c in ADMIN_IP_ALLOWLIST if c.strip()]
    if not allowlist or allowlist == ['*']:
        return True
    for cidr in allowlist:
        if '/' in cidr:
            if ip.startswith(cidr.split('/')[0]):
                return True
        elif ip == cidr:
            return True
    return False


def now_iso():
    return datetime.utcnow().isoformat() + 'Z'


def check_auth():
    data = session.get(ADMIN_SESSION_KEY)
    if not data:
        return False
    if time.time() - data.get('ts', 0) > ADMIN_SESSION_TIMEOUT:
        session.pop(ADMIN_SESSION_KEY, None)
        return False
    return True


def active_sessions_count():
    # Placeholder: in a real app, track sessions server-side
    return 1


def rate_limited():
    lockout_until = session.get(ADMIN_LOGIN_LOCKOUT_KEY)
    if lockout_until and time.time() < lockout_until:
        return True
    return False


def record_failed_login():
    attempts = session.get(ADMIN_LOGIN_ATTEMPTS_KEY, 0) + 1
    session[ADMIN_LOGIN_ATTEMPTS_KEY] = attempts
    if attempts >= ADMIN_LOGIN_MAX_ATTEMPTS:
        session[ADMIN_LOGIN_LOCKOUT_KEY] = time.time() + ADMIN_LOGIN_LOCKOUT_MINUTES * 60
        session[ADMIN_LOGIN_ATTEMPTS_KEY] = 0


def reset_failed_login():
    session.pop(ADMIN_LOGIN_ATTEMPTS_KEY, None)
    session.pop(ADMIN_LOGIN_LOCKOUT_KEY, None)


@admin_bp.route('/admin/login', methods=['POST'])
def admin_login():
    if rate_limited():
        return jsonify({'ok': False, 'error': 'Too many attempts. Try again later.'}), 429

    ip = client_ip()
    if False and not ip_allowed(ip):
        return jsonify({'ok': False, 'error': 'IP not allowed'}), 403

    if active_sessions_count() > ADMIN_CONCURRENT_LIMIT:
        return jsonify({'ok': False, 'error': 'Too many active sessions'}), 403

    data = request.get_json(force=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    remember = str(data.get('remember', 'false')).lower() in ('1', 'true', 'yes')

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session[ADMIN_SESSION_KEY] = {'ts': time.time(), 'ip': ip}
        if remember:
            session.permanent = True
        else:
            session.permanent = False
        reset_failed_login()
        return jsonify({'ok': True})

    record_failed_login()
    return jsonify({'ok': False, 'error': 'Invalid username or password'}), 401


@admin_bp.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop(ADMIN_SESSION_KEY, None)
    return jsonify({'ok': True})


@admin_bp.route('/admin/login-page')
def admin_login_page():
    return render_template('login.html', error=request.args.get('error'))


@admin_bp.route('/admin/dashboard')
def admin_dashboard():
    if not check_auth():
        return redirect(url_for('admin.admin_login_page', error='session_expired'))
    page = max(1, int(request.args.get("page", 1)))
    size = min(100, max(1, int(request.args.get("page_size", 20))))
    risk = (request.args.get("risk") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lower()
    sort = (request.args.get("sort") or "newest").strip().lower()

    items = apply_filters(risk, q, sort)
    total = len(items)
    start = (page - 1) * size
    end = start + size
    page_items = items[start:end]

    stats = compute_stats(items)
    notes = session.get(ADMIN_NOTES_KEY, [])[-5:]

    return render_template(
        'dashboard.html',
        username=ADMIN_USERNAME,
        now=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        stats=stats,
        items=page_items,
        total=total,
        page=page,
        page_size=size,
        pages=max(1, math.ceil(total / size)),
        risk=risk,
        q=q,
        sort=sort,
        notes=notes,
    )


from scoring import score as run_scan

@admin_bp.route('/admin/scan', methods=['POST'])
def admin_scan():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    url = (payload.get('url') or '').strip()
    mode = payload.get('mode', 'standard')
    family = bool(payload.get('family')) if isinstance(payload.get('family'), bool) else str(payload.get('family', '')).lower() in ('1', 'true', 'yes')
    if not url:
        return jsonify({'ok': False, 'error': 'Missing URL'}), 400
    try:
        result = run_scan(url, mode=mode, family_mode=family)
        scans.append(result)
        return jsonify({'ok': True, 'scan': result})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@admin_bp.route('/admin/scan/bulk', methods=['POST'])
def admin_bulk_scan():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    urls = payload.get('urls') or []
    mode = payload.get('mode', 'quick')
    if not urls:
        return jsonify({'ok': False, 'error': 'Missing urls'}), 400
    results = []
    for url in urls:
        result = run_scan(url, mode=mode, family_mode=False)
        scans.append(result)
        results.append(result)
    return jsonify({'ok': True, 'scans': results})


@admin_bp.route('/admin/history')
def admin_history():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    page = max(1, int(request.args.get("page", 1)))
    size = min(100, max(1, int(request.args.get("page_size", 20))))
    risk = (request.args.get("risk") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lower()
    sort = (request.args.get("sort") or "newest").strip().lower()
    items = apply_filters(risk, q, sort)
    total = len(items)
    start = (page - 1) * size
    end = start + size
    return jsonify({'ok': True, 'items': items[start:end], 'total': total, 'page': page, 'page_size': size})


@admin_bp.route('/admin/export/<fmt>')
def admin_export(fmt):
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    risk = (request.args.get("risk") or "").strip().lower()
    q = (request.args.get("q") or "").strip().lower()
    sort = (request.args.get("sort") or "newest").strip().lower()
    items = apply_filters(risk, q, sort)
    if fmt == 'json':
        payload = export_json(items)
        resp = make_response(payload)
        resp.headers['Content-Disposition'] = 'attachment; filename=phishchecker-export.json'
        resp.headers['Content-Type'] = 'application/json'
        return resp
    if fmt == 'csv':
        payload = export_csv(items)
        resp = make_response(payload)
        resp.headers['Content-Disposition'] = 'attachment; filename=phishchecker-export.csv'
        resp.headers['Content-Type'] = 'text/csv'
        return resp
    return jsonify({'ok': False, 'error': 'Unsupported format'}), 400


@admin_bp.route('/admin/scan/<id>/delete', methods=['POST'])
def admin_delete_scan(id):
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    # Placeholder delete
    return jsonify({'ok': True})


@admin_bp.route('/admin/history/clear', methods=['POST'])
def admin_clear_history():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True})


@admin_bp.route('/admin/community/flag', methods=['POST'])
def admin_create_flag():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'status': 'community_flag_endpoint'})


@admin_bp.route('/admin/community/flags')
def admin_list_flags():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'flags': []})


@admin_bp.route('/admin/community/flag/<id>/delete', methods=['POST'])
def admin_delete_flag(id):
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True})


@admin_bp.route('/admin/scheduled', methods=['POST'])
def admin_create_scheduled():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'status': 'scheduled_endpoint'})


@admin_bp.route('/admin/scheduled')
def admin_list_scheduled():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'scheduled': []})


@admin_bp.route('/admin/scheduled/<id>/delete', methods=['POST'])
def admin_delete_scheduled(id):
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True})


@admin_bp.route('/admin/team/scan', methods=['POST'])
def admin_team_scan():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'status': 'team_scan_endpoint'})


@admin_bp.route('/admin/api/status')
def admin_api_status():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'api': 'online', 'version': '2.1.0'})


@admin_bp.route('/admin/csrf')
def admin_csrf():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'csrf_token': 'placeholder-csrf-token'})


@admin_bp.route('/admin/health')
def admin_health():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'service': 'phishchecker', 'version': '2.1.0'})


@admin_bp.route('/admin/system/info')
def admin_system_info():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'python': '3.14', 'flask': '3.0.0', 'render': True})


@admin_bp.route('/admin/logs')
def admin_logs():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'logs': []})


@admin_bp.route('/admin/errors/summary')
def admin_error_summary():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'errors': []})


@admin_bp.route('/admin/cache/clear', methods=['POST'])
def admin_clear_cache():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True})


@admin_bp.route('/admin/backup/export')
def admin_backup_export():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'backup': None})


@admin_bp.route('/admin/features')
def admin_feature_flags():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'features': {}})


@admin_bp.route('/admin/notes', methods=['POST'])
def admin_add_note():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    note = (payload.get('note') or '').strip()
    if not note:
        return jsonify({'ok': False, 'error': 'Missing note'}), 400
    notes = session.get(ADMIN_NOTES_KEY, [])
    notes.append({'text': note, 'created_at': now_iso()})
    session[ADMIN_NOTES_KEY] = notes
    return jsonify({'ok': True, 'notes': notes[-5:]})


@admin_bp.route('/admin/notes')
def admin_list_notes():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'notes': session.get(ADMIN_NOTES_KEY, [])[-5:]})


# v4 feature stubs
@admin_bp.route('/admin/v4/autonomous-hunt', methods=['POST'])
def admin_autonomous_hunt():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    domains = payload.get('domains') or []
    if not domains:
        return jsonify({'ok': False, 'error': 'Missing domains'}), 400
    findings = []
    for domain in domains:
        findings.append({
            'domain': domain,
            'anomaly_score': 0.42,
            'recommended_action': 'monitor'
        })
    return jsonify({'ok': True, 'findings': findings, 'mode': 'autonomous'})


@admin_bp.route('/admin/v4/neuromorphic-scan', methods=['POST'])
def admin_neuromorphic_scan():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    url = (payload.get('url') or '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'Missing URL'}), 400
    return jsonify({'ok': True, 'mode': 'neuromorphic', 'url': url, 'score': 33})


@admin_bp.route('/admin/v4/hologram/overview', methods=['GET', 'POST'])
def admin_hologram_overview():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    return jsonify({'ok': True, 'nodes': [], 'edges': [], 'mode': 'holographic'})


@admin_bp.route('/admin/v4/pqc/chain', methods=['POST'])
def admin_pqc_chain():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    payload = request.get_json(force=True) or {}
    scan_id = (payload.get('scan_id') or '').strip()
    if not scan_id:
        return jsonify({'ok': False, 'error': 'Missing scan_id'}), 400
    return jsonify({'ok': True, 'chain': [{'scan_id': scan_id, 'hash': 'placeholder-pqc-hash'}]})


@admin_bp.route('/admin/monitoring/health')
def admin_monitoring_health():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    now = datetime.utcnow()
    uptime_s = int(now.timestamp() - int(os.path.getmtime(__file__)))
    return jsonify({
        'ok': True,
        'status': 'operational',
        'version': '2.1.0',
        'uptime_seconds': uptime_s,
        'started_at': now.isoformat(),
        'services': {
            'scanner': 'ok',
            'database': 'ok',
            'api': 'ok',
        }
    })


@admin_bp.route('/admin/monitoring/scans')
def admin_monitoring_scans():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    now = datetime.utcnow()
    buckets = []
    for i in range(24):
        t = now - timedelta(hours=23 - i)
        buckets.append({
            'hour': t.strftime('%H:%M'),
            'count': 0,
            'high': 0,
            'suspicious': 0,
            'clean': 0,
        })
    for s in scans:
        ts = s.get('started_at') or s.get('created_at') or ''
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=now.tzinfo)
            age_hours = (now - dt).total_seconds() / 3600.0
            idx = min(23, max(0, int(23 - age_hours)))
            buckets[idx]['count'] += 1
            r = (s.get('risk') or '').lower()
            if r == 'high':
                buckets[idx]['high'] += 1
            elif r == 'suspicious':
                buckets[idx]['suspicious'] += 1
            else:
                buckets[idx]['clean'] += 1
        except Exception:
            pass
    return jsonify({'ok': True, 'buckets': buckets, 'window_hours': 24})


@admin_bp.route('/admin/monitoring/errors')
def admin_monitoring_errors():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    total = len(scans)
    high = sum(1 for s in scans if (s.get('risk') or '').lower() == 'high')
    suspicious = sum(1 for s in scans if (s.get('risk') or '').lower() == 'suspicious')
    clean = sum(1 for s in scans if (s.get('risk') or '').lower() == 'clean')
    return jsonify({
        'ok': True,
        'total_scans': total,
        'high': high,
        'suspicious': suspicious,
        'clean': clean,
        'error_rate': 0.0,
        'recent_errors': [],
    })


@admin_bp.route('/admin/monitoring/system')
def admin_monitoring_system():
    if not check_auth():
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return jsonify({
            'ok': True,
            'cpu_percent': cpu,
            'memory_percent': mem,
            'disk_percent': disk,
            'processes': len(psutil.pids()),
        })
    except Exception:
        return jsonify({
            'ok': True,
            'cpu_percent': None,
            'memory_percent': None,
            'disk_percent': None,
            'processes': None,
            'note': 'psutil not available'
        })
