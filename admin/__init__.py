from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
import os
from datetime import datetime

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'melonhensem')
ADMIN_SESSION_KEY = 'admin_authenticated'

admin_bp = Blueprint('admin', __name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))

@admin_bp.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json(force=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session[ADMIN_SESSION_KEY] = True
        session.permanent = True
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Invalid username or password'}), 401

@admin_bp.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop(ADMIN_SESSION_KEY, None)
    return jsonify({'ok': True})

@admin_bp.route('/admin/dashboard')
def admin_dashboard():
    if not session.get(ADMIN_SESSION_KEY):
        return redirect(url_for('admin.admin_login_page'))
    return render_template('dashboard.html', username=ADMIN_USERNAME, now=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))

@admin_bp.route('/admin/login-page')
def admin_login_page():
    return render_template('login.html')
