"""
Network Security Dashboard – Full Feature Set
Authentication, Concurrent Scanning, Scan History, Background Jobs, PDF Export
"""
import os
import json
import sqlite3
import shutil
import logging
import threading
import socket
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import io
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from flask_mail import Mail, Message

# ReportLab for PDF export
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# Auth and modules
from auth import (
    init_auth_db, authenticate_user, login_required, role_required,
    has_permission, get_user_role, create_user, get_users,
    toggle_user_status, delete_user, ROLES
)
from scripts.ai_recommendations import AIRecommendations
from scripts.cve_integration import CVEService
from scripts.risk_engine import RiskEngine
from scripts.threat_intelligence import ThreatIntelligence
from scripts.anomaly_detection import compute_anomaly_scores, get_anomaly_summary, ensure_tables
from scripts.exploit_intelligence import ExploitIntelligence

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# App config
# -------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-development-only-change-me')
DB_PATH = os.environ.get('DB_PATH', 'data/network_scanner.db')
os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
DEFAULT_DB_PATH = 'data/network_scanner.db'
if DB_PATH != DEFAULT_DB_PATH and not os.path.exists(DB_PATH) and os.path.exists(DEFAULT_DB_PATH):
    shutil.copy2(DEFAULT_DB_PATH, DB_PATH)

# -------------------------------------------------------------------
# Email configuration (for reports)
# -------------------------------------------------------------------
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.sendgrid.net')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
    logger.warning("Email credentials not set. Email sending will fail.")

mail = Mail(app)

@app.route('/health')
def health_check():
    try:
        conn = get_db()
        conn.execute('SELECT 1')
        conn.close()
        return jsonify({'status': 'ok', 'service': 'sentinel-ai'})
    except Exception as error:
        logger.error(f'Health check failed: {error}')
        return jsonify({'status': 'error'}), 503

# -------------------------------------------------------------------
# Database helpers and table creation
# -------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_scan_history_table():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL,
            target TEXT NOT NULL,
            total_devices INTEGER,
            nmap_count INTEGER,
            mdns_count INTEGER,
            windows_count INTEGER,
            other_count INTEGER,
            duration REAL
        )
    ''')
    conn.commit()
    conn.close()

def init_scan_jobs_table():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            timeout INTEGER,
            retries INTEGER,
            status TEXT DEFAULT 'pending',
            progress INTEGER DEFAULT 0,
            result TEXT,
            error TEXT,
            created_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            duration REAL,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def init_device_locations_table():
    """Store operational asset placement separately from ML training data."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_locations (
            device_id INTEGER PRIMARY KEY,
            site TEXT NOT NULL DEFAULT 'Primary Site',
            building TEXT,
            floor TEXT,
            zone TEXT,
            rack TEXT,
            switch_port TEXT,
            notes TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

def init_audit_log_table():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            previous_hash TEXT,
            event_hash TEXT NOT NULL UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

def record_audit(action, resource_type=None, resource_id=None, details=None):
    """Append an integrity-linked audit event for accountability and evidence review."""
    try:
        now = datetime.now().isoformat()
        conn = get_db()
        previous = conn.execute('SELECT event_hash FROM audit_log ORDER BY id DESC LIMIT 1').fetchone()
        previous_hash = previous['event_hash'] if previous else ''
        payload = json.dumps({
            'event_time': now, 'user_id': session.get('user_id'),
            'username': session.get('username'), 'action': action,
            'resource_type': resource_type, 'resource_id': str(resource_id or ''),
            'details': details or {}, 'ip_address': request.remote_addr or '',
            'previous_hash': previous_hash
        }, sort_keys=True, default=str)
        import hashlib
        event_hash = hashlib.sha256(payload.encode()).hexdigest()
        conn.execute('''INSERT INTO audit_log
            (event_time, user_id, username, action, resource_type, resource_id,
             details, ip_address, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (now, session.get('user_id'), session.get('username'), action,
             resource_type, str(resource_id or ''), json.dumps(details or {}, default=str),
             request.remote_addr or '', previous_hash, event_hash))
        conn.commit()
        conn.close()
    except Exception as error:
        logger.warning(f'Audit event could not be recorded: {error}')

# Create all needed tables
init_auth_db(DB_PATH)          # users table
init_scan_history_table()
init_scan_jobs_table()
init_device_locations_table()
init_audit_log_table()

# -------------------------------------------------------------------
# Scan Job Helpers
# -------------------------------------------------------------------
def create_scan_job(target, scan_type, timeout, retries, user_id):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO scan_jobs
        (target, scan_type, timeout, retries, status, progress, created_at, user_id)
        VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)
    ''', (target, scan_type, timeout, retries, now, user_id))
    job_id = cursor.lastrowid
    conn.commit()
    conn.close()
    record_audit('scan_job_created', 'scan_job', job_id, {'target': target, 'scan_type': scan_type})
    return job_id

def update_scan_job(job_id, status=None, progress=None, result=None, error=None,
                    started_at=None, completed_at=None, duration=None):
    conn = get_db()
    cursor = conn.cursor()
    updates = []
    params = []
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if progress is not None:
        updates.append("progress = ?")
        params.append(progress)
    if result is not None:
        updates.append("result = ?")
        params.append(json.dumps(result))
    if error is not None:
        updates.append("error = ?")
        params.append(error)
    if started_at is not None:
        updates.append("started_at = ?")
        params.append(started_at)
    if completed_at is not None:
        updates.append("completed_at = ?")
        params.append(completed_at)
    if duration is not None:
        updates.append("duration = ?")
        params.append(duration)
    if not updates:
        return
    params.append(job_id)
    cursor.execute(f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()
    conn.close()

def get_scan_job(job_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_jobs WHERE id = ?', (job_id,))
    job = cursor.fetchone()
    conn.close()
    return dict(job) if job else None

# -------------------------------------------------------------------
# Concurrent scanning functions
# -------------------------------------------------------------------
# Check if nmap is available
def check_nmap():
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

OUI_CACHE = {}

def lookup_brand(mac):
    if not mac:
        return 'Unknown'
    prefix = mac[:8].upper().replace(':', '')
    if prefix in OUI_CACHE:
        return OUI_CACHE[prefix]
    return 'Unknown'

def scan_single_ip(ip, scan_args='-T4 -F'):
    """Scan a single IP with nmap and return device dict or None."""
    try:
        cmd = ['nmap', '-oX', '-', scan_args, ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.warning(f"nmap scan for {ip} returned non-zero: {result.returncode}")
            return None
        root = ET.fromstring(result.stdout)
        host = root.find('host')
        if host is None:
            return None
        addr = host.find('address')
        ip_addr = addr.get('addr') if addr is not None else ip
        hostname_elem = host.find('hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else ''
        os_elem = host.find('os/osmatch')
        os = os_elem.get('name') if os_elem is not None else 'Unknown'
        ports = []
        services = []   # store as list of dicts {service, port}
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.get('portid')
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    ports.append(int(port_id)) # type: ignore
                    services.append({'service': service_name, 'port': int(port_id)}) # type: ignore
        mac_elem = host.find('address[@addrtype="mac"]')
        mac = mac_elem.get('addr') if mac_elem is not None else ''
        brand = lookup_brand(mac)
        return {
            'ip_address': ip_addr,
            'hostname': hostname,
            'device_type': 'Unknown',
            'brand': brand,
            'os': os,
            'open_ports': ports,
            'services': services,   # now a list of dicts
            'mac_address': mac,
            'confidence': 0.9,
            'source': ['nmap']
        }
    except Exception as e:
        logger.error(f"Error scanning {ip}: {e}")
        return None

def save_device_to_db(device_data):
    """Insert or update a device record from a scan result."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (device_data.get('ip'),))
    existing = cursor.fetchone()
    if existing:
        cursor.execute('''
            UPDATE devices SET
                hostname = ?,
                device_type = ?,
                os = ?,
                mac_address = ?,
                open_ports = ?,
                services = ?,
                last_seen = ?
            WHERE ip_address = ?
        ''', (
            device_data.get('hostname', ''),
            device_data.get('device_type', 'Unknown'),
            device_data.get('os', 'Unknown'),
            device_data.get('mac', ''),
            json.dumps(device_data.get('open_ports', [])),
            json.dumps(device_data.get('services', [])),
            datetime.now().isoformat(),
            device_data.get('ip')
        ))
        device_id = existing['id']
    else:
        cursor.execute('''
            INSERT INTO devices
                (ip_address, mac_address, hostname, device_type, os,
                 open_ports, services, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_data.get('ip'),
            device_data.get('mac', ''),
            device_data.get('hostname', ''),
            device_data.get('device_type', 'Unknown'),
            device_data.get('os', 'Unknown'),
            json.dumps(device_data.get('open_ports', [])),
            json.dumps(device_data.get('services', [])),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        device_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return device_id

# -------------------------------------------------------------------
# Background scan thread function
# -------------------------------------------------------------------
def run_scan_in_background(job_id, target, scan_type, timeout, retries):
    try:
        logger.info(f"Background scan job {job_id} started for target {target}")
        update_scan_job(job_id, status='running', started_at=datetime.now().isoformat())
        start_time = datetime.now()

        # Check nmap
        if not check_nmap():
            error_msg = "nmap not found in PATH. Please install nmap."
            logger.error(error_msg)
            update_scan_job(job_id, status='failed', error=error_msg,
                            completed_at=datetime.now().isoformat())
            return

        # Parse network
        network = ipaddress.ip_network(target, strict=False)
        if network.prefixlen < 24:
            hosts = list(network.hosts())[:254]
        else:
            hosts = list(network.hosts())
        if not hosts:
            update_scan_job(job_id, status='failed', error='No hosts in network')
            return
        logger.info(f"Scanning {len(hosts)} IP addresses")

        # Concurrent scan
        devices = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(scan_single_ip, str(ip)): str(ip) for ip in hosts}
            total = len(future_to_ip)
            done = 0
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    devices.append(result)
                done += 1
                progress = int((done / total) * 100)
                update_scan_job(job_id, progress=progress)
                if done % 10 == 0:
                    logger.info(f"Scan progress: {done}/{total} IPs scanned, found {len(devices)} devices")

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Scan completed in {duration:.2f}s, found {len(devices)} devices")

        # Save devices to DB and run vulnerability analysis
        saved_device_ids = {}
        for dev in devices:
            dev_for_db = {
                'ip': dev['ip_address'],
                'hostname': dev['hostname'],
                'device_type': dev['device_type'],
                'os': dev['os'],
                'mac': dev['mac_address'],
                'open_ports': dev['open_ports'],
                'services': dev['services']  # already list of dicts
            }
            device_id = save_device_to_db(dev_for_db)
            saved_device_ids[dev['ip_address']] = device_id

        # Vulnerability analysis
        try:
            cve_service = CVEService(DB_PATH)
            risk_engine = RiskEngine(DB_PATH)
            threat_intel = ThreatIntelligence(DB_PATH)
            for ip, device_id in saved_device_ids.items():
                # re‑fetch device to get services
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('SELECT services FROM devices WHERE id = ?', (device_id,))
                row = cursor.fetchone()
                conn.close()
                if row and row['services']:
                    services = json.loads(row['services'])  # already list of dicts
                    if services:
                        logger.info(f"Analyzing {len(services)} services for device {ip}")
                        cves_found = cve_service.scan_device_services(device_id, services)
                        if cves_found:
                            cve_ids = [cve['cve_id'] for cve in cves_found]
                            threat_intel.analyze_cves(cve_ids)
                        risk_engine.calculate_risk_score(device_id)
                    else:
                        risk_engine.calculate_risk_score(device_id)
        except Exception as e:
            logger.error(f"Vulnerability analysis error: {e}")

        # Anomaly detection
        try:
            compute_anomaly_scores()
        except Exception as e:
            logger.error(f"Anomaly training failed: {e}")

        # Store scan history
        nmap_count = len([d for d in devices if 'nmap' in d.get('source', [])])
        mdns_count = len([d for d in devices if 'mdns' in d.get('source', [])])
        windows_count = len([d for d in devices if 'windows' in d.get('source', [])])
        other_count = len(devices) - nmap_count - mdns_count - windows_count

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history
            (scan_time, target, total_devices, nmap_count, mdns_count, windows_count, other_count, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            target,
            len(devices),
            nmap_count,
            mdns_count,
            windows_count,
            other_count,
            duration
        ))
        conn.commit()
        conn.close()

        # Final update
        update_scan_job(job_id, status='completed', progress=100,
                        result=devices,
                        completed_at=datetime.now().isoformat(),
                        duration=duration)
        logger.info(f"Background scan job {job_id} completed successfully")

    except Exception as e:
        logger.error(f"Background scan error: {e}", exc_info=True)
        update_scan_job(job_id, status='failed', error=str(e),
                        completed_at=datetime.now().isoformat())

# -------------------------------------------------------------------
# AUTHENTICATION ROUTES (unchanged)
# -------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        user = authenticate_user(username, password, DB_PATH, ip_address)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_role'] = user['role']
            session['full_name'] = user['full_name']
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/admin/users')
@login_required
@role_required(['administrator'])
def admin_users():
    users = get_users(DB_PATH)
    return render_template('admin.html', users=users, roles=ROLES)

@app.route('/admin/users/create', methods=['POST'])
@login_required
@role_required(['administrator'])
def create_user_route():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    email = request.form.get('email')
    full_name = request.form.get('full_name')
    if not all([username, password, role, email, full_name]):
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_users'))
    result = create_user(username, password, role, email, full_name, DB_PATH)
    if result['success']:
        flash(f'User {username} created successfully', 'success')
    else:
        flash(f'Error creating user: {result.get("error", "Unknown error")}', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@role_required(['administrator'])
def toggle_user(user_id):
    result = toggle_user_status(user_id, DB_PATH)
    if result['success']:
        flash('User status updated', 'success')
    else:
        flash('Error updating user status', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['administrator'])
def delete_user_route(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete yourself', 'danger')
        return redirect(url_for('admin_users'))
    result = delete_user(user_id, DB_PATH)
    if result['success']:
        flash('User deleted successfully', 'success')
    else:
        flash('Error deleting user', 'danger')
    return redirect(url_for('admin_users'))

# -------------------------------------------------------------------
# MAIN PAGES
# -------------------------------------------------------------------
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'),
                         full_name=session.get('full_name'))

@app.route('/ai-soc')
@login_required
def ai_soc():
    return render_template('ai_soc.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'),
                         full_name=session.get('full_name'))

@app.route('/ai-assistant')
@login_required
def ai_assistant():
    return render_template('ai_assistant.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'),
                         full_name=session.get('full_name'))

@app.route('/audit')
@login_required
@role_required(['administrator', 'manager'])
def audit_log_page():
    record_audit('audit_log_viewed', 'audit_log', 'all')
    return render_template('audit_log.html', user_role=session.get('user_role'), username=session.get('username'))

@app.route('/devices')
@login_required
def devices():
    record_audit('device_inventory_viewed', 'device_inventory', 'all')
    return render_template('devices.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/scan')
@login_required
@role_required(['administrator', 'manager'])
def scan_page():
    return render_template('scan.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/reports')
@login_required
def reports():
    record_audit('reports_viewed', 'report', 'reports')
    return render_template('reports.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/network')
@login_required
def network():
    record_audit('topology_viewed', 'network_topology', 'all')
    return render_template('network.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/map')
@login_required
def device_map():
    return render_template('device_map.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/recommendations')
@login_required
def recommendations():
    return render_template('recommendations.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/attack-intelligence')
@login_required
def attack_intelligence():
    return render_template('attack_intelligence.html',
                         user_role=session.get('user_role'),
                         username=session.get('username'))

@app.route('/cve/<cve_id>')
@login_required
def cve_detail(cve_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT cve_id, description, cvss_score, severity,
                   published_date, last_modified, references_text, cvss_vector
            FROM cves
            WHERE cve_id = ?
        ''', (cve_id,))
        cve = cursor.fetchone()
        if not cve:
            flash('CVE not found', 'danger')
            return redirect(url_for('devices'))
        cve_dict = dict(cve)
        if cve_dict.get('references_text'):
            try:
                cve_dict['references'] = json.loads(cve_dict['references_text'])
            except:
                cve_dict['references'] = []
        else:
            cve_dict['references'] = []
        cursor.execute('''
            SELECT d.id, d.ip_address, d.hostname, d.device_type, dv.service
            FROM device_vulnerabilities dv
            JOIN devices d ON dv.device_id = d.id
            WHERE dv.cve_id = ?
        ''', (cve_id,))
        affected_devices = [dict(row) for row in cursor.fetchall()]
        cursor.execute('''
            SELECT kev_status, exploit_count, epss_score, epss_percentile,
                   risk_score, risk_level, priority
            FROM threat_intel
            WHERE cve_id = ?
        ''', (cve_id,))
        threat_intel = cursor.fetchone()
        threat_dict = dict(threat_intel) if threat_intel else {}
        conn.close()
        return render_template('cve_detail.html',
                             cve=cve_dict,
                             affected_devices=affected_devices,
                             threat_intel=threat_dict,
                             user_role=session.get('user_role'),
                             username=session.get('username'))
    except Exception as e:
        logger.error(f"Error loading CVE details: {e}")
        flash('Error loading CVE details', 'danger')
        return redirect(url_for('devices'))

# ========================= PAGINATION HELPER =========================
def get_pagination_params(default_per_page=5, max_per_page=200):
    """Extract and validate page and per_page from request args."""
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get('per_page', default_per_page))
    except ValueError:
        per_page = default_per_page
    # Clamp values
    page = max(1, page)
    per_page = max(1, min(max_per_page, per_page))
    offset = (page - 1) * per_page
    return page, per_page, offset

# -------------------------------------------------------------------
# API ROUTES – DEVICES (with pagination)
# -------------------------------------------------------------------
@app.route('/api/devices')
@login_required
def get_devices():
    try:
        page, per_page, offset = get_pagination_params()
        conn = get_db()
        cursor = conn.cursor()
        # Total count
        cursor.execute('SELECT COUNT(*) FROM devices')
        total = cursor.fetchone()[0]
        cursor.execute('''
            SELECT d.*,
                   r.risk_score, r.risk_level, r.total_cves,
                   r.critical_cves, r.high_cves, r.recommendations
            FROM devices d
            LEFT JOIN device_risks r ON d.id = r.device_id
            ORDER BY r.risk_score DESC NULLS LAST
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        record_audit('device_inventory_exported', 'device_inventory', 'all', {'count': len(devices), 'format': 'json_api', 'page': page, 'per_page': per_page})
        return jsonify({
            'success': True,
            'devices': devices,
            'count': len(devices),
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/device-locations')
@login_required
def get_device_locations():
    """Return devices with operational locations, without changing ML data."""
    try:
        page, per_page, offset = get_pagination_params()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        total = cursor.fetchone()[0]
        cursor.execute('''
            SELECT d.id, d.ip_address, d.mac_address, d.hostname, d.device_type,
                   d.os, d.last_seen, r.risk_score, r.risk_level,
                   dl.site, dl.building, dl.floor, dl.zone, dl.rack,
                   dl.switch_port, dl.notes, dl.updated_at
            FROM devices d
            LEFT JOIN device_risks r ON d.id = r.device_id
            LEFT JOIN device_locations dl ON d.id = dl.device_id
            ORDER BY COALESCE(dl.site, 'Unassigned'), COALESCE(dl.zone, 'Unassigned'),
                     r.risk_score DESC NULLS LAST, d.ip_address
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        devices = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'success': True,
            'devices': devices,
            'count': len(devices),
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page,
            'location_mode': 'operational_zone'
        })
    except Exception as e:
        logger.error(f'Error loading device locations: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/device-locations/<int:device_id>', methods=['PUT'])
@login_required
@role_required(['administrator', 'manager'])
def update_device_location(device_id):
    try:
        payload = request.get_json(silent=True) or {}
        allowed = ('site', 'building', 'floor', 'zone', 'rack', 'switch_port', 'notes')
        values = {field: str(payload.get(field, '')).strip() for field in allowed}
        values['site'] = values['site'] or 'Primary Site'
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        cursor.execute('''
            INSERT INTO device_locations
                (device_id, site, building, floor, zone, rack, switch_port, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                site=excluded.site, building=excluded.building, floor=excluded.floor,
                zone=excluded.zone, rack=excluded.rack, switch_port=excluded.switch_port,
                notes=excluded.notes, updated_at=excluded.updated_at
        ''', (device_id, values['site'], values['building'], values['floor'], values['zone'],
              values['rack'], values['switch_port'], values['notes'], datetime.now().isoformat()))
        conn.commit()
        conn.close()
        record_audit('device_location_changed', 'device_location', device_id, values)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Error updating device location: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>')
@login_required
def get_device(device_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.*,
                   r.risk_score, r.risk_level, r.total_cves,
                   r.critical_cves, r.high_cves, r.recommendations
            FROM devices d
            LEFT JOIN device_risks r ON d.id = r.device_id
            WHERE d.id = ?
        ''', (device_id,))
        device = cursor.fetchone()
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        device_dict = dict(device)
        cursor.execute('''
            SELECT c.cve_id, c.description, c.cvss_score,
                   c.severity, c.published_date, dv.service
            FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            WHERE dv.device_id = ?
            ORDER BY c.cvss_score DESC
        ''', (device_id,))
        device_dict['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
        conn.close()
        record_audit('device_viewed', 'device', device_id, {'ip_address': device_dict.get('ip_address')})
        return jsonify({'success': True, 'device': device_dict})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – SCAN (Background + Concurrent)
# -------------------------------------------------------------------
@app.route('/api/scan/real', methods=['POST'])
@login_required
@role_required(['administrator', 'manager'])
def real_scan():
    """Start a background scan and return job_id."""
    try:
        data = request.get_json()
        target = data.get('target')
        scan_type = data.get('scan_type', 'quick')
        timeout = data.get('timeout', 30)
        retries = data.get('retries', 3)

        if not target:
            return jsonify({'success': False, 'error': 'Missing target'}), 400

        user_id = session.get('user_id')
        job_id = create_scan_job(target, scan_type, timeout, retries, user_id)

        # Start background thread
        thread = threading.Thread(target=run_scan_in_background,
                                  args=(job_id, target, scan_type, timeout, retries))
        thread.daemon = True
        thread.start()
        logger.info(f"Background scan job {job_id} started for user {user_id}")

        return jsonify({'success': True, 'job_id': job_id})
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/status/<int:job_id>')
@login_required
def scan_status(job_id):
    job = get_scan_job(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    if job['user_id'] != session.get('user_id') and session.get('user_role') not in ['administrator']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    response = {
        'success': True,
        'job': {
            'id': job['id'],
            'status': job['status'],
            'progress': job['progress'],
            'result': json.loads(job['result']) if job['result'] else None,
            'error': job['error'],
            'duration': job['duration'],
            'created_at': job['created_at'],
            'started_at': job['started_at'],
            'completed_at': job['completed_at']
        }
    }
    return jsonify(response)

@app.route('/api/scan/export/<int:job_id>')
@login_required
def export_scan_pdf(job_id):
    job = get_scan_job(job_id)
    if not job or job['status'] != 'completed':
        return jsonify({'success': False, 'error': 'No completed results'}), 400
    if job['user_id'] != session.get('user_id') and session.get('user_role') not in ['administrator']:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    devices = json.loads(job['result']) if job['result'] else []
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"Scan Report – {job['target']}", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Scan Type: {job['scan_type']}  |  Date: {job['completed_at']}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Table
    data = [['IP', 'Hostname', 'MAC', 'Brand', 'Device Type', 'OS', 'Open Ports', 'Confidence', 'Source']]
    for dev in devices:
        ports = ', '.join(map(str, dev.get('open_ports', [])))
        sources = ', '.join(dev.get('source', []))
        data.append([
            dev.get('ip_address', ''),
            dev.get('hostname', ''),
            dev.get('mac_address', ''),
            dev.get('brand', ''),
            dev.get('device_type', ''),
            dev.get('os', ''),
            ports,
            f"{dev.get('confidence', 0)*100:.1f}%",
            sources
        ])

    table = Table(data, colWidths=[80, 100, 100, 80, 80, 80, 80, 70, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name=f"scan_report_{job_id}_{datetime.now().strftime('%Y%m%d')}.pdf",
                     mimetype='application/pdf')

# -------------------------------------------------------------------
# API ROUTES – STATISTICS (including advanced)
# -------------------------------------------------------------------
@app.route('/api/statistics/overview')
@login_required
def get_statistics_overview():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        total_devices = cursor.fetchone()[0] or 0
        cursor.execute('SELECT device_type, COUNT(*) as count FROM devices GROUP BY device_type')
        devices_by_type = {row['device_type']: row['count'] for row in cursor.fetchall()}
        cursor.execute('SELECT risk_level, COUNT(*) as count FROM device_risks GROUP BY risk_level')
        risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}
        cursor.execute('SELECT AVG(risk_score) FROM device_risks')
        avg_risk = cursor.fetchone()[0] or 0
        cursor.execute('SELECT COUNT(*) FROM device_vulnerabilities')
        total_vulns = cursor.fetchone()[0] or 0
        cursor.execute('''
            SELECT COUNT(*) FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            WHERE c.severity = 'CRITICAL'
        ''')
        critical_vulns = cursor.fetchone()[0] or 0
        cursor.execute('''
            SELECT DATE(detected_date) as date, COUNT(*) as count
            FROM device_vulnerabilities
            WHERE detected_date >= DATE('now', '-30 days')
            GROUP BY DATE(detected_date)
            ORDER BY date
        ''')
        scan_history = [{'date': row['date'], 'count': row['count']} for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'success': True,
            'statistics': {
                'total_devices': total_devices,
                'devices_by_type': devices_by_type,
                'risk_distribution': risk_distribution,
                'average_risk_score': round(avg_risk, 2),
                'total_vulnerabilities': total_vulns,
                'critical_vulnerabilities': critical_vulns,
                'scan_history': scan_history,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai-assistant/chat', methods=['POST'])
@login_required
def ai_assistant_chat():
    """Answer bounded, evidence-based questions from the current project data."""
    try:
        payload = request.get_json(silent=True) or {}
        question = str(payload.get('question', '')).strip()
        if not question:
            return jsonify({'success': False, 'error': 'Question is required'}), 400
        if len(question) > 500:
            return jsonify({'success': False, 'error': 'Question is too long'}), 400

        normalized = question.lower()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) AS total FROM devices')
        total_devices = cursor.fetchone()['total'] or 0
        cursor.execute('''
            SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN c.severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical
            FROM device_vulnerabilities dv JOIN cves c ON dv.cve_id = c.cve_id
        ''')
        vulnerability_totals = dict(cursor.fetchone())
        cursor.execute('''
            SELECT d.ip_address, d.hostname, d.device_type, d.os, d.last_seen,
                   COALESCE(r.risk_score, 0) AS risk_score, COALESCE(r.risk_level, 'NONE') AS risk_level,
                   COALESCE(r.total_cves, 0) AS total_cves,
                   dl.site, dl.building, dl.floor, dl.zone
            FROM devices d LEFT JOIN device_risks r ON d.id = r.device_id
            LEFT JOIN device_locations dl ON d.id = dl.device_id
            ORDER BY risk_score DESC, total_cves DESC LIMIT 8
        ''')
        priority_devices = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if any(term in normalized for term in ('explain', 'why is', 'why are')):
            target = priority_devices[0] if priority_devices else None
            answer = (f"{target['hostname'] or target['ip_address']} is prioritized because it has {target['total_cves']} CVEs, a {target['risk_level']} risk level, and a risk score of {target['risk_score']}. Validate open services and patch exposure before containment.") if target else 'No scored device is available to explain yet.'
            intent = 'risk_explanation'
        elif any(term in normalized for term in ('compare scan', 'scan comparison', 'what changed')):
            conn = get_db()
            scans = [dict(row) for row in conn.execute('SELECT scan_time, target, total_devices FROM scan_history ORDER BY id DESC LIMIT 2').fetchall()]
            conn.close()
            answer = ('Latest scan comparison:\n' + '\n'.join(f"{item['scan_time']} · {item['target']} · {item['total_devices'] or 0} devices" for item in scans)) if scans else 'There are not enough completed scans to compare yet.'
            intent = 'scan_comparison'
        elif any(term in normalized for term in ('subnet', 'segment', 'network range')):
            groups = {}
            for item in priority_devices:
                parts = (item['ip_address'] or '').split('.')
                key = '.'.join(parts[:3]) + '.0/24' if len(parts) == 4 else 'unknown'
                groups[key] = groups.get(key, 0) + 1
            answer = 'Subnet summary:\n' + '\n'.join(f'{key}: {count} priority devices in current feed' for key, count in groups.items())
            intent = 'subnet_summary'
        elif any(term in normalized for term in ('attack path', 'lateral movement', 'attack route')):
            target = priority_devices[0] if priority_devices else None
            answer = (f"Likely attack path hypothesis: exposed services on {target['hostname'] or target['ip_address']} ({target['risk_level']} risk) could provide an initial foothold, followed by subnet-level lateral movement. Confirm with Network Topology and service evidence; this is a hypothesis, not proof of compromise.") if target else 'No prioritized asset is available for an attack-path hypothesis.'
            intent = 'attack_path_hypothesis'
        elif any(term in normalized for term in ('incident', 'contain', 'build an incident')):
            target = priority_devices[0] if priority_devices else None
            incident = f"Incident draft: investigate {target['hostname'] or target['ip_address']} ({target['risk_level']} risk), preserve scan evidence, restrict unnecessary exposure, validate patches, and document containment." if target else 'Incident draft requires at least one scored device.'
            record_audit('copilot_incident_drafted', 'device', target['ip_address'] if target else None, {'question': question, 'draft': incident})
            answer = incident
            intent = 'incident_draft'
        elif any(term in normalized for term in ('executive report', 'executive summary', 'briefing')):
            answer = f"Executive briefing: {total_devices} devices monitored, {vulnerability_totals['total']} vulnerability records, and {vulnerability_totals['critical']} critical findings. Immediate focus should be critical-risk assets, remediation ownership, and scan-to-scan change tracking."
            intent = 'executive_brief'
        elif any(term in normalized for term in ('where', 'location', 'floor', 'room', 'campus')):
            located = [item for item in priority_devices if item['floor'] or item['zone']]
            answer = ('The highest-priority devices with operational placement are:\n' + '\n'.join(f"{item['hostname'] or item['ip_address']} - {item['floor'] or 'Floor unassigned'} / {item['zone'] or 'Room unassigned'}" for item in located[:6])) if located else 'No priority devices have operational floor or room assignments yet. Open Campus Map to place them.'
            intent = 'campus_location'
        elif any(term in normalized for term in ('critical', 'riskiest', 'highest risk', 'priority', 'investigate first', 'which devices')):
            listed = priority_devices[:5]
            lines = [f"{item['hostname'] or item['ip_address']} ({item['ip_address']}) - {item['risk_level']} risk, {item['total_cves']} CVEs" for item in listed]
            answer = f"I found {vulnerability_totals['critical']} critical findings across {total_devices} devices. The highest-priority assets are:\n" + ('\n'.join(lines) if lines else 'No prioritized devices are available.')
            intent = 'risk_triage'
        elif any(term in normalized for term in ('router', 'routers', 'network equipment')):
            routers = [item for item in priority_devices if 'router' in (item['device_type'] or '').lower()]
            answer = f"The current priority feed contains {len(routers)} router records in its top results. Use Devices for the complete inventory.\n" + ('\n'.join(f"{item['ip_address']} - {item['risk_level']} risk" for item in routers) if routers else 'No routers appeared in the current priority feed.')
            intent = 'network_equipment'
        elif any(term in normalized for term in ('anomal', 'unusual', 'behavior')):
            ensure_tables()
            anomalies = get_anomaly_summary()
            answer = f"The anomaly engine currently reports {len(anomalies)} signal records. Open AI SOC or the anomaly view for the detailed evidence and model scores."
            intent = 'anomaly_review'
        elif any(term in normalized for term in ('recommend', 'next step', 'fix', 'remediat')):
            cursor = get_db().cursor()
            cursor.execute("SELECT title, priority, status FROM recommendations WHERE status NOT IN ('done', 'dismissed') ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT 5")
            recommendations = [dict(row) for row in cursor.fetchall()]
            answer = ('Your current remediation queue is:\n' + '\n'.join(f"{item['priority'].upper()}: {item['title']} ({item['status']})" for item in recommendations)) if recommendations else 'There are no open recommendations. Generate a new recommendation set from the Recommendations page.'
            intent = 'remediation'
        else:
            answer = f"I can help investigate this network. Current context: {total_devices} devices, {vulnerability_totals['total']} vulnerability records, and {vulnerability_totals['critical']} critical findings. Try asking about critical devices, routers, anomalies, recommendations, or campus locations."
            intent = 'overview'

        record_audit('copilot_query', 'ai_assistant', intent, {'question': question})
        return jsonify({'success': True, 'answer': answer, 'intent': intent, 'sources': ['live device inventory', 'risk and vulnerability tables', 'scan history', 'operational location data']})
    except Exception as e:
        logger.error(f'AI assistant error: {e}')
        return jsonify({'success': False, 'error': 'The assistant could not query current project data'}), 500

@app.route('/api/statistics/advanced')
@login_required
def get_advanced_stats():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT device_type, COUNT(*) as count FROM devices GROUP BY device_type')
        device_types = {row['device_type']: row['count'] for row in cursor.fetchall()}
        cursor.execute('SELECT os, COUNT(*) as count FROM devices GROUP BY os')
        os_dist = {row['os']: row['count'] for row in cursor.fetchall()}
        cursor.execute('SELECT risk_level, COUNT(*) as count FROM device_risks GROUP BY risk_level')
        risk_levels = {row['risk_level']: row['count'] for row in cursor.fetchall()}
        cursor.execute('''
            SELECT DATE(detected_date) as date, severity, COUNT(*) as count
            FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            WHERE detected_date >= DATE('now', '-7 days')
            GROUP BY DATE(detected_date), severity
            ORDER BY date
        ''')
        trend_data = {}
        for row in cursor.fetchall():
            date = row['date']
            severity = row['severity']
            count = row['count']
            if date not in trend_data:
                trend_data[date] = {'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0}
            if severity in trend_data[date]:
                trend_data[date][severity] = count
        dates = sorted(trend_data.keys())
        critical = [trend_data[d].get('CRITICAL',0) for d in dates]
        high = [trend_data[d].get('HIGH',0) for d in dates]
        medium = [trend_data[d].get('MEDIUM',0) for d in dates]
        low = [trend_data[d].get('LOW',0) for d in dates]
        conn.close()
        return jsonify({
            'success': True,
            'device_types': device_types,
            'os_distribution': os_dist,
            'risk_levels': risk_levels,
            'trend_dates': dates,
            'trend_critical': critical,
            'trend_high': high,
            'trend_medium': medium,
            'trend_low': low
        })
    except Exception as e:
        logger.error(f"Error getting advanced stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/statistics/top-cves')
@login_required
def get_top_cves():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT c.cve_id, c.cvss_score, c.severity,
                   COUNT(dv.device_id) as affected_devices,
                   c.description
            FROM cves c
            JOIN device_vulnerabilities dv ON c.cve_id = dv.cve_id
            GROUP BY c.cve_id
            ORDER BY c.cvss_score DESC
            LIMIT 10
        ''')
        top_cves = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'success': True, 'top_cves': top_cves})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/statistics/risk-timeline')
@login_required
def get_risk_timeline():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DATE(detected_date) as date,
                   COUNT(CASE WHEN c.severity = 'CRITICAL' THEN 1 END) as critical,
                   COUNT(CASE WHEN c.severity = 'HIGH' THEN 1 END) as high,
                   COUNT(CASE WHEN c.severity = 'MEDIUM' THEN 1 END) as medium,
                   COUNT(CASE WHEN c.severity = 'LOW' THEN 1 END) as low
            FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            WHERE detected_date >= DATE('now', '-7 days')
            GROUP BY DATE(detected_date)
            ORDER BY date
        ''')
        timeline = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'success': True, 'timeline': timeline})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – SCAN HISTORY (with pagination)
# -------------------------------------------------------------------
@app.route('/api/scan/history')
@login_required
def get_scan_history():
    try:
        page, per_page, offset = get_pagination_params()  # now uses default 5
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scan_history')
        total = cursor.fetchone()[0]
        cursor.execute('''
            SELECT * FROM scan_history
            ORDER BY scan_time DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({
            'success': True,
            'history': history,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"Error fetching scan history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – REPORTS
# -------------------------------------------------------------------
@app.route('/api/reports/executive')
@login_required
def get_executive_report():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM devices')
        total_devices = cursor.fetchone()[0] or 0
        cursor.execute('''
            SELECT COUNT(*) FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            WHERE c.severity = 'CRITICAL'
        ''')
        critical_vulns = cursor.fetchone()[0] or 0
        cursor.execute('SELECT COUNT(*) FROM device_vulnerabilities')
        total_vulns = cursor.fetchone()[0] or 0
        cursor.execute('SELECT AVG(risk_score) FROM device_risks')
        avg_risk = cursor.fetchone()[0] or 0
        conn.close()
        risk_level = 'LOW'
        recommendation = 'Network appears secure. Continue regular monitoring.'
        if critical_vulns > 0:
            risk_level = 'CRITICAL'
            recommendation = 'Immediate action required! Critical vulnerabilities detected.'
        elif total_vulns > 10:
            risk_level = 'HIGH'
            recommendation = 'Multiple vulnerabilities detected. Schedule remediation.'
        elif total_vulns > 0:
            risk_level = 'MEDIUM'
            recommendation = 'Some vulnerabilities present. Continue monitoring.'
        return jsonify({
            'success': True,
            'report': {
                'total_devices': total_devices,
                'critical_vulnerabilities': critical_vulns,
                'total_vulnerabilities': total_vulns,
                'average_risk_score': round(avg_risk, 2),
                'risk_level': risk_level,
                'recommendation': recommendation,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/reports/compliance')
@login_required
def get_compliance_report():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT c.severity, COUNT(*) as count
            FROM device_vulnerabilities dv
            JOIN cves c ON dv.cve_id = c.cve_id
            GROUP BY c.severity
        ''')
        severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
        total_vulns = sum(severity_counts.values()) or 1
        critical_vulns = severity_counts.get('CRITICAL', 0)
        high_vulns = severity_counts.get('HIGH', 0)
        score_cis = max(0, 100 - (critical_vulns * 10 + total_vulns * 0.5))
        score_nist = max(0, 100 - (critical_vulns * 8 + total_vulns * 0.3))
        score_iso = max(0, 100 - (critical_vulns * 12 + total_vulns * 0.2))
        conn.close()
        return jsonify({
            'success': True,
            'compliance': {
                'cis_score': round(min(100, score_cis), 1),
                'nist_score': round(min(100, score_nist), 1),
                'iso_score': round(min(100, score_iso), 1),
                'severity_counts': severity_counts,
                'overall_score': round((score_cis + score_nist + score_iso) / 3, 1)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/reports/send-email', methods=['POST'])
@login_required
@role_required(['administrator', 'manager'])
def send_report_email():
    try:
        email = request.form.get('email')
        pdf_file = request.files.get('pdf')
        if not email or not pdf_file:
            return jsonify({'success': False, 'error': 'Missing email or PDF file'}), 400
        if '@' not in email or '.' not in email:
            return jsonify({'success': False, 'error': 'Invalid email address'}), 400
        pdf_data = pdf_file.read()
        msg = Message(
            subject='Network Security Report',
            recipients=[email],
            body='Please find the attached network security report.',
            sender=('Your Network Scanner', app.config['MAIL_DEFAULT_SENDER'])
        )
        msg.attach(
            filename=f'report_{datetime.now().strftime("%Y-%m-%d")}.pdf',
            content_type='application/pdf',
            data=pdf_data
        )
        mail.send(msg)
        logger.info(f"Report sent successfully to {email}")
        return jsonify({'success': True, 'message': f'Report sent to {email}'})
    except Exception as e:
        logger.error(f"Email send error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – NETWORK GRAPH
# -------------------------------------------------------------------
def get_risk_color(risk_level):
    colors = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff8800',
        'MEDIUM': '#ffcc00',
        'LOW': '#00ff88',
        'NONE': '#8899aa'
    }
    return colors.get(risk_level, '#8899aa')

@app.route('/api/network/graph')
@login_required
def get_network_graph():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
                 SELECT d.id, d.ip_address, d.hostname, d.device_type, d.os,
                     r.risk_score, r.risk_level, r.total_cves, r.critical_cves,
                     dl.floor, dl.zone, dl.site
            FROM devices d
            LEFT JOIN device_risks r ON d.id = r.device_id
                 LEFT JOIN device_locations dl ON d.id = dl.device_id
        ''')
        devices = cursor.fetchall()
        conn.close()
        if not devices:
            return jsonify({'success': True, 'graph': {'nodes': [], 'links': []}})
        nodes = []
        for dev in devices:
            node = {
                'id': dev['id'],
                'label': dev['hostname'] or dev['ip_address'],
                'ip': dev['ip_address'],
                'device_type': dev['device_type'] or 'Unknown',
                'os': dev['os'] or 'Unknown',
                'risk_score': dev['risk_score'] or 0,
                'risk_level': dev['risk_level'] or 'NONE',
                'total_cves': dev['total_cves'] or 0,
                'critical_cves': dev['critical_cves'] or 0,
                'floor': dev['floor'] or '',
                'zone': dev['zone'] or '',
                'site': dev['site'] or '',
                'size': 22,
                'color': get_risk_color(dev['risk_level'] or 'NONE')
            }
            nodes.append(node)
        links = []
        for i, a in enumerate(nodes):
            for b in nodes[i+1:]:
                a_ip = a['ip'].split('.')
                b_ip = b['ip'].split('.')
                if len(a_ip) >= 3 and len(b_ip) >= 3 and a_ip[:3] == b_ip[:3]:
                    links.append({'source': a['id'], 'target': b['id'], 'type': 'subnet'})
        risk_summary = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'NONE':0}
        for node in nodes:
            risk_summary[node['risk_level']] = risk_summary.get(node['risk_level'], 0) + 1
        metadata = {'total_devices': len(nodes), 'risk_summary': risk_summary}
        return jsonify({
            'success': True,
            'graph': {'nodes': nodes, 'links': links, 'metadata': metadata}
        })
    except Exception as e:
        logger.error(f"Error in network graph: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – AI RECOMMENDATIONS (with pagination)
# -------------------------------------------------------------------
@app.route('/api/recommendations/generate', methods=['POST'])
@login_required
@role_required(['administrator', 'manager'])
def generate_recommendations():
    try:
        ai = AIRecommendations(DB_PATH)
        results = ai.generate_all_recommendations()
        if 'error' in results:
            return jsonify({'success': False, 'error': results['error']}), 500
        return jsonify({'success': True, 'summary': results['summary'], 'recommendations': results})
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/recommendations/all')
@login_required
def get_all_recommendations():
    try:
        page, per_page, offset = get_pagination_params()  # now uses default 5
        ai = AIRecommendations(DB_PATH)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM recommendations')
        total = cursor.fetchone()[0]
        cursor.execute('''
            SELECT r.*, d.ip_address as device_ip, d.device_type
            FROM recommendations r
            LEFT JOIN devices d ON r.device_id = d.id
            ORDER BY r.id DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        recommendations = [dict(row) for row in cursor.fetchall()]
        conn.close()
        summary = ai.get_recommendation_summary() if hasattr(ai, 'get_recommendation_summary') else {}
        return jsonify({
            'success': True,
            'recommendations': recommendations,
            'summary': summary,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/recommendations/<int:rec_id>')
@login_required
def get_recommendation(rec_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.*, d.ip_address as device_ip, d.device_type
            FROM recommendations r
            LEFT JOIN devices d ON r.device_id = d.id
            WHERE r.id = ?
        ''', (rec_id,))
        rec = cursor.fetchone()
        conn.close()
        if not rec:
            return jsonify({'success': False, 'error': 'Recommendation not found'}), 404
        return jsonify({'success': True, 'recommendation': dict(rec)})
    except Exception as e:
        logger.error(f"Error getting recommendation: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/recommendations/<int:rec_id>/status', methods=['PUT'])
@login_required
def update_recommendation_status(rec_id):
    try:
        data = request.get_json()
        status = data.get('status')
        if status not in ['pending', 'in_progress', 'done', 'dismissed']:
            return jsonify({'success': False, 'error': 'Invalid status'}), 400
        ai = AIRecommendations(DB_PATH)
        result = ai.update_recommendation_status(rec_id, status)
        record_audit('recommendation_status_changed', 'recommendation', rec_id, {'status': status})
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error updating recommendation status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – EXPLOIT INTELLIGENCE
# -------------------------------------------------------------------
@app.route('/api/exploit/search/<cve_id>')
@login_required
def search_exploits(cve_id):
    try:
        ei = ExploitIntelligence(DB_PATH)
        exploits = ei.search_github_exploits(cve_id)
        return jsonify({'success': True, 'cve_id': cve_id, 'exploits': exploits, 'count': len(exploits)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/attack/scenarios/<int:device_id>')
@login_required
def get_attack_scenarios(device_id):
    try:
        ei = ExploitIntelligence(DB_PATH)
        scenarios = ei.get_device_attack_scenarios(device_id)
        return jsonify({'success': True, 'device_id': device_id, 'scenarios': scenarios, 'count': len(scenarios)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/attack/analyze/<int:device_id>', methods=['POST'])
@login_required
def analyze_attack_scenario(device_id):
    try:
        ei = ExploitIntelligence(DB_PATH)
        result = ei.analyze_attack_scenario(device_id)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – ANOMALY DETECTION
# -------------------------------------------------------------------
@app.route('/api/anomalies/train', methods=['POST'])
@login_required
@role_required(['administrator', 'manager'])
def train_anomaly_model():
    try:
        compute_anomaly_scores()
        return jsonify({'success': True, 'message': 'Anomaly model trained and scores updated.'})
    except Exception as e:
        logger.error(f"Anomaly training error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/anomalies')
@login_required
def get_anomalies():
    try:
        ensure_tables()
        anomalies = get_anomaly_summary()
        return jsonify({'success': True, 'anomalies': anomalies})
    except Exception as e:
        logger.error(f"Error fetching anomalies: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# -------------------------------------------------------------------
# API ROUTES – AUDIT LOG (with pagination)
# -------------------------------------------------------------------
@app.route('/api/audit/log')
@login_required
@role_required(['administrator', 'manager'])
def get_audit_log():
    try:
        page, per_page, offset = get_pagination_params()  # now uses default 5
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
        rows = [dict(row) for row in conn.execute('''
            SELECT id, event_time, username, action, resource_type, resource_id,
                   details, ip_address, previous_hash, event_hash
            FROM audit_log
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()]
        conn.close()
        return jsonify({
            'success': True,
            'events': rows,
            'count': len(rows),
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as error:
        logger.error(f'Error loading audit log: {error}')
        return jsonify({'success': False, 'error': 'Audit log unavailable'}), 500

@app.route('/api/audit/verify')
@login_required
@role_required(['administrator', 'manager'])
def verify_audit_log():
    import hashlib
    conn = get_db()
    rows = [dict(row) for row in conn.execute('SELECT * FROM audit_log ORDER BY id').fetchall()]
    conn.close()
    previous = ''
    for row in rows:
        payload = json.dumps({
            'event_time': row['event_time'], 'user_id': row['user_id'],
            'username': row['username'], 'action': row['action'],
            'resource_type': row['resource_type'], 'resource_id': row['resource_id'],
            'details': json.loads(row['details'] or '{}'), 'ip_address': row['ip_address'],
            'previous_hash': previous
        }, sort_keys=True, default=str)
        if row['previous_hash'] != previous or hashlib.sha256(payload.encode()).hexdigest() != row['event_hash']:
            return jsonify({'success': True, 'valid': False, 'broken_at': row['id']})
        previous = row['event_hash']
    return jsonify({'success': True, 'valid': True, 'verified_events': len(rows)})

@app.route('/api/audit/event', methods=['POST'])
@login_required
def record_client_audit_event():
    payload = request.get_json(silent=True) or {}
    action = payload.get('action')
    if action not in {'report_exported', 'report_printed', 'copilot_action'}:
        return jsonify({'success': False, 'error': 'Unsupported audit action'}), 400
    record_audit(action, payload.get('resource_type', 'report'), payload.get('resource_id'), payload.get('details', {}))
    return jsonify({'success': True})

# -------------------------------------------------------------------
# CONTEXT PROCESSOR
# -------------------------------------------------------------------
@app.context_processor
def utility_processor():
    return {
        'user_role': session.get('user_role'),
        'username': session.get('username'),
        'full_name': session.get('full_name'),
        'has_permission': has_permission,
        'DEFAULT_PAGE_SIZE': 5   # frontend can use this for consistent pagination
    }

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
if __name__ == '__main__':
    from pathlib import Path
    Path('templates').mkdir(exist_ok=True)
    Path('static/css').mkdir(parents=True, exist_ok=True)

    import socket
    for port in [5000, 5001, 5002, 8080]:
        try:
            sock = socket.socket()
            sock.bind(('', port))
            sock.close()
            print("📝 Default credentials: admin / admin123")
            print("📧 Email reports will be sent using the configured SMTP settings.")
            print("✅ Background scanning and PDF export enabled.")
            print("✅ Pagination enabled for all large data endpoints (5 per page).")
            app.run(debug=True, host='0.0.0.0', port=port)
            break
        except:
            continue