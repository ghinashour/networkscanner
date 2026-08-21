"""
Authentication Module - Role-Based Access Control
"""

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, redirect, url_for, flash, jsonify
import logging

logger = logging.getLogger(__name__)

# User roles
ROLES = {
    'ADMIN': 'administrator',
    'MANAGER': 'manager',
    'ANALYST': 'security_analyst'
}

# Role permissions
PERMISSIONS = {
    'administrator': {
        'view_dashboard': True,
        'view_devices': True,
        'view_risks': True,
        'scan_network': True,
        'manage_users': True,
        'manage_devices': True,
        'view_reports': True,
        'export_data': True,
        'delete_data': True,
        'configure_settings': True
    },
    'manager': {
        'view_dashboard': True,
        'view_devices': True,
        'view_risks': True,
        'scan_network': True,
        'manage_users': False,
        'manage_devices': True,
        'view_reports': True,
        'export_data': True,
        'delete_data': False,
        'configure_settings': False
    },
    'security_analyst': {
        'view_dashboard': True,
        'view_devices': True,
        'view_risks': True,
        'scan_network': False,
        'manage_users': False,
        'manage_devices': False,
        'view_reports': True,
        'export_data': False,
        'delete_data': False,
        'configure_settings': False
    }
}

def hash_password(password):
    """Hash password using SHA-256 with salt"""
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.sha256((salt + password).encode()).hexdigest()

def verify_password(password, hashed):
    """Verify password against hash"""
    salt, hash_value = hashed.split(':')
    return hash_value == hashlib.sha256((salt + password).encode()).hexdigest()

def init_auth_db(db_path="data/network_scanner.db"):
    """Initialize authentication tables"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                created_at TEXT,
                last_login TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Login attempts table (for security)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT,
                attempt_time TEXT,
                success INTEGER
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO users 
                (username, password_hash, role, email, full_name, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                'admin',
                hash_password('admin123'),
                'administrator',
                'admin@network-scanner.local',
                'System Administrator',
                datetime.now().isoformat(),
                1
            ))
            logger.info("✅ Default admin user created (admin/admin123)")
        
        conn.commit()
        conn.close()
        logger.info("✅ Authentication database initialized")
        
    except Exception as e:
        logger.error(f"Error initializing auth database: {e}")
        raise

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Decorator to require specific role(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session:
                flash('Please login to access this page', 'warning')
                return redirect(url_for('login'))
            if session['user_role'] not in allowed_roles and session['user_role'] != 'administrator':
                flash('You do not have permission to access this page', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def has_permission(permission):
    """Check if current user has a specific permission"""
    if 'user_role' not in session:
        return False
    role = session['user_role']
    return PERMISSIONS.get(role, {}).get(permission, False)

def get_user_role(user_id, db_path="data/network_scanner.db"):
    """Get user role from database"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except:
        return None

def authenticate_user(username, password, db_path="data/network_scanner.db", ip_address=None):
    """Authenticate a user"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Log attempt
        cursor.execute('''
            INSERT INTO login_attempts (username, ip_address, attempt_time, success)
            VALUES (?, ?, ?, ?)
        ''', (username, ip_address, datetime.now().isoformat(), 0))
        
        # Get user
        cursor.execute('''
            SELECT id, username, password_hash, role, full_name 
            FROM users 
            WHERE username = ? AND is_active = 1
        ''', (username,))
        user = cursor.fetchone()
        
        if not user:
            conn.commit()
            conn.close()
            return None
        
        user_id, username, password_hash, role, full_name = user
        
        # Verify password
        if verify_password(password, password_hash):
            # Update last login
            cursor.execute('''
                UPDATE users SET last_login = ? WHERE id = ?
            ''', (datetime.now().isoformat(), user_id))
            
            # Update login attempt
            cursor.execute('''
                UPDATE login_attempts SET success = 1 
                WHERE username = ? AND attempt_time = (
                    SELECT MAX(attempt_time) FROM login_attempts WHERE username = ?
                )
            ''', (username, username))
            
            conn.commit()
            conn.close()
            
            return {
                'id': user_id,
                'username': username,
                'role': role,
                'full_name': full_name
            }
        
        conn.commit()
        conn.close()
        return None
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None

def create_user(username, password, role, email, full_name, db_path="data/network_scanner.db"):
    """Create a new user"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return {'success': False, 'error': 'Username already exists'}
        
        # Create user
        cursor.execute('''
            INSERT INTO users 
            (username, password_hash, role, email, full_name, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            username,
            hash_password(password),
            role,
            email,
            full_name,
            datetime.now().isoformat(),
            1
        ))
        
        conn.commit()
        conn.close()
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return {'success': False, 'error': str(e)}

def get_users(db_path="data/network_scanner.db"):
    """Get all users"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, role, email, full_name, created_at, last_login, is_active
            FROM users
            ORDER BY created_at DESC
        ''')
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return users
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return []

def toggle_user_status(user_id, db_path="data/network_scanner.db"):
    """Toggle user active status"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET is_active = CASE is_active WHEN 1 THEN 0 ELSE 1 END
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def delete_user(user_id, db_path="data/network_scanner.db"):
    """Delete a user"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}