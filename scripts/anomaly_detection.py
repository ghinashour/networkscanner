"""
scripts/anomaly_detection.py
Anomaly detection using Isolation Forest on device features.
Includes automatic table creation and graceful fallbacks.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import json
import logging
from datetime import datetime, timedelta
import sqlite3
import os

logger = logging.getLogger(__name__)

DB_PATH = "data/network_scanner.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_tables():
    """Create anomaly tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            snapshot_date TEXT NOT NULL,
            open_ports TEXT,
            services TEXT,
            os TEXT,
            device_type TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_scores (
            device_id INTEGER PRIMARY KEY,
            score REAL NOT NULL,
            label TEXT,
            last_updated TEXT,
            FOREIGN KEY(device_id) REFERENCES devices(id)
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("Anomaly tables verified/created.")

def extract_features_from_history(device_id=None, days=30):
    """Extract feature vectors from device_history for the last `days` days."""
    conn = get_db()
    c = conn.cursor()
    query = '''
        SELECT device_id, open_ports, services, os, device_type
        FROM device_history
        WHERE snapshot_date >= DATE('now', ?)
    '''
    params = (f'-{days} days',)
    if device_id:
        query += ' AND device_id = ?'
        params = (f'-{days} days', device_id)
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    if not rows:
        return None

    data = []
    for row in rows:
        ports = json.loads(row['open_ports']) if row['open_ports'] else []
        services = json.loads(row['services']) if row['services'] else []
        num_ports = len(ports)
        num_services = len(services)
        os_hash = hash(row['os'] or 'unknown') % 1000
        type_hash = hash(row['device_type'] or 'unknown') % 1000
        data.append([num_ports, num_services, os_hash, type_hash])
    return np.array(data)

def compute_anomaly_scores(device_id=None):
    """
    Compute anomaly scores for all devices (or a specific one) and store in anomaly_scores.
    If no historical data exists, populate device_history with current device snapshots first.
    """
    ensure_tables()
    conn = get_db()
    c = conn.cursor()

    # --- Step 1: Populate device_history if empty ---
    c.execute("SELECT COUNT(*) FROM device_history")
    if c.fetchone()[0] == 0:
        logger.info("No device history found; creating initial snapshots from devices table.")
        c.execute("SELECT id, open_ports, services, os, device_type FROM devices")
        devices = c.fetchall()
        for dev in devices:
            c.execute('''
                INSERT INTO device_history (device_id, snapshot_date, open_ports, services, os, device_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                dev['id'],
                datetime.now().isoformat(),
                dev['open_ports'],
                dev['services'],
                dev['os'],
                dev['device_type']
            ))
        conn.commit()

    # --- Step 2: Get current devices and their latest features ---
    if device_id:
        c.execute("SELECT id, open_ports, services, os, device_type FROM devices WHERE id = ?", (device_id,))
        devices = [c.fetchone()]
    else:
        c.execute("SELECT id, open_ports, services, os, device_type FROM devices")
        devices = c.fetchall()

    if not devices:
        conn.close()
        logger.warning("No devices found to compute anomalies.")
        return

    # --- Step 3: Train global Isolation Forest on all historical data ---
    X_global = extract_features_from_history()  # all devices, last 30 days
    if X_global is None or len(X_global) < 5:
        logger.warning("Insufficient historical data (need at least 5 samples). Skipping anomaly scoring.")
        # Delete any existing scores to avoid stale data
        c.execute("DELETE FROM anomaly_scores")
        conn.commit()
        conn.close()
        return

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_global)

    # --- Step 4: Score each device ---
    for dev in devices:
        dev_id = dev['id']
        ports = json.loads(dev['open_ports']) if dev['open_ports'] else []
        services = json.loads(dev['services']) if dev['services'] else []
        features = np.array([[len(ports), len(services),
                              hash(dev['os'] or 'unknown') % 1000,
                              hash(dev['device_type'] or 'unknown') % 1000]])

        pred = model.predict(features)
        score = model.decision_function(features)[0]  # negative = anomalous
        label = 'anomaly' if pred[0] == -1 else 'normal'

        # Upsert
        c.execute('''
            INSERT INTO anomaly_scores (device_id, score, label, last_updated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                score = excluded.score,
                label = excluded.label,
                last_updated = excluded.last_updated
        ''', (dev_id, float(score), label, datetime.now().isoformat()))

    conn.commit()
    conn.close()
    logger.info("Anomaly scores updated for %d devices.", len(devices))

def get_anomaly_summary():
    """Return a list of devices with anomaly scores, normalized to 0-1 (higher = more anomalous)."""
    ensure_tables()
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT d.id, d.ip_address, d.hostname, a.score, a.label, a.last_updated,
                   r.risk_level
            FROM anomaly_scores a
            JOIN devices d ON a.device_id = d.id
            LEFT JOIN device_risks r ON d.id = r.device_id
            ORDER BY a.score ASC
        ''')
        rows = c.fetchall()
    except sqlite3.OperationalError as e:
        # Table might not exist yet
        logger.warning("Anomaly scores table not found: %s", e)
        return []
    finally:
        conn.close()

    if not rows:
        return []

    scores = [row['score'] for row in rows]
    min_score = min(scores)
    max_score = max(scores)
    if max_score - min_score > 1e-9:
        normalized = [(s - min_score) / (max_score - min_score) for s in scores]
    else:
        normalized = [0.5] * len(scores)

    result = []
    for i, row in enumerate(rows):
        result.append({
            'id': row['id'],
            'ip': row['ip_address'],
            'hostname': row['hostname'] or '',
            'anomaly_score': normalized[i],  # 0-1, higher = more anomalous
            'label': row['label'],
            'risk_level': row['risk_level'] or 'NONE',
            'last_updated': row['last_updated']
        })
    return result