"""
AI Recommendations Engine - Intelligent Security Recommendations
Uses Groq LLM (or fallback) for generative, context‑aware recommendations.
"""

import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
import joblib
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# -----------------------------------------------------------------------------
# LLM Clients
# -----------------------------------------------------------------------------
try:
    from groq import Groq
except ImportError:
    Groq = None

# -----------------------------------------------------------------------------
# Configuration (read from environment)
# -----------------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama3-70b-8192")   # updated default

# OpenAI/Ollama fallbacks (optional)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Provider: "groq", "openai", or "ollama"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq")

logger = logging.getLogger(__name__)


class AIRecommendations:
    def __init__(self, db_path="data/network_scanner.db", model_path=None):
        self.db_path = db_path
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = []

        if model_path:
            self.load_model(model_path)
        else:
            self._find_latest_model()

        self.init_db()

    # -------------------------------------------------------------------------
    # ML Model Handling
    # -------------------------------------------------------------------------
    def _find_latest_model(self):
        model_dir = Path("data/models")
        if model_dir.exists():
            models = sorted(model_dir.glob("device_classifier_*.pkl"))
            if models:
                self.load_model(str(models[-1]))
                logger.info(f"Loaded latest model: {models[-1].name}")

    def load_model(self, model_path: str):
        try:
            data = joblib.load(model_path)
            self.model = data.get('model')
            self.scaler = data.get('scaler')
            self.label_encoder = data.get('label_encoder')
            self.feature_names = data.get('feature_names', [])
            logger.info(f"✅ ML model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")

    # -------------------------------------------------------------------------
    # Database Initialization
    # -------------------------------------------------------------------------
    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    recommendation_type TEXT,
                    priority TEXT,
                    title TEXT,
                    description TEXT,
                    action TEXT,
                    created_date TEXT,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            conn.commit()
            conn.close()
            logger.info("✅ Recommendations database initialized")
        except Exception as e:
            logger.error(f"Error initializing recommendations DB: {e}")

    # -------------------------------------------------------------------------
    # Data Retrieval
    # -------------------------------------------------------------------------
    def _get_devices(self) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT d.*, 
                       r.risk_score, r.risk_level, r.total_cves,
                       r.critical_cves, r.high_cves, r.recommendations as existing_rec
                FROM devices d
                LEFT JOIN device_risks r ON d.id = r.device_id
                ORDER BY r.risk_score DESC
            ''')
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return devices
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []

    def _get_device_vulnerabilities(self, device_id: int) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT c.cve_id, c.description, c.cvss_score, 
                       c.severity, c.published_date, dv.service
                FROM device_vulnerabilities dv
                JOIN cves c ON dv.cve_id = c.cve_id
                WHERE dv.device_id = ?
                ORDER BY c.cvss_score DESC
            ''', (device_id,))
            vulns = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return vulns
        except Exception as e:
            logger.error(f"Error getting vulnerabilities for device {device_id}: {e}")
            return []

    def _safe_int(self, value, default=0):
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _safe_float(self, value, default=0.0):
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # -------------------------------------------------------------------------
    # LLM Integration (Groq)
    # -------------------------------------------------------------------------
    def _call_llm(self, prompt: str) -> str:
        provider = LLM_PROVIDER.lower()

        if provider == "groq":
            if Groq is None:
                raise ImportError("Groq library not installed. Run: pip install groq")
            if not GROQ_API_KEY:
                raise ValueError("GROQ_API_KEY environment variable not set.")
            try:
                client = Groq(api_key=GROQ_API_KEY)
                response = client.chat.completions.create(
                    model=GROQ_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=800
                )
                return response.choices[0].message.content.strip() # type: ignore
            except Exception as e:
                logger.error(f"Groq API error: {e}")
                raise

        elif provider == "openai":
            import openai
            if not OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY not set.")
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=800
            )
            return response.choices[0].message.content.strip() # type: ignore

        elif provider == "ollama":
            payload = {
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3}
            }
            resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()

        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

    def _generate_llm_recommendations(self, device: Dict, vulns: List[Dict]) -> List[Dict]:
        prompt = f"""You are an expert security advisor. Based on the following device scan data and known vulnerabilities, provide up to 5 actionable security recommendations. Each recommendation must have a priority (critical, high, medium, low), a title, a description, an action to mitigate, and a type (e.g., vulnerability, hardening, network, os, iot, best_practice, monitoring).

Return the recommendations as a JSON array of objects, with fields: priority, title, description, action, recommendation_type. Do not add any extra text outside the JSON.

Device details:
- IP: {device.get('ip_address', 'Unknown')}
- Hostname: {device.get('hostname', 'Unknown')}
- OS: {device.get('os', 'Unknown')}
- Device Type: {device.get('device_type', 'Unknown')}
- Open Ports: {device.get('open_ports', '[]')}
- Services: {device.get('services', '[]')}
- Risk Score: {device.get('risk_score', 0)}
- Total CVEs: {device.get('total_cves', 0)}
- Critical CVEs: {device.get('critical_cves', 0)}
- High CVEs: {device.get('high_cves', 0)}

Vulnerabilities (CVEs) affecting this device:
{json.dumps([{'cve_id': v['cve_id'], 'severity': v.get('severity'), 'description': v.get('description', '')[:150]} for v in vulns], indent=2)}

Prioritize critical and high severity issues. Provide specific, actionable steps. If there are no vulnerabilities, suggest best practices for this device type.
"""
        try:
            response_text = self._call_llm(prompt)
            # Remove markdown code blocks if present
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            recs = json.loads(response_text)
            if not isinstance(recs, list):
                raise ValueError("LLM did not return a JSON array.")
            for r in recs:
                r.setdefault('recommendation_type', 'general')
                r.setdefault('priority', 'medium')
            return recs
        except Exception as e:
            logger.error(f"LLM generation failed: {e}. Falling back to rule-based.")
            return self._generate_rule_based_recommendations(device, vulns)

    # -------------------------------------------------------------------------
    # Rule-Based Fallback (simplified but comprehensive)
    # -------------------------------------------------------------------------
    def _generate_rule_based_recommendations(self, device: Dict, vulns: List[Dict]) -> List[Dict]:
        """Heuristic rules – used as fallback when LLM fails."""
        recommendations = []
        risk_score = self._safe_float(device.get('risk_score'), 0.0)
        total_cves = self._safe_int(device.get('total_cves'), 0)
        critical_cves = self._safe_int(device.get('critical_cves'), 0)
        high_cves = self._safe_int(device.get('high_cves'), 0)
        device_type = device.get('device_type', 'Unknown')
        os_name = device.get('os', '').lower()
        ip = device.get('ip_address', '')
        hostname = device.get('hostname', '')

        # Parse open ports and services
        open_ports = []
        services_list = []
        try:
            ports_json = device.get('open_ports', '[]')
            if ports_json:
                open_ports = json.loads(ports_json) if isinstance(ports_json, str) else ports_json
            services_json = device.get('services', '[]')
            if services_json:
                services_list = json.loads(services_json) if isinstance(services_json, str) else services_json
        except:
            pass
        open_ports = list(set(open_ports))
        service_names = [s.get('service', '').lower() for s in services_list if isinstance(s, dict)]

        # Critical
        if critical_cves > 0:
            cve_ids = [v['cve_id'] for v in vulns if v.get('severity') == 'CRITICAL'][:5]
            cve_str = ', '.join(cve_ids[:3])
            recommendations.append({
                'priority': 'critical',
                'title': f'🔴 {critical_cves} Critical Vulnerabilities on {hostname or ip}',
                'description': f'Device has {critical_cves} critical CVEs (e.g., {cve_str}). Immediate patching required.',
                'action': f'Apply patches for {cve_str}. If no patch, isolate or apply compensating controls.',
                'recommendation_type': 'vulnerability'
            })

        if risk_score >= 9.0:
            recommendations.append({
                'priority': 'critical',
                'title': f'🚨 Extremely High Risk (Score {risk_score:.1f}/10)',
                'description': f'Device {hostname or ip} has a critical risk score.',
                'action': 'Isolate device, conduct forensic analysis, and implement emergency patching.',
                'recommendation_type': 'risk'
            })

        # Dangerous services
        dangerous = {
            'smb': ('SMB exposed – ransomware risk', 'Disable SMBv1, apply MS17-010, restrict access.'),
            'rdp': ('RDP exposed – brute‑force risk', 'Use VPN/RDG, enable NLA, enforce strong passwords.'),
            'telnet': ('Telnet enabled – plaintext credentials', 'Replace with SSH immediately.'),
            'ftp': ('FTP unencrypted', 'Switch to SFTP/FTPS.'),
        }
        for svc, (desc, action) in dangerous.items():
            if svc == 'smb' and 445 in open_ports:
                recommendations.append({
                    'priority': 'critical',
                    'title': f'⚠️ SMB Service Exposed (Port 445)',
                    'description': f'SMB exposed on {hostname or ip}. {desc}',
                    'action': action,
                    'recommendation_type': 'hardening'
                })
                break
            elif svc == 'rdp' and 3389 in open_ports:
                recommendations.append({
                    'priority': 'critical',
                    'title': f'🔑 RDP Service Exposed (Port 3389)',
                    'description': f'RDP open on {hostname or ip}. {desc}',
                    'action': action,
                    'recommendation_type': 'hardening'
                })
                break
            elif svc == 'telnet':
                recommendations.append({
                    'priority': 'critical',
                    'title': f'🚫 Telnet Enabled',
                    'description': f'Telnet running on {hostname or ip}. {desc}',
                    'action': action,
                    'recommendation_type': 'hardening'
                })
                break

        # High
        if high_cves > 0:
            high_cve_ids = [v['cve_id'] for v in vulns if v.get('severity') == 'HIGH'][:3]
            recommendations.append({
                'priority': 'high',
                'title': f'🟠 {high_cves} High‑Severity Vulnerabilities',
                'description': f'Device has {high_cves} high CVEs (e.g., {", ".join(high_cve_ids)}).',
                'action': f'Apply patches for {", ".join(high_cve_ids)} within 30 days.',
                'recommendation_type': 'vulnerability'
            })

        eol_indicators = ['windows 7', 'windows 8', 'ubuntu 16', 'centos 6', 'debian 8', 'rhel 6']
        if any(ind in os_name for ind in eol_indicators):
            recommendations.append({
                'priority': 'high',
                'title': '🔄 End-of-Life Operating System',
                'description': f'{hostname or ip} runs {device["os"]} (unsupported).',
                'action': 'Plan migration to a supported OS (e.g., Windows Server 2022, Ubuntu 22.04).',
                'recommendation_type': 'os'
            })

        if len(open_ports) > 15:
            recommendations.append({
                'priority': 'high',
                'title': '🔌 Excessive Open Ports (Large Attack Surface)',
                'description': f'{len(open_ports)} open ports on {hostname or ip}.',
                'action': 'Review and close unnecessary ports.',
                'recommendation_type': 'network'
            })

        if not hostname:
            recommendations.append({
                'priority': 'high',
                'title': '🏷️ Missing Hostname',
                'description': f'Device {ip} lacks a hostname.',
                'action': 'Assign a descriptive hostname in DNS.',
                'recommendation_type': 'best_practice'
            })

        # Medium/Low
        if total_cves > 0 and critical_cves == 0 and high_cves == 0:
            recommendations.append({
                'priority': 'medium',
                'title': f'📋 {total_cves} Medium/Low Vulnerabilities',
                'description': 'Manageable vulnerabilities – address in routine maintenance.',
                'action': 'Apply patches and review risk acceptance for low severity.',
                'recommendation_type': 'vulnerability'
            })

        if device_type == 'IoT':
            recommendations.append({
                'priority': 'medium',
                'title': '📡 IoT Device Security Review',
                'description': f'IoT device {hostname or ip} may have limited security.',
                'action': 'Check firmware updates; isolate in separate VLAN; disable UPnP/Telnet/default credentials.',
                'recommendation_type': 'iot'
            })

        if 22 in open_ports and 'ssh' in service_names:
            recommendations.append({
                'priority': 'medium',
                'title': '🔑 SSH Hardening',
                'description': f'SSH open on {hostname or ip}.',
                'action': 'Disable root login, enforce key-based auth, change default port (optional).',
                'recommendation_type': 'hardening'
            })

        # Always add a generic firewall recommendation (low priority)
        recommendations.append({
            'priority': 'low',
            'title': '🛡️ Enable Host Firewall',
            'description': f'Ensure host-based firewall is enabled on {hostname or ip}.',
            'action': 'Enable Windows Firewall or iptables/nftables; default deny inbound.',
            'recommendation_type': 'best_practice'
        })

        # Deduplicate and limit
        seen = set()
        unique = []
        for rec in recommendations:
            if rec['title'] not in seen:
                seen.add(rec['title'])
                unique.append(rec)
        return unique[:8]

    # -------------------------------------------------------------------------
    # Main Generation Method
    # -------------------------------------------------------------------------
    def generate_all_recommendations(self, use_llm: bool = True) -> Dict:
        logger.info("Generating AI recommendations...")
        results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'summary': {}
        }

        devices = self._get_devices()
        if not devices:
            return {'error': 'No devices found'}

        for device in devices:
            device_id = device['id']
            vulns = self._get_device_vulnerabilities(device_id)

            if use_llm:
                try:
                    recs = self._generate_llm_recommendations(device, vulns)
                except Exception as e:
                    logger.warning(f"LLM failed for device {device_id}: {e}. Falling back to rules.")
                    recs = self._generate_rule_based_recommendations(device, vulns)
            else:
                recs = self._generate_rule_based_recommendations(device, vulns)

            for rec in recs:
                priority = rec.get('priority', 'medium').lower()
                if priority not in ['critical', 'high', 'medium', 'low']:
                    priority = 'medium'
                rec['priority'] = priority
                results[priority].append(rec)
                self._save_recommendation(device_id, rec)

        results['summary'] = {
            'total_recommendations': (len(results['critical']) + len(results['high']) +
                                      len(results['medium']) + len(results['low'])),
            'critical_count': len(results['critical']),
            'high_count': len(results['high']),
            'medium_count': len(results['medium']),
            'low_count': len(results['low']),
            'devices_analyzed': len(devices),
            'timestamp': datetime.now().isoformat()
        }

        logger.info(f"✅ Generated {results['summary']['total_recommendations']} recommendations")
        return results

    # -------------------------------------------------------------------------
    # Database Save & API Methods
    # -------------------------------------------------------------------------
    def _save_recommendation(self, device_id: int, rec: Dict):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO recommendations 
                (device_id, recommendation_type, priority, title, description, action, created_date, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                rec.get('recommendation_type', 'general'),
                rec['priority'],
                rec['title'],
                rec['description'],
                rec['action'],
                datetime.now().isoformat(),
                'pending'
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving recommendation: {e}")

    def get_device_recommendations(self, device_id: int) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM recommendations
                WHERE device_id = ?
                ORDER BY CASE priority 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                END
            ''', (device_id,))
            recs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return recs
        except Exception as e:
            logger.error(f"Error getting recommendations: {e}")
            return []

    def get_all_recommendations(self) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT r.*, d.ip_address, d.device_type
                FROM recommendations r
                JOIN devices d ON r.device_id = d.id
                ORDER BY CASE priority 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                END,
                r.created_date DESC
            ''')
            recs = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return recs
        except Exception as e:
            logger.error(f"Error getting all recommendations: {e}")
            return []

    def update_recommendation_status(self, rec_id: int, status: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE recommendations SET status = ? WHERE id = ?', (status, rec_id))
            conn.commit()
            conn.close()
            return {'success': True}
        except Exception as e:
            logger.error(f"Error updating recommendation status: {e}")
            return {'success': False, 'error': str(e)}

    def get_recommendation_summary(self) -> Dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # Fixed: use aliases for count columns
            cursor.execute('''
                SELECT priority, COUNT(*) as count
                FROM recommendations
                GROUP BY priority
            ''')
            priority_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM recommendations
                GROUP BY status
            ''')
            status_counts = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute('''
                SELECT recommendation_type, COUNT(*) as count
                FROM recommendations
                GROUP BY recommendation_type
                ORDER BY count DESC
                LIMIT 5
            ''')
            type_counts = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()
            return {
                'priority_counts': priority_counts,
                'status_counts': status_counts,
                'type_counts': type_counts,
                'total': sum(priority_counts.values()),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting recommendation summary: {e}")
            return {}