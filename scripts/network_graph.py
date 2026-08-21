"""
Enhanced Network Graph Generator - Creates network topology with auto-layout
"""

import sqlite3
import json
import networkx as nx
from networkx.readwrite import json_graph
from datetime import datetime
import logging
import random

logger = logging.getLogger(__name__)

class NetworkGraph:
    def __init__(self, db_path="data/network_scanner.db"):
        self.db_path = db_path
        self.G = nx.Graph()
        
    def get_network_graph(self):
        """Generate network graph from devices and connections"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all devices with their vulnerabilities
            cursor.execute('''
                SELECT DISTINCT d.id, d.ip_address, d.device_type, d.hostname, d.os,
                       r.risk_score, r.risk_level, r.total_cves, r.critical_cves,
                       GROUP_CONCAT(DISTINCT v.cve_id) as cves
                FROM devices d
                LEFT JOIN device_risks r ON d.id = r.device_id
                LEFT JOIN device_vulnerabilities dv ON d.id = dv.device_id
                LEFT JOIN vulnerabilities v ON dv.vulnerability_id = v.id
                GROUP BY d.id
            ''')
            
            devices = [dict(row) for row in cursor.fetchall()]
            
            # Get connections from scan history (simulated)
            connections = self._get_connections(devices)
            
            conn.close()
            
            # Build graph
            self.G = nx.Graph()
            
            # Add nodes
            for device in devices:
                self._add_device_node(device)
            
            # Add edges
            for conn in connections:
                self._add_connection(conn)
            
            # Auto-layout with spring layout
            pos = nx.spring_layout(self.G, k=2, iterations=50, seed=42)
            
            # Convert to JSON for D3.js
            graph_data = json_graph.node_link_data(self.G)
            
            # Add metadata and positions
            for i, node in enumerate(graph_data['nodes']):
                if i in pos:
                    node['x'] = pos[i][0] * 500  # Scale for better visibility
                    node['y'] = pos[i][1] * 500
                # Add device type icon
                node['icon'] = self._get_device_icon(node.get('device_type', ''))
            
            graph_data['metadata'] = {
                'total_devices': len(devices),
                'timestamp': datetime.now().isoformat(),
                'risk_summary': self._get_risk_summary(devices)
            }
            
            return {'success': True, 'graph': graph_data}
            
        except Exception as e:
            logger.error(f"Error generating network graph: {e}")
            return {'success': False, 'error': str(e)}
    
    def _add_device_node(self, device):
        """Add a device node to the graph"""
        device_id = device['id']
        risk_level = device.get('risk_level', 'NONE')
        
        # Determine color based on risk
        color_map = {
            'CRITICAL': '#ff4444',
            'HIGH': '#ff8800',
            'MEDIUM': '#ffcc00',
            'LOW': '#00ff88',
            'NONE': '#8899aa'
        }
        
        # Determine size based on importance
        total_cves = device.get('total_cves', 0)
        critical_cves = device.get('critical_cves', 0)
        size = 20 + (total_cves * 2) + (critical_cves * 3)
        size = min(size, 60)
        
        self.G.add_node(
            device_id,
            label=device['ip_address'],
            device_type=device.get('device_type', 'Unknown'),
            hostname=device.get('hostname', ''),
            os=device.get('os', 'Unknown'),
            risk_score=device.get('risk_score', 0),
            risk_level=risk_level,
            color=color_map.get(risk_level, '#8899aa'),
            size=size,
            total_cves=total_cves,
            critical_cves=critical_cves,
            cves=device.get('cves', '').split(',') if device.get('cves') else []
        )
    
    def _add_connection(self, conn):
        """Add a connection edge between devices"""
        source = conn.get('source')
        target = conn.get('target')
        if source and target and self.G.has_node(source) and self.G.has_node(target):
            self.G.add_edge(
                source,
                target,
                weight=conn.get('weight', 1),
                type=conn.get('type', 'network')
            )
    
    def _get_connections(self, devices):
        """Generate connections based on network topology"""
        connections = []
        
        # Group devices by subnet
        subnets = {}
        for device in devices:
            ip = device['ip_address']
            if ip:
                parts = ip.split('.')
                if len(parts) >= 3:
                    subnet = '.'.join(parts[:3])
                    if subnet not in subnets:
                        subnets[subnet] = []
                    subnets[subnet].append(device['id'])
        
        # Connect devices within same subnet
        for subnet, device_ids in subnets.items():
            # Connect to a central switch (first device in subnet)
            if len(device_ids) > 1:
                central = device_ids[0]
                for device_id in device_ids[1:]:
                    connections.append({
                        'source': central,
                        'target': device_id,
                        'weight': 1,
                        'type': 'network'
                    })
            
            # Additional connections between close devices
            for i in range(len(device_ids)):
                for j in range(i + 2, min(i + 4, len(device_ids))):
                    if random.random() < 0.3:  # 30% chance of extra connection
                        connections.append({
                            'source': device_ids[i],
                            'target': device_ids[j],
                            'weight': 0.5,
                            'type': 'network'
                        })
        
        return connections
    
    def _get_risk_summary(self, devices):
        """Get risk summary from devices"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'NONE': 0
        }
        
        for device in devices:
            risk = device.get('risk_level', 'NONE')
            summary[risk] = summary.get(risk, 0) + 1
        
        return summary
    
    def _get_device_icon(self, device_type):
        """Get emoji icon for device type"""
        icons = {
            'Server': '🖥️',
            'Workstation': '💻',
            'Network': '🌐',
            'IoT': '📱',
            'Printer': '🖨️',
            'Camera': '📷',
            'Mobile': '📱',
            'Router': '📡',
            'Switch': '🔀',
            'Firewall': '🔥',
            'Database': '🗄️',
            'Web': '🌍'
        }
        return icons.get(device_type, '🔹')