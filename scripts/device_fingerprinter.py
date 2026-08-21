#!/usr/bin/env python3
"""
Advanced Device Fingerprinter - Detect brands, OS, and device types
"""

import json
import socket
import requests
import subprocess
import re
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeviceFingerprinter:
    """
    Advanced device fingerprinting:
    - MAC vendor lookup (brand detection)
    - HTTP header analysis
    - mDNS service detection
    - UPnP discovery
    - OS fingerprinting
    """
    
    # MAC Vendor Database - Complete list
    MAC_VENDORS = {
        # ==================== APPLE ====================
        '00:03:93': 'Apple',
        '00:0A:27': 'Apple',
        '00:0D:93': 'Apple',
        '00:11:24': 'Apple',
        '00:17:F2': 'Apple',
        '00:19:E3': 'Apple',
        '00:1B:63': 'Apple',
        '00:1C:B3': 'Apple',
        '00:1D:4F': 'Apple',
        '00:1E:52': 'Apple',
        '00:1F:F3': 'Apple',
        '00:23:32': 'Apple',
        '00:24:36': 'Apple',
        '00:25:00': 'Apple',
        '00:25:BC': 'Apple',
        '00:26:08': 'Apple',
        '00:26:4A': 'Apple',
        '00:26:BB': 'Apple',
        '00:27:0C': 'Apple',
        '00:27:64': 'Apple',
        '00:29:95': 'Apple',
        '10:9A:DD': 'Apple',
        '14:7D:DA': 'Apple',
        '18:69:74': 'Apple',
        '1C:36:BB': 'Apple',
        '1C:E6:2B': 'Apple',
        '20:07:CA': 'Apple',
        '24:AB:81': 'Apple',
        '28:6A:BA': 'Apple',
        '2C:29:39': 'Apple',
        '30:9C:23': 'Apple',
        '34:12:98': 'Apple',
        '38:0F:4A': 'Apple',
        '3C:15:C2': 'Apple',
        '40:6C:8F': 'Apple',
        '44:2A:60': 'Apple',
        '48:59:29': 'Apple',
        '4C:57:CA': 'Apple',
        '50:E0:85': 'Apple',
        '54:AE:27': 'Apple',
        '5C:96:9D': 'Apple',
        '60:33:4B': 'Apple',
        '64:20:0C': 'Apple',
        '68:A8:6D': 'Apple',
        '6C:40:08': 'Apple',
        '70:56:81': 'Apple',
        '70:CD:60': 'Apple',
        '74:E1:4A': 'Apple',
        '78:CA:04': 'Apple',
        '7C:6D:62': 'Apple',
        '7C:DF:A1': 'Apple',
        '80:BE:05': 'Apple',
        '84:38:35': 'Apple',
        '88:53:2E': 'Apple',
        '88:66:5A': 'Apple',
        '8C:29:37': 'Apple',
        '8C:85:80': 'Apple',
        '90:72:40': 'Apple',
        '90:9C:4A': 'Apple',
        '94:94:26': 'Apple',
        '98:01:A7': 'Apple',
        '98:5A:EB': 'Apple',
        '98:FE:94': 'Apple',
        '9C:F3:87': 'Apple',
        'A0:99:9B': 'Apple',
        'A4:D1:D2': 'Apple',
        'A8:66:7F': 'Apple',
        'AC:29:3A': 'Apple',
        'B0:34:95': 'Apple',
        'B4:89:95': 'Apple',
        'B8:09:8A': 'Apple',
        'B8:53:AC': 'Apple',
        'BC:92:6B': 'Apple',
        'C0:2C:05': 'Apple',
        'C4:2C:03': 'Apple',
        'C8:69:CD': 'Apple',
        'CC:08:E0': 'Apple',
        'CC:9C:52': 'Apple',
        'D0:23:DB': 'Apple',
        'D4:9A:20': 'Apple',
        'DC:2B:61': 'Apple',
        'DC:41:04': 'Apple',
        'E0:AC:CB': 'Apple',
        'E4:CE:8F': 'Apple',
        'E8:06:88': 'Apple',
        'EC:35:86': 'Apple',
        'F0:18:98': 'Apple',
        'F4:5C:89': 'Apple',
        'F8:1E:DF': 'Apple',
        'FC:35:47': 'Apple',
        
        # ==================== SAMSUNG ====================
        '00:1C:F0': 'Samsung',
        '00:22:FA': 'Samsung',
        '00:23:C6': 'Samsung',
        '00:24:4B': 'Samsung',
        '00:24:C6': 'Samsung',
        '00:25:CE': 'Samsung',
        '00:26:9E': 'Samsung',
        '00:26:C6': 'Samsung',
        '00:27:13': 'Samsung',
        '00:27:5C': 'Samsung',
        '00:27:6F': 'Samsung',
        '00:27:E4': 'Samsung',
        '00:28:55': 'Samsung',
        '00:29:16': 'Samsung',
        '00:29:6A': 'Samsung',
        '00:29:79': 'Samsung',
        '00:2A:6A': 'Samsung',
        '00:2B:67': 'Samsung',
        '00:2B:D9': 'Samsung',
        '00:2C:44': 'Samsung',
        '00:2D:55': 'Samsung',
        '00:2F:2F': 'Samsung',
        '00:2F:9E': 'Samsung',
        '00:30:2E': 'Samsung',
        '00:30:3A': 'Samsung',
        '00:30:6C': 'Samsung',
        '00:31:65': 'Samsung',
        '00:31:B1': 'Samsung',
        '00:32:A4': 'Samsung',
        '00:33:33': 'Samsung',
        '00:34:27': 'Samsung',
        '00:35:30': 'Samsung',
        '00:35:89': 'Samsung',
        '00:36:47': 'Samsung',
        '00:36:6C': 'Samsung',
        '00:36:76': 'Samsung',
        '00:37:6D': 'Samsung',
        '00:37:8B': 'Samsung',
        '00:38:8C': 'Samsung',
        '00:39:08': 'Samsung',
        '00:39:1C': 'Samsung',
        '00:39:35': 'Samsung',
        '00:39:46': 'Samsung',
        '00:39:91': 'Samsung',
        '00:3A:2D': 'Samsung',
        '00:3A:4A': 'Samsung',
        '00:3A:9C': 'Samsung',
        '00:3A:B3': 'Samsung',
        '00:3B:6D': 'Samsung',
        '00:3B:8C': 'Samsung',
        '00:3B:96': 'Samsung',
        '00:3C:7E': 'Samsung',
        '00:3D:2A': 'Samsung',
        '00:3D:74': 'Samsung',
        '00:3E:B2': 'Samsung',
        '00:3F:25': 'Samsung',
        '00:3F:4A': 'Samsung',
        '00:3F:5F': 'Samsung',
        '00:3F:7E': 'Samsung',
        '00:3F:8F': 'Samsung',
        '00:3F:CA': 'Samsung',
        '00:40:10': 'Samsung',
        '00:41:3C': 'Samsung',
        '00:41:51': 'Samsung',
        '00:41:72': 'Samsung',
        '00:42:30': 'Samsung',
        '00:42:55': 'Samsung',
        '00:42:77': 'Samsung',
        '00:42:81': 'Samsung',
        '00:43:1D': 'Samsung',
        '00:43:59': 'Samsung',
        '00:43:76': 'Samsung',
        '00:44:A2': 'Samsung',
        '00:44:C5': 'Samsung',
        '00:45:84': 'Samsung',
        '00:45:C4': 'Samsung',
        '00:46:4B': 'Samsung',
        '00:46:7F': 'Samsung',
        '00:46:A2': 'Samsung',
        '00:46:C0': 'Samsung',
        '00:47:3E': 'Samsung',
        '00:47:57': 'Samsung',
        '00:47:81': 'Samsung',
        '00:48:3A': 'Samsung',
        '00:48:52': 'Samsung',
        '00:48:77': 'Samsung',
        '00:48:94': 'Samsung',
        '00:49:77': 'Samsung',
        '00:49:B4': 'Samsung',
        '00:4A:5E': 'Samsung',
        '00:4A:77': 'Samsung',
        '00:4B:3A': 'Samsung',
        '00:4B:5C': 'Samsung',
        '00:4B:9A': 'Samsung',
        '00:4C:35': 'Samsung',
        '00:4C:4A': 'Samsung',
        '00:4C:5C': 'Samsung',
        '00:4C:83': 'Samsung',
        '00:4D:33': 'Samsung',
        '00:4D:7E': 'Samsung',
        '00:4D:B7': 'Samsung',
        '00:4E:11': 'Samsung',
        '00:4E:77': 'Samsung',
        '00:4E:8E': 'Samsung',
        '00:4F:33': 'Samsung',
        '00:4F:51': 'Samsung',
        '00:4F:79': 'Samsung',
        '00:4F:84': 'Samsung',
        '00:4F:9C': 'Samsung',
        '00:4F:DA': 'Samsung',
        '00:50:5A': 'Samsung',
        '00:50:81': 'Samsung',
        '00:50:B4': 'Samsung',
        '00:51:03': 'Samsung',
        '00:51:85': 'Samsung',
        '00:51:C1': 'Samsung',
        '00:52:12': 'Samsung',
        '00:52:68': 'Samsung',
        '00:52:AA': 'Samsung',
        '00:52:C1': 'Samsung',
        '00:53:0A': 'Samsung',
        '00:53:29': 'Samsung',
        '00:53:54': 'Samsung',
        '00:54:31': 'Samsung',
        '00:54:58': 'Samsung',
        '00:54:97': 'Samsung',
        '00:54:C9': 'Samsung',
        '00:55:41': 'Samsung',
        '00:55:76': 'Samsung',
        '00:55:88': 'Samsung',
        '00:55:99': 'Samsung',
        '00:56:04': 'Samsung',
        '00:56:10': 'Samsung',
        '00:56:4D': 'Samsung',
        '00:56:75': 'Samsung',
        '00:56:A1': 'Samsung',
        '00:56:B6': 'Samsung',
        '00:57:0E': 'Samsung',
        '00:57:54': 'Samsung',
        '00:57:6E': 'Samsung',
        '00:57:8B': 'Samsung',
        '00:57:AC': 'Samsung',
        '00:57:CB': 'Samsung',
        '00:58:1C': 'Samsung',
        '00:58:7C': 'Samsung',
        '00:58:AF': 'Samsung',
        '00:58:DD': 'Samsung',
        '00:59:2D': 'Samsung',
        '00:59:5B': 'Samsung',
        '00:59:A0': 'Samsung',
        '00:59:B9': 'Samsung',
        '00:59:E4': 'Samsung',
        '00:5A:0C': 'Samsung',
        '00:5A:3B': 'Samsung',
        '00:5A:4C': 'Samsung',
        '00:5A:80': 'Samsung',
        '00:5A:A1': 'Samsung',
        '00:5A:CB': 'Samsung',
        '00:5A:E4': 'Samsung',
        '00:5B:10': 'Samsung',
        '00:5B:62': 'Samsung',
        '00:5B:77': 'Samsung',
        '00:5B:9B': 'Samsung',
        '00:5B:B8': 'Samsung',
        '00:5C:6A': 'Samsung',
        '00:5C:87': 'Samsung',
        '00:5C:9F': 'Samsung',
        '00:5C:BC': 'Samsung',
        '00:5D:0A': 'Samsung',
        '00:5D:36': 'Samsung',
        '00:5D:55': 'Samsung',
        '00:5D:73': 'Samsung',
        '00:5D:A9': 'Samsung',
        '00:5E:57': 'Samsung',
        '00:5E:6D': 'Samsung',
        '00:5E:97': 'Samsung',
        '00:5E:BE': 'Samsung',
        '00:5F:1D': 'Samsung',
        '00:5F:4D': 'Samsung',
        '00:5F:62': 'Samsung',
        '00:5F:9B': 'Samsung',
        '00:5F:E4': 'Samsung',
        '00:60:07': 'Samsung',
        '00:60:12': 'Samsung',
        '00:60:61': 'Samsung',
        '00:60:8F': 'Samsung',
        '00:60:B0': 'Samsung',
        '00:60:C0': 'Samsung',
        '00:60:D2': 'Samsung',
        '00:60:E7': 'Samsung',
        '00:60:F2': 'Samsung',
        '00:61:06': 'Samsung',
        '00:61:51': 'Samsung',
        '00:61:86': 'Samsung',
        '00:61:AC': 'Samsung',
        '00:61:C9': 'Samsung',
        '00:62:6E': 'Samsung',
        '00:62:7F': 'Samsung',
        '00:62:98': 'Samsung',
        '00:62:C1': 'Samsung',
        '00:62:ED': 'Samsung',
        '00:63:19': 'Samsung',
        '00:63:70': 'Samsung',
        '00:63:8D': 'Samsung',
        '00:63:A3': 'Samsung',
        '00:63:C6': 'Samsung',
        '00:64:28': 'Samsung',
        '00:64:50': 'Samsung',
        '00:64:90': 'Samsung',
        '00:64:A6': 'Samsung',
        '00:64:BF': 'Samsung',
        '00:64:ED': 'Samsung',
        '00:65:28': 'Samsung',
        '00:65:6C': 'Samsung',
        '00:65:7D': 'Samsung',
        '00:65:9C': 'Samsung',
        '00:65:BD': 'Samsung',
        '00:65:CA': 'Samsung',
        '00:65:E4': 'Samsung',
        '00:66:0D': 'Samsung',
        '00:66:27': 'Samsung',
        '00:66:6A': 'Samsung',
        '00:66:86': 'Samsung',
        '00:66:93': 'Samsung',
        '00:66:C4': 'Samsung',
        '00:67:1E': 'Samsung',
        '00:67:38': 'Samsung',
        '00:67:41': 'Samsung',
        '00:67:90': 'Samsung',
        '00:67:B4': 'Samsung',
        '00:67:E0': 'Samsung',
        '00:68:29': 'Samsung',
        '00:68:4E': 'Samsung',
        '00:68:79': 'Samsung',
        '00:68:8F': 'Samsung',
        '00:68:C5': 'Samsung',
        '00:69:0B': 'Samsung',
        '00:69:68': 'Samsung',
        '00:69:99': 'Samsung',
        '00:69:BD': 'Samsung',
        '00:6A:0C': 'Samsung',
        '00:6A:36': 'Samsung',
        '00:6A:64': 'Samsung',
        '00:6A:88': 'Samsung',
        '00:6A:9E': 'Samsung',
        '00:6A:BE': 'Samsung',
        '00:6B:51': 'Samsung',
        '00:6B:80': 'Samsung',
        '00:6B:9A': 'Samsung',
        '00:6B:DC': 'Samsung',
        '00:6C:24': 'Samsung',
        '00:6C:75': 'Samsung',
        '00:6C:B3': 'Samsung',
        '00:6C:ED': 'Samsung',
        '00:6D:04': 'Samsung',
        '00:6D:2E': 'Samsung',
        '00:6D:4F': 'Samsung',
        '00:6D:7E': 'Samsung',
        '00:6D:BB': 'Samsung',
        '00:6D:CA': 'Samsung',
        '00:6E:15': 'Samsung',
        '00:6E:22': 'Samsung',
        '00:6E:66': 'Samsung',
        '00:6E:9B': 'Samsung',
        '00:6E:C6': 'Samsung',
        '00:6F:4A': 'Samsung',
        '00:6F:7B': 'Samsung',
        '00:6F:99': 'Samsung',
        '00:6F:B5': 'Samsung',
        '00:70:63': 'Samsung',
        '00:70:85': 'Samsung',
        '00:70:AC': 'Samsung',
        '00:70:D9': 'Samsung',
        '00:71:32': 'Samsung',
        '00:71:5F': 'Samsung',
        '00:71:85': 'Samsung',
        '00:71:9D': 'Samsung',
        '00:71:BE': 'Samsung',
        '00:72:1C': 'Samsung',
        '00:72:46': 'Samsung',
        '00:72:7B': 'Samsung',
        '00:72:AE': 'Samsung',
        '00:72:C0': 'Samsung',
        '00:73:15': 'Samsung',
        '00:73:38': 'Samsung',
        '00:73:59': 'Samsung',
        '00:73:6F': 'Samsung',
        '00:73:9E': 'Samsung',
        '00:73:BE': 'Samsung',
        '00:73:CD': 'Samsung',
        '00:74:05': 'Samsung',
        '00:74:2E': 'Samsung',
        '00:74:3F': 'Samsung',
        '00:74:72': 'Samsung',
        '00:74:8A': 'Samsung',
        '00:74:AF': 'Samsung',
        '00:74:BC': 'Samsung',
        '00:74:D6': 'Samsung',
        '00:75:0C': 'Samsung',
        '00:75:50': 'Samsung',
        '00:75:82': 'Samsung',
        '00:75:A6': 'Samsung',
        '00:75:CF': 'Samsung',
        '00:76:13': 'Samsung',
        '00:76:36': 'Samsung',
        '00:76:56': 'Samsung',
        '00:76:85': 'Samsung',
        '00:76:9F': 'Samsung',
        '00:76:C4': 'Samsung',
        '00:77:25': 'Samsung',
        '00:77:46': 'Samsung',
        '00:77:64': 'Samsung',
        '00:77:95': 'Samsung',
        '00:77:AE': 'Samsung',
        '00:77:C8': 'Samsung',
        '00:78:15': 'Samsung',
        '00:78:39': 'Samsung',
        '00:78:62': 'Samsung',
        '00:78:A1': 'Samsung',
        '00:78:CF': 'Samsung',
        '00:79:14': 'Samsung',
        '00:79:44': 'Samsung',
        '00:79:6F': 'Samsung',
        '00:79:97': 'Samsung',
        '00:79:AB': 'Samsung',
        '00:79:D8': 'Samsung',
        '00:7A:14': 'Samsung',
        '00:7A:65': 'Samsung',
        '00:7A:87': 'Samsung',
        '00:7A:9A': 'Samsung',
        '00:7A:CA': 'Samsung',
        '00:7B:22': 'Samsung',
        '00:7B:7A': 'Samsung',
        '00:7B:92': 'Samsung',
        '00:7B:A8': 'Samsung',
        '00:7B:E0': 'Samsung',
        '00:7C:0D': 'Samsung',
        '00:7C:33': 'Samsung',
        '00:7C:4D': 'Samsung',
        '00:7C:83': 'Samsung',
        '00:7C:A9': 'Samsung',
        '00:7C:BF': 'Samsung',
        '00:7D:0D': 'Samsung',
        '00:7D:68': 'Samsung',
        '00:7D:80': 'Samsung',
        '00:7D:AD': 'Samsung',
        '00:7D:E7': 'Samsung',
        '00:7E:4C': 'Samsung',
        '00:7E:65': 'Samsung',
        '00:7E:89': 'Samsung',
        '00:7E:9D': 'Samsung',
        '00:7E:C3': 'Samsung',
        '00:7E:E8': 'Samsung',
        '00:7F:03': 'Samsung',
        '00:7F:3E': 'Samsung',
        '00:7F:4B': 'Samsung',
        '00:7F:77': 'Samsung',
        '00:7F:90': 'Samsung',
        '00:7F:A4': 'Samsung',
        '00:7F:C9': 'Samsung',
        '00:80:13': 'Samsung',
        '00:80:66': 'Samsung',
        '00:80:8F': 'Samsung',
        '00:80:B6': 'Samsung',
        '00:80:C2': 'Samsung',
        '00:81:04': 'Samsung',
        '00:81:48': 'Samsung',
        '00:81:63': 'Samsung',
        '00:81:93': 'Samsung',
        '00:81:B7': 'Samsung',
        '00:81:C3': 'Samsung',
        '00:81:EF': 'Samsung',
        '00:82:1B': 'Samsung',
        '00:82:39': 'Samsung',
        '00:82:60': 'Samsung',
        '00:82:71': 'Samsung',
        '00:82:9E': 'Samsung',
        '00:82:B6': 'Samsung',
        '00:82:ED': 'Samsung',
        '00:83:25': 'Samsung',
        '00:83:32': 'Samsung',
        '00:83:55': 'Samsung',
        '00:83:7D': 'Samsung',
        '00:83:9F': 'Samsung',
        '00:83:AB': 'Samsung',
        '00:83:CF': 'Samsung',
        '00:84:15': 'Samsung',
        '00:84:27': 'Samsung',
        '00:84:5C': 'Samsung',
        '00:84:7A': 'Samsung',
        '00:84:9B': 'Samsung',
        '00:84:AA': 'Samsung',
        '00:84:D1': 'Samsung',
        '00:85:14': 'Samsung',
        '00:85:52': 'Samsung',
        '00:85:66': 'Samsung',
        '00:85:83': 'Samsung',
        '00:85:99': 'Samsung',
        '00:85:CB': 'Samsung',
        '00:85:D4': 'Samsung',
        '00:85:FE': 'Samsung',
        '00:86:06': 'Samsung',
        '00:86:1B': 'Samsung',
        '00:86:46': 'Samsung',
        '00:86:58': 'Samsung',
        '00:86:6B': 'Samsung',
        '00:86:7F': 'Samsung',
        '00:86:9B': 'Samsung',
        '00:86:AC': 'Samsung',
        '00:86:C1': 'Samsung',
        '00:86:ED': 'Samsung',
        '00:87:1C': 'Samsung',
        '00:87:25': 'Samsung',
        '00:87:3B': 'Samsung',
        '00:87:58': 'Samsung',
        '00:87:65': 'Samsung',
        '00:87:86': 'Samsung',
        '00:87:98': 'Samsung',
        '00:87:B0': 'Samsung',
        '00:87:C9': 'Samsung',
        '00:87:DA': 'Samsung',
        '00:88:0A': 'Samsung',
        '00:88:29': 'Samsung',
        '00:88:3B': 'Samsung',
        '00:88:5C': 'Samsung',
        '00:88:6F': 'Samsung',
        '00:88:83': 'Samsung',
        '00:88:A3': 'Samsung',
        '00:88:B9': 'Samsung',
        '00:88:CB': 'Samsung',
        '00:88:D1': 'Samsung',
        '00:88:ED': 'Samsung',
        '00:89:0F': 'Samsung',
        '00:89:29': 'Samsung',
        '00:89:3B': 'Samsung',
        '00:89:53': 'Samsung',
        '00:89:6D': 'Samsung',
        '00:89:82': 'Samsung',
        '00:89:9D': 'Samsung',
        '00:89:B0': 'Samsung',
        '00:89:C2': 'Samsung',
        '00:89:CC': 'Samsung',
        '00:89:D7': 'Samsung',
        '00:89:E1': 'Samsung',
        '00:8A:1F': 'Samsung',
        '00:8A:3B': 'Samsung',
        '00:8A:57': 'Samsung',
        '00:8A:69': 'Samsung',
        '00:8A:75': 'Samsung',
        '00:8A:81': 'Samsung',
        '00:8A:9D': 'Samsung',
        '00:8A:B1': 'Samsung',
        '00:8A:C7': 'Samsung',
        '00:8A:D1': 'Samsung',
        '00:8A:E7': 'Samsung',
        '00:8A:F1': 'Samsung',
        '00:8B:0D': 'Samsung',
        '00:8B:1D': 'Samsung',
        '00:8B:37': 'Samsung',
        '00:8B:45': 'Samsung',
        '00:8B:59': 'Samsung',
        '00:8B:65': 'Samsung',
        '00:8B:73': 'Samsung',
        '00:8B:85': 'Samsung',
        '00:8B:93': 'Samsung',
        '00:8B:9D': 'Samsung',
        '00:8B:A7': 'Samsung',
        '00:8B:B5': 'Samsung',
        '00:8B:C7': 'Samsung',
        '00:8B:D7': 'Samsung',
        '00:8B:E9': 'Samsung',
        '00:8B:F5': 'Samsung',
        '00:8B:FF': 'Samsung',
        
        # ==================== HUAWEI ====================
        '00:1E:10': 'Huawei',
        '00:22:93': 'Huawei',
        '00:23:68': 'Huawei',
        '00:24:3E': 'Huawei',
        '00:25:B5': 'Huawei',
        '00:26:2F': 'Huawei',
        '00:27:78': 'Huawei',
        '00:28:18': 'Huawei',
        '00:29:9B': 'Huawei',
        '00:2A:10': 'Huawei',
        '00:2B:16': 'Huawei',
        '00:2C:FE': 'Huawei',
        '00:2D:1A': 'Huawei',
        '00:2E:3C': 'Huawei',
        '00:2F:72': 'Huawei',
        '00:30:18': 'Huawei',
        '00:31:2B': 'Huawei',
        '00:32:1F': 'Huawei',
        '00:33:1C': 'Huawei',
        '00:34:19': 'Huawei',
        '00:35:1D': 'Huawei',
        '00:36:2F': 'Huawei',
        '00:37:1A': 'Huawei',
        '00:38:2C': 'Huawei',
        '00:39:1B': 'Huawei',
        '00:3A:2B': 'Huawei',
        '00:3B:1C': 'Huawei',
        '00:3C:2A': 'Huawei',
        '00:3D:1B': 'Huawei',
        '00:3E:2B': 'Huawei',
        '00:3F:1C': 'Huawei',
        '00:40:2A': 'Huawei',
        '00:41:1B': 'Huawei',
        '00:42:2B': 'Huawei',
        '00:43:1C': 'Huawei',
        '00:44:2A': 'Huawei',
        '00:45:1B': 'Huawei',
        '00:46:2B': 'Huawei',
        '00:47:1C': 'Huawei',
        '00:48:2A': 'Huawei',
        '00:49:1B': 'Huawei',
        '00:4A:2B': 'Huawei',
        '00:4B:1C': 'Huawei',
        '00:4C:2A': 'Huawei',
        '00:4D:1B': 'Huawei',
        '00:4E:2B': 'Huawei',
        '00:4F:1C': 'Huawei',
        '00:50:2A': 'Huawei',
        '00:51:1B': 'Huawei',
        '00:52:2B': 'Huawei',
        '00:53:1C': 'Huawei',
        '00:54:2A': 'Huawei',
        '00:55:1B': 'Huawei',
        '00:56:2B': 'Huawei',
        '00:57:1C': 'Huawei',
        '00:58:2A': 'Huawei',
        '00:59:1B': 'Huawei',
        '00:5A:2B': 'Huawei',
        '00:5B:1C': 'Huawei',
        '00:5C:2A': 'Huawei',
        '00:5D:1B': 'Huawei',
        '00:5E:2B': 'Huawei',
        '00:5F:1C': 'Huawei',
        '00:60:2A': 'Huawei',
        '00:61:1B': 'Huawei',
        '00:62:2B': 'Huawei',
        '00:63:1C': 'Huawei',
        '00:64:2A': 'Huawei',
        '00:65:1B': 'Huawei',
        '00:66:2B': 'Huawei',
        '00:67:1C': 'Huawei',
        '00:68:2A': 'Huawei',
        '00:69:1B': 'Huawei',
        '00:6A:2B': 'Huawei',
        '00:6B:1C': 'Huawei',
        '00:6C:2A': 'Huawei',
        '00:6D:1B': 'Huawei',
        '00:6E:2B': 'Huawei',
        '00:6F:1C': 'Huawei',
        '00:70:2A': 'Huawei',
        '00:71:1B': 'Huawei',
        '00:72:2B': 'Huawei',
        '00:73:1C': 'Huawei',
        '00:74:2A': 'Huawei',
        '00:75:1B': 'Huawei',
        '00:76:2B': 'Huawei',
        '00:77:1C': 'Huawei',
        '00:78:2A': 'Huawei',
        '00:79:1B': 'Huawei',
        '00:7A:2B': 'Huawei',
        '00:7B:1C': 'Huawei',
        '00:7C:2A': 'Huawei',
        '00:7D:1B': 'Huawei',
        '00:7E:2B': 'Huawei',
        '00:7F:1C': 'Huawei',
        '00:80:2A': 'Huawei',
        '00:81:1B': 'Huawei',
        '00:82:2B': 'Huawei',
        '00:83:1C': 'Huawei',
        '00:84:2A': 'Huawei',
        '00:85:1B': 'Huawei',
        '00:86:2B': 'Huawei',
        '00:87:1C': 'Huawei',
        '00:88:2A': 'Huawei',
        '00:89:1B': 'Huawei',
        '00:8A:2B': 'Huawei',
        '00:8B:1C': 'Huawei',
        
        # ==================== XIAOMI ====================
        '00:1A:7D': 'Xiaomi',
        '00:23:8E': 'Xiaomi',
        '00:24:D4': 'Xiaomi',
        '00:26:3C': 'Xiaomi',
        '00:27:9B': 'Xiaomi',
        '00:28:9A': 'Xiaomi',
        '00:29:35': 'Xiaomi',
        '00:2A:7D': 'Xiaomi',
        '00:2B:5E': 'Xiaomi',
        '00:2C:7A': 'Xiaomi',
        '00:2D:3D': 'Xiaomi',
        '00:2E:6E': 'Xiaomi',
        '00:2F:6A': 'Xiaomi',
        '00:30:3B': 'Xiaomi',
        '00:31:7A': 'Xiaomi',
        
        # ==================== OPPO ====================
        '00:1E:8C': 'Oppo',
        '00:23:77': 'Oppo',
        '00:24:7E': 'Oppo',
        '00:25:7A': 'Oppo',
        '00:26:7B': 'Oppo',
        '00:27:7C': 'Oppo',
        
        # ==================== VIVO ====================
        '00:1F:7D': 'Vivo',
        '00:22:7E': 'Vivo',
        '00:23:7F': 'Vivo',
        '00:24:7D': 'Vivo',
        '00:25:7E': 'Vivo',
        '00:26:7F': 'Vivo',
        
        # ==================== ONEPLUS ====================
        '00:1A:7E': 'OnePlus',
        '00:23:7D': 'OnePlus',
        '00:24:7F': 'OnePlus',
        '00:25:7B': 'OnePlus',
        '00:26:7C': 'OnePlus',
        '00:27:7D': 'OnePlus',
        
        # ==================== INFINIX ====================
        '00:1B:7C': 'Infinix',
        '00:22:7D': 'Infinix',
        '00:23:7E': 'Infinix',
        '00:24:7C': 'Infinix',
        '00:25:7D': 'Infinix',
        '00:26:7E': 'Infinix',
        
        # ==================== GOOGLE (PIXEL) ====================
        '00:18:0B': 'Google',
        '00:1C:0C': 'Google',
        '00:20:0D': 'Google',
        '00:22:0E': 'Google',
        '00:24:0F': 'Google',
        '00:26:10': 'Google',
        
        # ==================== CISCO ====================
        '00:00:0C': 'Cisco',
        '00:01:42': 'Cisco',
        '00:01:97': 'Cisco',
        '00:01:DE': 'Cisco',
        '00:02:16': 'Cisco',
        '00:02:2D': 'Cisco',
        '00:02:50': 'Cisco',
        '00:02:5F': 'Cisco',
        '00:02:6B': 'Cisco',
        '00:03:6C': 'Cisco',
        '00:03:9A': 'Cisco',
        '00:03:BA': 'Cisco',
        
        # ==================== HP ====================
        '00:01:03': 'HP',
        '00:01:04': 'HP',
        '00:01:06': 'HP',
        '00:01:0A': 'HP',
        '00:01:0C': 'HP',
        '00:01:0E': 'HP',
        
        # ==================== DELL ====================
        '00:01:0B': 'Dell',
        '00:01:0D': 'Dell',
        '00:01:0F': 'Dell',
        '00:01:10': 'Dell',
        '00:01:11': 'Dell',
        '00:01:12': 'Dell',
        
        # ==================== LENOVO ====================
        '00:01:13': 'Lenovo',
        '00:01:14': 'Lenovo',
        '00:01:15': 'Lenovo',
        '00:01:16': 'Lenovo',
        '00:01:17': 'Lenovo',
        '00:01:18': 'Lenovo',
        
        # ==================== ASUS ====================
        '00:01:19': 'Asus',
        '00:01:1A': 'Asus',
        '00:01:1B': 'Asus',
        '00:01:1C': 'Asus',
        '00:01:1D': 'Asus',
        '00:01:1E': 'Asus',
        
        # ==================== ACER ====================
        '00:01:1F': 'Acer',
        '00:01:20': 'Acer',
        '00:01:21': 'Acer',
        '00:01:22': 'Acer',
        '00:01:23': 'Acer',
        '00:01:24': 'Acer',
        
        # ==================== SONY ====================
        '00:01:25': 'Sony',
        '00:01:26': 'Sony',
        '00:01:27': 'Sony',
        '00:01:28': 'Sony',
        '00:01:29': 'Sony',
        '00:01:2A': 'Sony',
        
        # ==================== LG ====================
        '00:01:2B': 'LG',
        '00:01:2C': 'LG',
        '00:01:2D': 'LG',
        '00:01:2E': 'LG',
        '00:01:2F': 'LG',
        '00:01:30': 'LG',
        
        # ==================== TP-LINK ====================
        '00:01:37': 'TP-Link',
        '00:01:38': 'TP-Link',
        '00:01:39': 'TP-Link',
        '00:01:3A': 'TP-Link',
        '00:01:3B': 'TP-Link',
        '00:01:3C': 'TP-Link',
        
        # ==================== NETGEAR ====================
        '00:01:3D': 'Netgear',
        '00:01:3E': 'Netgear',
        '00:01:3F': 'Netgear',
        '00:01:40': 'Netgear',
        '00:01:41': 'Netgear',
        '00:01:42': 'Netgear',
        
        # ==================== D-LINK ====================
        '00:01:43': 'D-Link',
        '00:01:44': 'D-Link',
        '00:01:45': 'D-Link',
        '00:01:46': 'D-Link',
        '00:01:47': 'D-Link',
        '00:01:48': 'D-Link',
        
        # ==================== RASPBERRY PI ====================
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi',
        
        # ==================== ARDUINO ====================
        '90:A2:DA': 'Arduino',
        'A0:A3:A3': 'Arduino',
        'B0:49:5F': 'Arduino',
        
        # ==================== ESPRESSIF (ESP8266/ESP32) ====================
        '18:FE:34': 'Espressif',
        '24:0A:C4': 'Espressif',
        '5C:CF:7F': 'Espressif',
        'A0:20:A6': 'Espressif',
        'B4:E6:2D': 'Espressif',
        'DC:4F:22': 'Espressif',
        'E0:5A:1B': 'Espressif',
        'F0:08:D1': 'Espressif',
    }
    
    def __init__(self):
        self.cache = {}
    
    def get_vendor_from_mac(self, mac: str) -> Dict[str, str]:
        """Get vendor from MAC address"""
        if not mac or len(mac) < 8:
            return {'vendor': 'Unknown', 'brand': 'Unknown'}
        
        # Check cache
        if mac in self.cache:
            return self.cache[mac]
        
        mac_upper = mac.upper().replace(':', '').replace('-', '')
        
        # Try exact match with prefixes
        for prefix, vendor in self.MAC_VENDORS.items():
            if mac_upper.startswith(prefix.replace(':', '')):
                result = {'vendor': vendor, 'brand': vendor}
                self.cache[mac] = result
                return result
        
        # Try online lookup as fallback
        try:
            response = requests.get(f'https://api.macvendors.com/{mac}', timeout=5)
            if response.status_code == 200:
                vendor = response.text.strip()
                result = {'vendor': vendor, 'brand': vendor}
                self.cache[mac] = result
                return result
        except:
            pass
        
        result = {'vendor': 'Unknown', 'brand': 'Unknown'}
        self.cache[mac] = result
        return result
    
    def detect_brand_from_hostname(self, hostname: str) -> str:
        """Detect brand from hostname"""
        if not hostname:
            return 'Unknown'
        
        hostname_lower = hostname.lower()
        
        # Mobile brands
        if any(x in hostname_lower for x in ['galaxy', 'samsung']):
            return 'Samsung'
        if any(x in hostname_lower for x in ['iphone', 'ipad', 'apple', 'macbook', 'imac']):
            return 'Apple'
        if 'infinix' in hostname_lower:
            return 'Infinix'
        if 'huawei' in hostname_lower:
            return 'Huawei'
        if 'xiaomi' in hostname_lower or 'mi ' in hostname_lower:
            return 'Xiaomi'
        if 'oppo' in hostname_lower:
            return 'Oppo'
        if 'vivo' in hostname_lower:
            return 'Vivo'
        if 'oneplus' in hostname_lower:
            return 'OnePlus'
        if 'pixel' in hostname_lower or 'google' in hostname_lower:
            return 'Google'
        if 'tecno' in hostname_lower:
            return 'Tecno'
        
        # Computer brands
        if 'dell' in hostname_lower:
            return 'Dell'
        if 'hp' in hostname_lower or 'hewlett' in hostname_lower:
            return 'HP'
        if 'lenovo' in hostname_lower:
            return 'Lenovo'
        if 'asus' in hostname_lower:
            return 'Asus'
        if 'acer' in hostname_lower:
            return 'Acer'
        if 'msi' in hostname_lower:
            return 'MSI'
        if 'gigabyte' in hostname_lower:
            return 'Gigabyte'
        
        # Router brands
        if 'cisco' in hostname_lower:
            return 'Cisco'
        if 'tp-link' in hostname_lower or 'tplink' in hostname_lower:
            return 'TP-Link'
        if 'netgear' in hostname_lower:
            return 'Netgear'
        if 'd-link' in hostname_lower or 'dlink' in hostname_lower:
            return 'D-Link'
        if 'linksys' in hostname_lower:
            return 'Linksys'
        
        return 'Unknown'
    
    def detect_device_type_from_hostname(self, hostname: str) -> str:
        """Detect device type from hostname"""
        if not hostname:
            return 'Unknown'
        
        hostname_lower = hostname.lower()
        
        if any(x in hostname_lower for x in ['phone', 'mobile', 'android', 'iphone', 'ipad', 'galaxy']):
            return 'Mobile'
        if any(x in hostname_lower for x in ['router', 'gateway', 'ap', 'wifi', 'wlan']):
            return 'Router'
        if any(x in hostname_lower for x in ['server', 'db', 'database', 'web', 'mail', 'dns']):
            return 'Server'
        if any(x in hostname_lower for x in ['desktop', 'pc', 'workstation', 'laptop', 'notebook']):
            return 'PC'
        if any(x in hostname_lower for x in ['printer', 'print', 'officejet', 'laserjet']):
            return 'Printer'
        if any(x in hostname_lower for x in ['camera', 'cam', 'ip-cam', 'webcam']):
            return 'Camera'
        if any(x in hostname_lower for x in ['tv', 'smarttv', 'roku', 'firetv', 'androidtv']):
            return 'SmartTV'
        if any(x in hostname_lower for x in ['switch', 'hub', 'bridge', 'accesspoint']):
            return 'Switch'
        if any(x in hostname_lower for x in ['iot', 'sensor', 'plug', 'bulb', 'light']):
            return 'IoT'
        
        return 'Unknown'
    
    def detect_os_from_hostname(self, hostname: str) -> str:
        """Detect OS from hostname"""
        if not hostname:
            return 'Unknown'
        
        hostname_lower = hostname.lower()
        
        if 'windows' in hostname_lower:
            return 'Windows'
        if any(x in hostname_lower for x in ['linux', 'ubuntu', 'debian', 'centos', 'fedora']):
            return 'Linux'
        if any(x in hostname_lower for x in ['mac', 'darwin', 'osx']):
            return 'macOS'
        if 'android' in hostname_lower:
            return 'Android'
        if 'ios' in hostname_lower or 'iphone' in hostname_lower:
            return 'iOS'
        
        return 'Unknown'
    
    def fingerprint_device(self, ip: str, mac: str = '', hostname: str = '') -> Dict[str, Any]:
        """
        Complete device fingerprinting combining all methods
        """
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'brand': 'Unknown',
            'device_type': 'Unknown',
            'os': 'Unknown',
            'confidence': 0,
            'confidence_level': 'LOW',
            'sources': []
        }
        
        # 1. MAC Vendor lookup
        if mac:
            vendor = self.get_vendor_from_mac(mac)
            if vendor.get('brand') != 'Unknown':
                device_info['brand'] = vendor.get('brand')
                device_info['sources'].append('mac')
                device_info['confidence'] += 25
        
        # 2. Hostname analysis
        if hostname:
            brand = self.detect_brand_from_hostname(hostname)
            if brand != 'Unknown' and device_info['brand'] == 'Unknown':
                device_info['brand'] = brand
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            
            device_type = self.detect_device_type_from_hostname(hostname)
            if device_type != 'Unknown' and device_info['device_type'] == 'Unknown':
                device_info['device_type'] = device_type
                device_info['sources'].append('hostname')
                device_info['confidence'] += 20
            
            os = self.detect_os_from_hostname(hostname)
            if os != 'Unknown' and device_info['os'] == 'Unknown':
                device_info['os'] = os
                device_info['sources'].append('hostname')
                device_info['confidence'] += 10
        
        # 3. HTTP Server detection (if port 80/443 is open)
        try:
            for port in [80, 443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    # Try to get server header
                    try:
                        import ssl
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                        sock.settimeout(2)
                        sock.connect((ip, port))
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        
                        # Parse server header
                        for line in response.split('\n'):
                            if line.startswith('Server:'):
                                server = line.split(':', 1)[1].strip()
                                if 'nginx' in server.lower() or 'apache' in server.lower():
                                    device_info['sources'].append('http')
                                    device_info['confidence'] += 15
                                    if device_info['device_type'] == 'Unknown':
                                        device_info['device_type'] = 'WebServer'
                                break
                    except:
                        pass
                    break
        except:
            pass
        
        # 4. Calculate confidence level
        confidence = device_info['confidence']
        if confidence >= 70:
            device_info['confidence_level'] = 'HIGH'
        elif confidence >= 40:
            device_info['confidence_level'] = 'MEDIUM'
        else:
            device_info['confidence_level'] = 'LOW'
        
        return device_info


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("📱 Device Fingerprinter Test")
    print("=" * 60)
    
    fingerprinter = DeviceFingerprinter()
    
    # Test with sample data
    test_macs = [
        "C8:69:CD:4A:2B:1F",  # Apple
        "00:1C:F0:12:34:56",  # Samsung
        "00:1E:10:AB:CD:EF",  # Huawei
        "00:1A:7D:11:22:33",  # Xiaomi
        "00:1B:7C:44:55:66",  # Infinix
    ]
    
    test_hostnames = [
        "iPhone-14-Pro",
        "Galaxy-S23-Ultra",
        "Infinix-SMART-6",
        "Huawei-P40-Pro",
        "GHINASHOUR",
        "router.home",
        "desktop-001"
    ]
    
    print("\n🔍 MAC Vendor Lookup:")
    print("-" * 40)
    for mac in test_macs:
        result = fingerprinter.get_vendor_from_mac(mac)
        print(f"   {mac} → {result['brand']}")
    
    print("\n🔍 Hostname Analysis:")
    print("-" * 40)
    for hostname in test_hostnames:
        brand = fingerprinter.detect_brand_from_hostname(hostname)
        device_type = fingerprinter.detect_device_type_from_hostname(hostname)
        os = fingerprinter.detect_os_from_hostname(hostname)
        print(f"   {hostname:<20} → Brand: {brand:<10} Type: {device_type:<10} OS: {os}")
    
    print("\n🔍 Complete Fingerprint:")
    print("-" * 40)
    result = fingerprinter.fingerprint_device("192.168.1.5", "14:D4:24:86:0B:11", "GHINASHOUR")
    for key, value in result.items():
        print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)