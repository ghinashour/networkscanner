#!/usr/bin/env python3
"""
Security Hardened Scanner
- Input validation and sanitization
- Rate limiting
- Command injection prevention
- Scope controls
"""

import re
import ipaddress
import time
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import logging
from functools import wraps

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityHardenedScanner:
    """
    Wrapper for network scanners with security controls
    """
    
    # Allowed characters (prevents command injection)
    ALLOWED_CHARS = re.compile(r'^[a-zA-Z0-9\.\-_:/]+$')
    
    # Forbidden patterns (command injection)
    FORBIDDEN_PATTERNS = [
        r'[;&|$`]',           # Shell metacharacters
        r'\(.*\)',            # Command substitution
        r'\b(rm|del|format|mkfs)\b',  # Dangerous commands
        r'>\s*\S+',           # Output redirection
        r'<\s*\S+',           # Input redirection
        r'\.\./',             # Path traversal
        r'\bwget\b',          # File download
        r'\bcurl\b',          # File download
        r'\bnc\b',            # Netcat
    ]
    
    # Rate limiting: max scans per minute
    RATE_LIMIT_PER_MINUTE = 5
    # Max targets per scan
    MAX_TARGETS = 256  # /24 subnet (254 hosts)
    # Cooldown between scans (seconds)
    SCAN_COOLDOWN = 10
    
    def __init__(self):
        self.scan_history = []
        self.last_scan_time = None
    
    def validate_target(self, target: str) -> Tuple[bool, Optional[str]]:
        """
        Validate target input for security
        
        Returns:
            (is_valid, error_message)
        """
        # 1. Check for forbidden characters
        if not self.ALLOWED_CHARS.match(target):
            return False, f"Invalid characters in target: {target}"
        
        # 2. Check for forbidden patterns
        for pattern in self.FORBIDDEN_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                return False, f"Forbidden pattern detected: {pattern}"
        
        # 3. Validate IP/subnet format
        try:
            if '/' in target:
                # CIDR notation
                ipaddress.ip_network(target, strict=False)
            else:
                # Single IP
                ipaddress.ip_address(target)
        except ValueError as e:
            return False, f"Invalid IP/subnet format: {e}"
        
        # 4. Check target size
        target_count = self._count_targets(target)
        if target_count > self.MAX_TARGETS:
            return False, f"Target too large ({target_count} hosts, max {self.MAX_TARGETS})"
        
        return True, None
    
    def _count_targets(self, target: str) -> int:
        """Count number of hosts in target"""
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return network.num_addresses
            else:
                return 1
        except:
            return 0
    
    def check_rate_limit(self) -> Tuple[bool, str]:
        """
        Check if rate limit is exceeded
        
        Returns:
            (allowed, message)
        """
        # Clean old entries (older than 1 minute)
        now = datetime.now()
        self.scan_history = [
            t for t in self.scan_history 
            if (now - t) < timedelta(minutes=1)
        ]
        
        if len(self.scan_history) >= self.RATE_LIMIT_PER_MINUTE:
            return False, f"Rate limit exceeded. Max {self.RATE_LIMIT_PER_MINUTE} scans per minute"
        
        # Check cooldown
        if self.last_scan_time:
            elapsed = (now - self.last_scan_time).total_seconds()
            if elapsed < self.SCAN_COOLDOWN:
                return False, f"Cooldown in effect. Wait {self.SCAN_COOLDOWN - elapsed:.1f}s"
        
        return True, "OK"
    
    def log_scan(self, target: str, user: str = None): # type: ignore
        """Log a scan for rate limiting"""
        self.scan_history.append(datetime.now())
        self.last_scan_time = datetime.now()
        
        logger.info(f"✅ Scan logged: target={target}, user={user or 'anonymous'}")
    
    def validate_scan(self, target: str, user: str = None) -> Tuple[bool, str]: # type: ignore
        """
        Complete validation before scanning
        
        Returns:
            (allowed, message)
        """
        # Validate target
        valid, error = self.validate_target(target)
        if not valid:
            return False, f"Target validation failed: {error}"
        
        # Check rate limit
        allowed, message = self.check_rate_limit()
        if not allowed:
            return False, f"Rate limit: {message}"
        
        return True, "Scan allowed"
    
    def sanitize_input(self, user_input: str) -> str:
        """
        Sanitize user input by removing dangerous characters
        """
        # Remove forbidden patterns
        for pattern in self.FORBIDDEN_PATTERNS:
            user_input = re.sub(pattern, '', user_input, flags=re.IGNORECASE)
        
        # Only allow alphanumeric, dots, dashes, underscores, colons, slashes
        user_input = re.sub(r'[^a-zA-Z0-9\.\-_:/]', '', user_input)
        
        return user_input
    
    def get_scan_rules(self) -> dict:
        """Get current scan rules"""
        return {
            'max_targets': self.MAX_TARGETS,
            'rate_limit_per_minute': self.RATE_LIMIT_PER_MINUTE,
            'scan_cooldown': self.SCAN_COOLDOWN,
            'forbidden_patterns': self.FORBIDDEN_PATTERNS
        }


# ============================================================================
# DECORATORS FOR SCAN FUNCTIONS
# ============================================================================

def secure_scan(security_checker: SecurityHardenedScanner):
    """
    Decorator to secure scan functions
    """
    def decorator(func):
        @wraps(func)
        def wrapper(target, *args, **kwargs):
            # Validate
            allowed, message = security_checker.validate_scan(target)
            if not allowed:
                logger.warning(f"⛔ Scan blocked: {message}")
                return {'error': message, 'blocked': True}
            
            # Execute scan
            logger.info(f"🔍 Secure scan starting: {target}")
            try:
                result = func(target, *args, **kwargs)
                # Log successful scan
                security_checker.log_scan(target)
                return result
            except Exception as e:
                logger.error(f"❌ Scan failed: {e}")
                return {'error': str(e), 'blocked': False}
        
        return wrapper
    return decorator


# ============================================================================
# QUICK TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🔐 Security Hardened Scanner Test")
    print("=" * 60)
    
    # Initialize security checker
    security = SecurityHardenedScanner()
    
    # Test inputs
    test_targets = [
        ("192.168.1.1", True),
        ("192.168.1.0/24", True),
        ("192.168.1.1; rm -rf /", False),  # Command injection
        ("192.168.1.1 | ls", False),        # Command injection
        ("192.168.1.0/0", False),           # Too large
        ("192.168.1.1 $(whoami)", False),   # Command substitution
    ]
    
    print("\n📋 Validation Tests:")
    print("-" * 60)
    
    for target, expected in test_targets:
        valid, error = security.validate_target(target)
        status = "✅ PASS" if valid == expected else "❌ FAIL"
        print(f"   {status} - {target}")
        if error:
            print(f"      {error}")
    
    # Test rate limiting
    print("\n📋 Rate Limiting Tests:")
    print("-" * 60)
    
    # Try multiple scans quickly
    for i in range(7):
        allowed, message = security.check_rate_limit()
        status = "✅" if allowed else "⛔"
        print(f"   {status} Scan {i+1}: {message}")
        if allowed:
            security.log_scan("192.168.1.1")
        time.sleep(0.5)
    
    print("\n📋 Scan Rules:")
    print("-" * 60)
    rules = security.get_scan_rules()
    for key, value in rules.items():
        print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)