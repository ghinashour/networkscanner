"""
Database models for the AI Network Scanner.
Defines SQLAlchemy ORM models for all entities.
"""
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float,
    Boolean, ForeignKey, JSON, Table
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

# Association table for many-to-many relationship between hosts and scans
scan_hosts = Table(
    'scan_hosts',
    Base.metadata,
    Column('scan_id', Integer, ForeignKey('scans.id')),
    Column('host_id', Integer, ForeignKey('hosts.id'))
)

class Scan(Base):
    """Stores scan session information."""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), unique=True, nullable=False)  # UUID or timestamp-based
    scan_type = Column(String(50), nullable=False)  # 'quick', 'full', 'custom'
    target_range = Column(String(100), nullable=False)
    start_time = Column(DateTime, default=func.now())  # Use func.now() instead of datetime.utcnow
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), default='running')  # 'running', 'completed', 'failed'
    total_hosts = Column(Integer, default=0)
    active_hosts = Column(Integer, default=0)
    scan_parameters = Column(JSON, nullable=True)  # Store scan settings
    
    # Relationships
    hosts = relationship('Host', secondary=scan_hosts, back_populates='scans')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'scan_type': self.scan_type,
            'target_range': self.target_range,
            'start_time': self.start_time.isoformat() if self.start_time is not None else None,
            'end_time': self.end_time.isoformat() if self.end_time is not None else None,
            'status': self.status,
            'total_hosts': self.total_hosts,
            'active_hosts': self.active_hosts
        }

class Host(Base):
    """Stores discovered network hosts."""
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_name = Column(String(100), nullable=True)
    os_family = Column(String(50), nullable=True)
    os_accuracy = Column(Integer, nullable=True)  # Percentage
    status = Column(String(20), default='up')  # 'up', 'down', 'unknown'
    device_type = Column(String(50), nullable=True)  # Will be set by ML model
    confidence = Column(Float, nullable=True)  # ML model confidence
    first_seen = Column(DateTime, default=func.now())  # Use func.now()
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())  # Auto-update on change
    notes = Column(Text, nullable=True)
    
    # Relationships
    services = relationship('Service', back_populates='host', cascade='all, delete-orphan')
    vulnerabilities = relationship('Vulnerability', back_populates='host')
    scans = relationship('Scan', secondary=scan_hosts, back_populates='hosts')
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'os_name': self.os_name,
            'os_family': self.os_family,
            'os_accuracy': self.os_accuracy,
            'status': self.status,
            'device_type': self.device_type,
            'confidence': self.confidence,
'first_seen': self.first_seen.isoformat() if self.first_seen is not None else None,
'last_seen': self.last_seen.isoformat() if self.last_seen is not None else None
        }

class Service(Base):
    """Stores network services running on hosts."""
    __tablename__ = 'services'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    port: Mapped[int]
    protocol: Mapped[str]
    service_name: Mapped[str | None]
    service_version: Mapped[str | None]
    banner = Column(Text, nullable=True)
    state: Mapped[str]
    product = Column(String(100), nullable=True)
    extra_info = Column(JSON, nullable=True)  # Additional service info
    first_seen = Column(DateTime, default=func.now())  # Use func.now()
    last_seen = Column(DateTime, default=func.now(), onupdate=func.now())  # Auto-update
    
    # Relationships
    host = relationship('Host', back_populates='services')
    vulnerabilities = relationship('Vulnerability', back_populates='service')
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'port': self.port,
            'protocol': self.protocol,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'banner': self.banner,
            'state': self.state,
            'product': self.product
        }

class Vulnerability(Base):
    """Stores vulnerabilities discovered from CVE lookup."""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), nullable=False, index=True)  # CVE-YYYY-XXXX
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    service_id = Column(Integer, ForeignKey('services.id'), nullable=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(50), nullable=True)
    severity = Column(String(20), nullable=True)  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    exploit_available = Column(Boolean, default=False)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=func.now())  # Use func.now()
    
    # Relationships
    host = relationship('Host', back_populates='vulnerabilities')
    service = relationship('Service', back_populates='vulnerabilities')
    
    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'host_id': self.host_id,
            'service_id': self.service_id,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'exploit_available': self.exploit_available,
            'remediation': self.remediation,
'discovered_at': self.discovered_at.isoformat() if self.discovered_at is not None else None
        }

class DeviceClassification(Base):
    """Stores device classification results from ML model."""
    __tablename__ = 'device_classifications'
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), unique=True, nullable=False)
    predicted_type = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    features_used = Column(JSON, nullable=True)  # Store features used for classification
    training_version = Column(String(20), nullable=True)
    classified_at = Column(DateTime, default=func.now())  # Use func.now()
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'predicted_type': self.predicted_type,
            'confidence': self.confidence,
'classified_at': self.classified_at.isoformat() if self.classified_at is not None else None
        }

class RiskScore(Base):
    """Stores risk scores calculated for hosts."""
    __tablename__ = 'risk_scores'
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), unique=True, nullable=False)
    overall_risk = Column(Float, nullable=False)  # 0-10 scale
    risk_level = Column(String(20), nullable=False)  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    vulnerability_risk = Column(Float, nullable=True)
    exposure_risk = Column(Float, nullable=True)
    service_risk = Column(Float, nullable=True)
    factors = Column(JSON, nullable=True)  # Detailed risk factors
    calculated_at = Column(DateTime, default=func.now())  # Use func.now()
    
    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'overall_risk': self.overall_risk,
            'risk_level': self.risk_level,
'calculated_at': self.calculated_at.isoformat() if self.calculated_at is not None else None
        }