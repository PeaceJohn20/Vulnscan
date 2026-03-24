"""
Database models — SQLite via SQLAlchemy
Entities: User, Asset, Scan, ScanResult, Vulnerability, Report
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import bcrypt

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(20),  default="customer")
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active     = db.Column(db.Boolean, default=True)

    assets  = db.relationship("Asset",  back_populates="owner", cascade="all, delete-orphan")
    scans   = db.relationship("Scan",   back_populates="user",  cascade="all, delete-orphan")
    reports = db.relationship("Report", back_populates="user",  cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    def to_dict(self):
        return {
            "id":         self.id,
            "username":   self.username,
            "email":      self.email,
            "role":       self.role,
            "created_at": self.created_at.isoformat(),
            "is_active":  self.is_active,
        }


class Asset(db.Model):
    __tablename__ = "assets"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    ip_address  = db.Column(db.String(50))
    hostname    = db.Column(db.String(255))
    asset_type  = db.Column(db.String(50), default="host")
    description = db.Column(db.Text)
    owner_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    owner = db.relationship("User",  back_populates="assets")
    scans = db.relationship("Scan",  back_populates="asset", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id":          self.id,
            "name":        self.name,
            "ip_address":  self.ip_address,
            "hostname":    self.hostname,
            "asset_type":  self.asset_type,
            "description": self.description,
            "owner_id":    self.owner_id,
            "created_at":  self.created_at.isoformat(),
        }


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id          = db.Column(db.Integer, primary_key=True)
    cve_id      = db.Column(db.String(30),  unique=True, nullable=False)
    description = db.Column(db.Text)
    severity    = db.Column(db.String(20))
    cvss_score  = db.Column(db.Float)
    published   = db.Column(db.String(30))
    references  = db.Column(db.Text)
    fetched_at  = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scan_results = db.relationship("ScanResult", back_populates="vulnerability")

    def to_dict(self):
        import json
        refs = []
        try:
            refs = json.loads(self.references) if self.references else []
        except Exception:
            pass
        return {
            "id":          self.id,
            "cve_id":      self.cve_id,
            "description": self.description,
            "severity":    self.severity,
            "cvss_score":  self.cvss_score,
            "published":   self.published,
            "references":  refs,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id         = db.Column(db.Integer, primary_key=True)
    asset_id   = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"),  nullable=False)
    target     = db.Column(db.String(255), nullable=False)
    scan_type  = db.Column(db.String(50),  default="full")
    status     = db.Column(db.String(30),  default="pending")
    started_at = db.Column(db.DateTime)
    ended_at   = db.Column(db.DateTime)
    raw_output = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    asset   = db.relationship("Asset",      back_populates="scans")
    user    = db.relationship("User",       back_populates="scans")
    results = db.relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    reports = db.relationship("Report",     back_populates="scan")

    def to_dict(self):
        return {
            "id":           self.id,
            "asset_id":     self.asset_id,
            "target":       self.target,
            "scan_type":    self.scan_type,
            "status":       self.status,
            "started_at":   self.started_at.isoformat() if self.started_at else None,
            "ended_at":     self.ended_at.isoformat()   if self.ended_at   else None,
            "created_at":   self.created_at.isoformat(),
            "result_count": len(self.results),
        }


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id               = db.Column(db.Integer, primary_key=True)
    scan_id          = db.Column(db.Integer, db.ForeignKey("scans.id"),           nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id"))
    finding_type     = db.Column(db.String(50))
    port             = db.Column(db.Integer)
    protocol         = db.Column(db.String(10))
    service          = db.Column(db.String(100))
    version          = db.Column(db.String(100))
    severity         = db.Column(db.String(20))
    description      = db.Column(db.Text)
    remediation      = db.Column(db.Text)
    raw_detail       = db.Column(db.Text)

    scan          = db.relationship("Scan",          back_populates="results")
    vulnerability = db.relationship("Vulnerability", back_populates="scan_results")

    def to_dict(self):
        return {
            "id":           self.id,
            "scan_id":      self.scan_id,
            "finding_type": self.finding_type,
            "port":         self.port,
            "protocol":     self.protocol,
            "service":      self.service,
            "version":      self.version,
            "severity":     self.severity,
            "description":  self.description,
            "remediation":  self.remediation,
            "cve":          self.vulnerability.cve_id    if self.vulnerability else None,
            "cvss_score":   self.vulnerability.cvss_score if self.vulnerability else None,
        }


class Report(db.Model):
    __tablename__ = "reports"

    id         = db.Column(db.Integer, primary_key=True)
    scan_id    = db.Column(db.Integer, db.ForeignKey("scans.id"),  nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"),  nullable=False)
    filename   = db.Column(db.String(255))
    file_path  = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scan = db.relationship("Scan",   back_populates="reports")
    user = db.relationship("User",   back_populates="reports")

    def to_dict(self):
        return {
            "id":         self.id,
            "scan_id":    self.scan_id,
            "filename":   self.filename,
            "created_at": self.created_at.isoformat(),
        }


def init_db():
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        admin = User(username="Peace", email="peacejohnwazza450@gmail.com", role="admin")
        admin.set_password("Justdoit@25")
        db.session.add(admin)
        db.session.commit()
        print("[VulnScan] Default admin seeded: Peace / Justdoit@25")
