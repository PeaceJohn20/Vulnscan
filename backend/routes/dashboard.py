"""
Dashboard routes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import jsonify, Blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import User, Scan, ScanResult, Asset
from scanners.cve_fetcher import fetch_recent_cves

dashboard_bp = Blueprint("dashboard", __name__)


def _current_user():
    return User.query.get(get_jwt_identity())


@dashboard_bp.route("/stats", methods=["GET"])
@jwt_required()
def stats():
    user = _current_user()
    if user.role == "admin":
        total_scans  = Scan.query.count()
        total_assets = Asset.query.count()
        all_results  = ScanResult.query.all()
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
    else:
        total_scans  = Scan.query.filter_by(user_id=user.id).count()
        total_assets = Asset.query.filter_by(owner_id=user.id).count()
        scan_ids     = [s.id for s in Scan.query.filter_by(user_id=user.id).all()]
        all_results  = ScanResult.query.filter(ScanResult.scan_id.in_(scan_ids)).all() if scan_ids else []
        recent_scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(5).all()

    severity_counts = {
        "Critical": sum(1 for r in all_results if r.severity == "Critical"),
        "High":     sum(1 for r in all_results if r.severity == "High"),
        "Medium":   sum(1 for r in all_results if r.severity == "Medium"),
        "Low":      sum(1 for r in all_results if r.severity == "Low"),
    }
    return jsonify({
        "total_scans":     total_scans,
        "total_assets":    total_assets,
        "total_findings":  len(all_results),
        "severity_counts": severity_counts,
        "recent_scans":    [s.to_dict() for s in recent_scans],
    }), 200


@dashboard_bp.route("/recent-cves", methods=["GET"])
@jwt_required()
def recent_cves():
    try:
        cves = fetch_recent_cves(days_back=7, limit=10)
    except Exception:
        cves = []
    return jsonify(cves), 200
