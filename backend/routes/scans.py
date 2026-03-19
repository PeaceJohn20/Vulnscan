"""
Scan routes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, User, Asset, Scan, ScanResult
from scanners.orchestrator import run_full_scan, run_code_scan
import threading

scans_bp = Blueprint("scans", __name__)


def _current_user():
    return User.query.get(get_jwt_identity())


@scans_bp.route("", methods=["POST"])
@jwt_required()
def start_scan():
    user = _current_user()
    data = request.get_json() or {}
    asset_id = data.get("asset_id")
    if not asset_id:
        return jsonify({"error": "asset_id is required"}), 400
    asset = Asset.query.get(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    if user.role != "admin" and asset.owner_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    target    = asset.ip_address or asset.hostname
    scan_type = data.get("scan_type", "full")
    scan = Scan(asset_id=asset.id, user_id=user.id, target=target,
                scan_type=scan_type, status="pending")
    db.session.add(scan)
    db.session.commit()
    app = current_app._get_current_object()
    t = threading.Thread(target=run_full_scan, args=(app, scan.id), daemon=True)
    t.start()
    return jsonify({"message": "Scan started", "scan": scan.to_dict()}), 202


@scans_bp.route("/code", methods=["POST"])
@jwt_required()
def code_scan():
    user = _current_user()
    data = request.get_json() or {}
    code_content = data.get("code")
    if not code_content:
        return jsonify({"error": "code field is required"}), 400
    asset_id = data.get("asset_id")
    if not asset_id:
        return jsonify({"error": "asset_id is required"}), 400
    asset = Asset.query.get(asset_id)
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    scan = Scan(asset_id=asset.id, user_id=user.id,
                target=asset.ip_address or asset.hostname or "code-scan",
                scan_type="code", status="pending")
    db.session.add(scan)
    db.session.commit()
    app = current_app._get_current_object()
    t = threading.Thread(target=run_code_scan, args=(app, scan.id, code_content), daemon=True)
    t.start()
    return jsonify({"message": "Code scan started", "scan": scan.to_dict()}), 202


@scans_bp.route("", methods=["GET"])
@jwt_required()
def list_scans():
    user = _current_user()
    if user.role == "admin":
        scans = Scan.query.order_by(Scan.created_at.desc()).all()
    else:
        scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).all()
    return jsonify([s.to_dict() for s in scans]), 200


@scans_bp.route("/<int:sid>", methods=["GET"])
@jwt_required()
def get_scan(sid):
    user = _current_user()
    scan = Scan.query.get_or_404(sid)
    if user.role != "admin" and scan.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(scan.to_dict()), 200


@scans_bp.route("/<int:sid>/results", methods=["GET"])
@jwt_required()
def get_scan_results(sid):
    user = _current_user()
    scan = Scan.query.get_or_404(sid)
    if user.role != "admin" and scan.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    results = ScanResult.query.filter_by(scan_id=sid).all()
    return jsonify({
        "scan":    scan.to_dict(),
        "results": [r.to_dict() for r in results],
        "summary": {
            "total":    len(results),
            "critical": sum(1 for r in results if r.severity == "Critical"),
            "high":     sum(1 for r in results if r.severity == "High"),
            "medium":   sum(1 for r in results if r.severity == "Medium"),
            "low":      sum(1 for r in results if r.severity == "Low"),
        }
    }), 200
