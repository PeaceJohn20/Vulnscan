"""
Reports routes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, User, Scan, ScanResult, Report
from scanners.report_generator import generate_report
import uuid

reports_bp = Blueprint("reports", __name__)
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")


def _current_user():
    return User.query.get(get_jwt_identity())


@reports_bp.route("/generate/<int:scan_id>", methods=["POST"])
@jwt_required()
def generate(scan_id):
    user = _current_user()
    scan = Scan.query.get_or_404(scan_id)
    if user.role != "admin" and scan.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    if scan.status != "completed":
        return jsonify({"error": "Scan is not complete yet"}), 400
    results  = ScanResult.query.filter_by(scan_id=scan_id).all()
    filename = f"vulnscan_report_{scan_id}_{uuid.uuid4().hex[:8]}.pdf"
    out_path = os.path.join(REPORTS_DIR, filename)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    try:
        generate_report(scan, results, out_path, user=user)
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {e}"}), 500
    report = Report(scan_id=scan_id, user_id=user.id, filename=filename, file_path=out_path)
    db.session.add(report)
    db.session.commit()
    return jsonify({"message": "Report generated", "report": report.to_dict()}), 201


@reports_bp.route("", methods=["GET"])
@jwt_required()
def list_reports():
    user = _current_user()
    if user.role == "admin":
        rpts = Report.query.order_by(Report.created_at.desc()).all()
    else:
        rpts = Report.query.filter_by(user_id=user.id).order_by(Report.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rpts]), 200


@reports_bp.route("/<int:rid>/download", methods=["GET"])
@jwt_required()
def download_report(rid):
    user   = _current_user()
    report = Report.query.get_or_404(rid)
    if user.role != "admin" and report.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    if not os.path.exists(report.file_path):
        return jsonify({"error": "Report file not found on disk"}), 404
    return send_file(report.file_path, as_attachment=True,
                     download_name=report.filename, mimetype="application/pdf")
