"""
Asset routes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from database import db, User, Asset

assets_bp = Blueprint("assets", __name__)


def _current_user():
    return User.query.get(get_jwt_identity())


@assets_bp.route("", methods=["GET"])
@jwt_required()
def list_assets():
    user = _current_user()
    if user.role == "admin":
        assets = Asset.query.all()
    else:
        assets = Asset.query.filter_by(owner_id=user.id).all()
    return jsonify([a.to_dict() for a in assets]), 200


@assets_bp.route("", methods=["POST"])
@jwt_required()
def create_asset():
    user = _current_user()
    data = request.get_json() or {}
    if not data.get("name"):
        return jsonify({"error": "name is required"}), 400
    if not (data.get("ip_address") or data.get("hostname")):
        return jsonify({"error": "ip_address or hostname is required"}), 400
    asset = Asset(
        name=data["name"],
        ip_address=data.get("ip_address"),
        hostname=data.get("hostname"),
        asset_type=data.get("asset_type", "host"),
        description=data.get("description", ""),
        owner_id=user.id,
    )
    db.session.add(asset)
    db.session.commit()
    return jsonify(asset.to_dict()), 201


@assets_bp.route("/<int:aid>", methods=["GET"])
@jwt_required()
def get_asset(aid):
    user  = _current_user()
    asset = Asset.query.get_or_404(aid)
    if user.role != "admin" and asset.owner_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(asset.to_dict()), 200


@assets_bp.route("/<int:aid>", methods=["PUT"])
@jwt_required()
def update_asset(aid):
    user  = _current_user()
    asset = Asset.query.get_or_404(aid)
    if user.role != "admin" and asset.owner_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json() or {}
    for field in ("name", "ip_address", "hostname", "asset_type", "description"):
        if field in data:
            setattr(asset, field, data[field])
    db.session.commit()
    return jsonify(asset.to_dict()), 200


@assets_bp.route("/<int:aid>", methods=["DELETE"])
@jwt_required()
def delete_asset(aid):
    user  = _current_user()
    asset = Asset.query.get_or_404(aid)
    if user.role != "admin" and asset.owner_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    db.session.delete(asset)
    db.session.commit()
    return jsonify({"message": "Asset deleted"}), 200
