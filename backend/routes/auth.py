"""
Authentication routes
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from database import db, User

auth_bp = Blueprint("auth", __name__)
limiter = Limiter(get_remote_address)

def _current_user():
    uid = get_jwt_identity()
    return User.query.get(uid)

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per hour")
def register():
    data = request.get_json() or {}
    if not all(k in data for k in ("username", "email", "password")):
        return jsonify({"error": "username, email and password are required"}), 400
    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "Username already taken"}), 409
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 409
    user = User(username=data["username"], email=data["email"], role="customer")
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()
    token = create_access_token(identity=str(user.id))
    return jsonify({"token": token, "user": user.to_dict()}), 201

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(username=data.get("username")).first()
    if not user or not user.check_password(data.get("password", "")):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"error": "Account disabled"}), 403
    token = create_access_token(identity=str(user.id))
    return jsonify({"token": token, "user": user.to_dict()}), 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user = _current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict()), 200

@auth_bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    user = _current_user()
    if not user or user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify([u.to_dict() for u in User.query.all()]), 200

@auth_bp.route("/users/<int:uid>", methods=["PUT"])
@jwt_required()
def update_user(uid):
    actor = _current_user()
    if not actor or actor.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    target = User.query.get_or_404(uid)
    data = request.get_json() or {}
    if "is_active" in data:
        target.is_active = data["is_active"]
    if "role" in data and data["role"] in ("admin", "customer"):
        target.role = data["role"]
    db.session.commit()
    return jsonify(target.to_dict()), 200