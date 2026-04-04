"""
VulnScan - Vulnerability Scanning Tool
"""

import sys
import os

# Ensure Python finds all modules in the backend folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from database import db, init_db
from routes.auth import auth_bp
from routes.scans import scans_bp
from routes.assets import assets_bp
from routes.reports import reports_bp
from routes.dashboard import dashboard_bp


def create_app():
    app = Flask(__name__)

    # Configuration
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///vulnscan.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "vulnscan-secret-key-2026")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False

    # Extensions
    CORS(app, origins=["*"], supports_credentials=True)
    JWTManager(app)
    db.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp,      url_prefix="/api/auth")
    app.register_blueprint(scans_bp,     url_prefix="/api/scans")
    app.register_blueprint(assets_bp,    url_prefix="/api/assets")
    app.register_blueprint(reports_bp,   url_prefix="/api/reports")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")

    with app.app_context():
        init_db()
 
    @app.route('/')
    def serve_frontend():
        return send_from_directory(os.path.join(os.path.dirname(__file__), '../frontend'), 'index.html')

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
