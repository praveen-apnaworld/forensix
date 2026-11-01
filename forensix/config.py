"""
config.py - Configuration for the Digital Forensics Toolkit

This file stores all the settings our Flask application needs.
Think of it like a settings panel for the entire app.
"""

import os

# Get the folder where this file lives (the project root)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Main configuration class for the application."""

    # Secret key for Flask sessions and CSRF protection
    # In production, use a random string. For our college project, this is fine.
    SECRET_KEY = 'forensix-toolkit-secret-key-2026'

    # Database location - stored inside the database/ folder
    DATABASE = os.path.join(BASE_DIR, 'database', 'forensix.db')

    # Upload settings
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload size

    # Allowed file extensions for evidence upload
    # We allow common file types for forensic analysis
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff',
        'doc', 'docx', 'xls', 'xlsx', 'csv', 'log', 'xml', 'json',
        'html', 'htm', 'zip', 'tar', 'gz', '7z', 'rar',
        'mp3', 'mp4', 'avi', 'wav', 'exe', 'dll', 'sys', 'dat',
        'db', 'sqlite', 'pcap', 'eml', 'msg'
    }

    # Application info
    APP_NAME = 'Digital Forensics Toolkit'
    APP_VERSION = '1.0.0'
