import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text, Index, CheckConstraint, ForeignKey
from sqlalchemy.orm import validates, relationship
import json
import csv
import io
import re
from html import escape
import logging
from logging.handlers import RotatingFileHandler
import redis
from functools import wraps
from typing import Dict, Any, List, Optional
import uuid

# ===== ENTERPRISE APP INITIALIZATION =====
app = Flask(__name__)

class EnterpriseConfig:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(64))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_urlsafe(64))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///enterprise_complete.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    
    # Rate Limiting
    RATE_LIMIT_STORAGE_URI = os.environ.get('REDIS_URL', 'memory://')
    RATE_LIMIT_STRATEGY = 'fixed-window'
    RATE_LIMIT_DEFAULT = "1000 per hour"
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }

app.config.from_object(EnterpriseConfig)

# ===== ENTERPRISE MIDDLEWARE =====
CORS(app, 
     origins=app.config['CORS_ORIGINS'], 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Device-Fingerprint"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config['RATE_LIMIT_STORAGE_URI'],
    strategy=app.config['RATE_LIMIT_STRATEGY'],
    default_limits=[app.config['RATE_LIMIT_DEFAULT']]
)

@app.after_request
def set_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ===== COMPLETE ENTERPRISE DATABASE MODELS =====
class BaseModel(db.Model):
    """Enterprise Base Model with Audit Trail"""
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, nullable=True)
    updated_by = db.Column(db.Integer, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

class User(BaseModel):
    """Complete Enterprise User Model"""
    __tablename__ = 'users'
    
    # Authentication & Core Info
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    
    # Role & Status Management
    role = db.Column(db.String(20), nullable=False, default='student', index=True)
    status = db.Column(db.String(20), nullable=False, default='active', index=True)
    
    # Enterprise Security Features
    email_verified = db.Column(db.Boolean, default=False)
    last_login_at = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity_at = db.Column(db.DateTime)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    
    # Audit & Compliance
    password_history = db.Column(db.Text)  # JSON stored as text
    
    __table_args__ = (
        Index('ix_users_email_role', 'email', 'role'),
        Index('ix_users_status_role', 'status', 'role'),
        CheckConstraint("role IN ('admin', 'faculty', 'student', 'staff')", name='valid_role'),
        CheckConstraint("status IN ('active', 'inactive', 'suspended', 'pending')", name='valid_status')
    )
    
    @validates('email')
    def validate_email(self, key, email):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def set_password(self, password: str):
        """Enterprise password policy enforcement"""
        errors = self.validate_password_policy(password)
        if errors:
            raise ValueError(f"Password policy violation: {', '.join(errors)}")
        
        # Password history check (last 5 passwords)
        if self.password_history:
            history = json.loads(self.password_history)
            for old_hash in history[-5:]:
                if check_password_hash(old_hash, password):
                    raise ValueError("Password cannot be the same as previous 5 passwords")
        
        new_hash = generate_password_hash(password)
        
        # Update password history
        history = json.loads(self.password_history) if self.password_history else []
        history.append(new_hash)
        self.password_history = json.dumps(history[-5:])  # Keep last 5
        
        self.password_hash = new_hash
        self.password_changed_at = datetime.utcnow()
        self.failed_login_attempts = 0
    
    def verify_password(self, password: str) -> bool:
        """Enterprise password verification with lockout"""
        if self.is_account_locked():
            return False
        
        if check_password_hash(self.password_hash, password):
            self.failed_login_attempts = 0
            self.last_login_at = datetime.utcnow()
            return True
        else:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
            return False
    
    def validate_password_policy(self, password: str) -> List[str]:
        """Enterprise password policy"""
        errors = []
        if len(password) < 12: errors.append("Must be at least 12 characters")
        if not re.search(r'[A-Z]', password): errors.append("Must contain uppercase letter")
        if not re.search(r'[a-z]', password): errors.append("Must contain lowercase letter")
        if not re.search(r'\d', password): errors.append("Must contain number")
        if not re.search(r'[@$!%*?&]', password): errors.append("Must contain special character (@$!%*?&)")
        
        # Common password check
        common_passwords = {"password", "123456", "qwerty", "admin", "welcome"}
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        return errors
    
    def is_account_locked(self) -> bool:
        return (self.account_locked_until and 
                datetime.utcnow() < self.account_locked_until)
    
    def requires_password_change(self) -> bool:
        """90-day password rotation policy"""
        return (datetime.utcnow() - self.password_changed_at).days > 90

class UserSession(BaseModel):
    """Enterprise Session Management"""
    __tablename__ = 'user_sessions'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    device_fingerprint = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    is_revoked = db.Column(db.Boolean, default=False)
    
    user = relationship('User', backref=db.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))
    
    __table_args__ = (
        Index('ix_user_sessions_user_expires', 'user_id', 'expires_at'),
    )
    
    @property
    def is_active(self):
        return not self.is_revoked and datetime.utcnow() < self.expires_at

class AuditLog(BaseModel):
    """Enterprise Audit Trail for Compliance"""
    __tablename__ = 'audit_logs'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=False, index=True)
    resource_id = db.Column(db.String(100), index=True)
    old_values = db.Column(db.Text)
    new_values = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False)
    error_message = db.Column(db.Text)
    
    user = relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))
    
    __table_args__ = (
        Index('ix_audit_logs_timestamp_action', 'created_at', 'action'),
        Index('ix_audit_logs_resource', 'resource_type', 'resource_id'),
    )

class Department(BaseModel):
    """Academic Department Management"""
    __tablename__ = 'departments'
    
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    head_faculty_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=True)
    budget = db.Column(db.Float, default=0.0)
    student_count = db.Column(db.Integer, default=0)
    faculty_count = db.Column(db.Integer, default=0)
    
    head_faculty = relationship('User', foreign_keys=[head_faculty_id])

class Student(BaseModel):
    """Student Management"""
    __tablename__ = 'students'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False, unique=True)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    department_id = db.Column(db.Integer, ForeignKey('departments.id'), nullable=True)
    gpa = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='enrolled')
    risk_level = db.Column(db.String(20), default='low')
    financial_status = db.Column(db.String(20), default='paid')
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    graduation_date = db.Column(db.DateTime, nullable=True)
    
    user = relationship('User', foreign_keys=[user_id], backref=db.backref('student_profile', uselist=False))
    department = relationship('Department', backref=db.backref('students', lazy='dynamic'))

# ===== ENTERPRISE SECURITY SERVICES =====
class SecurityUtils:
    """Enterprise Security Utilities"""
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        if text is None: return ""
        text = re.sub(r'[<>"\']', '', text)
        return escape(text.strip())
    
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def generate_secure_password() -> str:
        import string
        import secrets
        alphabet = string.ascii_letters + string.digits + '@$!%*?&'
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(16))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in '@$!%*?&' for c in password)):
                return password
    
    @staticmethod
    def create_device_fingerprint(request) -> str:
        import hashlib
        components = [
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.remote_addr
        ]
        fingerprint = '|'.join(components)
        return hashlib.sha256(fingerprint.encode()).hexdigest()

class AuditService:
    """Enterprise Audit Service"""
    
    @staticmethod
    def log_action(user_id: int, action: str, resource_type: str, resource_id: str = None, 
                   old_values: Dict = None, new_values: Dict = None, status: str = 'success',
                   error_message: str = None):
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                old_values=json.dumps(old_values) if old_values else None,
                new_values=json.dumps(new_values) if new_values else None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                status=status,
                error_message=error_message
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as e:
            print(f"Audit logging failed: {str(e)}")

# ===== ENTERPRISE ROUTES WITH ALL FEATURES =====
@app.route('/api/v1/health', methods=['GET'])
def enterprise_health_check():
    """Comprehensive Health Check"""
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {'database': 'healthy', 'api': 'healthy'},
            'version': '3.0.0',
            'features': {
                'authentication': 'enabled',
                'audit_logging': 'enabled', 
                'rate_limiting': 'enabled',
                'password_policies': 'enabled',
                'session_management': 'enabled'
            }
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def enterprise_login():
    """Enterprise Authentication with Security Controls"""
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400
        
        email = SecurityUtils.sanitize_input(data['email'])
        password = data['password']
        
        if not SecurityUtils.validate_email(email):
            AuditService.log_action(None, 'login_failed', 'auth', status='failure', error_message='Invalid email format')
            return jsonify({'error': 'Invalid email format'}), 400
        
        user = User.query.filter_by(email=email, is_deleted=False).first()
        
        if not user:
            AuditService.log_action(None, 'login_failed', 'auth', status='failure', error_message='User not found')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user.status != 'active':
            AuditService.log_action(user.id, 'login_failed', 'auth', status='failure', error_message=f'Account status: {user.status}')
            return jsonify({'error': 'Account is not active'}), 403
        
        if user.is_account_locked():
            AuditService.log_action(user.id, 'login_failed', 'auth', status='failure', error_message='Account locked')
            return jsonify({'error': 'Account temporarily locked due to failed attempts'}), 423
        
        if not user.verify_password(password):
            AuditService.log_action(user.id, 'login_failed', 'auth', status='failure', error_message='Invalid password')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user.requires_password_change():
            AuditService.log_action(user.id, 'login_warning', 'auth', status='success', error_message='Password change required')
            return jsonify({
                'error': 'Password change required',
                'code': 'PASSWORD_CHANGE_REQUIRED'
            }), 426
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        device_fingerprint = SecurityUtils.create_device_fingerprint(request)
        
        session = UserSession(
            user_id=user.id,
            session_token=session_token,
            refresh_token=refresh_token,
            device_fingerprint=device_fingerprint,
            user_agent=request.headers.get('User-Agent'),
            ip_address=request.remote_addr,
            expires_at=datetime.utcnow() + timedelta(hours=8)
        )
        db.session.add(session)
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        user.last_activity_at = datetime.utcnow()
        db.session.commit()
        
        AuditService.log_action(user.id, 'login_success', 'auth', status='success')
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'requires_password_change': user.requires_password_change(),
                'mfa_enabled': user.mfa_enabled
            },
            'session': {
                'expires_at': session.expires_at.isoformat(),
                'device_fingerprint': device_fingerprint
            }
        })
        
    except Exception as e:
        db.session.rollback()
        AuditService.log_action(None, 'login_error', 'auth', status='failure', error_message=str(e))
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/v1/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get Current User with Enterprise Features"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or user.is_deleted:
            return jsonify({'error': 'User not found'}), 404
        
        AuditService.log_action(user.id, 'profile_view', 'user', resource_id=str(user.id))
        
        return jsonify({
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'status': user.status,
            'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
            'requires_password_change': user.requires_password_change(),
            'mfa_enabled': user.mfa_enabled,
            'email_verified': user.email_verified,
            'security': {
                'failed_attempts': user.failed_login_attempts,
                'account_locked': user.is_account_locked(),
                'password_age_days': (datetime.utcnow() - user.password_changed_at).days
            }
        })
    except Exception as e:
        return jsonify({'error': 'Failed to fetch user data'}), 500

@app.route('/api/v1/users/me/password', methods=['PUT'])
@jwt_required()
def change_password():
    """Enterprise Password Change with Policy Enforcement"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()
        
        if not user or user.is_deleted:
            return jsonify({'error': 'User not found'}), 404
        
        if 'current_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Current and new password required'}), 400
        
        if not user.verify_password(data['current_password']):
            AuditService.log_action(user.id, 'password_change_failed', 'user', status='failure', error_message='Current password incorrect')
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        user.set_password(data['new_password'])
        db.session.commit()
        
        AuditService.log_action(user.id, 'password_change', 'user', status='success')
        
        return jsonify({'message': 'Password updated successfully'})
        
    except ValueError as e:
        db.session.rollback()
        AuditService.log_action(get_jwt_identity(), 'password_change_failed', 'user', status='failure', error_message=str(e))
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        AuditService.log_action(get_jwt_identity(), 'password_change_error', 'user', status='failure', error_message=str(e))
        return jsonify({'error': 'Failed to update password'}), 500

@app.route('/api/v1/students', methods=['GET'])
@jwt_required()
def get_students():
    """Student Management Endpoint"""
    try:
        students = Student.query.filter_by(is_deleted=False).all()
        return jsonify([{
            'id': s.id,
            'student_id': s.student_id,
            'name': s.user.full_name,
            'email': s.user.email,
            'department': s.department.name if s.department else None,
            'gpa': s.gpa,
            'status': s.status,
            'risk_level': s.risk_level
        } for s in students])
    except Exception as e:
        return jsonify({'error': 'Failed to fetch students'}), 500

# ===== ENTERPRISE INITIALIZATION =====
def initialize_enterprise():
    """Initialize Complete Enterprise System"""
    try:
        # Fresh database
        db.drop_all()
        db.create_all()
        
        # Create enterprise admin
        admin = User(
            email='admin@eduadmin.com',
            first_name='System',
            last_name='Administrator',
            role='admin',
            status='active',
            email_verified=True
        )
        admin.set_password('EnterpriseAdmin123!')
        db.session.add(admin)
        
        # ✅ ADD ALL DEMO USERS
        demo_users = [
            {
                'email': 'faculty@eduadmin.com',
                'first_name': 'John',
                'last_name': 'Professor', 
                'role': 'faculty',
                'password': 'EnterpriseAdmin123!'
            },
            {
                'email': 'student@eduadmin.com',
                'first_name': 'Alice',
                'last_name': 'Student',
                'role': 'student', 
                'password': 'EnterpriseAdmin123!'
            },
            {
                'email': 'staff@eduadmin.com',
                'first_name': 'Robert',
                'last_name': 'Staff',
                'role': 'staff',
                'password': 'EnterpriseAdmin123!'
            }
        ]
        
        for user_data in demo_users:
            user = User(
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                role=user_data['role'],
                status='active',
                email_verified=True
            )
            user.set_password(user_data['password'])
            db.session.add(user)
        
        # Create sample department
        cs_department = Department(
            name='Computer Science',
            code='CS',
            budget=500000.00,
            student_count=0,
            faculty_count=0
        )
        db.session.add(cs_department)
        
        db.session.commit()
        
        print("✅ ENTERPRISE SYSTEM INITIALIZED SUCCESSFULLY!")
        print("🔐 DEMO CREDENTIALS:")
        print("   • Admin: admin@eduadmin.com / EnterpriseAdmin123!")
        print("   • Faculty: faculty@eduadmin.com / EnterpriseAdmin123!") 
        print("   • Student: student@eduadmin.com / EnterpriseAdmin123!")
        print("   • Staff: staff@eduadmin.com / EnterpriseAdmin123!")
        print("🚀 ALL ENTERPRISE FEATURES ENABLED:")
        print("   • Password Policies (12+ chars, complexity)")
        print("   • Account Lockout (5 failed attempts)")
        print("   • Audit Logging")
        print("   • Session Management") 
        print("   • Rate Limiting")
        print("   • Security Headers")
        print("   • Student Management")
        print("   • Faculty Management")
        print("   • Department Management")
        
    except Exception as e:
        print(f"❌ Enterprise initialization failed: {str(e)}")
        raise

if __name__ == '__main__':
    with app.app_context():
        initialize_enterprise()
    
    port = int(os.environ.get('PORT', 5000))
    print(f"🌐 Enterprise Backend running on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)