import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text, Index, CheckConstraint, ForeignKey, UniqueConstraint, inspect
from sqlalchemy.orm import validates, relationship
from sqlalchemy.exc import IntegrityError, OperationalError
import json
import re
from html import escape
import logging
from logging.handlers import RotatingFileHandler
import ssl
from typing import Dict, Any, List, Optional
import uuid

# ===== PRODUCTION APP INITIALIZATION =====
app = Flask(__name__)

class ProductionConfig:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(64))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_urlsafe(64))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///production.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'pool_timeout': 30
    }
    
    # Rate Limiting
    RATE_LIMIT_STORAGE_URI = os.environ.get('REDIS_URL', 'memory://')
    RATE_LIMIT_STRATEGY = 'fixed-window'
    RATE_LIMIT_DEFAULT = "1000 per hour"
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,https://yourdomain.com').split(',')
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'production.log')
    MAX_LOG_SIZE = 100 * 1024 * 1024  # 100MB
    BACKUP_COUNT = 10

app.config.from_object(ProductionConfig)

# ===== PRODUCTION MIDDLEWARE =====
CORS(app, 
     origins=app.config['CORS_ORIGINS'], 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-Device-Fingerprint"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"])

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATE_LIMIT_STORAGE_URI'],
    strategy=app.config['RATE_LIMIT_STRATEGY'],
    default_limits=[app.config['RATE_LIMIT_DEFAULT']],
    headers_enabled=True
)

@app.after_request
def set_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ===== PRODUCTION LOGGING SETUP =====
def setup_logging():
    """Production logging configuration"""
    # Remove all handlers associated with the root logger
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        app.config['LOG_FILE'],
        maxBytes=app.config['MAX_LOG_SIZE'],
        backupCount=app.config['BACKUP_COUNT']
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
    
    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
    
    # Suppress default handler
    app.logger.propagate = False

# ===== ENTERPRISE DATABASE MODELS =====
class BaseModel(db.Model):
    """Production Base Model with Audit Trail"""
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_by_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=True)
    updated_by_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=True)

class User(BaseModel):
    """Production User Model with Enterprise Security"""
    __tablename__ = 'users'
    
    # Core Information
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    
    # Role & Status
    role = db.Column(db.String(20), nullable=False, default='user', index=True)
    status = db.Column(db.String(20), nullable=False, default='active', index=True)
    
    # Security Features
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)
    last_login_at = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity_at = db.Column(db.DateTime)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(32))
    mfa_backup_codes = db.Column(db.Text)  # JSON array
    
    # Compliance
    password_history = db.Column(db.Text)  # JSON array of last 5 hashes
    terms_accepted_at = db.Column(db.DateTime)
    privacy_accepted_at = db.Column(db.DateTime)
    
    # Relationships
    sessions = db.relationship('UserSession', back_populates='user', foreign_keys='UserSession.user_id', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', back_populates='user', foreign_keys='AuditLog.user_id')
    
    __table_args__ = (
        Index('ix_users_email_status', 'email', 'status'),
        Index('ix_users_role_status', 'role', 'status'),
        CheckConstraint("role IN ('super_admin', 'admin', 'manager', 'user')", name='valid_role'),
        CheckConstraint("status IN ('active', 'inactive', 'suspended', 'pending_verification')", name='valid_status'),
    )
    
    @validates('email')
    def validate_email(self, key, email):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    @validates('phone')
    def validate_phone(self, key, phone):
        if phone and not re.match(r'^\+?[1-9]\d{1,14}$', phone):
            raise ValueError("Invalid phone format")
        return phone
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def set_password(self, password: str):
        """Enterprise password policy enforcement"""
        errors = self.validate_password_policy(password)
        if errors:
            raise ValueError(f"Password policy violation: {', '.join(errors)}")
        
        # Password history check
        if self.password_history:
            history = json.loads(self.password_history)
            for old_hash in history:
                if check_password_hash(old_hash, password):
                    raise ValueError("Password cannot be the same as previous passwords")
        
        new_hash = generate_password_hash(password)
        
        # Update password history (keep last 5)
        history = json.loads(self.password_history) if self.password_history else []
        history.append(new_hash)
        self.password_history = json.dumps(history[-5:])
        
        self.password_hash = new_hash
        self.password_changed_at = datetime.utcnow()
        self.failed_login_attempts = 0
    
    def verify_password(self, password: str) -> bool:
        """Password verification with account lockout"""
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
        if len(password) < 12: 
            errors.append("Must be at least 12 characters")
        if not re.search(r'[A-Z]', password): 
            errors.append("Must contain uppercase letter")
        if not re.search(r'[a-z]', password): 
            errors.append("Must contain lowercase letter")
        if not re.search(r'\d', password): 
            errors.append("Must contain number")
        if not re.search(r'[@$!%*?&]', password): 
            errors.append("Must contain special character (@$!%*?&)")
        
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
    
    def generate_mfa_backup_codes(self) -> List[str]:
        """Generate MFA backup codes"""
        codes = [secrets.token_urlsafe(8) for _ in range(10)]
        hashed_codes = [generate_password_hash(code) for code in codes]
        self.mfa_backup_codes = json.dumps(hashed_codes)
        return codes

class UserSession(BaseModel):
    """Production Session Management"""
    __tablename__ = 'user_sessions'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    refresh_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    device_fingerprint = db.Column(db.String(255), nullable=False, index=True)
    user_agent = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False)
    
    user = db.relationship('User', back_populates='sessions', foreign_keys=[user_id])
    
    __table_args__ = (
        Index('ix_user_sessions_user_device', 'user_id', 'device_fingerprint'),
        Index('ix_user_sessions_expires_revoked', 'expires_at', 'is_revoked'),
    )
    
    @property
    def is_active(self):
        return not self.is_revoked and datetime.utcnow() < self.expires_at

class AuditLog(BaseModel):
    """Production Audit Trail"""
    __tablename__ = 'audit_logs'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(100), nullable=False, index=True)
    resource_id = db.Column(db.String(100), index=True)
    old_values = db.Column(db.Text)
    new_values = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, index=True)
    error_message = db.Column(db.Text)
    
    user = db.relationship('User', back_populates='audit_logs', foreign_keys=[user_id])
    
    __table_args__ = (
        Index('ix_audit_logs_timestamp_action', 'created_at', 'action'),
        Index('ix_audit_logs_resource', 'resource_type', 'resource_id'),
        Index('ix_audit_logs_user_action', 'user_id', 'action'),
    )

class APIKey(BaseModel):
    """API Key Management"""
    __tablename__ = 'api_keys'
    
    user_id = db.Column(db.Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(255), unique=True, nullable=False, index=True)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    permissions = db.Column(db.Text)  # JSON array of permissions
    
    user = db.relationship('User', foreign_keys=[user_id])
    
    __table_args__ = (
        Index('ix_api_keys_user_expires', 'user_id', 'expires_at'),
    )
    
    @property
    def is_active(self):
        return not self.is_deleted and (not self.expires_at or datetime.utcnow() < self.expires_at)

# ===== PRODUCTION SERVICES =====
class SecurityService:
    """Production Security Service"""
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        if text is None: 
            return ""
        text = re.sub(r'[<>"\']', '', text)
        return escape(text.strip())
    
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def create_device_fingerprint(request) -> str:
        import hashlib
        components = [
            request.headers.get('User-Agent', ''),
            request.headers.get('Accept-Language', ''),
            request.headers.get('Accept-Encoding', ''),
            request.remote_addr
        ]
        fingerprint = '|'.join(components)
        return hashlib.sha256(fingerprint.encode()).hexdigest()
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Comprehensive password strength validation"""
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 1
        else:
            feedback.append("Should be at least 12 characters")
        
        if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Should include both uppercase and lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Should include numbers")
        
        if re.search(r'[@$!%*?&]', password):
            score += 1
        else:
            feedback.append("Should include special characters (@$!%*?&)")
        
        # Entropy check
        if len(set(password)) >= 8:
            score += 1
        else:
            feedback.append("Should have more unique characters")
        
        strength_levels = {
            0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"
        }
        
        return {
            "score": score,
            "strength": strength_levels.get(score, "Very Weak"),
            "feedback": feedback,
            "is_acceptable": score >= 3
        }

class AuditService:
    """Production Audit Service"""
    
    @staticmethod
    def log_security_event(user_id: int, action: str, resource_type: str, 
                          resource_id: str = None, status: str = 'success',
                          error_message: str = None):
        """Log security-related events"""
        AuditService.log_action(
            user_id, action, resource_type, resource_id,
            status=status, error_message=error_message
        )
    
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
                old_values=json.dumps(old_values, default=str) if old_values else None,
                new_values=json.dumps(new_values, default=str) if new_values else None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                status=status,
                error_message=error_message
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Audit logging failed: {str(e)}")

class RateLimitService:
    """Production Rate Limiting Service"""
    
    @staticmethod
    def get_client_identifier():
        """Get client identifier for rate limiting"""
        # Use multiple factors for better identification
        factors = [
            request.remote_addr,
            request.headers.get('User-Agent', ''),
            request.headers.get('X-Device-Fingerprint', '')
        ]
        identifier = '|'.join(factors)
        return identifier

# ===== PRODUCTION ROUTES =====
@app.route('/api/v1/health', methods=['GET'])
@limiter.limit("100 per minute")
def health_check():
    """Comprehensive Health Check"""
    try:
        # Database health
        db.session.execute(text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'environment': os.environ.get('FLASK_ENV', 'production'),
            'services': {
                'database': 'healthy',
                'api': 'healthy'
            },
            'uptime': str(datetime.utcnow() - app.start_time) if hasattr(app, 'start_time') else 'unknown'
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/api/v1/auth/login', methods=['POST'])
@limiter.limit("5 per minute", key_func=RateLimitService.get_client_identifier)
def login():
    """Production Authentication"""
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400
        
        email = SecurityService.sanitize_input(data['email'])
        password = data['password']
        
        if not SecurityService.validate_email(email):
            AuditService.log_security_event(None, 'login_failed', 'auth', status='failure', error_message='Invalid email format')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = User.query.filter_by(email=email, is_deleted=False).first()
        
        if not user:
            # Log failed attempt even if user doesn't exist (security measure)
            AuditService.log_security_event(None, 'login_failed', 'auth', status='failure', error_message='User not found')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user.status != 'active':
            AuditService.log_security_event(user.id, 'login_failed', 'auth', status='failure', error_message=f'Account status: {user.status}')
            return jsonify({'error': 'Account is not active'}), 403
        
        if user.is_account_locked():
            AuditService.log_security_event(user.id, 'login_failed', 'auth', status='failure', error_message='Account locked')
            return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
        
        if not user.verify_password(password):
            AuditService.log_security_event(user.id, 'login_failed', 'auth', status='failure', error_message='Invalid password')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if password change is required
        password_change_required = user.requires_password_change()
        
        # Create session
        device_fingerprint = SecurityService.create_device_fingerprint(request)
        
        # Revoke existing sessions for this device
        UserSession.query.filter_by(
            user_id=user.id, 
            device_fingerprint=device_fingerprint,
            is_revoked=False
        ).update({'is_revoked': True})
        
        session = UserSession(
            user_id=user.id,
            session_token=SecurityService.generate_secure_token(),
            refresh_token=SecurityService.generate_secure_token(),
            device_fingerprint=device_fingerprint,
            user_agent=request.headers.get('User-Agent'),
            ip_address=request.remote_addr,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(session)
        
        # Create JWT tokens
        additional_claims = {
            'session_id': session.id,
            'device_fingerprint': device_fingerprint,
            'role': user.role
        }
        
        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims,
            expires_delta=timedelta(minutes=30)
        )
        
        user.last_activity_at = datetime.utcnow()
        db.session.commit()
        
        AuditService.log_security_event(user.id, 'login_success', 'auth')
        
        response_data = {
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': 1800,  # 30 minutes
            'user': {
                'id': user.uuid,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'mfa_enabled': user.mfa_enabled,
                'email_verified': user.email_verified
            }
        }
        
        if password_change_required:
            response_data['warning'] = 'Password change required'
            response_data['code'] = 'PASSWORD_CHANGE_REQUIRED'
        
        return jsonify(response_data)
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Login error: {str(e)}")
        AuditService.log_security_event(None, 'login_error', 'auth', status='failure', error_message=str(e))
        return jsonify({'error': 'Authentication failed'}), 500

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """Production Logout"""
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()
        session_id = claims.get('session_id')
        
        if session_id:
            session = UserSession.query.get(session_id)
            if session and session.user_id == current_user_id:
                session.is_revoked = True
                session.updated_at = datetime.utcnow()
        
        AuditService.log_security_event(current_user_id, 'logout', 'auth')
        db.session.commit()
        
        return jsonify({'message': 'Successfully logged out'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/v1/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get Current User Profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or user.is_deleted:
            return jsonify({'error': 'User not found'}), 404
        
        AuditService.log_action(user.id, 'profile_view', 'user', resource_id=user.uuid)
        
        return jsonify({
            'id': user.uuid,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': user.phone,
            'role': user.role,
            'status': user.status,
            'mfa_enabled': user.mfa_enabled,
            'email_verified': user.email_verified,
            'phone_verified': user.phone_verified,
            'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
            'created_at': user.created_at.isoformat(),
            'security': {
                'requires_password_change': user.requires_password_change(),
                'failed_attempts': user.failed_login_attempts,
                'account_locked': user.is_account_locked(),
                'password_age_days': (datetime.utcnow() - user.password_changed_at).days
            }
        })
    except Exception as e:
        app.logger.error(f"Get user error: {str(e)}")
        return jsonify({'error': 'Failed to fetch user data'}), 500

@app.route('/api/v1/users/me/password', methods=['PUT'])
@jwt_required()
@limiter.limit("5 per hour", key_func=RateLimitService.get_client_identifier)
def change_password():
    """Production Password Change"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        data = request.get_json()
        
        if not user or user.is_deleted:
            return jsonify({'error': 'User not found'}), 404
        
        if not data or 'current_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Current and new password required'}), 400
        
        # Verify current password
        if not user.verify_password(data['current_password']):
            AuditService.log_security_event(user.id, 'password_change_failed', 'user', status='failure', error_message='Current password incorrect')
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password strength
        strength_check = SecurityService.validate_password_strength(data['new_password'])
        if not strength_check['is_acceptable']:
            return jsonify({
                'error': 'Password does not meet security requirements',
                'details': strength_check
            }), 400
        
        # Set new password
        user.set_password(data['new_password'])
        db.session.commit()
        
        AuditService.log_security_event(user.id, 'password_change', 'user', status='success')
        
        return jsonify({'message': 'Password updated successfully'})
        
    except ValueError as e:
        db.session.rollback()
        AuditService.log_security_event(get_jwt_identity(), 'password_change_failed', 'user', status='failure', error_message=str(e))
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Password change error: {str(e)}")
        AuditService.log_security_event(get_jwt_identity(), 'password_change_error', 'user', status='failure', error_message=str(e))
        return jsonify({'error': 'Failed to update password'}), 500

@app.route('/api/v1/users/me/sessions', methods=['GET'])
@jwt_required()
def get_user_sessions():
    """Get User Sessions"""
    try:
        current_user_id = get_jwt_identity()
        sessions = UserSession.query.filter_by(
            user_id=current_user_id, 
            is_deleted=False
        ).order_by(UserSession.created_at.desc()).limit(10).all()
        
        return jsonify([{
            'id': session.id,
            'device_fingerprint': session.device_fingerprint,
            'user_agent': session.user_agent,
            'ip_address': session.ip_address,
            'created_at': session.created_at.isoformat(),
            'last_accessed': session.last_accessed.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'is_active': session.is_active
        } for session in sessions])
        
    except Exception as e:
        app.logger.error(f"Get sessions error: {str(e)}")
        return jsonify({'error': 'Failed to fetch sessions'}), 500

@app.route('/api/v1/users/me/sessions/<int:session_id>', methods=['DELETE'])
@jwt_required()
def revoke_session(session_id):
    """Revoke User Session"""
    try:
        current_user_id = get_jwt_identity()
        session = UserSession.query.filter_by(
            id=session_id, 
            user_id=current_user_id,
            is_deleted=False
        ).first()
        
        if not session:
            return jsonify({'error': 'Session not found'}), 404
        
        session.is_revoked = True
        session.updated_at = datetime.utcnow()
        db.session.commit()
        
        AuditService.log_security_event(current_user_id, 'session_revoked', 'user_session', resource_id=str(session_id))
        
        return jsonify({'message': 'Session revoked successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Revoke session error: {str(e)}")
        return jsonify({'error': 'Failed to revoke session'}), 500

# ===== ERROR HANDLERS =====
@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit exceeded handler"""
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description)
    }), 429

@app.errorhandler(500)
def internal_error_handler(e):
    """Internal server error handler"""
    app.logger.error(f"Internal server error: {str(e)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500

@app.errorhandler(404)
def not_found_handler(e):
    """Not found error handler"""
    return jsonify({
        'error': 'Resource not found',
        'message': 'The requested resource was not found'
    }), 404

@app.errorhandler(401)
def unauthorized_handler(e):
    """Unauthorized error handler"""
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401

@app.errorhandler(403)
def forbidden_handler(e):
    """Forbidden error handler"""
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions'
    }), 403

# ===== DATABASE MANAGEMENT =====
def safe_create_tables():
    """Safely create tables that don't exist"""
    inspector = inspect(db.engine)
    existing_tables = inspector.get_table_names()
    
    tables_to_create = []
    
    for table_name in ['users', 'user_sessions', 'audit_logs', 'api_keys']:
        if table_name not in existing_tables:
            tables_to_create.append(table_name)
    
    if tables_to_create:
        app.logger.info(f"Creating tables: {tables_to_create}")
        db.create_all()
    else:
        app.logger.info("All tables already exist")

# ===== PRODUCTION INITIALIZATION =====
def initialize_production():
    """Initialize Production System"""
    try:
        # Setup logging
        setup_logging()
        
        app.logger.info("Starting production initialization...")
        
        # Safely create tables
        safe_create_tables()
        
        # Create initial admin user if doesn't exist
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@yourcompany.com')
        admin_user = User.query.filter_by(email=admin_email).first()
        
        if not admin_user:
            app.logger.info("Creating initial admin user...")
            admin_user = User(
                email=admin_email,
                first_name='System',
                last_name='Administrator',
                role='super_admin',
                status='active',
                email_verified=True,
                terms_accepted_at=datetime.utcnow(),
                privacy_accepted_at=datetime.utcnow()
            )
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!@#Secure')
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("Initial admin user created successfully")
        else:
            app.logger.info("Admin user already exists")
        
        app.start_time = datetime.utcnow()
        app.logger.info("Production system initialized successfully")
        
    except Exception as e:
        app.logger.critical(f"Production initialization failed: {str(e)}")
        # Don't raise the exception, just log it and continue
        app.logger.info("Application starting with existing database...")

if __name__ == '__main__':
    with app.app_context():
        initialize_production()
    
    # Production WSGI server (when running directly, use for development only)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.logger.info(f"Starting production server on port {port}")
    print(f"🚀 Production Enterprise API running on http://localhost:{port}")
    print("📚 API Documentation:")
    print("   • GET  /api/v1/health - Health check")
    print("   • POST /api/v1/auth/login - User login")
    print("   • POST /api/v1/auth/logout - User logout") 
    print("   • GET  /api/v1/users/me - Get current user")
    print("   • PUT  /api/v1/users/me/password - Change password")
    print("   • GET  /api/v1/users/me/sessions - Get user sessions")
    
    app.run(host='0.0.0.0', port=port, debug=debug)