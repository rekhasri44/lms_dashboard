import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { 
  GraduationCap, 
  Eye, 
  EyeOff, 
  Shield, 
  AlertCircle, 
  CheckCircle2,
  University,
  BookOpen,
  Users
} from 'lucide-react';
import { validationService } from '../services/validationService';
import { securityService } from '../services/securityService';
import './LoginPage.css';

const LoginPage = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [lockUntil, setLockUntil] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');
  const [currentTime, setCurrentTime] = useState(new Date());
  
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  // Update current time every minute
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  // Check authentication status and redirect
  useEffect(() => {
    if (isAuthenticated) {
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);

  // Check for success messages or session expiry
  useEffect(() => {
    const message = searchParams.get('message');
    const session = searchParams.get('session');
    
    if (message === 'password_reset') {
      setSuccessMessage('Password reset successfully. Please log in with your new password.');
    }
    
    if (session === 'expired') {
      setError('Your session has expired. Please log in again.');
    }
  }, [searchParams]);

  // Check rate limiting on component mount
  useEffect(() => {
    const lockTime = securityService.checkRateLimit();
    if (lockTime) {
      setLockUntil(lockTime);
    }
  }, []);

  // Update lock countdown
  useEffect(() => {
    if (!lockUntil) return;

    const interval = setInterval(() => {
      const now = Date.now();
      if (now >= lockUntil) {
        setLockUntil(null);
        securityService.clearLock();
        clearInterval(interval);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [lockUntil]);

  const handleInputChange = useCallback((field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Clear errors when user starts typing
    if (error) setError('');
    if (successMessage) setSuccessMessage('');
  }, [error, successMessage]);

  const validateForm = useCallback(() => {
    const emailValidation = validationService.validateEmail(formData.email);
    if (!emailValidation.isValid) {
      return { isValid: false, error: emailValidation.error };
    }

    const passwordValidation = validationService.validatePassword(formData.password);
    if (!passwordValidation.isValid) {
      return { isValid: false, error: passwordValidation.error };
    }

    return { isValid: true };
  }, [formData.email, formData.password]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Check if account is locked
    if (lockUntil) {
      const timeLeft = Math.ceil((lockUntil - Date.now()) / 1000);
      setError(`Too many failed attempts. Please try again in ${timeLeft} seconds.`);
      return;
    }

    // Validate form
    const validation = validateForm();
    if (!validation.isValid) {
      setError(validation.error);
      return;
    }

    setLoading(true);
    setError('');

    try {
      const result = await login(formData.email, formData.password);
      
      if (result.success) {
        // Reset attempts on successful login
        securityService.resetAttempts();
        setAttempts(0);
        
        // Show success message
        setSuccessMessage(`Welcome back, ${result.user.name || result.user.first_name || 'User'}!`);
        
        // Navigate after a brief delay to show success message
        setTimeout(() => {
          const from = location.state?.from?.pathname || getRoleBasedRedirect(result.user.role);
          navigate(from, { replace: true });
        }, 1000);
        
      } else {
        // Handle failed attempt
        const newAttempts = attempts + 1;
        setAttempts(newAttempts);
        
        const lockTime = securityService.recordFailedAttempt(newAttempts);
        if (lockTime) {
          setLockUntil(lockTime);
        }
        
        setError(
          result.code === 'INVALID_CREDENTIALS' 
            ? 'Invalid email or password. Please try again.'
            : result.error || 'Login failed. Please try again.'
        );
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('A system error occurred. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const getRoleBasedRedirect = (role) => {
    const routes = {
      admin: '/dashboard',
      faculty: '/dashboard',
      staff: '/dashboard',
      student: '/dashboard'
    };
    return routes[role] || '/dashboard';
  };

  const getLockMessage = () => {
    if (!lockUntil) return null;
    
    const timeLeft = Math.ceil((lockUntil - Date.now()) / 1000);
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    
    return `Account temporarily locked. Please try again in ${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: true 
    });
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const lockMessage = getLockMessage();

  return (
    <div className="login-container">
      {/* Left Panel - Branding and Information */}
      <div className="login-left-panel">
        <div className="login-branding">
          <div className="logo">
            <University size={42} className="logo-icon" />
            <div className="logo-text">
              <h1>EduAdmin</h1>
              <span>Enterprise Dashboard</span>
            </div>
          </div>
          
          <div className="system-info">
            <div className="time-display">
              <div className="current-time">{formatTime(currentTime)}</div>
              <div className="current-date">{formatDate(currentTime)}</div>
            </div>
          </div>
        </div>

        <div className="login-features">
          <div className="feature-card">
            <div className="feature-icon">
              <Users size={24} />
            </div>
            <div className="feature-content">
              <h3>Student Management</h3>
              <p>Manage 12,847 students with comprehensive tracking and analytics</p>
            </div>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <BookOpen size={24} />
            </div>
            <div className="feature-content">
              <h3>Course Management</h3>
              <p>Oversee 486 courses with real-time enrollment and performance data</p>
            </div>
          </div>

          <div className="feature-card">
            <div className="feature-icon">
              <Shield size={24} />
            </div>
            <div className="feature-content">
              <h3>Advanced Analytics</h3>
              <p>Predictive insights and risk assessment for informed decision-making</p>
            </div>
          </div>
        </div>

        <div className="login-stats">
          <div className="stat-item">
            <div className="stat-value">12,847</div>
            <div className="stat-label">Total Students</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">324</div>
            <div className="stat-label">Faculty Members</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">486</div>
            <div className="stat-label">Courses</div>
          </div>
        </div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="login-right-panel">
        <div className="login-card">
          <div className="login-header">
            <h2>Welcome Back</h2>
            <p>Sign in to your institutional account</p>
          </div>

          {/* Success Message */}
          {successMessage && (
            <div className="success-message" role="alert">
              <CheckCircle2 size={16} />
              {successMessage}
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="login-form" noValidate>
            <div className="form-group">
              <label htmlFor="email">Institutional Email</label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                value={formData.email}
                onChange={(e) => handleInputChange('email', e.target.value)}
                placeholder="your.email@university.edu"
                required
                disabled={loading || lockUntil}
                autoFocus
                aria-describedby="email-error"
              />
            </div>

            <div className="form-group">
              <div className="password-label-container">
                <label htmlFor="password">Password</label>
                <button
                  type="button"
                  className="forgot-password-link"
                  onClick={() => navigate('/forgot-password')}
                  disabled={loading || lockUntil}
                >
                  Forgot password?
                </button>
              </div>
              <div className="password-input">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={formData.password}
                  onChange={(e) => handleInputChange('password', e.target.value)}
                  placeholder="Enter your password"
                  required
                  disabled={loading || lockUntil}
                  aria-describedby="password-error"
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading || lockUntil}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="error-message" role="alert" id="login-error">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            {/* Lock Message */}
            {lockMessage && (
              <div className="lock-message" role="alert">
                <Shield size={16} />
                <span>{lockMessage}</span>
              </div>
            )}

            {/* Attempts Warning */}
            {attempts > 0 && !lockUntil && (
              <div className="warning-message">
                <AlertCircle size={14} />
                <span>Failed attempts: {attempts}. After 5 attempts, your account will be temporarily locked.</span>
              </div>
            )}

            <button 
              type="submit" 
              className={`login-button ${loading ? 'loading' : ''}`}
              disabled={loading || lockUntil || !formData.email || !formData.password}
              aria-busy={loading}
              aria-describedby={error ? 'login-error' : undefined}
            >
              {loading ? (
                <>
                  <div className="spinner" aria-label="Signing in..."></div>
                  Authenticating...
                </>
              ) : (
                'Sign In to Dashboard'
              )}
            </button>
          </form>

          <div className="login-footer">
            <div className="security-notice">
              <Shield size={14} />
              <span>Protected by Enterprise Security System</span>
            </div>
            <div className="support-info">
              <span>Need assistance? </span>
              <a href="mailto:it-support@university.edu" className="support-link">
                Contact IT Support
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;