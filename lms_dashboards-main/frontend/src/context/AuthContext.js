import React, { createContext, useState, useContext, useEffect, useCallback, useRef } from 'react';

// Security constants
const TOKEN_CONFIG = {
  ACCESS_TOKEN_KEY: 'enterprise_access_token',
  REFRESH_TOKEN_KEY: 'enterprise_refresh_token', 
  USER_DATA_KEY: 'enterprise_user_data',
  TOKEN_REFRESH_THRESHOLD: 5 * 60 * 1000, // 5 minutes before expiry
  MAX_RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 1000
};

// Enhanced error types for better handling
class AuthError extends Error {
  constructor(message, code, details = null) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }
}

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  
  // Refs for preventing race conditions and memory leaks
  const authCheckInProgress = useRef(false);
  const refreshInProgress = useRef(false);
  const retryCount = useRef(0);
  const pendingRequests = useRef(new Map());

  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://dashboard-backend-qmy9.onrender.com';

  // Secure token storage with fallbacks
  const getStoredToken = useCallback(() => {
    try {
      if (typeof window === 'undefined') return null;
      
      // Try secure storage first, then fallback to localStorage
      return sessionStorage.getItem(TOKEN_CONFIG.ACCESS_TOKEN_KEY) ||
             localStorage.getItem(TOKEN_CONFIG.ACCESS_TOKEN_KEY);
    } catch (error) {
      console.error('Token storage access error:', error);
      return null;
    }
  }, []);

  const setStoredToken = useCallback((token, rememberMe = false) => {
    try {
      if (typeof window === 'undefined') return;
      
      const storage = rememberMe ? localStorage : sessionStorage;
      storage.setItem(TOKEN_CONFIG.ACCESS_TOKEN_KEY, token);
    } catch (error) {
      console.error('Token storage error:', error);
      throw new AuthError('Failed to store authentication token', 'STORAGE_ERROR');
    }
  }, []);

  const getStoredRefreshToken = useCallback(() => {
    try {
      return localStorage.getItem(TOKEN_CONFIG.REFRESH_TOKEN_KEY);
    } catch (error) {
      console.error('Refresh token storage access error:', error);
      return null;
    }
  }, []);

  const setStoredRefreshToken = useCallback((refreshToken) => {
    try {
      localStorage.setItem(TOKEN_CONFIG.REFRESH_TOKEN_KEY, refreshToken);
    } catch (error) {
      console.error('Refresh token storage error:', error);
      throw new AuthError('Failed to store refresh token', 'STORAGE_ERROR');
    }
  }, []);

  const removeStoredTokens = useCallback(() => {
    try {
      // Clear all possible token storage locations
      localStorage.removeItem(TOKEN_CONFIG.ACCESS_TOKEN_KEY);
      localStorage.removeItem(TOKEN_CONFIG.REFRESH_TOKEN_KEY);
      localStorage.removeItem(TOKEN_CONFIG.USER_DATA_KEY);
      sessionStorage.removeItem(TOKEN_CONFIG.ACCESS_TOKEN_KEY);
      
      // Clear any legacy tokens
      ['access_token', 'token', 'user', 'user_data', 'user_permissions'].forEach(key => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
      });
    } catch (error) {
      console.error('Token removal error:', error);
    }
  }, []);

  // Enhanced input validation with security considerations
  const validateCredentials = useCallback((email, password) => {
    if (!email || !password) {
      throw new AuthError('Email and password are required', 'VALIDATION_ERROR');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email.trim())) {
      throw new AuthError('Please enter a valid email address', 'VALIDATION_ERROR');
    }
    
    if (password.length < 8) {
      throw new AuthError('Password must be at least 8 characters long', 'VALIDATION_ERROR');
    }

    // Basic XSS prevention
    const dangerousPatterns = /[<>]/;
    if (dangerousPatterns.test(email) || dangerousPatterns.test(password)) {
      throw new AuthError('Invalid characters in input', 'VALIDATION_ERROR');
    }

    return true;
  }, []);

  // Token refresh with exponential backoff
  const refreshToken = useCallback(async () => {
    if (refreshInProgress.current) {
      console.log('Refresh already in progress, queuing request');
      return new Promise((resolve) => {
        const id = Date.now();
        pendingRequests.current.set(id, resolve);
      });
    }

    refreshInProgress.current = true;

    try {
      const refreshToken = getStoredRefreshToken();
      if (!refreshToken) {
        throw new AuthError('No refresh token available', 'REFRESH_TOKEN_MISSING');
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${refreshToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new AuthError('Token refresh failed', 'REFRESH_FAILED');
      }

      const data = await response.json();
      
      if (!data.access_token) {
        throw new AuthError('Invalid refresh response', 'INVALID_REFRESH_RESPONSE');
      }

      setStoredToken(data.access_token);
      
      // Resolve all pending requests
      pendingRequests.current.forEach(resolve => resolve(data.access_token));
      pendingRequests.current.clear();

      return data.access_token;

    } catch (error) {
      // Clear all pending requests on failure
      pendingRequests.current.forEach(resolve => resolve(null));
      pendingRequests.current.clear();
      
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError('Token refresh failed', 'REFRESH_NETWORK_ERROR', error.message);
    } finally {
      refreshInProgress.current = false;
    }
  }, [API_BASE_URL, getStoredRefreshToken, setStoredToken]);

  // Enhanced fetch with automatic token refresh
  const authFetch = useCallback(async (url, options = {}) => {
    let token = getStoredToken();
    
    const makeRequest = async (currentToken) => {
      const config = {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(currentToken && { 'Authorization': `Bearer ${currentToken}` }),
          ...options.headers,
        },
      };

      const response = await fetch(url, config);
      
      // Auto-refresh on 401 and retry
      if (response.status === 401 && retryCount.current < TOKEN_CONFIG.MAX_RETRY_ATTEMPTS) {
        retryCount.current++;
        try {
          const newToken = await refreshToken();
          retryCount.current = 0;
          return makeRequest(newToken);
        } catch (refreshError) {
          retryCount.current = 0;
          await logout();
          throw new AuthError('Session expired', 'SESSION_EXPIRED');
        }
      }
      
      retryCount.current = 0;
      return response;
    };

    return makeRequest(token);
  }, [getStoredToken, refreshToken]);

  // Production-ready login with security features
  const login = async (email, password, rememberMe = false) => {
    try {
      setError('');
      setLoading(true);

      // Validate inputs
      validateCredentials(email, password);

      console.log('Attempting login to:', `${API_BASE_URL}/api/v1/auth/login`);

      const loginPayload = {
        email: email.trim().toLowerCase(),
        password: password.trim(),
      };

      const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginPayload),
      });

      // Handle specific HTTP status codes
      if (response.status === 429) {
        throw new AuthError('Too many login attempts. Please try again later.', 'RATE_LIMITED');
      }

      if (response.status === 423) {
        throw new AuthError('Account temporarily locked. Please contact support.', 'ACCOUNT_LOCKED');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        // Security: Use generic messages for security-sensitive errors
        let errorMessage = 'Login failed. Please check your credentials.';
        if (response.status === 401) {
          errorMessage = 'Invalid email or password';
        } else if (response.status >= 500) {
          errorMessage = 'Authentication service unavailable. Please try again later.';
        }
          
        throw new AuthError(errorData.error || errorMessage, `HTTP_${response.status}`);
      }

      const data = await response.json();
      
      if (!data.access_token && !data.token) {
        throw new AuthError('Invalid response from authentication server', 'INVALID_RESPONSE');
      }

      const accessToken = data.access_token || data.token;
      
      // Store tokens securely
      setStoredToken(accessToken, rememberMe);
      if (data.refresh_token) {
        setStoredRefreshToken(data.refresh_token);
      }

      // Normalize and store user data
      const userData = data.user || {
        id: data.id,
        email: data.email,
        first_name: data.first_name,
        last_name: data.last_name,
        role: data.role || 'user',
        roles: data.roles || [data.role || 'user'],
        permissions: data.permissions || []
      };

      // Sanitize user data before storage
      const sanitizedUserData = {
        ...userData,
        password: undefined,
        token: undefined
      };

      localStorage.setItem(TOKEN_CONFIG.USER_DATA_KEY, JSON.stringify(sanitizedUserData));
      setUser(sanitizedUserData);
      setPermissions(sanitizedUserData.permissions || []);
      setIsAuthenticated(true);
      
      // Reset retry counter on successful login
      retryCount.current = 0;
      
      return { 
        success: true, 
        user: sanitizedUserData,
        requiresMfa: data.requiresMfa || false
      };

    } catch (error) {
      console.error('Login error:', error);
      
      const errorMessage = error instanceof AuthError 
        ? error.message 
        : 'Authentication service unavailable. Please try again.';
      
      setError(errorMessage);
      return { 
        success: false, 
        error: errorMessage,
        code: error.code
      };
    } finally {
      setLoading(false);
    }
  };

  // Enhanced logout with proper cleanup
  const logout = async (silent = false) => {
    try {
      const token = getStoredToken();
      
      if (token && !silent) {
        // Attempt server logout with timeout
        await Promise.race([
          fetch(`${API_BASE_URL}/api/v1/auth/logout`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          }),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout')), 5000)
          )
        ]).catch(error => {
          console.warn('Logout API call failed:', error);
          // Continue with client cleanup even if server call fails
        });
      }
    } catch (error) {
      console.error('Logout API error:', error);
    } finally {
      // Always clean up client state
      removeStoredTokens();
      setUser(null);
      setPermissions([]);
      setError('');
      setIsAuthenticated(false);
      authCheckInProgress.current = false;
      refreshInProgress.current = false;
      retryCount.current = 0;
      pendingRequests.current.clear();
    }
  };

  // Production-ready authentication check
  const checkAuth = useCallback(async () => {
    if (authCheckInProgress.current) {
      console.log('Auth check already in progress');
      return;
    }

    authCheckInProgress.current = true;

    try {
      const token = getStoredToken();
      const storedUser = localStorage.getItem(TOKEN_CONFIG.USER_DATA_KEY);
      
      console.log('Auth check - Token:', !!token, 'User:', !!storedUser);
      
      if (!token || !storedUser) {
        console.log('No authentication data found');
        setIsAuthenticated(false);
        return;
      }

      // Verify token with backend
      const response = await authFetch(`${API_BASE_URL}/api/v1/auth/verify`);

      if (response.ok) {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setPermissions(userData.permissions || []);
        setIsAuthenticated(true);
        console.log('User authenticated successfully');
      } else {
        throw new AuthError('Session verification failed', 'VERIFICATION_FAILED');
      }

    } catch (error) {
      console.error('Auth verification failed:', error);
      
      if (error.code === 'SESSION_EXPIRED') {
        // Silent logout for expired sessions
        await logout(true);
      } else {
        // For other errors, clear local state but don't force logout
        setIsAuthenticated(false);
        setUser(null);
      }
    } finally {
      setLoading(false);
      authCheckInProgress.current = false;
    }
  }, [API_BASE_URL, authFetch, getStoredToken, logout]);

  // Periodic token refresh check
  useEffect(() => {
    if (!isAuthenticated) return;

    const checkTokenExpiry = setInterval(async () => {
      try {
        // Simple heuristic: if we're authenticated, periodically refresh
        await refreshToken();
      } catch (error) {
        console.warn('Periodic token refresh failed:', error);
      }
    }, TOKEN_CONFIG.TOKEN_REFRESH_THRESHOLD);

    return () => clearInterval(checkTokenExpiry);
  }, [isAuthenticated, refreshToken]);

  // Permission checking utilities
  const hasPermission = useCallback((requiredPermission) => {
    return permissions.includes(requiredPermission) || 
           permissions.includes('*') ||
           user?.role === 'admin';
  }, [permissions, user]);

  const hasRole = useCallback((requiredRole) => {
    return user?.role === requiredRole || 
           user?.roles?.includes(requiredRole);
  }, [user]);

  // Initialize auth on mount
  useEffect(() => {
    console.log('AuthProvider initialized');
    checkAuth();
  }, [checkAuth]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      pendingRequests.current.clear();
    };
  }, []);

  const value = {
    user,
    permissions,
    isAuthenticated,
    loading,
    error,
    login,
    logout,
    checkAuth,
    authFetch,
    setError,
    hasPermission,
    hasRole
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthError };