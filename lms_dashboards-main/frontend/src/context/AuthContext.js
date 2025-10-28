import React, { createContext, useState, useContext, useEffect } from 'react';

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Production API base URL from environment
  const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'https://dashboard-backend-qmy9.onrender.com';

  // Enhanced token management
  const getStoredToken = () => {
    try {
      return localStorage.getItem('access_token') || localStorage.getItem('enterprise_access_token');
    } catch (error) {
      console.error('Token storage error:', error);
      return null;
    }
  };

  const setStoredToken = (token) => {
    try {
      localStorage.setItem('access_token', token);
      localStorage.setItem('enterprise_access_token', token);
    } catch (error) {
      console.error('Token storage error:', error);
    }
  };

  const removeStoredTokens = () => {
    try {
      localStorage.removeItem('access_token');
      localStorage.removeItem('enterprise_access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('enterprise_refresh_token');
      localStorage.removeItem('user');
    } catch (error) {
      console.error('Token removal error:', error);
    }
  };

  // Production-ready login function
  const login = async (email, password) => {
    try {
      setError('');
      setLoading(true);

      console.log('Attempting login to:', `${API_BASE_URL}/api/v1/auth/login`);

      // Try v1 endpoint first, then fallback to legacy
      let response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      // If v1 fails, try legacy endpoint
      if (!response.ok) {
        console.log('v1 login failed, trying legacy endpoint...');
        response = await fetch(`${API_BASE_URL}/api/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email, password }),
        });
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Login failed. Please check your credentials.');
      }

      const data = await response.json();
      console.log('Login response:', data);
      
      if (data.access_token || data.token) {
        const token = data.access_token || data.token;
        setStoredToken(token);
        
        // Handle different user response formats
        const userData = data.user || {
          id: data.id,
          email: data.email,
          first_name: data.first_name,
          last_name: data.last_name,
          role: data.role || 'admin',
          roles: [data.role || 'admin']
        };
        
        localStorage.setItem('user', JSON.stringify(userData));
        setUser(userData);
        setIsAuthenticated(true);
        
        return { success: true, user: userData };
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      console.error('Login error:', error);
      const errorMessage = error.message || 'Login failed. Please try again.';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  // Enhanced logout
  const logout = async () => {
    try {
      const token = getStoredToken();
      if (token) {
        // Try to call logout endpoint (but don't block if it fails)
        await fetch(`${API_BASE_URL}/api/v1/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }).catch(() => {
          console.log('Logout API call failed, continuing with client cleanup');
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      removeStoredTokens();
      setUser(null);
      setIsAuthenticated(false);
      setError('');
    }
  };

  // Check authentication status
  const checkAuth = async () => {
    const token = getStoredToken();
    const storedUser = localStorage.getItem('user');
    
    if (token && storedUser) {
      try {
        // Verify token is still valid by calling protected endpoint
        const response = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        if (response.ok) {
          const userData = await response.json();
          setUser(userData);
          setIsAuthenticated(true);
        } else {
          throw new Error('Token invalid');
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        removeStoredTokens();
        setIsAuthenticated(false);
        setUser(null);
      }
    } else {
      setIsAuthenticated(false);
      setUser(null);
    }
    setLoading(false);
  };

  // Check auth status on app start
  useEffect(() => {
    checkAuth();
  }, []);

  const value = {
    user,
    isAuthenticated,
    loading,
    error,
    login,
    logout,
    checkAuth,
    setError,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};