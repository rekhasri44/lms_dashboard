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

  // Enterprise token management
  const getStoredToken = () => {
    try {
      return localStorage.getItem('enterprise_access_token');
    } catch (error) {
      console.error('Token storage error:', error);
      return null;
    }
  };

  const setStoredToken = (token) => {
    try {
      localStorage.setItem('enterprise_access_token', token);
    } catch (error) {
      console.error('Token storage error:', error);
    }
  };

  const removeStoredTokens = () => {
    try {
      localStorage.removeItem('enterprise_access_token');
      localStorage.removeItem('enterprise_refresh_token');
    } catch (error) {
      console.error('Token removal error:', error);
    }
  };

  // Enterprise API call with error handling
  const enterpriseApiCall = async (url, options = {}) => {
    const token = getStoredToken();
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(`/api/v1${url}`, config);
      
      if (response.status === 401) {
        // Token expired, try to refresh
        await refreshToken();
        return enterpriseApiCall(url, options);
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API call failed:', error);
      throw error;
    }
  };

  // Enterprise login
  const login = async (email, password) => {
    try {
      setError('');
      setLoading(true);

      const data = await enterpriseApiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      if (data.access_token) {
        setStoredToken(data.access_token);
        setUser(data.user);
        
        // Handle password change requirement
        if (data.user.requires_password_change) {
          setError('PASSWORD_CHANGE_REQUIRED');
        }
        
        return { success: true, user: data.user };
      } else {
        setError(data.error || 'Login failed');
        return { success: false, error: data.error };
      }
    } catch (error) {
      const errorMessage = error.message.includes('Failed to fetch') 
        ? 'Network error. Please check your connection.'
        : error.message || 'Login failed. Please try again.';
      
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  // Enterprise logout
  const logout = async () => {
    try {
      await enterpriseApiCall('/auth/logout', { method: 'POST' });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      removeStoredTokens();
      setUser(null);
      setError('');
    }
  };

  // Token refresh
  const refreshToken = async () => {
    try {
      const refreshToken = localStorage.getItem('enterprise_refresh_token');
      if (!refreshToken) throw new Error('No refresh token');
      
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${refreshToken}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setStoredToken(data.access_token);
        return data.access_token;
      } else {
        throw new Error('Token refresh failed');
      }
    } catch (error) {
      removeStoredTokens();
      setUser(null);
      throw error;
    }
  };

  // Check auth status on app start
  useEffect(() => {
    const checkAuthStatus = async () => {
      const token = getStoredToken();
      if (token) {
        try {
          const userData = await enterpriseApiCall('/users/me');
          setUser(userData);
        } catch (error) {
          removeStoredTokens();
          console.error('Auth check failed:', error);
        }
      }
      setLoading(false);
    };

    checkAuthStatus();
  }, []);

  const value = {
    user,
    loading,
    error,
    login,
    logout,
    setError,
    enterpriseApiCall,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};