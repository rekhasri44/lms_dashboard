// components/ProtectedRoute.jsx
import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Navigate, useLocation } from 'react-router-dom';

const ProtectedRoute = ({ 
  children, 
  requiredRole, 
  requiredPermission,
  fallbackPath = '/unauthorized' 
}) => {
  const { isAuthenticated, user, hasPermission, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner-large"></div>
        <p>Verifying authentication...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    // Redirect to login with return url
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role requirement
  if (requiredRole && user?.role !== requiredRole) {
    return <Navigate to={fallbackPath} replace />;
  }

  // Check permission requirement
  if (requiredPermission && !hasPermission(requiredPermission)) {
    return <Navigate to={fallbackPath} replace />;
  }

  return children;
};

export default ProtectedRoute;