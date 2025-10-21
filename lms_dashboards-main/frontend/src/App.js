import React, { lazy, Suspense, useEffect, useCallback } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./components/LoginPage";
import "./App.css";

// Enterprise Configuration
const ENTERPRISE_CONFIG = {
  ROUTES: {
    LOGIN: '/',
    DASHBOARD: '/dashboard',
    STUDENT: '/student',
    FACULTY: '/faculty',
    COURSE: '/course',
    ANALYTICS: '/analytics',
    REPORTS: '/reports',
    SETTINGS: '/settings',
    UNAUTHORIZED: '/unauthorized'
  },
  FEATURE_FLAGS: {
    ENABLE_ROLE_BASED_ACCESS: process.env.REACT_APP_ENABLE_RBAC === 'true',
    ENABLE_PERFORMANCE_MONITORING: process.env.REACT_APP_ENABLE_MONITORING === 'true',
    ENABLE_AUTO_LOGOUT: process.env.REACT_APP_ENABLE_AUTO_LOGOUT === 'true'
  },
  PERFORMANCE: {
    PRELOAD_STRATEGY: 'viewport', // 'viewport' | 'aggressive' | 'conservative'
    LAZY_LOAD_TIMEOUT: 3000,
    ROUTE_TRANSITION_DELAY: 150
  }
};

// Simple lazy loading - FIXED VERSION
const EduDashboard = lazy(() => import("./EduDashboard"));
const StudentManagement = lazy(() => import("./StudentManagement"));
const FacultyManagement = lazy(() => import("./FacultyManagement"));
const CourseManagement = lazy(() => import("./CourseManagement"));
const Analytics = lazy(() => import("./Analytics"));
const Reports = lazy(() => import("./Reports"));
const SettingsPage = lazy(() => import("./Settings"));

// Enhanced loading components with accessibility
const LoadingSpinner = ({ message = "Loading application...", size = "medium" }) => (
  <div 
    className="loading-container" 
    role="status" 
    aria-live="polite"
    aria-label={message}
  >
    <div className={`loading-spinner ${size}`} aria-hidden="true"></div>
    <p>{message}</p>
    {ENTERPRISE_CONFIG.PERFORMANCE.LAZY_LOAD_TIMEOUT && (
      <div className="loading-progress" aria-hidden="true">
        <div className="loading-bar"></div>
      </div>
    )}
  </div>
);

// Route-specific loading components
const RouteLoading = ({ message = "Loading...", moduleName = "" }) => (
  <div className="route-loading-container">
    <LoadingSpinner message={message} size="small" />
    {moduleName && (
      <div className="module-info">
        <small>Loading: {moduleName}</small>
      </div>
    )}
  </div>
);

// Enhanced Protected Route with Role-Based Access Control
const ProtectedRoute = ({ 
  children, 
  requiredRoles = [], 
  fallbackPath = ENTERPRISE_CONFIG.ROUTES.UNAUTHORIZED 
}) => {
  const { isAuthenticated, loading, user } = useAuth();
  const location = useLocation();

  if (loading) {
    return <RouteLoading message="Checking authentication..." moduleName="Auth Check" />;
  }

  if (!isAuthenticated) {
    // Redirect to login with return url
    return (
      <Navigate 
        to={ENTERPRISE_CONFIG.ROUTES.LOGIN} 
        replace 
        state={{ from: location }}
      />
    );
  }

  // Role-based access control
  if (ENTERPRISE_CONFIG.FEATURE_FLAGS.ENABLE_ROLE_BASED_ACCESS && 
      requiredRoles.length > 0 && 
      user?.roles) {
    
    const hasRequiredRole = requiredRoles.some(role => 
      user.roles.includes(role)
    );

    if (!hasRequiredRole) {
      console.warn(`Unauthorized access attempt by user ${user.id} to ${location.pathname}`);
      
      // Log unauthorized access attempts
      if (window.monitoringService) {
        window.monitoringService.track('unauthorized_access_attempt', {
          userId: user.id,
          path: location.pathname,
          requiredRoles,
          userRoles: user.roles,
          timestamp: new Date().toISOString()
        });
      }
      
      return <Navigate to={fallbackPath} replace />;
    }
  }

  return children;
};

// Performance Monitoring Hook
const usePerformanceMonitoring = () => {
  useEffect(() => {
    if (!ENTERPRISE_CONFIG.FEATURE_FLAGS.ENABLE_PERFORMANCE_MONITORING) return;

    const observer = new PerformanceObserver((list) => {
      list.getEntries().forEach((entry) => {
        if (entry.entryType === 'navigation') {
          // Log initial load performance
          console.log('App Performance Metrics:', {
            loadTime: entry.loadEventEnd - entry.fetchStart,
            domContentLoaded: entry.domContentLoadedEventEnd - entry.fetchStart,
            firstPaint: entry.domContentLoadedEventEnd - entry.fetchStart
          });

          if (window.analyticsService) {
            window.analyticsService.track('app_performance', {
              loadTime: entry.loadEventEnd - entry.fetchStart,
              domContentLoaded: entry.domContentLoadedEventEnd - entry.fetchStart,
              userAgent: navigator.userAgent,
              timestamp: new Date().toISOString()
            });
          }
        }
      });
    });

    observer.observe({ entryTypes: ['navigation', 'paint'] });

    return () => observer.disconnect();
  }, []);
};

// Route Change Tracking
const useRouteTracking = () => {
  const location = useLocation();

  useEffect(() => {
    if (ENTERPRISE_CONFIG.FEATURE_FLAGS.ENABLE_PERFORMANCE_MONITORING) {
      // Track route changes for analytics
      if (window.analyticsService) {
        window.analyticsService.track('route_change', {
          path: location.pathname,
          timestamp: new Date().toISOString()
        });
      }

      // Measure route transition performance
      const startTime = performance.now();
      return () => {
        const endTime = performance.now();
        const transitionTime = endTime - startTime;
        
        console.log(`Route transition: ${location.pathname} - ${transitionTime.toFixed(2)}ms`);
        
        if (window.analyticsService && transitionTime > 1000) {
          window.analyticsService.track('slow_route_transition', {
            path: location.pathname,
            transitionTime,
            threshold: 1000,
            timestamp: new Date().toISOString()
          });
        }
      };
    }
  }, [location]);
};

// Enhanced Error Boundary with Monitoring
class EnterpriseErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null,
      errorInfo: null,
      errorId: null
    };
  }

  static getDerivedStateFromError(error) {
    // Generate unique error ID for tracking
    const errorId = `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return { 
      hasError: true, 
      error,
      errorId
    };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    
    console.error("Enterprise Error Boundary Caught:", error, errorInfo);
    
    // Enhanced error reporting for production
    if (window.monitoringService) {
      window.monitoringService.captureException(error, {
        errorId: this.state.errorId,
        errorInfo,
        componentStack: errorInfo.componentStack,
        userAgent: navigator.userAgent,
        url: window.location.href,
        timestamp: new Date().toISOString(),
        context: {
          route: window.location.pathname,
          appVersion: process.env.REACT_APP_VERSION || '1.0.0'
        }
      });
    }

    // Fallback to basic error logging if monitoring service not available
    if (process.env.NODE_ENV === 'production' && !window.monitoringService) {
      fetch('/api/log-error', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          errorId: this.state.errorId,
          message: error.message,
          stack: error.stack,
          componentStack: errorInfo.componentStack,
          url: window.location.href,
          timestamp: new Date().toISOString()
        })
      }).catch(console.error);
    }
  }

  resetErrorBoundary = () => {
    this.setState({ 
      hasError: false, 
      error: null, 
      errorInfo: null,
      errorId: null 
    });
  };

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = ENTERPRISE_CONFIG.ROUTES.DASHBOARD;
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="enterprise-error-container">
          <div className="enterprise-error-content">
            <div className="error-header">
              <div className="error-icon" aria-hidden="true">
                ⚠️
              </div>
              <h1>Application Error</h1>
              {this.state.errorId && (
                <div className="error-id">
                  Error ID: <code>{this.state.errorId}</code>
                </div>
              )}
            </div>
            
            <div className="error-body">
              <p className="error-message">
                We're sorry, but something went wrong. Our team has been notified and is working to fix the issue.
              </p>
              
              {process.env.NODE_ENV === 'development' && (
                <details className="error-details">
                  <summary>Technical Details (Development)</summary>
                  <div className="error-stack">
                    <h4>Error:</h4>
                    <pre>{this.state.error?.toString()}</pre>
                    <h4>Component Stack:</h4>
                    <pre>{this.state.errorInfo?.componentStack}</pre>
                  </div>
                </details>
              )}
            </div>
            
            <div className="error-actions">
              <button 
                onClick={this.resetErrorBoundary}
                className="error-btn primary"
                aria-label="Try to recover from error"
              >
                Try Again
              </button>
              <button 
                onClick={this.handleGoHome}
                className="error-btn secondary"
                aria-label="Go to dashboard"
              >
                Go to Dashboard
              </button>
              <button 
                onClick={this.handleReload}
                className="error-btn secondary"
                aria-label="Reload entire application"
              >
                Reload App
              </button>
            </div>
            
            <div className="error-support">
              <p>
                If the problem persists, please contact support with the Error ID above.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// App Initialization Component
const AppInitializer = ({ children }) => {
  usePerformanceMonitoring();
  
  useEffect(() => {
    // Initialize any global error handlers
    const handleGlobalError = (event) => {
      console.error('Global error caught:', event.error);
      
      if (window.monitoringService) {
        window.monitoringService.captureException(event.error, {
          type: 'global_error',
          timestamp: new Date().toISOString(),
          url: window.location.href
        });
      }
    };

    const handleUnhandledRejection = (event) => {
      console.error('Unhandled promise rejection:', event.reason);
      
      if (window.monitoringService) {
        window.monitoringService.captureException(event.reason, {
          type: 'unhandled_rejection',
          timestamp: new Date().toISOString()
        });
      }
    };

    window.addEventListener('error', handleGlobalError);
    window.addEventListener('unhandledrejection', handleUnhandledRejection);

    return () => {
      window.removeEventListener('error', handleGlobalError);
      window.removeEventListener('unhandledrejection', handleUnhandledRejection);
    };
  }, []);

  return children;
};

// Router Content Component - ENTERPRISE READY WITH FIXED ROUTES
const RouterContent = () => {
  useRouteTracking();
  
  return (
    <Routes>
      {/* Public Route */}
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.LOGIN} 
        element={<LoginPage />} 
      />
      
      {/* Protected Routes - Using explicit routes for reliability */}
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty', 'staff']}>
            <Suspense fallback={<RouteLoading message="Loading Dashboard..." moduleName="Dashboard" />}>
              <EduDashboard />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.STUDENT} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <Suspense fallback={<RouteLoading message="Loading Student Management..." moduleName="Student Management" />}>
              <StudentManagement />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.FACULTY} 
        element={
          <ProtectedRoute requiredRoles={['admin']}>
            <Suspense fallback={<RouteLoading message="Loading Faculty Management..." moduleName="Faculty Management" />}>
              <FacultyManagement />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.COURSE} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <Suspense fallback={<RouteLoading message="Loading Course Management..." moduleName="Course Management" />}>
              <CourseManagement />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.ANALYTICS} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <Suspense fallback={<RouteLoading message="Loading Analytics..." moduleName="Analytics" />}>
              <Analytics />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.REPORTS} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty', 'staff']}>
            <Suspense fallback={<RouteLoading message="Loading Reports..." moduleName="Reports" />}>
              <Reports />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.SETTINGS} 
        element={
          <ProtectedRoute requiredRoles={['admin']}>
            <Suspense fallback={<RouteLoading message="Loading Settings..." moduleName="Settings" />}>
              <SettingsPage />
            </Suspense>
          </ProtectedRoute>
        } 
      />
      
      {/* Fallback Routes */}
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.UNAUTHORIZED} 
        element={
          <div className="unauthorized-container">
            <h1>Access Denied</h1>
            <p>You don't have permission to access this page.</p>
          </div>
        } 
      />
      
      {/* Catch all route */}
      <Route 
        path="*" 
        element={
          <Navigate to={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} replace />
        } 
      />
    </Routes>
  );
};

// Main App Component
function App() {
  return (
    <EnterpriseErrorBoundary>
      <AuthProvider>
        <Router>
          <AppInitializer>
            <Suspense fallback={
              <LoadingSpinner message="Initializing Application..." />
            }>
              <RouterContent />
            </Suspense>
          </AppInitializer>
        </Router>
      </AuthProvider>
    </EnterpriseErrorBoundary>
  );
}

export default App;