import React, { lazy, Suspense, useEffect, useCallback, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation, useNavigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./components/LoginPage";
import { 
  BarChart3, 
  Users, 
  GraduationCap, 
  BookOpen, 
  FileText, 
  Settings as SettingsIcon,
  LogOut,
  Menu,
  X,
  Bell
} from 'lucide-react';
import "./App.css";

// Enterprise Configuration
const ENTERPRISE_CONFIG = {
  ROUTES: {
    LOGIN: '/login',
    DASHBOARD: '/dashboard',
    STUDENT: '/students',
    FACULTY: '/faculty',
    COURSE: '/courses',
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

// Lazy loaded components
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

// Public Route Component (redirect if already authenticated)
const PublicRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <RouteLoading message="Checking authentication..." moduleName="Auth Check" />;
  }
  
  return !isAuthenticated ? children : <Navigate to={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} replace />;
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

// Navigation Sidebar Component
const Sidebar = ({ isOpen, onClose }) => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const navigationItems = [
    { path: ENTERPRISE_CONFIG.ROUTES.DASHBOARD, icon: BarChart3, label: 'Overview', roles: ['admin', 'faculty', 'staff'] },
    { path: ENTERPRISE_CONFIG.ROUTES.STUDENT, icon: Users, label: 'Students', roles: ['admin', 'faculty'] },
    { path: ENTERPRISE_CONFIG.ROUTES.FACULTY, icon: GraduationCap, label: 'Faculty', roles: ['admin'] },
    { path: ENTERPRISE_CONFIG.ROUTES.COURSE, icon: BookOpen, label: 'Courses', roles: ['admin', 'faculty'] },
    { path: ENTERPRISE_CONFIG.ROUTES.ANALYTICS, icon: BarChart3, label: 'Analytics', roles: ['admin', 'faculty'] },
    { path: ENTERPRISE_CONFIG.ROUTES.REPORTS, icon: FileText, label: 'Reports', roles: ['admin', 'faculty', 'staff'] },
    { path: ENTERPRISE_CONFIG.ROUTES.SETTINGS, icon: SettingsIcon, label: 'Settings', roles: ['admin'] },
  ];

  const handleLogout = async () => {
    try {
      await logout();
      navigate(ENTERPRISE_CONFIG.ROUTES.LOGIN);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const isActivePath = (path) => {
    if (path === ENTERPRISE_CONFIG.ROUTES.DASHBOARD) {
      return location.pathname === ENTERPRISE_CONFIG.ROUTES.DASHBOARD;
    }
    return location.pathname.startsWith(path);
  };

  // Filter navigation items based on user roles
  const filteredNavigationItems = navigationItems.filter(item => {
    if (!ENTERPRISE_CONFIG.FEATURE_FLAGS.ENABLE_ROLE_BASED_ACCESS || !user?.roles) {
      return true;
    }
    return item.roles.some(role => user.roles.includes(role));
  });

  return (
    <>
      {/* Mobile Overlay */}
      {isOpen && (
        <div 
          className="sidebar-overlay" 
          onClick={onClose}
          aria-hidden="true"
        />
      )}
      
      {/* Sidebar */}
      <aside className={`sidebar ${isOpen ? 'sidebar-open' : ''}`}>
        <div className="sidebar-header">
          <div className="logo">
            <GraduationCap className="logo-icon" />
            <span className="logo-text">EduAdmin</span>
          </div>
          <button 
            className="sidebar-close" 
            onClick={onClose}
            aria-label="Close sidebar"
          >
            <X size={20} />
          </button>
        </div>

        {/* User Info */}
        <div className="user-info">
          <div className="user-avatar">
            <GraduationCap size={24} />
          </div>
          <div className="user-details">
            <div className="user-name">
              {user?.first_name && user?.last_name 
                ? `${user.first_name} ${user.last_name}`
                : user?.email || 'User'
              }
            </div>
            <div className="user-role">
              {user?.roles ? user.roles.map(role => role.charAt(0).toUpperCase() + role.slice(1)).join(', ') : 'Administrator'}
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Navigation</div>
            <ul className="nav-links">
              {filteredNavigationItems.map((item) => {
                const Icon = item.icon;
                const isActive = isActivePath(item.path);
                
                return (
                  <li key={item.path}>
                    <button
                      className={`nav-link ${isActive ? 'active' : ''}`}
                      onClick={() => {
                        navigate(item.path);
                        onClose();
                      }}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      <Icon className="nav-icon" size={20} />
                      <span>{item.label}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        </nav>

        {/* Footer Actions */}
        <div className="sidebar-footer">
          <button 
            className="logout-button"
            onClick={handleLogout}
            aria-label="Logout"
          >
            <LogOut size={20} />
            <span>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
};

// Main Layout Component
const MainLayout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { user } = useAuth();
  const location = useLocation();

  const getPageTitle = () => {
    const path = location.pathname;
    if (path === ENTERPRISE_CONFIG.ROUTES.DASHBOARD) return 'Educational Dashboard';
    if (path === ENTERPRISE_CONFIG.ROUTES.STUDENT) return 'Student Management';
    if (path === ENTERPRISE_CONFIG.ROUTES.FACULTY) return 'Faculty Management';
    if (path === ENTERPRISE_CONFIG.ROUTES.COURSE) return 'Course Management';
    if (path === ENTERPRISE_CONFIG.ROUTES.ANALYTICS) return 'Analytics & Insights';
    if (path === ENTERPRISE_CONFIG.ROUTES.REPORTS) return 'Reports & Analytics';
    if (path === ENTERPRISE_CONFIG.ROUTES.SETTINGS) return 'System Settings';
    return 'EduAdmin';
  };

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        onClose={() => setSidebarOpen(false)} 
      />

      {/* Main Content */}
      <main className="main-content">
        {/* Top Header */}
        <header className="top-header">
          <div className="header-left">
            <button 
              className="menu-toggle"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
            >
              <Menu size={24} />
            </button>
            <h1 className="page-title">{getPageTitle()}</h1>
          </div>

          <div className="header-right">
            {/* Notifications */}
            <button className="header-button" aria-label="Notifications">
              <Bell size={20} />
              <span className="notification-badge">3</span>
            </button>

            {/* User Menu */}
            <div className="user-menu">
              <div className="user-avatar-small">
                <GraduationCap size={20} />
              </div>
              <div className="user-info-small">
                <span className="user-name-small">
                  {user?.first_name && user?.last_name 
                    ? `${user.first_name} ${user.last_name}`
                    : user?.email || 'User'
                  }
                </span>
                <span className="user-role-small">
                  {user?.roles ? user.roles.map(role => role.charAt(0).toUpperCase() + role.slice(1)).join(', ') : 'Admin'}
                </span>
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className="page-content">
          {children}
        </div>
      </main>
    </div>
  );
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

// Router Content Component
const RouterContent = () => {
  useRouteTracking();
  
  return (
    <Routes>
      {/* Public Route */}
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.LOGIN} 
        element={
          <PublicRoute>
            <LoginPage />
          </PublicRoute>
        } 
      />
      
      {/* Protected Routes with Layout */}
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty', 'staff']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Dashboard..." moduleName="Dashboard" />}>
                <EduDashboard />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.STUDENT} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Student Management..." moduleName="Student Management" />}>
                <StudentManagement />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.FACULTY} 
        element={
          <ProtectedRoute requiredRoles={['admin']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Faculty Management..." moduleName="Faculty Management" />}>
                <FacultyManagement />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.COURSE} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Course Management..." moduleName="Course Management" />}>
                <CourseManagement />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.ANALYTICS} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Analytics..." moduleName="Analytics" />}>
                <Analytics />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.REPORTS} 
        element={
          <ProtectedRoute requiredRoles={['admin', 'faculty', 'staff']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Reports..." moduleName="Reports" />}>
                <Reports />
              </Suspense>
            </MainLayout>
          </ProtectedRoute>
        } 
      />
      
      <Route 
        path={ENTERPRISE_CONFIG.ROUTES.SETTINGS} 
        element={
          <ProtectedRoute requiredRoles={['admin']}>
            <MainLayout>
              <Suspense fallback={<RouteLoading message="Loading Settings..." moduleName="Settings" />}>
                <SettingsPage />
              </Suspense>
            </MainLayout>
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
      
      {/* Default redirects */}
      <Route path="/" element={<Navigate to={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} replace />} />
      <Route path="*" element={<Navigate to={ENTERPRISE_CONFIG.ROUTES.DASHBOARD} replace />} />
    </Routes>
  );
};

// Main App Component
function App() {
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    // Simulate app initialization
    const timer = setTimeout(() => {
      setIsInitialized(true);
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

  if (!isInitialized) {
    return (
      <div className="app-initialization">
        <div className="initialization-content">
          <GraduationCap size={48} className="app-logo" />
          <h1>EduAdmin</h1>
          <p>Enterprise Educational Dashboard</p>
          <div className="loading-spinner"></div>
        </div>
      </div>
    );
  }

  return (
    <EnterpriseErrorBoundary>
      <AuthProvider>
        <Router>
          <AppInitializer>
            <div className="App">
              <RouterContent />
            </div>
          </AppInitializer>
        </Router>
      </AuthProvider>
    </EnterpriseErrorBoundary>
  );
}

export default App;