import React, { lazy, Suspense } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./components/LoginPage";
import "./App.css";

// Lazy load components for better performance
const EduDashboard = lazy(() => import("./EduDashboard"));
const StudentManagement = lazy(() => import("./StudentManagement"));
const FacultyManagement = lazy(() => import("./FacultyManagement"));
const CourseManagement = lazy(() => import("./CourseManagement"));
const Analytics = lazy(() => import("./Analytics"));
const Reports = lazy(() => import("./Reports"));
const SettingsPage = lazy(() => import("./Settings"));

// Loading component with better UX
const LoadingSpinner = () => (
  <div className="loading-container">
    <div className="loading-spinner"></div>
    <p>Loading application...</p>
  </div>
);

// Route-specific loading components
const RouteLoading = ({ message = "Loading..." }) => (
  <div className="loading-container">
    <div className="loading-spinner"></div>
    <p>{message}</p>
  </div>
);

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <RouteLoading message="Checking authentication..." />;
  }
  
  return isAuthenticated ? children : <Navigate to="/" replace />;
};

// Error Boundary component (simple version)
const ErrorFallback = ({ error, resetErrorBoundary }) => (
  <div className="error-container">
    <h2>Something went wrong</h2>
    <p>{error.message}</p>
    <button onClick={resetErrorBoundary}>Try again</button>
  </div>
);

function App() {
  return (
    <AuthProvider>
      <Router>
        <Suspense fallback={<LoadingSpinner />}>
          <Routes>
            <Route path="/" element={<LoginPage />} />
            
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Dashboard..." />}>
                    <EduDashboard />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/student" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Student Management..." />}>
                    <StudentManagement />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/faculty" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Faculty Management..." />}>
                    <FacultyManagement />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/course" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Course Management..." />}>
                    <CourseManagement />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/analytics" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Analytics..." />}>
                    <Analytics />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/reports" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Reports..." />}>
                    <Reports />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            <Route 
              path="/settings" 
              element={
                <ProtectedRoute>
                  <Suspense fallback={<RouteLoading message="Loading Settings..." />}>
                    <SettingsPage />
                  </Suspense>
                </ProtectedRoute>
              } 
            />
            
            {/* Catch all route with replace to prevent history buildup */}
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </Suspense>
      </Router>
    </AuthProvider>
  );
}

export default App;