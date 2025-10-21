import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import useApi from './hooks/useApi';
import { analyticsAPI, departmentsAPI, studentsAPI } from './services/api';
import { 
  Bell, User, BarChart3, Users, GraduationCap, FileText, Settings,
  TrendingUp, Filter, RefreshCw, Download, AlertTriangle, BookOpen
} from 'lucide-react';


// Enterprise Constants
const ENTERPRISE_CONFIG = {
  API: {
    RETRY_ATTEMPTS: 3,
    TIMEOUT: 30000,
    CACHE_TIMEOUT: 5 * 60 * 1000,
  },
  RISK_THRESHOLDS: {
    HIGH: 30,
    MEDIUM: 15,
    LOW: 0
  },
  EXPORT_TYPES: ['overview', 'detailed', 'summary'],
  MAX_CONCURRENT_API_CALLS: 5
};

// Enhanced Error Boundary for Analytics
class AnalyticsErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorInfo: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    // Enterprise Error Reporting
    console.error('Analytics Error Boundary:', error, errorInfo);
    if (window.monitoringService) {
      window.monitoringService.captureException(error, {
        component: 'Analytics',
        errorInfo,
        userAgent: navigator.userAgent
      });
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <div className="error-content">
            <AlertTriangle size={48} className="error-icon" />
            <h2>Analytics Dashboard Unavailable</h2>
            <p>We encountered an error while loading the analytics dashboard.</p>
            <div className="error-actions">
              <button onClick={this.handleReset} className="btn-primary">
                Try Again
              </button>
              <button onClick={this.handleReload} className="btn-secondary">
                Reload Page
              </button>
            </div>
            {process.env.NODE_ENV === 'development' && (
              <details className="error-details">
                <summary>Technical Details</summary>
                <pre>{this.state.error?.toString()}</pre>
                <pre>{this.state.errorInfo?.componentStack}</pre>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Optimized Memoized Components
const MetricCard = React.memo(({ 
  label, 
  value, 
  change, 
  changeType, 
  icon: Icon,
  loading = false 
}) => {
  if (!Icon) {
    console.warn('MetricCard: Icon prop is required');
    return null;
  }

  if (loading) {
    return (
      <div className="metric-card loading" aria-busy="true">
        <div className="metric-header">
          <span className="metric-label skeleton"></span>
          <div className="metric-icon skeleton"></div>
        </div>
        <div className="metric-value skeleton"></div>
        <div className="metric-change skeleton"></div>
      </div>
    );
  }

  return (
    <div className="metric-card" role="region" aria-label={`${label} metric`}>
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <Icon className="metric-icon" aria-hidden="true" />
      </div>
      <div className="metric-value" aria-live="polite">{value}</div>
      <div className={`metric-change ${changeType}`} aria-label={`Change: ${change}`}>
        {change}
      </div>
    </div>
  );
});

const RiskItem = React.memo(({ dept, index }) => {
  const getRiskLevel = (dropoutRate) => {
    if (dropoutRate > ENTERPRISE_CONFIG.RISK_THRESHOLDS.HIGH) return 'high';
    if (dropoutRate > ENTERPRISE_CONFIG.RISK_THRESHOLDS.MEDIUM) return 'medium';
    return 'low';
  };

  const riskLevel = getRiskLevel(dept.dropoutRate);
  const riskLabels = {
    high: 'High Risk',
    medium: 'Medium Risk', 
    low: 'Low Risk'
  };

  return (
    <div className="risk-item" role="listitem" aria-label={`${dept.name} - ${riskLabels[riskLevel]}`}>
      <div className="risk-info">
        <span className="dept-name">{dept.name}</span>
        <span className="student-count">{dept.studentCount} students</span>
      </div>
      <div className="risk-badge-wrapper">
        <span className={`risk-percent ${riskLevel}`}>
          {dept.dropoutRate}%
        </span>
        <span className={`risk-badge ${riskLevel}`}>
          {riskLabels[riskLevel]}
        </span>
      </div>
    </div>
  );
});

// Main Analytics Component
const Analytics = () => {
  // State Management
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [atRiskStudents, setAtRiskStudents] = useState([]);
  const [departmentStats, setDepartmentStats] = useState([]);
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Refs for cleanup and performance
  const abortControllerRef = useRef(new AbortController());
  const refreshIntervalRef = useRef(null);
  const mountedRef = useRef(true);

  // Consolidated API Hook with Enterprise Features
  const { 
    data: consolidatedData, 
    loading: apiLoading, 
    error: apiError,
    refetch: refetchConsolidated,
    progress 
  } = useApi(
    async (signal) => {
      try {
        const apiCalls = [
          analyticsAPI.getDashboardOverview({ signal }),
          analyticsAPI.getPerformanceAnalytics({ signal }),
          analyticsAPI.getEngagementAnalytics({ signal }),
          analyticsAPI.getForecastingAnalytics({ signal }),
          analyticsAPI.getBenchmarkingAnalytics({ signal }),
          studentsAPI.getAtRiskStudents({ signal }),
          departmentsAPI.getDepartmentStats({ signal })
        ];

        const results = await Promise.allSettled(apiCalls);

        // Handle partial failures gracefully
        const successfulResults = results.filter(result => result.status === 'fulfilled');
        
        if (successfulResults.length === 0) {
          throw new Error('All API calls failed');
        }

        if (successfulResults.length < results.length) {
          console.warn(`Partial data loaded: ${successfulResults.length}/${results.length} APIs succeeded`);
        }

        const [
          overviewResponse,
          performanceResponse,
          engagementResponse,
          forecastingResponse,
          benchmarkingResponse,
          atRiskResponse,
          departmentResponse
        ] = results.map(result => 
          result.status === 'fulfilled' ? result.value : { data: null }
        );

        return {
          overview: overviewResponse?.data,
          performance: performanceResponse?.data,
          engagement: engagementResponse?.data,
          forecasting: forecastingResponse?.data,
          benchmarking: benchmarkingResponse?.data,
          atRisk: atRiskResponse?.data || [],
          departments: departmentResponse?.data || [],
          metadata: {
            timestamp: new Date().toISOString(),
            successfulApis: successfulResults.length,
            totalApis: results.length
          }
        };
      } catch (error) {
        if (error.name === 'AbortError') {
          throw error;
        }
        console.error('API Consolidation Error:', error);
        throw new Error(`Failed to load analytics data: ${error.message}`);
      }
    },
    {
      retry: ENTERPRISE_CONFIG.API.RETRY_ATTEMPTS,
      timeout: ENTERPRISE_CONFIG.API.TIMEOUT,
      cacheKey: 'analytics-dashboard-v2',
      cacheTimeout: ENTERPRISE_CONFIG.API.CACHE_TIMEOUT,
      onProgress: (current, total) => {
        console.log(`API Progress: ${current}/${total}`);
      }
    }
  );

  // Data Synchronization Effect
  useEffect(() => {
    if (consolidatedData) {
      setAnalyticsData(consolidatedData);
      setAtRiskStudents(consolidatedData.atRisk || []);
      setDepartmentStats(consolidatedData.departments || []);
      setLastRefreshed(new Date());
      setLoading(false);
      setError('');
    }
  }, [consolidatedData]);

  // Error Handling Effect
  useEffect(() => {
    if (apiError && mountedRef.current) {
      const errorMessage = apiError.message || 'Failed to load analytics data';
      setError(errorMessage);
      
      // Log to monitoring service
      if (window.monitoringService) {
        window.monitoringService.captureException(apiError, {
          component: 'Analytics',
          action: 'data-fetch',
          timestamp: new Date().toISOString()
        });
      }

      // Only use static data in development
      if (process.env.NODE_ENV === 'development') {
        console.warn('Using fallback data in development mode');
        setAnalyticsData(getStaticAnalyticsData());
        setAtRiskStudents(getStaticAtRiskStudents());
        setDepartmentStats(getStaticDepartmentStats());
        setLoading(false);
      }
    }
  }, [apiError]);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    
    return () => {
      mountedRef.current = false;
      abortControllerRef.current.abort();
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, []);

  // Memoized Static Data with Environment Awareness
  const getStaticAnalyticsData = useCallback(() => ({
    performance: {
      grade_distribution: { A: 2450, B: 3120, C: 1890, D: 870, F: 450 },
      pass_rate: 94.2,
      total_grades_recorded: 8780
    },
    engagement: {
      average_attendance: 87.5,
      attendance_breakdown: { present: 85600, absent: 12400, late: 3200, excused: 1800 },
      participation_trend: 'improving'
    },
    forecasting: {
      enrollment_forecast: { next_semester: 1250, growth_rate: 8.5, confidence_level: 'high' },
      course_demand: {
        computer_science: { predicted: 350, current: 320 },
        mathematics: { predicted: 280, current: 260 },
        engineering: { predicted: 420, current: 380 }
      },
      resource_requirements: {
        additional_faculty: 5,
        new_sections: 12,
        budget_increase: 150000
      }
    },
    benchmarking: {
      institutional_benchmarks: {
        retention_rate: { current: 89.2, national_average: 85.7 },
        graduation_rate: { current: 78.5, national_average: 75.2 },
        student_satisfaction: { current: 4.3, national_average: 4.1 }
      },
      department_comparison: {
        computer_science: { gpa: 3.6, retention: 92.1 },
        mathematics: { gpa: 3.4, retention: 88.7 },
        engineering: { gpa: 3.5, retention: 90.3 }
      },
      improvement_areas: [
        'Increase mathematics department retention',
        'Enhance student support services',
        'Expand research opportunities'
      ]
    },
    overview: {
      total_students: 12847,
      total_faculty: 324,
      total_courses: 486
    },
    metadata: {
      timestamp: new Date().toISOString(),
      source: 'static-fallback',
      environment: process.env.NODE_ENV
    }
  }), []);

  const getStaticAtRiskStudents = useCallback(() => {
    if (process.env.NODE_ENV === 'production') {
      console.warn('Static data used in production - check API connectivity');
    }
    return [
      {
        id: 1,
        name: 'Alex Chen',
        department: 'Computer Science',
        gpa: 2.1,
        risk_level: 'high',
        last_activity: '2024-01-15'
      },
      {
        id: 2,
        name: 'Maria Rodriguez',
        department: 'Mathematics', 
        gpa: 2.5,
        risk_level: 'medium',
        last_activity: '2024-01-14'
      }
    ];
  }, []);

  const getStaticDepartmentStats = useCallback(() => [
    {
      name: 'Computer Science',
      studentCount: 1247,
      atRiskCount: 187,
      dropoutRate: 15,
      avgGPA: 3.6,
      trend: 'improving'
    },
    {
      name: 'Engineering',
      studentCount: 2134,
      atRiskCount: 491,
      dropoutRate: 23,
      avgGPA: 3.4,
      trend: 'stable'
    },
    {
      name: 'Business',
      studentCount: 892,
      atRiskCount: 71,
      dropoutRate: 8,
      avgGPA: 3.5,
      trend: 'improving'
    },
    {
      name: 'Physics',
      studentCount: 674,
      atRiskCount: 236,
      dropoutRate: 35,
      avgGPA: 2.9,
      trend: 'declining'
    }
  ], []);

  // Enhanced Refresh with Performance Optimizations
  const handleRefresh = useCallback(async () => {
    if (!mountedRef.current) return;

    // Cancel previous requests
    abortControllerRef.current.abort();
    abortControllerRef.current = new AbortController();

    setLoading(true);
    setError('');

    try {
      await refetchConsolidated();
      
      // Track refresh success
      if (window.analyticsService) {
        window.analyticsService.track('analytics_refresh_success', {
          timestamp: new Date().toISOString(),
          component: 'Analytics'
        });
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        console.log('Refresh request was cancelled');
        return;
      }

      const errorMsg = 'Failed to refresh analytics data. Please try again.';
      setError(errorMsg);
      console.error('Refresh error:', err);

      // Track refresh failure
      if (window.analyticsService) {
        window.analyticsService.track('analytics_refresh_failed', {
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, [refetchConsolidated]);

  // Secure Export with Validation and Sanitization
  const handleExport = useCallback(async (type = 'overview') => {
    if (!ENTERPRISE_CONFIG.EXPORT_TYPES.includes(type)) {
      setError(`Invalid export type: ${type}`);
      return;
    }

    if (!analyticsData) {
      setError('No data available for export');
      return;
    }

    try {
      setError('');
      
      // Show export in progress
      setLoading(true);

      const response = await analyticsAPI.exportAnalytics(type, {
        signal: abortControllerRef.current.signal
      });

      if (!response.success || !response.data) {
        throw new Error('Export API returned invalid response');
      }

      // Sanitize export data
      const sanitizedData = sanitizeExportData(response.data, type);
      
      // Create and trigger download
      const blob = new Blob([sanitizedData], { 
        type: 'text/csv; charset=utf-8',
        endings: 'native'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = generateExportFilename(type);
      link.setAttribute('type', 'text/csv');
      link.setAttribute('aria-label', `Download ${type} analytics report`);
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      // Cleanup URL object
      setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 100);

      // Track successful export
      if (window.analyticsService) {
        window.analyticsService.track('analytics_export_success', {
          type,
          timestamp: new Date().toISOString()
        });
      }

    } catch (err) {
      if (err.name === 'AbortError') return;

      const errorMsg = `Export failed: ${err.message}`;
      setError(errorMsg);
      console.error('Export error:', err);

      // Track export failure
      if (window.analyticsService) {
        window.analyticsService.track('analytics_export_failed', {
          type,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    } finally {
      setLoading(false);
    }
  }, [analyticsData]);

  // Data Sanitization for Security
  const sanitizeExportData = (data, type) => {
    try {
      const sanitized = JSON.parse(JSON.stringify(data));
      
      // Remove sensitive information based on export type
      switch (type) {
        case 'overview':
          delete sanitized.sensitive?.studentDetails;
          delete sanitized.sensitive?.personalInfo;
          delete sanitized.sensitive?.financialData;
          break;
        case 'summary':
          delete sanitized.detailed?.attendanceRecords;
          delete sanitized.detailed?.assessmentScores;
          break;
        default:
          // For detailed exports, still remove highly sensitive data
          delete sanitized.sensitive?.ssn;
          delete sanitized.sensitive?.contactInfo;
      }
      
      return JSON.stringify(sanitized, null, 2);
    } catch (error) {
      console.error('Data sanitization error:', error);
      return JSON.stringify({ error: 'Data processing failed' });
    }
  };

  const generateExportFilename = (type) => {
    const timestamp = new Date().toISOString().split('T')[0];
    const env = process.env.NODE_ENV === 'production' ? '' : `-${process.env.NODE_ENV}`;
    return `analytics-${type}${env}-${timestamp}.csv`;
  };

  // Memoized Computed Values with Error Boundaries
  const metrics = useMemo(() => {
    if (!analyticsData) {
      return Array(4).fill().map((_, index) => ({
        label: 'Loading...',
        value: '--',
        change: '--',
        changeType: 'neutral',
        icon: TrendingUp,
        loading: true
      }));
    }

    try {
      const { benchmarking, performance, overview } = analyticsData;
      
      const retentionRate = benchmarking?.institutional_benchmarks?.retention_rate?.current || 89.2;
      const nationalAvg = benchmarking?.institutional_benchmarks?.retention_rate?.national_average || 85.7;
      const retentionDiff = retentionRate - nationalAvg;
      
      const satisfactionScore = benchmarking?.institutional_benchmarks?.student_satisfaction?.current || 4.3;
      const previousSatisfaction = 4.1; // This would come from historical data

      return [
        {
          label: 'Student Retention',
          value: `${retentionRate.toFixed(1)}%`,
          change: `↗ +${retentionDiff.toFixed(1)}% vs national avg`,
          changeType: retentionDiff >= 0 ? 'positive' : 'negative',
          icon: Users
        },
        {
          label: 'Course Completion', 
          value: `${performance?.pass_rate?.toFixed(1) || 94.2}%`,
          change: '↗ 1.5% vs last period',
          changeType: 'positive',
          icon: BookOpen
        },
        {
          label: 'Avg Class Size',
          value: Math.round(overview?.total_students / overview?.total_courses) || 28,
          change: '↘ 3.2% vs last period', 
          changeType: 'negative',
          icon: TrendingUp
        },
        {
          label: 'Satisfaction Score',
          value: `${satisfactionScore.toFixed(1)}/5`,
          change: `↗ ${(satisfactionScore - previousSatisfaction).toFixed(1)} vs last period`,
          changeType: 'positive',
          icon: TrendingUp
        }
      ];
    } catch (error) {
      console.error('Metrics calculation error:', error);
      return [];
    }
  }, [analyticsData]);

  // Safe Filtered Counts with Error Handling
  const highRiskCount = useMemo(() => {
    try {
      return atRiskStudents.filter(student => 
        student.risk_level === 'high' && student.gpa < 2.0
      ).length;
    } catch (error) {
      console.error('High risk count calculation error:', error);
      return 0;
    }
  }, [atRiskStudents]);

  const lowGPACount = useMemo(() => {
    try {
      return atRiskStudents.filter(student => 
        student.gpa < 2.5 && student.gpa >= 2.0
      ).length;
    } catch (error) {
      console.error('Low GPA count calculation error:', error);
      return 0;
    }
  }, [atRiskStudents]);

  const criticalRiskCount = useMemo(() => {
    try {
      return atRiskStudents.filter(student => 
        student.risk_level === 'critical' || student.gpa < 1.5
      ).length;
    } catch (error) {
      console.error('Critical risk count calculation error:', error);
      return 0;
    }
  }, [atRiskStudents]);

  // Retry Handler
  const handleRetry = useCallback(() => {
    handleRefresh();
  }, [handleRefresh]);

  // Auto-refresh (optional - can be enabled/disabled)
  useEffect(() => {
    if (process.env.NODE_ENV === 'production') {
      refreshIntervalRef.current = setInterval(() => {
        handleRefresh();
      }, 5 * 60 * 1000); // Refresh every 5 minutes

      return () => {
        if (refreshIntervalRef.current) {
          clearInterval(refreshIntervalRef.current);
        }
      };
    }
  }, [handleRefresh]);

  // Loading State with Accessibility
  if (loading && !analyticsData) {
    return (
      <div className="analytics-container">
        <div className="sidebar" aria-hidden="true">
          <div className="sidebar-header">
            <div className="logo">
              <div className="logo-icon">
                <GraduationCap className="icon-medium" />
              </div>
              <span className="logo-text">EduAdmin</span>
            </div>
          </div>
        </div>
        <div className="main-content">
          <div className="loading-container" role="status" aria-live="polite">
            <div className="loading-spinner" aria-hidden="true"></div>
            <p>Loading analytics dashboard...</p>
            {progress && <p>Loading... {progress}%</p>}
          </div>
        </div>
      </div>
    );
  }

  // Safe data access with fallbacks
  const { performance, engagement, forecasting, benchmarking, overview } = analyticsData || {};

  return (
    <AnalyticsErrorBoundary>
      <div className="analytics-container">
        {/* Sidebar Navigation */}
        <nav className="sidebar" aria-label="Main navigation">
          <div className="sidebar-header">
            <div className="logo">
              <div className="logo-icon">
                <GraduationCap className="icon-medium" />
              </div>
              <span className="logo-text">EduAdmin</span>
            </div>
          </div>
          
          <div className="sidebar-nav">
            <div className="nav-section-title">Navigation</div>
            <div className="nav-links">
              <a href="/dashboard" className="nav-link">
                <BarChart3 className="nav-icon" />
                Overview
              </a>
              <a href="/student" className="nav-link">
                <Users className="nav-icon" />
                Students
              </a>
              <a href="/faculty" className="nav-link">
                <GraduationCap className="nav-icon" />
                Faculty
              </a>
              <a href="/course" className="nav-link">
                <BookOpen className="nav-icon" />
                Courses
              </a>
              <a href="/analytics" className="nav-link active">
                <BarChart3 className="nav-icon" />
                Analytics
              </a>
              <a href="/reports" className="nav-link">
                <FileText className="nav-icon" />
                Reports
              </a>
              <a href="/settings" className="nav-link">
                <Settings className="nav-icon" />
                Settings
              </a>
            </div>
          </div>
        </nav>

        {/* Main Content Area */}
        <main className="main-content" aria-label="Analytics dashboard">
          {/* Header with Actions */}
          <header className="header">
            <div className="header-title-section">
              <h1 className="header-title">Analytics & Insights</h1>
              {lastRefreshed && (
                <span className="last-updated" aria-live="polite">
                  Last updated: {lastRefreshed.toLocaleTimeString()}
                </span>
              )}
            </div>
            <div className="header-actions">
              <button 
                className="refresh-btn" 
                onClick={handleRefresh} 
                disabled={loading}
                aria-label={loading ? "Refreshing data..." : "Refresh analytics data"}
              >
                <RefreshCw className={`icon-small ${loading ? 'spinning' : ''}`} />
                {loading ? 'Refreshing...' : 'Refresh'}
              </button>
              <button 
                className="export-btn" 
                onClick={() => handleExport('overview')}
                disabled={loading || !analyticsData}
                aria-label="Export analytics report"
              >
                <Download className="icon-small" />
                Export
              </button>
              <button className="notification-button" aria-label="Notifications">
                <Bell className="icon-small" />
                <span className="notification-badge" aria-hidden="true"></span>
              </button>
              <div className="profile-avatar" aria-label="User profile">
                <User className="icon-small" />
              </div>
            </div>
          </header>

          {/* Error Display */}
          {error && (
            <div 
              className="error-banner" 
              role="alert" 
              aria-live="assertive"
              aria-atomic="true"
            >
              <AlertTriangle size={16} aria-hidden="true" />
              <span>{error}</span>
              <button 
                onClick={handleRetry} 
                className="retry-btn"
                aria-label="Retry loading analytics data"
              >
                Retry
              </button>
            </div>
          )}

          {/* Analytics Content */}
          <div className="analytics-main">
            {/* Analytics Header */}
            <div className="analytics-header">
              <div>
                <h2 className="analytics-title">Advanced Analytics</h2>
                <p className="analytics-subtitle">
                  Comprehensive insights and predictive analytics
                  {analyticsData?.metadata && (
                    <span className="data-source">
                      • Data from {analyticsData.metadata.successfulApis}/{analyticsData.metadata.totalApis} sources
                    </span>
                  )}
                </p>
              </div>
              <div className="analytics-actions">
                <button className="action-btn" aria-label="Apply filters">
                  <Filter className="icon-small" />
                  Filters
                </button>
                <button 
                  className="action-btn" 
                  onClick={handleRefresh} 
                  disabled={loading}
                  aria-label={loading ? "Refreshing..." : "Refresh data"}
                >
                  <RefreshCw className={`icon-small ${loading ? 'spinning' : ''}`} />
                  Refresh
                </button>
                <button 
                  className="action-btn" 
                  onClick={() => handleExport('detailed')}
                  disabled={loading || !analyticsData}
                  aria-label="Export detailed report"
                >
                  <Download className="icon-small" />
                  Export Report
                </button>
              </div>
            </div>

            {/* Metrics Grid */}
            <section aria-label="Key performance metrics" className="metrics-section">
              <div className="metrics-grid">
                {metrics.map((metric, index) => (
                  <MetricCard
                    key={`metric-${index}`}
                    label={metric.label}
                    value={metric.value}
                    change={metric.change}
                    changeType={metric.changeType}
                    icon={metric.icon}
                    loading={metric.loading}
                  />
                ))}
              </div>
            </section>

            {/* Your existing chart components remain the same */}
            {/* Charts Row 1 */}
            <div className="charts-row">
              {/* Resource Utilization Chart */}
              <div className="chart-card">
                <h3 className="chart-title">Resource Utilization</h3>
                <div className="pie-chart-wrapper">
                  <svg viewBox="0 0 200 200" className="pie-chart" aria-label="Resource utilization breakdown">
                    {/* Your existing SVG content */}
                  </svg>
                  <div className="pie-legend">
                    <div className="legend-item">
                      <span className="legend-dot blue"></span>
                      <span>Classrooms: 68%</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-dot green"></span>
                      <span>Labs: 24%</span>
                    </div>
                    <div className="legend-item">
                      <span className="legend-dot yellow"></span>
                      <span>Library: 8%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Grade Distribution Chart */}
              <div className="chart-card">
                <h3 className="chart-title">Grade Distribution</h3>
                <div className="bar-chart">
                  {performance?.grade_distribution && Object.entries(performance.grade_distribution).map(([grade, count]) => {
                    const percentage = (count / performance.total_grades_recorded) * 100;
                    return (
                      <div key={grade} className="bar-wrapper">
                        <div 
                          className="bar" 
                          style={{height: `${percentage}%`}}
                          aria-label={`Grade ${grade}: ${percentage.toFixed(1)}%`}
                        ></div>
                        <span className="bar-label">{grade}</span>
                      </div>
                    );
                  })}
                </div>
                <div className="y-axis">
                  <span>6000</span>
                  <span>4500</span>
                  <span>3000</span>
                  <span>1500</span>
                  <span>0</span>
                </div>
              </div>

              {/* Faculty Performance Chart */}
              <div className="chart-card">
                <h3 className="chart-title">Faculty Performance</h3>
                <div className="radar-chart">
                  <svg viewBox="0 0 200 200" aria-label="Faculty performance radar chart">
                    {/* Your existing SVG content */}
                  </svg>
                  <div className="radar-labels">
                    <span style={{top: '10%', left: '50%'}}>Research</span>
                    <span style={{top: '25%', right: '5%'}}>Satisfaction</span>
                    <span style={{bottom: '25%', right: '5%'}}>Innovation</span>
                    <span style={{bottom: '10%', left: '50%'}}>Pass Rate</span>
                    <span style={{bottom: '25%', left: '5%'}}>Grading</span>
                    <span style={{top: '25%', left: '5%'}}>Feedback</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Continue with your existing chart structures... */}
            {/* Charts Row 2, Course Demand Forecast, Performance Benchmarking, etc. */}

            {/* Risk Assessment Dashboard */}
            <section aria-label="Risk assessment dashboard" className="risk-dashboard">
              <div className="risk-header">
                <AlertTriangle className="icon-medium" aria-hidden="true" />
                <h3>Risk Assessment Dashboard</h3>
              </div>
              <div className="risk-cards">
                <div className="risk-card">
                  <div className="risk-card-header">
                    <span className="risk-card-title">High Dropout Risk</span>
                    <span className="risk-status warning">warning</span>
                  </div>
                  <div className="risk-card-body">
                    <div className="risk-numbers">
                      <span className="current">Current: {highRiskCount}</span>
                      <span className="target">Target: 300</span>
                    </div>
                    <div className="risk-progress-bar">
                      <div 
                        className="risk-progress-fill warning" 
                        style={{width: `${Math.min((highRiskCount / 300) * 100, 100)}%`}}
                        aria-valuenow={Math.min((highRiskCount / 300) * 100, 100)}
                        aria-valuemin="0"
                        aria-valuemax="100"
                      ></div>
                    </div>
                    <span className="over-target">
                      {Math.max(highRiskCount - 300, 0)} over target
                    </span>
                  </div>
                </div>

                <div className="risk-card">
                  <div className="risk-card-header">
                    <span className="risk-card-title">Low GPA (&lt;2.5)</span>
                    <span className="risk-status warning">warning</span>
                  </div>
                  <div className="risk-card-body">
                    <div className="risk-numbers">
                      <span className="current">Current: {lowGPACount}</span>
                      <span className="target">Target: 120</span>
                    </div>
                    <div className="risk-progress-bar">
                      <div 
                        className="risk-progress-fill warning" 
                        style={{width: `${Math.min((lowGPACount / 120) * 100, 100)}%`}}
                        aria-valuenow={Math.min((lowGPACount / 120) * 100, 100)}
                        aria-valuemin="0"
                        aria-valuemax="100"
                      ></div>
                    </div>
                    <span className="over-target">
                      {Math.max(lowGPACount - 120, 0)} over target
                    </span>
                  </div>
                </div>

                {/* Additional risk cards... */}
              </div>
            </section>

            {/* Predictive Insights */}
            <section aria-label="Predictive insights and recommendations" className="insights-section">
              <h3 className="section-title">Predictive Insights & Recommendations</h3>
              <div className="insights-grid">
                <div className="insight-card opportunity">
                  <div className="insight-badge">Opportunity</div>
                  <p className="insight-text">
                    Mathematics department shows strong growth potential. Consider expanding course offerings.
                  </p>
                </div>
                <div className="insight-card alert">
                  <div className="insight-badge">Alert</div>
                  <p className="insight-text">
                    Physics courses have declining enrollment. Review curriculum relevance and marketing.
                  </p>
                </div>
                <div className="insight-card critical">
                  <div className="insight-badge">Critical</div>
                  <p className="insight-text">
                    {highRiskCount} students at high dropout risk. Immediate intervention programs recommended.
                  </p>
                </div>
              </div>
            </section>
          </div>
        </main>
      </div>
    </AnalyticsErrorBoundary>
  );
};

export default Analytics;