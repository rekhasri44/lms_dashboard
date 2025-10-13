import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Bell, 
  User, 
  BarChart3, 
  BookOpen, 
  Users, 
  GraduationCap, 
  FileText, 
  Settings,
  TrendingUp,
  Filter,
  RefreshCw,
  Download,
  AlertTriangle,
  Info,
  CheckCircle,
  X,
  Calendar,
  DollarSign
} from 'lucide-react';
import { analyticsAPI, studentsAPI, coursesAPI, facultyAPI, departmentsAPI } from '../services/api';
import { useApi } from '../hooks/useApi';
import './Analytics.css';

// Memoized chart components
const MetricCard = React.memo(({ label, value, change, changeType, icon: Icon }) => (
  <div className="metric-card">
    <div className="metric-header">
      <span className="metric-label">{label}</span>
      <Icon className="metric-icon blue" />
    </div>
    <div className="metric-value">{value}</div>
    <div className={`metric-change ${changeType}`}>{change}</div>
  </div>
));

const RiskItem = React.memo(({ dept, index }) => (
  <div key={index} className="risk-item">
    <div className="risk-info">
      <span className="dept-name">{dept.name}</span>
      <span className="student-count">{dept.studentCount} students</span>
    </div>
    <div className="risk-badge-wrapper">
      <span className={`risk-percent ${dept.dropoutRate > 30 ? 'red' : dept.dropoutRate > 15 ? 'yellow' : 'green'}`}>
        {dept.dropoutRate}%
      </span>
      <span className={`risk-badge ${dept.dropoutRate > 30 ? 'high' : dept.dropoutRate > 15 ? 'medium' : 'low'}`}>
        {dept.dropoutRate > 30 ? 'High Risk' : dept.dropoutRate > 15 ? 'Medium Risk' : 'Low Risk'}
      </span>
    </div>
  </div>
));

const Analytics = () => {
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [atRiskStudents, setAtRiskStudents] = useState([]);
  const [departmentStats, setDepartmentStats] = useState([]);

  // Real API integration for all analytics data
  const { data: overviewData, refetch: refetchOverview } = useApi(
    () => analyticsAPI.getDashboardOverview()
  );

  const { data: performanceData, refetch: refetchPerformance } = useApi(
    () => analyticsAPI.getPerformanceAnalytics()
  );

  const { data: engagementData, refetch: refetchEngagement } = useApi(
    () => analyticsAPI.getEngagementAnalytics()
  );

  const { data: forecastingData, refetch: refetchForecasting } = useApi(
    () => analyticsAPI.getForecastingAnalytics()
  );

  const { data: benchmarkingData, refetch: refetchBenchmarking } = useApi(
    () => analyticsAPI.getBenchmarkingAnalytics()
  );

  const { data: atRiskData, refetch: refetchAtRisk } = useApi(
    () => studentsAPI.getAtRiskStudents()
  );

  const { data: departmentStatsData, refetch: refetchDepartmentStats } = useApi(
    () => departmentsAPI.getDepartmentStats()
  );

  // Consolidated API calls with useCallback
  const fetchAllAnalytics = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      
      const [
        overviewResponse,
        performanceResponse,
        engagementResponse,
        forecastingResponse,
        benchmarkingResponse,
        atRiskResponse
      ] = await Promise.all([
        analyticsAPI.getDashboardOverview(),
        analyticsAPI.getPerformanceAnalytics(),
        analyticsAPI.getEngagementAnalytics(),
        analyticsAPI.getForecastingAnalytics(),
        analyticsAPI.getBenchmarkingAnalytics(),
        studentsAPI.getAtRiskStudents()
      ]);

      const combinedData = {
        overview: overviewResponse.data,
        performance: performanceResponse.data,
        engagement: engagementResponse.data,
        forecasting: forecastingResponse.data,
        benchmarking: benchmarkingResponse.data
      };
      
      setAnalyticsData(combinedData);
      setAtRiskStudents(atRiskResponse.data || []);
      
      // Calculate department stats
      const deptStats = calculateDepartmentStats(overviewResponse.data, atRiskResponse.data);
      setDepartmentStats(deptStats);

    } catch (err) {
      console.error('Failed to fetch analytics data:', err);
      setError('Failed to load analytics data. Using demo data.');
      setAnalyticsData(getStaticAnalyticsData());
      setAtRiskStudents(getStaticAtRiskStudents());
      setDepartmentStats(getStaticDepartmentStats());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAllAnalytics();
  }, [fetchAllAnalytics]);

  // Combine all data when APIs resolve
  useEffect(() => {
    if (overviewData && performanceData && engagementData) {
      const combinedData = {
        overview: overviewData,
        performance: performanceData,
        engagement: engagementData,
        forecasting: forecastingData,
        benchmarking: benchmarkingData,
        atRisk: atRiskData || [],
        departments: departmentStatsData || []
      };
      
      setAnalyticsData(combinedData);
      
      // Calculate department stats from available data
      const deptStats = calculateDepartmentStats(overviewData, atRiskData);
      setDepartmentStats(deptStats);
      setLoading(false);
    }
  }, [overviewData, performanceData, engagementData, forecastingData, benchmarkingData, atRiskData, departmentStatsData]);

  // Memoized handlers
  const handleRefresh = useCallback(async () => {
    setLoading(true);
    setError('');
    
    try {
      await Promise.all([
        refetchOverview(),
        refetchPerformance(),
        refetchEngagement(),
        refetchForecasting(),
        refetchBenchmarking(),
        refetchAtRisk(),
        refetchDepartmentStats()
      ]);
    } catch (err) {
      setError('Failed to refresh analytics data');
      console.error('Refresh error:', err);
    } finally {
      setLoading(false);
    }
  }, [refetchOverview, refetchPerformance, refetchEngagement, refetchForecasting, refetchBenchmarking, refetchAtRisk, refetchDepartmentStats]);

  // Export functionality
  const handleExport = useCallback(async (type) => {
    try {
      setError('');
      // This would call your backend export endpoint
      const response = await analyticsAPI.exportAnalytics(type);
      
      if (response.success && response.data) {
        const blob = new Blob([response.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `analytics_${type}_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(`Failed to export ${type} data`);
      console.error('Export error:', err);
    }
  }, []);

  // Memoized calculations
  const calculateDepartmentStats = useCallback((overview, atRiskData) => {
    // This would normally come from your backend
    // For now, we'll calculate from available data
    return [
      {
        name: 'Computer Science',
        studentCount: 1247,
        atRiskCount: atRiskData?.filter(s => s.department === 'Computer Science').length || 0,
        dropoutRate: 15,
        avgGPA: 3.6
      },
      {
        name: 'Engineering',
        studentCount: 2134,
        atRiskCount: atRiskData?.filter(s => s.department === 'Engineering').length || 0,
        dropoutRate: 23,
        avgGPA: 3.4
      },
      {
        name: 'Mathematics',
        studentCount: 892,
        atRiskCount: atRiskData?.filter(s => s.department === 'Mathematics').length || 0,
        dropoutRate: 8,
        avgGPA: 3.2
      },
      {
        name: 'Physics',
        studentCount: 674,
        atRiskCount: atRiskData?.filter(s => s.department === 'Physics').length || 0,
        dropoutRate: 35,
        avgGPA: 2.9
      }
    ];
  }, []);

  // Memoized static data
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
    }
  }), []);

  const getStaticAtRiskStudents = useCallback(() => [
    {
      id: 1,
      name: 'Alex Chen',
      department: 'Computer Science',
      gpa: 2.1,
      risk_level: 'high'
    },
    {
      id: 2,
      name: 'Maria Rodriguez',
      department: 'Mathematics', 
      gpa: 2.5,
      risk_level: 'medium'
    }
  ], []);

  const getStaticDepartmentStats = useCallback(() => [
    {
      name: 'Computer Science',
      studentCount: 1247,
      atRiskCount: 187,
      dropoutRate: 15,
      avgGPA: 3.6
    },
    {
      name: 'Engineering',
      studentCount: 2134,
      atRiskCount: 491,
      dropoutRate: 23,
      avgGPA: 3.4
    },
    {
      name: 'Business',
      studentCount: 892,
      atRiskCount: 71,
      dropoutRate: 8,
      avgGPA: 3.5
    },
    {
      name: 'Physics',
      studentCount: 674,
      atRiskCount: 236,
      dropoutRate: 35,
      avgGPA: 2.9
    }
  ], []);

  // Memoized computed values
  const metrics = useMemo(() => {
    if (!analyticsData) return [];
    
    const { benchmarking, performance } = analyticsData;
    
    return [
      {
        label: 'Student Retention',
        value: `${benchmarking?.institutional_benchmarks?.retention_rate?.current || 89.2}%`,
        change: `↗ +${(benchmarking?.institutional_benchmarks?.retention_rate?.current - benchmarking?.institutional_benchmarks?.retention_rate?.national_average).toFixed(1) || 3.5}% vs national avg`,
        changeType: 'positive',
        icon: Users
      },
      {
        label: 'Course Completion', 
        value: `${performance?.pass_rate || 94.2}%`,
        change: '↗ 1.5% vs last period',
        changeType: 'positive',
        icon: BookOpen
      },
      {
        label: 'Avg Class Size',
        value: '28.5',
        change: '↘ 3.2% vs last period', 
        changeType: 'negative',
        icon: TrendingUp
      },
      {
        label: 'Satisfaction Score',
        value: `${benchmarking?.institutional_benchmarks?.student_satisfaction?.current || 4.3}/5`,
        change: '↗ 0.2% vs last period',
        changeType: 'positive',
        icon: TrendingUp
      }
    ];
  }, [analyticsData]);

  const highRiskCount = useMemo(() => 
    atRiskStudents.filter(s => s.risk_level === 'high').length, 
    [atRiskStudents]
  );

  const lowGPACount = useMemo(() => 
    atRiskStudents.filter(s => s.gpa < 2.5).length, 
    [atRiskStudents]
  );

  const handleRetry = () => {
    fetchAllAnalytics();
  };

  const getRiskLevelClass = (riskLevel) => {
    switch(riskLevel) {
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'low';
    }
  };

  const getRiskLabel = (riskLevel) => {
    switch(riskLevel) {
      case 'high': return 'High Risk';
      case 'medium': return 'Medium Risk';
      case 'low': return 'Low Risk';
      default: return 'Low Risk';
    }
  };

  if (loading && !analyticsData) {
    return (
      <div className="analytics-container">
        <div className="sidebar">
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
          <div className="loading-container">
            <div className="loading-spinner"></div>
            <p>Loading analytics data...</p>
          </div>
        </div>
      </div>
    );
  }

  const { performance, engagement, forecasting, benchmarking, overview } = analyticsData;

  const { data: financialData } = useApi(
  () => financialAPI.getFinancialOverview()
);

  return (
    <div className="analytics-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">
              <GraduationCap className="icon-medium" />
            </div>
            <span className="logo-text">EduAdmin</span>
          </div>
        </div>
        
        <nav className="sidebar-nav">
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
        </nav>
      </div>

      {/* Main Content */}
      <div className="main-content">
        {/* Header */}
        <header className="header">
          <h1 className="header-title">Analytics & Insights</h1>
          <div className="header-actions">
            <button className="refresh-btn" onClick={handleRefresh} disabled={loading}>
              <RefreshCw className={`icon-small ${loading ? 'spinning' : ''}`} />
            </button>
            <button className="export-btn" onClick={() => handleExport('overview')}>
              <Download className="icon-small" />
            </button>
            <button className="notification-button">
              <Bell className="icon-small" />
              <span className="notification-badge"></span>
            </button>
            <div className="profile-avatar">
              <User className="icon-small" />
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="analytics-main">
          {/* Advanced Analytics Header */}
          <div className="analytics-header">
            <div>
              <h2 className="analytics-title">Advanced Analytics</h2>
              <p className="analytics-subtitle">Comprehensive insights and predictive analytics</p>
            </div>
            <div className="analytics-actions">
              <button className="action-btn">
                <Filter className="icon-small" />
                Filters
              </button>
              <button className="action-btn" onClick={handleRefresh} disabled={loading}>
                <RefreshCw className={`icon-small ${loading ? 'spinning' : ''}`} />
                Refresh
              </button>
              <button className="action-btn" onClick={() => handleExport('overview')}>
                <Download className="icon-small" />
                Export Report
              </button>
            </div>
          </div>

          {error && (
            <div className="error-banner">
              <AlertTriangle size={16} />
              <span>{error}</span>
              <button onClick={handleRetry} className="retry-btn">
                Retry
              </button>
            </div>
          )}

          {/* Optimized Metrics Cards */}
          <div className="metrics-grid">
            {metrics.map((metric, index) => (
              <MetricCard
                key={index}
                label={metric.label}
                value={metric.value}
                change={metric.change}
                changeType={metric.changeType}
                icon={metric.icon}
              />
            ))}
          </div>

          {/* Charts Row 1 */}
          <div className="charts-row">
            <div className="chart-card">
              <h3 className="chart-title">Resource Utilization</h3>
              <div className="pie-chart-wrapper">
                <svg viewBox="0 0 200 200" className="pie-chart">
                  <circle cx="100" cy="100" r="80" fill="none" stroke="#3b82f6" strokeWidth="60" strokeDasharray="339 424" transform="rotate(-90 100 100)" />
                  <circle cx="100" cy="100" r="80" fill="none" stroke="#10b981" strokeWidth="60" strokeDasharray="102 424" strokeDashoffset="-339" transform="rotate(-90 100 100)" />
                  <circle cx="100" cy="100" r="80" fill="none" stroke="#eab308" strokeWidth="60" strokeDasharray="34 424" strokeDashoffset="-441" transform="rotate(-90 100 100)" />
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

            <div className="chart-card">
              <h3 className="chart-title">Grade Distribution</h3>
              <div className="bar-chart">
                {performance?.grade_distribution && Object.entries(performance.grade_distribution).map(([grade, count]) => {
                  const percentage = (count / performance.total_grades_recorded) * 100;
                  return (
                    <div key={grade} className="bar-wrapper">
                      <div className="bar" style={{height: `${percentage}%`}}></div>
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

            <div className="chart-card">
              <h3 className="chart-title">Faculty Performance</h3>
              <div className="radar-chart">
                <svg viewBox="0 0 200 200">
                  <polygon points="100,30 160,70 160,130 100,170 40,130 40,70" fill="none" stroke="#e5e7eb" strokeWidth="1" />
                  <polygon points="100,50 140,80 140,120 100,150 60,120 60,80" fill="none" stroke="#e5e7eb" strokeWidth="1" />
                  <polygon points="100,70 120,90 120,110 100,130 80,110 80,90" fill="none" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="100" y2="30" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="160" y2="70" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="160" y2="130" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="100" y2="170" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="40" y2="130" stroke="#e5e7eb" strokeWidth="1" />
                  <line x1="100" y1="100" x2="40" y2="70" stroke="#e5e7eb" strokeWidth="1" />
                  <polygon points="100,36 152,74 152,126 100,156 48,126 48,74" fill="#3b82f6" fillOpacity="0.3" stroke="#3b82f6" strokeWidth="2" />
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

          {/* Charts Row 2 */}
          <div className="charts-row2">
            <div className="chart-card2">
              <h3 className="chart-title">Dropout Risk by Department</h3>
              <div className="risk-list">
                {departmentStats.map((dept, index) => (
                  <RiskItem key={dept.name} dept={dept} index={index} />
                ))}
              </div>
            </div>

            <div className="chart-card2">
              <h3 className="chart-title">Pass Rates by Subject</h3>
              <div className="pass-rates">
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>Mathematics</span>
                    <span className="pass-percent">87%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '87%'}}></div>
                  </div>
                </div>
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>Physics</span>
                    <span className="pass-percent">79%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '79%'}}></div>
                  </div>
                </div>
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>Chemistry</span>
                    <span className="pass-percent">91%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '91%'}}></div>
                  </div>
                </div>
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>Computer Science</span>
                    <span className="pass-percent">94%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '94%'}}></div>
                  </div>
                </div>
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>English</span>
                    <span className="pass-percent">96%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '96%'}}></div>
                  </div>
                </div>
                <div className="pass-rate-item">
                  <div className="pass-rate-header">
                    <span>History</span>
                    <span className="pass-percent">89%</span>
                  </div>
                  <div className="pass-rate-bar">
                    <div className="pass-rate-fill" style={{width: '89%'}}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Course Demand Forecast */}
          <div className="chart-card full-width">
            <h3 className="chart-title">Course Demand Forecast</h3>
            <div className="line-chart-container">
              <div className="line-legend">
                <div className="legend-item">
                  <span className="legend-dot blue"></span>
                  <span>Computer Science</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot green"></span>
                  <span>Engineering</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot yellow"></span>
                  <span>Business</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot orange"></span>
                  <span>Mathematics</span>
                </div>
              </div>
              <svg viewBox="0 0 600 200" className="line-chart">
                <defs>
                  <pattern id="grid" width="100" height="50" patternUnits="userSpaceOnUse">
                    <path d="M 100 0 L 0 0 0 50" fill="none" stroke="#e5e7eb" strokeWidth="1"/>
                  </pattern>
                </defs>
                <rect width="100%" height="100%" fill="url(#grid)" />
                <polyline fill="none" stroke="#3b82f6" strokeWidth="2" points="0,150 100,140 200,125 300,110 400,95 500,85 600,75"/>
                <polyline fill="none" stroke="#10b981" strokeWidth="2" points="0,175 100,170 200,165 300,160 400,155 500,150 600,145"/>
                <polyline fill="none" stroke="#eab308" strokeWidth="2" points="0,185 100,180 200,175 300,170 400,165 500,160 600,155"/>
                <polyline fill="none" stroke="#f97316" strokeWidth="2" points="0,190 100,188 200,185 300,182 400,180 500,175 600,170"/>
              </svg>
              <div className="x-axis">
                <span>Fall 22</span>
                <span>Spring 23</span>
                <span>Fall 23</span>
                <span>Spring 24</span>
                <span>Fall 24</span>
                <span>Spring 25</span>
              </div>
              <div className="y-axis-left">
                <span>400</span>
                <span>300</span>
                <span>200</span>
                <span>100</span>
                <span>0</span>
              </div>
            </div>
          </div>

          {/* Performance Benchmarking & Student Engagement */}
          <div className="charts-row2">
            <div className="chart-card2">
              <h3 className="chart-title">Performance Benchmarking</h3>
              <div className="benchmark-list">
                <div className="benchmark-item">
                  <span className="benchmark-label">Pass Rate</span>
                  <div className="benchmark-bar-wrapper">
                    <div className="benchmark-bar">
                      <div className="benchmark-fill" style={{width: '94%'}}></div>
                    </div>
                    <span className="benchmark-value">0.94</span>
                  </div>
                </div>
                <div className="benchmark-item">
                  <span className="benchmark-label">Student Satisfaction</span>
                  <div className="benchmark-bar-wrapper">
                    <div className="benchmark-bar">
                      <div className="benchmark-fill" style={{width: '88%'}}></div>
                    </div>
                    <span className="benchmark-value">0.88</span>
                  </div>
                </div>
                <div className="benchmark-item">
                  <span className="benchmark-label">Faculty Ratio</span>
                  <div className="benchmark-bar-wrapper">
                    <div className="benchmark-bar">
                      <div className="benchmark-fill" style={{width: '75%'}}></div>
                    </div>
                    <span className="benchmark-value">0.75</span>
                  </div>
                </div>
                <div className="benchmark-item">
                  <span className="benchmark-label">Research Output</span>
                  <div className="benchmark-bar-wrapper">
                    <div className="benchmark-bar">
                      <div className="benchmark-fill" style={{width: '82%'}}></div>
                    </div>
                    <span className="benchmark-value">0.82</span>
                  </div>
                </div>
                <div className="benchmark-item">
                  <span className="benchmark-label">Employment Rate</span>
                  <div className="benchmark-bar-wrapper">
                    <div className="benchmark-bar">
                      <div className="benchmark-fill" style={{width: '91%'}}></div>
                    </div>
                    <span className="benchmark-value">0.91</span>
                  </div>
                </div>
              </div>
              <div className="x-axis-benchmark">
                <span>0</span>
                <span>0.25</span>
                <span>0.5</span>
                <span>0.75</span>
                <span>1</span>
              </div>
            </div>

            <div className="chart-card2">
              <h3 className="chart-title">Student Engagement Trends</h3>
              <div className="engagement-legend">
                <div className="legend-item">
                  <span className="legend-dot blue"></span>
                  <span>Attendance</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot green"></span>
                  <span>Assignment Submission</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot yellow"></span>
                  <span>Discussion Participation</span>
                </div>
              </div>
              <svg viewBox="0 0 400 150" className="engagement-chart">
                <defs>
                  <pattern id="grid2" width="66.67" height="37.5" patternUnits="userSpaceOnUse">
                    <path d="M 66.67 0 L 0 0 0 37.5" fill="none" stroke="#e5e7eb" strokeWidth="1"/>
                  </pattern>
                </defs>
                <rect width="100%" height="100%" fill="url(#grid2)" />
                <polyline fill="none" stroke="#3b82f6" strokeWidth="2" points="0,30 66.67,27 133.33,25 200,24 266.67,22 333.33,20 400,18"/>
                <polyline fill="none" stroke="#10b981" strokeWidth="2" points="0,75 66.67,65 133.33,60 200,55 266.67,50 333.33,45 400,18"/>
                <polyline fill="none" stroke="#eab308" strokeWidth="2" points="0,112 66.67,105 133.33,105 200,100 266.67,85 333.33,75 400,93"/>
              </svg>
              <div className="x-axis">
                <span>Jan</span>
                <span>Feb</span>
                <span>Mar</span>
                <span>Apr</span>
                <span>May</span>
                <span>Jun</span>
              </div>
              <div className="y-axis-left">
                <span>100</span>
                <span>75</span>
                <span>50</span>
                <span>25</span>
                <span>0</span>
              </div>
            </div>
          </div>

          {/* Institutional Trends & Department Performance */}
          <div className="charts-row2">
            <div className="chart-card2">
              <h3 className="chart-title">Institutional Trends</h3>
              <svg viewBox="0 0 400 200" className="trend-chart">
                <rect x="40" y="40" width="60" height="120" fill="#3b82f6"/>
                <rect x="120" y="35" width="60" height="125" fill="#3b82f6"/>
                <rect x="200" y="30" width="60" height="130" fill="#3b82f6"/>
                <rect x="280" y="32" width="60" height="128" fill="#3b82f6"/>
                <rect x="360" y="28" width="60" height="132" fill="#3b82f6"/>
                <polyline fill="none" stroke="#10b981" strokeWidth="2" points="70,100 150,95 230,90 310,92 390,88"/>
                <circle cx="70" cy="100" r="4" fill="#10b981"/>
                <circle cx="150" cy="95" r="4" fill="#10b981"/>
                <circle cx="230" cy="90" r="4" fill="#10b981"/>
                <circle cx="310" cy="92" r="4" fill="#10b981"/>
                <circle cx="390" cy="88" r="4" fill="#10b981"/>
              </svg>
              <div className="x-axis">
                <span>Aug</span>
                <span>Sep</span>
                <span>Oct</span>
                <span>Nov</span>
                <span>Dec</span>
              </div>
            </div>

            <div className="chart-card2">
              <h3 className="chart-title">Department Performance</h3>
              <div className="donut-chart-wrapper">
                <svg viewBox="0 0 200 200" className="donut-chart">
                  <circle cx="100" cy="100" r="70" fill="none" stroke="#3b82f6" strokeWidth="40" strokeDasharray="123 439" transform="rotate(-90 100 100)" />
                  <circle cx="100" cy="100" r="70" fill="none" stroke="#10b981" strokeWidth="40" strokeDasharray="70 439" strokeDashoffset="-123" transform="rotate(-90 100 100)" />
                  <circle cx="100" cy="100" r="70" fill="none" stroke="#eab308" strokeWidth="40" strokeDasharray="79 439" strokeDashoffset="-193" transform="rotate(-90 100 100)" />
                  <circle cx="100" cy="100" r="70" fill="none" stroke="#3b82f6" strokeWidth="40" strokeDasharray="70 439" strokeDashoffset="-272" transform="rotate(-90 100 100)" />
                </svg>
                <div className="donut-legend">
                  <div className="legend-item">
                    <span className="legend-dot blue"></span>
                    <span>Computer Science: 28%</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot green"></span>
                    <span>Mathematics: 22%</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot yellow"></span>
                    <span>Physics: 18%</span>
                  </div>
                  <div className="legend-item">
                    <span className="legend-dot blue"></span>
                    <span>Biology: 16%</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Risk Assessment Dashboard */}
          <div className="risk-dashboard">
            <div className="risk-header">
              <AlertTriangle className="icon-medium" />
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
                    <div className="risk-progress-fill warning" style={{width: `${Math.min((highRiskCount / 300) * 100, 100)}%`}}></div>
                  </div>
                  <span className="over-target">{Math.max(highRiskCount - 300, 0)} over target</span>
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
                    <div className="risk-progress-fill warning" style={{width: `${Math.min((lowGPACount / 120) * 100, 100)}%`}}></div>
                  </div>
                  <span className="over-target">{Math.max(lowGPACount - 120, 0)} over target</span>
                </div>
              </div>

              <div className="risk-card">
                <div className="risk-card-header">
                  <span className="risk-card-title">Poor Attendance</span>
                  <span className="risk-status critical">critical</span>
                </div>
                <div className="risk-card-body">
                  <div className="risk-numbers">
                    <span className="current">Current: 89</span>
                    <span className="target">Target: 50</span>
                  </div>
                  <div className="risk-progress-bar">
                    <div className="risk-progress-fill critical" style={{width: '89%'}}></div>
                  </div>
                  <span className="over-target">39 over target</span>
                </div>
              </div>

              <div className="risk-card">
                <div className="risk-card-header">
                  <span className="risk-card-title">Financial Issues</span>
                  <span className="risk-status warning">warning</span>
                </div>
                <div className="risk-card-body">
                  <div className="risk-numbers">
                    <span className="current">Current: 234</span>
                    <span className="target">Target: 200</span>
                  </div>
                  <div className="risk-progress-bar">
                    <div className="risk-progress-fill warning" style={{width: '87%'}}></div>
                  </div>
                  <span className="over-target">34 over target</span>
                </div>
              </div>
            </div>
          </div>

          {/* Predictive Insights */}
          <div className="insights-section">
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
          </div>
        </main>
      </div>
    </div>
  );
};

export default Analytics;