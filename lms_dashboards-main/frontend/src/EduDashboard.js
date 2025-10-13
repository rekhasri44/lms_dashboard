import React, { useState, useEffect } from 'react';
import { 
  Bell, User, BarChart3, BookOpen, Users, GraduationCap, FileText, Settings,
  Info, X, CheckCircle, AlertTriangle, Calendar, RefreshCw, Mail, Phone,
  TrendingUp, Filter, Download, Eye, Send, DollarSign,
  ArrowUp, ArrowDown, Clock, XCircle
} from 'lucide-react';
import { analyticsAPI, systemAPI, studentsAPI, facultyAPI, coursesAPI, reportsAPI } from '../services/api';
import { useApi } from '../hooks/useApi';
import './EduDashboard.css';

const EduDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [atRiskStudents, setAtRiskStudents] = useState([]);
  const [facultyWorkload, setFacultyWorkload] = useState([]);
  const [courseEnrollment, setCourseEnrollment] = useState([]);
  const [recentActivity, setRecentActivity] = useState([]);
  const [systemAlerts, setSystemAlerts] = useState([]);

  // Real API integration for all dashboard data
  const { data: overviewData, refetch: refetchOverview } = useApi(
    () => analyticsAPI.getDashboardOverview()
  );

  const { data: performanceData, refetch: refetchPerformance } = useApi(
    () => analyticsAPI.getPerformanceAnalytics()
  );

  const { data: atRiskData, refetch: refetchAtRisk } = useApi(
    () => studentsAPI.getAtRiskStudents()
  );

  const { data: alertsData, refetch: refetchAlerts } = useApi(
    () => systemAPI.getAlerts()
  );

  // Original useEffect for initial data fetch
  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Combine all data when APIs resolve
  useEffect(() => {
    if (overviewData && performanceData) {
      setDashboardData({
        overview: overviewData,
        performance: performanceData,
        atRisk: atRiskData || []
      });
      setLoading(false);
    }
  }, [overviewData, performanceData, atRiskData]);

  useEffect(() => {
    if (alertsData) {
      setSystemAlerts(alertsData.slice(0, 5)); // Show only 5 most recent alerts
    }
  }, [alertsData]);

  // Simulate real-time updates every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refetchOverview();
      refetchPerformance();
      refetchAlerts();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError('');
      
      const [
        overviewResponse, 
        alertsResponse, 
        atRiskResponse, 
        analyticsResponse,
        workloadResponse,
        enrollmentResponse
      ] = await Promise.all([
        analyticsAPI.getDashboardOverview(),
        systemAPI.getAlerts(),
        studentsAPI.getAtRiskStudents(),
        analyticsAPI.getPerformanceAnalytics(),
        facultyAPI.getFacultyWorkload(),
        coursesAPI.getEnrollmentStats()
      ]);

      setDashboardData({
        overview: overviewResponse.data,
        alerts: alertsResponse.data,
        analytics: analyticsResponse.data,
        atRiskStudents: atRiskResponse.data,
        facultyWorkload: workloadResponse.data,
        courseEnrollment: enrollmentResponse.data
      });

      // Transform backend alerts to frontend notifications
      const transformedNotifications = alertsResponse.data.map(alert => ({
        id: alert.id,
        type: alert.alert_type?.toLowerCase() || 'info',
        title: alert.title,
        message: alert.message,
        audience: alert.target_audience || 'all',
        time: alert.created_at,
        expires: alert.expires_at,
        author: 'System',
        status: alert.status
      }));
      
      setNotifications(transformedNotifications);
      setAtRiskStudents(atRiskResponse.data || []);
      setFacultyWorkload(workloadResponse.data || []);
      setCourseEnrollment(enrollmentResponse.data || []);

    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
      setError('Failed to load dashboard data. Please check your backend connection.');
      setDashboardData(getStaticFallbackData());
      setNotifications(getStaticNotifications());
      setAtRiskStudents(getStaticAtRiskStudents());
      setFacultyWorkload(getStaticFacultyWorkload());
      setCourseEnrollment(getStaticCourseEnrollment());
    } finally {
      setLoading(false);
    }
  };

  // Manual refresh
  const handleRefresh = () => {
    setLoading(true);
    Promise.all([
      refetchOverview(),
      refetchPerformance(),
      refetchAtRisk(),
      refetchAlerts()
    ]).finally(() => {
      setLoading(false);
    });
  };

  // Generate recent activity from available data
  useEffect(() => {
    if (dashboardData) {
      const activities = [
        {
          id: 1,
          type: 'enrollment',
          message: '15 new students enrolled in Computer Science',
          time: '2 hours ago',
          icon: '👥'
        },
        {
          id: 2,
          type: 'completion',
          message: 'Course "Advanced Algorithms" completed by 92% of students',
          time: '4 hours ago',
          icon: '🎓'
        },
        {
          id: 3,
          type: 'alert',
          message: 'High dropout risk detected in Physics department',
          time: '6 hours ago',
          icon: '⚠️'
        },
        {
          id: 4,
          type: 'achievement',
          message: 'Faculty research paper published in top journal',
          time: '1 day ago',
          icon: '📚'
        }
      ];
      setRecentActivity(activities);
    }
  }, [dashboardData]);

  // Calculate metrics for display
  const calculateMetrics = () => {
    if (!dashboardData) return {};
    
    const { overview, performance, atRisk } = dashboardData;
    
    return {
      totalStudents: overview?.total_students || 0,
      totalFaculty: overview?.total_faculty || 0,
      totalCourses: overview?.total_courses || 0,
      passRate: performance?.pass_rate || 0,
      atRiskCount: atRisk?.length || 0,
      avgAttendance: performance?.attendance_rate || 0
    };
  };

  const metrics = calculateMetrics();

  // Static fallback data
  const getStaticFallbackData = () => ({
    overview: {
      total_students: 12847,
      total_faculty: 324,
      total_courses: 486,
      total_departments: 12,
      active_semester: 'Spring 2024',
      system_status: 'operational'
    },
    analytics: {
      grade_distribution: { A: 2450, B: 3120, C: 1890, D: 870, F: 450 },
      pass_rate: 94.2,
      attendance_breakdown: { present: 85600, absent: 12400, late: 3200, excused: 1800 },
      average_attendance: 87.5
    }
  });

  const getStaticNotifications = () => [
    {
      id: 1,
      type: 'info',
      title: 'New Course Registration Opens',
      message: 'Registration for Summer 2024 courses begins Monday, January 22nd at 8:00 AM.',
      audience: 'Students & Advisors',
      time: '2024-01-15 09:00',
      expires: '2024-01-25',
      author: 'Academic Office',
      status: 'active'
    },
    {
      id: 2,
      type: 'success',
      title: 'Library Hours Extended',
      message: 'The library will now be open 24/7 during finals week.',
      audience: 'Students',
      time: '2024-01-14 16:45',
      expires: '2024-02-10',
      author: 'Library Services',
      status: 'active'
    }
  ];

  const getStaticAtRiskStudents = () => [
    {
      id: 1,
      student_id: 'STU001',
      name: 'Alex Chen',
      department: 'Computer Science',
      gpa: 2.1,
      risk_level: 'high',
      financial_status: 'pending'
    },
    {
      id: 2,
      student_id: 'STU002',
      name: 'Maria Rodriguez',
      department: 'Mathematics',
      gpa: 2.5,
      risk_level: 'medium',
      financial_status: 'paid'
    }
  ];

  const getStaticFacultyWorkload = () => [
    {
      faculty_id: 1,
      name: 'Dr. Emily Thompson',
      department: 'Computer Science',
      sections_count: 3,
      total_students: 145,
      workload_hours: 40,
      utilization_percentage: 100
    },
    {
      faculty_id: 2,
      name: 'Prof. Michael Davis',
      department: 'Mathematics',
      sections_count: 2,
      total_students: 89,
      workload_hours: 35,
      utilization_percentage: 88
    }
  ];

  const getStaticCourseEnrollment = () => [
    {
      course_code: 'CS101',
      course_title: 'Introduction to Programming',
      sections_count: 5,
      total_enrolled: 125,
      total_capacity: 130,
      utilization_rate: 96.2
    },
    {
      course_code: 'MATH201',
      course_title: 'Calculus II',
      sections_count: 3,
      total_enrolled: 89,
      total_capacity: 120,
      utilization_rate: 74.2
    }
  ];

  const removeNotification = (id) => {
    setNotifications(notifications.filter(n => n.id !== id));
  };

  const getIcon = (type) => {
    switch(type) {
      case 'info': return <Info className="icon-small" />;
      case 'success': return <CheckCircle className="icon-small" />;
      case 'warning': return <AlertTriangle className="icon-small" />;
      default: return <Info className="icon-small" />;
    }
  };

  const activeNotifications = notifications.filter(n => n.status === 'active');

  if (loading) {
    return (
      <div className="dashboard-container">
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
            <p>Loading dashboard data...</p>
          </div>
        </div>
      </div>
    );
  }

  const { overview, analytics } = dashboardData;

  return (
    <div className="dashboard-container">
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
            <a href="/dashboard" className="nav-link active">
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
            <a href="/analytics" className="nav-link">
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
        {/* New Header Section */}
        <div className="dashboard-header">
          <div className="header-content">
            <h1 className="dashboard-title">Educational Dashboard</h1>
            <p className="dashboard-subtitle">
              Welcome back! Here's what's happening today.
            </p>
          </div>
          <div className="header-actions">
            <button className="refresh-btn" onClick={handleRefresh} disabled={loading}>
              <RefreshCw size={16} className={loading ? 'spinning' : ''} />
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
            <button className="export-btn">
              <Download size={16} />
              Export Report
            </button>
            <button className="notification-button">
              <Bell className="icon-small" />
              {activeNotifications.length > 0 && (
                <span className="notification-badge">{activeNotifications.length}</span>
              )}
            </button>
            <div className="profile-avatar">
              <User className="icon-small" />
            </div>
          </div>
        </div>

        {error && (
          <div className="error-banner">
            <AlertTriangle size={16} />
            <span>{error}</span>
            <button onClick={fetchDashboardData} className="retry-btn">
              Retry
            </button>
          </div>
        )}

        {/* New System Alerts Section */}
        {systemAlerts.length > 0 && (
          <div className="alerts-section">
            <div className="section-header">
              <h3>
                <AlertTriangle size={20} />
                System Alerts
              </h3>
              <span className="alert-count">{systemAlerts.length} active</span>
            </div>
            <div className="alerts-grid">
              {systemAlerts.map(alert => (
                <div key={alert.id} className={`alert-card ${alert.priority}`}>
                  <div className="alert-header">
                    <span className="alert-title">{alert.title}</span>
                    <span className={`alert-priority ${alert.priority}`}>
                      {alert.priority}
                    </span>
                  </div>
                  <p className="alert-message">{alert.message}</p>
                  <div className="alert-footer">
                    <span className="alert-time">
                      <Clock size={12} />
                      {new Date(alert.created_at).toLocaleDateString()}
                    </span>
                    <button className="alert-action">
                      View Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* New Key Metrics Section */}
        <div className="metrics-grid">
          <div className="metric-card primary">
            <div className="metric-icon">
              <Users size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.totalStudents.toLocaleString()}</div>
              <div className="metric-label">Total Students</div>
              <div className="metric-change positive">
                <ArrowUp size={14} />
                +5.2% from last month
              </div>
            </div>
          </div>

          <div className="metric-card success">
            <div className="metric-icon">
              <GraduationCap size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.totalFaculty}</div>
              <div className="metric-label">Faculty Members</div>
              <div className="metric-change positive">
                <ArrowUp size={14} />
                +2.1% from last month
              </div>
            </div>
          </div>

          <div className="metric-card warning">
            <div className="metric-icon">
              <BookOpen size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.totalCourses}</div>
              <div className="metric-label">Active Courses</div>
              <div className="metric-change neutral">
                <span>No change</span>
              </div>
            </div>
          </div>

          <div className="metric-card info">
            <div className="metric-icon">
              <TrendingUp size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.passRate}%</div>
              <div className="metric-label">Pass Rate</div>
              <div className="metric-change positive">
                <ArrowUp size={14} />
                +1.8% from last semester
              </div>
            </div>
          </div>

          <div className="metric-card danger">
            <div className="metric-icon">
              <AlertTriangle size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.atRiskCount}</div>
              <div className="metric-label">At-Risk Students</div>
              <div className="metric-change negative">
                <ArrowDown size={14} />
                -3.2% from last week
              </div>
            </div>
          </div>

          <div className="metric-card secondary">
            <div className="metric-icon">
              <BarChart3 size={24} />
            </div>
            <div className="metric-content">
              <div className="metric-value">{metrics.avgAttendance}%</div>
              <div className="metric-label">Avg Attendance</div>
              <div className="metric-change positive">
                <ArrowUp size={14} />
                +2.4% from last month
              </div>
            </div>
          </div>
        </div>

        {/* New Charts and Detailed Metrics Section */}
        <div className="charts-section">
          <div className="chart-row">
            {/* Performance Chart */}
            <div className="chart-card">
              <div className="chart-header">
                <h3>Academic Performance</h3>
                <div className="chart-actions">
                  <button className="chart-action-btn">
                    <Eye size={14} />
                  </button>
                  <button className="chart-action-btn">
                    <Download size={14} />
                  </button>
                </div>
              </div>
              <div className="chart-content">
                {dashboardData?.performance?.grade_distribution ? (
                  <div className="grade-distribution">
                    {Object.entries(dashboardData.performance.grade_distribution).map(([grade, count]) => {
                      const percentage = (count / dashboardData.performance.total_grades_recorded) * 100;
                      return (
                        <div key={grade} className="grade-bar">
                          <div className="grade-label">{grade}</div>
                          <div className="grade-bar-container">
                            <div 
                              className="grade-bar-fill" 
                              style={{ width: `${percentage}%` }}
                            ></div>
                          </div>
                          <div className="grade-count">{count}</div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="no-data">
                    <BarChart3 size={32} />
                    <p>No performance data available</p>
                  </div>
                )}
              </div>
              <div className="chart-footer">
                <div className="chart-stats">
                  <div className="stat-item">
                    <span className="stat-label">Pass Rate:</span>
                    <span className="stat-value">{metrics.passRate}%</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-label">Total Grades:</span>
                    <span className="stat-value">
                      {dashboardData?.performance?.total_grades_recorded?.toLocaleString() || 0}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* At-Risk Students */}
            <div className="chart-card">
              <div className="chart-header">
                <h3>At-Risk Students</h3>
                <span className="risk-count">{metrics.atRiskCount} students</span>
              </div>
              <div className="chart-content">
                {dashboardData?.atRisk && dashboardData.atRisk.length > 0 ? (
                  <div className="risk-list">
                    {dashboardData.atRisk.slice(0, 5).map(student => (
                      <div key={student.id} className="risk-item">
                        <div className="student-info">
                          <div className="student-name">{student.name}</div>
                          <div className="student-details">
                            {student.department} • GPA: {student.gpa}
                          </div>
                        </div>
                        <div className={`risk-level ${student.risk_level}`}>
                          {student.risk_level}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="no-data">
                    <CheckCircle size={32} />
                    <p>No at-risk students detected</p>
                  </div>
                )}
              </div>
              <div className="chart-footer">
                <button className="view-all-btn">
                  View All At-Risk Students
                </button>
              </div>
            </div>
          </div>

          <div className="chart-row">
            {/* Recent Activity */}
            <div className="chart-card">
              <div className="chart-header">
                <h3>Recent Activity</h3>
                <span className="activity-count">{recentActivity.length} activities</span>
              </div>
              <div className="chart-content">
                <div className="activity-list">
                  {recentActivity.map(activity => (
                    <div key={activity.id} className="activity-item">
                      <div className="activity-icon">{activity.icon}</div>
                      <div className="activity-content">
                        <div className="activity-message">{activity.message}</div>
                        <div className="activity-time">{activity.time}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="chart-card">
              <div className="chart-header">
                <h3>Quick Stats</h3>
                <Calendar size={16} />
              </div>
              <div className="chart-content">
                <div className="stats-grid-mini">
                  <div className="stat-mini">
                    <div className="stat-mini-value">87%</div>
                    <div className="stat-mini-label">Course Completion</div>
                  </div>
                  <div className="stat-mini">
                    <div className="stat-mini-value">94%</div>
                    <div className="stat-mini-label">Student Satisfaction</div>
                  </div>
                  <div className="stat-mini">
                    <div className="stat-mini-value">78%</div>
                    <div className="stat-mini-label">Resource Usage</div>
                  </div>
                  <div className="stat-mini">
                    <div className="stat-mini-value">$2.4M</div>
                    <div className="stat-mini-label">Semester Revenue</div>
                  </div>
                </div>
              </div>
              <div className="chart-footer">
                <div className="system-status">
                  <div className="status-item online">
                    <CheckCircle size={14} />
                    <span>All Systems Operational</span>
                  </div>
                  <div className="status-item">
                    <Clock size={14} />
                    <span>Last updated: {new Date().toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* New Department Performance Section */}
        <div className="department-section">
          <div className="section-header">
            <h3>Department Performance</h3>
            <button className="view-report-btn">
              View Detailed Report
            </button>
          </div>
          <div className="department-grid">
            <div className="department-card">
              <div className="department-header">
                <h4>Computer Science</h4>
                <span className="performance-score high">92%</span>
              </div>
              <div className="department-metrics">
                <div className="metric">
                  <span className="metric-label">Enrollment:</span>
                  <span className="metric-value">1,247</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Pass Rate:</span>
                  <span className="metric-value">94%</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Satisfaction:</span>
                  <span className="metric-value">4.6/5</span>
                </div>
              </div>
            </div>

            <div className="department-card">
              <div className="department-header">
                <h4>Engineering</h4>
                <span className="performance-score medium">85%</span>
              </div>
              <div className="department-metrics">
                <div className="metric">
                  <span className="metric-label">Enrollment:</span>
                  <span className="metric-value">2,134</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Pass Rate:</span>
                  <span className="metric-value">87%</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Satisfaction:</span>
                  <span className="metric-value">4.3/5</span>
                </div>
              </div>
            </div>

            <div className="department-card">
              <div className="department-header">
                <h4>Mathematics</h4>
                <span className="performance-score low">78%</span>
              </div>
              <div className="department-metrics">
                <div className="metric">
                  <span className="metric-label">Enrollment:</span>
                  <span className="metric-value">892</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Pass Rate:</span>
                  <span className="metric-value">79%</span>
                </div>
                <div className="metric">
                  <span className="metric-label">Satisfaction:</span>
                  <span className="metric-value">4.1/5</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* New Upcoming Events Section */}
        <div className="events-section">
          <div className="section-header">
            <h3>Upcoming Events</h3>
            <button className="view-calendar-btn">
              View Full Calendar
            </button>
          </div>
          <div className="events-list">
            <div className="event-item">
              <div className="event-date">
                <div className="event-day">15</div>
                <div className="event-month">MAR</div>
              </div>
              <div className="event-details">
                <div className="event-title">Faculty Development Workshop</div>
                <div className="event-time">10:00 AM - 2:00 PM</div>
              </div>
              <div className="event-status upcoming">Upcoming</div>
            </div>
            
            <div className="event-item">
              <div className="event-date">
                <div className="event-day">20</div>
                <div className="event-month">MAR</div>
              </div>
              <div className="event-details">
                <div className="event-title">Semester End Review Meeting</div>
                <div className="event-time">9:00 AM - 11:00 AM</div>
              </div>
              <div className="event-status upcoming">Upcoming</div>
            </div>
            
            <div className="event-item">
              <div className="event-date">
                <div className="event-day">25</div>
                <div className="event-month">MAR</div>
              </div>
              <div className="event-details">
                <div className="event-title">Student Research Symposium</div>
                <div className="event-time">All Day</div>
              </div>
              <div className="event-status upcoming">Upcoming</div>
            </div>
          </div>
        </div>

        <main className="main-content-area">
          {/* System Maintenance Alert */}
          <div className="system-alert maintenance-alert">
            <div className="alert-content">
              <AlertTriangle className="alert-icon" />
              <div className="alert-body">
                <h3 className="alert-title">System Maintenance Scheduled</h3>
                <p className="alert-message">
                  The student portal will be unavailable tomorrow from 2:00 AM to 4:00 AM for scheduled maintenance.
                </p>
                <p className="alert-meta">IT Administration • 2024-01-16 14:30</p>
              </div>
              <button className="alert-close">
                <X className="icon-small" />
              </button>
            </div>
          </div>

          {/* System Announcements */}
          <div className="announcements-container">
            <div className="announcements-header">
              <div className="announcements-title-section">
                <Calendar className="icon-medium" />
                <h2 className="announcements-title">System Announcements</h2>
              </div>
              <div className="announcements-actions">
                <span className="active-count">{activeNotifications.length} active</span>
                <button className="create-announcement-btn">
                  Create Announcement
                </button>
              </div>
            </div>

            <div className="announcements-list">
              {notifications.map((notification) => (
                <div key={notification.id} className="announcement-item">
                  <div className="announcement-content">
                    <div className="announcement-icon-wrapper">
                      <div className={`announcement-icon ${notification.type}`}>
                        {getIcon(notification.type)}
                      </div>
                    </div>
                    <div className="announcement-body">
                      <h3 className="announcement-title">{notification.title}</h3>
                      <p className="announcement-message">{notification.message}</p>
                      <div className="announcement-meta">
                        <span className="meta-item">
                          <Users className="meta-icon" />
                          {notification.audience}
                        </span>
                        <span className="meta-item">
                          <Calendar className="meta-icon" />
                          {new Date(notification.time).toLocaleString()}
                        </span>
                        {notification.expires && (
                          <span className="meta-item">Expires: {new Date(notification.expires).toLocaleDateString()}</span>
                        )}
                      </div>
                      <p className="announcement-author">By {notification.author}</p>
                    </div>
                  </div>
                  <div className="announcement-actions">
                    <span className={`status-badge ${notification.type}`}>
                      {notification.type}
                    </span>
                    <button 
                      onClick={() => removeNotification(notification.id)}
                      className="remove-btn"
                    >
                      <X className="icon-small" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* System Overview Section */}
          <div className="system-overview">
            <h2 className="section-title">System Overview</h2>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-content">
                  <div className="stat-info">
                    <p className="stat-label">Total Students</p>
                    <div className="stat-icon-wrapper">
                      <Users className="stat-icon-small blue" />
                    </div>
                  </div>
                  <div className="stat-main">
                    <p className="stat-value">{overview.total_students?.toLocaleString()}</p>
                    <p className="stat-change positive">↗ 8.2% from last semester</p>
                  </div>
                </div>
              </div>
              
              <div className="stat-card">
                <div className="stat-content">
                  <div className="stat-info">
                    <p className="stat-label">Active Faculty</p>
                    <div className="stat-icon-wrapper">
                      <GraduationCap className="stat-icon-small green" />
                    </div>
                  </div>
                  <div className="stat-main">
                    <p className="stat-value">{overview.total_faculty}</p>
                    <p className="stat-change positive">↗ 2.1% from last month</p>
                  </div>
                </div>
              </div>
              
              <div className="stat-card">
                <div className="stat-content">
                  <div className="stat-info">
                    <p className="stat-label">Courses Offered</p>
                    <div className="stat-icon-wrapper">
                      <BookOpen className="stat-icon-small blue" />
                    </div>
                  </div>
                  <div className="stat-main">
                    <p className="stat-value">{overview.total_courses}</p>
                    <p className="stat-change neutral">— No change this semester</p>
                  </div>
                </div>
              </div>
              
              <div className="stat-card">
                <div className="stat-content">
                  <div className="stat-info">
                    <p className="stat-label">Pass Rate</p>
                    <div className="stat-icon-wrapper">
                      <BarChart3 className="stat-icon-small blue" />
                    </div>
                  </div>
                  <div className="stat-main">
                    <p className="stat-value">{analytics.pass_rate}%</p>
                    <p className="stat-change positive">↗ 1.8% from last year</p>
                  </div>
                </div>
              </div>
              
              <div className="stat-card live-card">
                <div className="stat-content">
                  <div className="stat-info">
                    <p className="stat-label">Active Users</p>
                    <div className="live-indicator">
                      <div className="live-dot"></div>
                      <span className="live-text">LIVE</span>
                    </div>
                  </div>
                  <div className="stat-main">
                    <p className="stat-value">1,220</p>
                    <p className="stat-change neutral">Currently online</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Analytics & Performance Section */}
          <div className="analytics-section">
            <h2 className="section-title">Analytics & Performance</h2>
            <div className="analytics-grid">
              {/* Resource Utilization */}
              <div className="analytics-card">
                <h3 className="analytics-card-title">Resource Utilization</h3>
                <div className="pie-chart-container">
                  <div className="pie-chart">
                    <div className="pie-segment classrooms" style={{transform: 'rotate(0deg)'}}>
                      <div className="pie-slice" style={{transform: 'rotate(245deg)'}}></div>
                    </div>
                    <div className="pie-segment labs" style={{transform: 'rotate(245deg)'}}>
                      <div className="pie-slice" style={{transform: 'rotate(86deg)'}}></div>
                    </div>
                    <div className="pie-segment library" style={{transform: 'rotate(331deg)'}}>
                      <div className="pie-slice" style={{transform: 'rotate(29deg)'}}></div>
                    </div>
                    <div className="pie-center"></div>
                  </div>
                  <div className="pie-labels">
                    <div className="pie-label">
                      <span className="color-dot classrooms-dot"></span>
                      <span>Classrooms: 68%</span>
                    </div>
                    <div className="pie-label">
                      <span className="color-dot labs-dot"></span>
                      <span>Labs: 24%</span>
                    </div>
                    <div className="pie-label">
                      <span className="color-dot library-dot"></span>
                      <span>Library: 8%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Grade Distribution */}
              <div className="analytics-card">
                <h3 className="analytics-card-title">Grade Distribution</h3>
                <div className="bar-chart">
                  {analytics.grade_distribution && Object.entries(analytics.grade_distribution).map(([grade, count]) => (
                    <div key={grade} className="bar-container">
                      <div className="bar" style={{height: `${(count / analytics.total_grades_recorded) * 100}%`}}>
                        <div className="bar-fill"></div>
                      </div>
                      <div className="bar-label">{grade}</div>
                    </div>
                  ))}
                </div>
                <div className="chart-y-axis">
                  <span>{Math.max(...Object.values(analytics.grade_distribution || {}))}</span>
                  <span>{Math.round(Math.max(...Object.values(analytics.grade_distribution || {})) * 0.75)}</span>
                  <span>{Math.round(Math.max(...Object.values(analytics.grade_distribution || {})) * 0.5)}</span>
                  <span>{Math.round(Math.max(...Object.values(analytics.grade_distribution || {})) * 0.25)}</span>
                  <span>0</span>
                </div>
              </div>

              {/* Faculty Performance */}
              <div className="analytics-card">
                <h3 className="analytics-card-title">Faculty Performance</h3>
                <div className="performance-metrics">
                  <div className="metric-row">
                    <span className="metric-label">Research</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '85%'}}></div>
                    </div>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Student Satisfaction</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '92%'}}></div>
                    </div>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Innovation</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '78%'}}></div>
                    </div>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Pass Rate</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '94%'}}></div>
                    </div>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Grading Speed</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '88%'}}></div>
                    </div>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Feedback Score</span>
                    <div className="metric-bar">
                      <div className="metric-fill" style={{width: '90%'}}></div>
                    </div>
                  </div>
                </div>
                <div className="performance-scale">
                  <span>0</span>
                  <span>2</span>
                  <span>5</span>
                </div>
              </div>
            </div>
          </div>

          {/* Department Analytics Section */}
          <div className="department-analytics">
            <div className="department-grid">
              {/* Dropout Risk by Department */}
              <div className="department-card">
                <h3 className="department-card-title">Dropout Risk by Department</h3>
                <div className="dropout-risk-list">
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Computer Science</span>
                      <span className="student-count">1247 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage low">15%</span>
                      <span className="risk-label low">Low Risk</span>
                    </div>
                  </div>
                  
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Engineering</span>
                      <span className="student-count">2134 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage medium">23%</span>
                      <span className="risk-label medium">Medium Risk</span>
                    </div>
                  </div>
                  
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Business</span>
                      <span className="student-count">892 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage low">8%</span>
                      <span className="risk-label low">Low Risk</span>
                    </div>
                  </div>
                  
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Physics</span>
                      <span className="student-count">674 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage high">35%</span>
                      <span className="risk-label high">High Risk</span>
                    </div>
                  </div>
                  
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Mathematics</span>
                      <span className="student-count">456 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage low">18%</span>
                      <span className="risk-label low">Low Risk</span>
                    </div>
                  </div>
                  
                  <div className="risk-item">
                    <div className="risk-info">
                      <span className="department-name">Literature</span>
                      <span className="student-count">334 students</span>
                    </div>
                    <div className="risk-indicator">
                      <span className="risk-percentage low">12%</span>
                      <span className="risk-label low">Low Risk</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Pass Rates by Subject */}
              <div className="department-card">
                <h3 className="department-card-title">Pass Rates by Subject</h3>
                <div className="pass-rates-list">
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">Mathematics</span>
                      <span className="pass-percentage">87%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '87%'}}></div>
                    </div>
                  </div>
                  
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">Physics</span>
                      <span className="pass-percentage">79%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '79%'}}></div>
                    </div>
                  </div>
                  
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">Chemistry</span>
                      <span className="pass-percentage">91%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '91%'}}></div>
                    </div>
                  </div>
                  
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">Computer Science</span>
                      <span className="pass-percentage">94%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '94%'}}></div>
                    </div>
                  </div>
                  
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">English</span>
                      <span className="pass-percentage">96%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '96%'}}></div>
                    </div>
                  </div>
                  
                  <div className="pass-rate-item">
                    <div className="subject-info">
                      <span className="subject-name">History</span>
                      <span className="pass-percentage">89%</span>
                    </div>
                    <div className="pass-rate-bar">
                      <div className="pass-rate-fill" style={{width: '89%'}}></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="advanced-analytics">
            <h2 className="section-title"></h2>
            
            {/* Course Demand Forecast */}
            <div className="forecast-section">
              <div className="forecast-card">
                <h3 className="forecast-card-title">Course Demand Forecast</h3>
                <div className="line-chart-container">
                  <div className="chart-legend">
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
                  <div className="line-chart">
                    <div className="chart-y-axis-forecast">
                      <span>400</span>
                      <span>300</span>
                      <span>200</span>
                      <span>100</span>
                      <span>0</span>
                    </div>
                    <div className="chart-area">
                      <svg className="line-chart-svg" viewBox="0 0 400 200">
                        {/* Grid lines */}
                        <defs>
                          <pattern id="grid" width="66.67" height="50" patternUnits="userSpaceOnUse">
                            <path d="M 66.67 0 L 0 0 0 50" fill="none" stroke="#e5e7eb" strokeWidth="1"/>
                          </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#grid)" />
                        
                        {/* Computer Science Line (Blue) */}
                        <polyline
                          fill="none"
                          stroke="#3b82f6"
                          strokeWidth="2"
                          points="0,150 66.67,140 133.33,125 200,110 266.67,95 333.33,85 400,75"
                        />
                        <circle cx="0" cy="150" r="3" fill="#3b82f6" />
                        <circle cx="66.67" cy="140" r="3" fill="#3b82f6" />
                        <circle cx="133.33" cy="125" r="3" fill="#3b82f6" />
                        <circle cx="200" cy="110" r="3" fill="#3b82f6" />
                        <circle cx="266.67" cy="95" r="3" fill="#3b82f6" />
                        <circle cx="333.33" cy="85" r="3" fill="#3b82f6" />
                        <circle cx="400" cy="75" r="3" fill="#3b82f6" />
                        
                        {/* Engineering Line (Green) */}
                        <polyline
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="2"
                          points="0,175 66.67,170 133.33,165 200,160 266.67,155 333.33,150 400,145"
                        />
                        <circle cx="0" cy="175" r="3" fill="#10b981" />
                        <circle cx="66.67" cy="170" r="3" fill="#10b981" />
                        <circle cx="133.33" cy="165" r="3" fill="#10b981" />
                        <circle cx="200" cy="160" r="3" fill="#10b981" />
                        <circle cx="266.67" cy="155" r="3" fill="#10b981" />
                        <circle cx="333.33" cy="150" r="3" fill="#10b981" />
                        <circle cx="400" cy="145" r="3" fill="#10b981" />
                        
                        {/* Business Line (Yellow) */}
                        <polyline
                          fill="none"
                          stroke="#eab308"
                          strokeWidth="2"
                          points="0,185 66.67,180 133.33,175 200,170 266.67,165 333.33,160 400,155"
                        />
                        <circle cx="0" cy="185" r="3" fill="#eab308" />
                        <circle cx="66.67" cy="180" r="3" fill="#eab308" />
                        <circle cx="133.33" cy="175" r="3" fill="#eab308" />
                        <circle cx="200" cy="170" r="3" fill="#eab308" />
                        <circle cx="266.67" cy="165" r="3" fill="#eab308" />
                        <circle cx="333.33" cy="160" r="3" fill="#eab308" />
                        <circle cx="400" cy="155" r="3" fill="#eab308" />
                        
                        {/* Mathematics Line (Orange) */}
                        <polyline
                          fill="none"
                          stroke="#f97316"
                          strokeWidth="2"
                          points="0,190 66.67,188 133.33,185 200,182 266.67,180 333.33,175 400,170"
                        />
                        <circle cx="0" cy="190" r="3" fill="#f97316" />
                        <circle cx="66.67" cy="188" r="3" fill="#f97316" />
                        <circle cx="133.33" cy="185" r="3" fill="#f97316" />
                        <circle cx="200" cy="182" r="3" fill="#f97316" />
                        <circle cx="266.67" cy="180" r="3" fill="#f97316" />
                        <circle cx="333.33" cy="175" r="3" fill="#f97316" />
                        <circle cx="400" cy="170" r="3" fill="#f97316" />
                      </svg>
                      <div className="chart-x-axis">
                        <span>Fall 22</span>
                        <span>Spring 23</span>
                        <span>Fall 23</span>
                        <span>Spring 24</span>
                        <span>Fall 24</span>
                        <span>Spring 25</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Performance Benchmarking & Student Engagement */}
            <div className="benchmarking-engagement-grid">
              {/* Performance Benchmarking */}
              <div className="benchmarking-card">
                <h3 className="benchmarking-card-title">Performance Benchmarking</h3>
                <div className="horizontal-bar-chart">
                  <div className="benchmark-item">
                    <div className="benchmark-label">Pass Rate</div>
                    <div className="benchmark-bar-container">
                      <div className="benchmark-bar">
                        <div className="benchmark-fill" style={{width: '94%'}}></div>
                      </div>
                      <span className="benchmark-value">0.94</span>
                    </div>
                  </div>
                  
                  <div className="benchmark-item">
                    <div className="benchmark-label">Student Satisfaction</div>
                    <div className="benchmark-bar-container">
                      <div className="benchmark-bar">
                        <div className="benchmark-fill" style={{width: '88%'}}></div>
                      </div>
                      <span className="benchmark-value">0.88</span>
                    </div>
                  </div>
                  
                  <div className="benchmark-item">
                    <div className="benchmark-label">Faculty Ratio</div>
                    <div className="benchmark-bar-container">
                      <div className="benchmark-bar">
                        <div className="benchmark-fill" style={{width: '75%'}}></div>
                      </div>
                      <span className="benchmark-value">0.75</span>
                    </div>
                  </div>
                  
                  <div className="benchmark-item">
                    <div className="benchmark-label">Research Output</div>
                    <div className="benchmark-bar-container">
                      <div className="benchmark-bar">
                        <div className="benchmark-fill" style={{width: '82%'}}></div>
                      </div>
                      <span className="benchmark-value">0.82</span>
                    </div>
                  </div>
                  
                  <div className="benchmark-item">
                    <div className="benchmark-label">Employment Rate</div>
                    <div className="benchmark-bar-container">
                      <div className="benchmark-bar">
                        <div className="benchmark-fill" style={{width: '91%'}}></div>
                      </div>
                      <span className="benchmark-value">0.91</span>
                    </div>
                  </div>
                  
                  <div className="benchmark-scale">
                    <span>0</span>
                    <span>0.25</span>
                    <span>0.5</span>
                    <span>0.75</span>
                    <span>1</span>
                  </div>
                </div>
              </div>

              {/* Student Engagement Trends */}
              <div className="engagement-card">
                <h3 className="engagement-card-title">Student Engagement Trends</h3>
                <div className="engagement-chart-container">
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
                  <div className="engagement-chart">
                    <div className="engagement-y-axis">
                      <span>100</span>
                      <span>75</span>
                      <span>50</span>
                      <span>25</span>
                      <span>0</span>
                    </div>
                    <div className="engagement-chart-area">
                      <svg className="engagement-chart-svg" viewBox="0 0 300 150">
                        {/* Grid lines */}
                        <defs>
                          <pattern id="engagement-grid" width="50" height="37.5" patternUnits="userSpaceOnUse">
                            <path d="M 50 0 L 0 0 0 37.5" fill="none" stroke="#e5e7eb" strokeWidth="1"/>
                          </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#engagement-grid)" />
                        
                        {/* Attendance Line (Blue) */}
                        <polyline
                          fill="none"
                          stroke="#3b82f6"
                          strokeWidth="2"
                          points="0,30 50,27 100,25 150,24 200,22 250,20 300,18"
                        />
                        <circle cx="0" cy="30" r="2" fill="#3b82f6" />
                        <circle cx="50" cy="27" r="2" fill="#3b82f6" />
                        <circle cx="100" cy="25" r="2" fill="#3b82f6" />
                        <circle cx="150" cy="24" r="2" fill="#3b82f6" />
                        <circle cx="200" cy="22" r="2" fill="#3b82f6" />
                        <circle cx="250" cy="20" r="2" fill="#3b82f6" />
                        <circle cx="300" cy="18" r="2" fill="#3b82f6" />
                        
                        {/* Assignment Submission Line (Green) */}
                        <polyline
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="2"
                          points="0,75 50,65 100,60 150,55 200,50 250,45 300,18"
                        />
                        <circle cx="0" cy="75" r="2" fill="#10b981" />
                        <circle cx="50" cy="65" r="2" fill="#10b981" />
                        <circle cx="100" cy="60" r="2" fill="#10b981" />
                        <circle cx="150" cy="55" r="2" fill="#10b981" />
                        <circle cx="200" cy="50" r="2" fill="#10b981" />
                        <circle cx="250" cy="45" r="2" fill="#10b981" />
                        <circle cx="300" cy="18" r="2" fill="#10b981" />
                        
                        {/* Discussion Participation Line (Yellow) */}
                        <polyline
                          fill="none"
                          stroke="#eab308"
                          strokeWidth="2"
                          points="0,112 50,105 100,105 150,100 200,85 250,75 300,93"
                        />
                        <circle cx="0" cy="112" r="2" fill="#eab308" />
                        <circle cx="50" cy="105" r="2" fill="#eab308" />
                        <circle cx="100" cy="105" r="2" fill="#eab308" />
                        <circle cx="150" cy="100" r="2" fill="#eab308" />
                        <circle cx="200" cy="85" r="2" fill="#eab308" />
                        <circle cx="250" cy="75" r="2" fill="#eab308" />
                        <circle cx="300" cy="93" r="2" fill="#eab308" />
                      </svg>
                      <div className="engagement-x-axis">
                        <span>Jan</span>
                        <span>Feb</span>
                        <span>Mar</span>
                        <span>Apr</span>
                        <span>May</span>
                        <span>Jun</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="gap-analysis-section">
            <div className="gap-analysis-header">
              <h2 className="section-title">Gap Analysis & Predictive Insights</h2>
            </div>
            
            <div className="priority-opportunities">
              <div className="priority-header">
                <h3 className="priority-title">Priority Improvement Opportunities</h3>
                <span className="opportunities-count">5 opportunities identified</span>
              </div>
              
              <div className="opportunities-grid">
                <div className="opportunity-card high-impact">
                  <div className="opportunity-header">
                    <div className="opportunity-number">#1</div>
                    <div className="impact-badge high">high impact</div>
                  </div>
                  <h4 className="opportunity-title">Reduce Physics Department Dropout Rate</h4>
                  <p className="opportunity-description">Implement early intervention system for at-risk students</p>
                  
                  <div className="opportunity-details">
                    <div className="detail-row">
                      <span className="detail-label">Category:</span>
                      <span className="detail-value">Academic Performance</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Timeline:</span>
                      <span className="detail-value">3 months</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Effort:</span>
                      <span className="detail-value">medium</span>
                    </div>
                  </div>
                  
                  <div className="expected-impact">
                    <span className="impact-label">Expected Impact:</span>
                    <span className="impact-value positive">15% reduction in dropout rate</span>
                  </div>
                  
                  <button className="action-plan-btn">
                    Create Action Plan →
                  </button>
                </div>

                <div className="opportunity-card medium-impact">
                  <div className="opportunity-header">
                    <div className="opportunity-number">#2</div>
                    <div className="impact-badge medium">medium impact</div>
                  </div>
                  <h4 className="opportunity-title">Enhance Faculty Digital Skills</h4>
                  <p className="opportunity-description">Provide comprehensive LMS training program</p>
                  
                  <div className="opportunity-details">
                    <div className="detail-row">
                      <span className="detail-label">Category:</span>
                      <span className="detail-value">Technology Adoption</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Timeline:</span>
                      <span className="detail-value">6 weeks</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Effort:</span>
                      <span className="detail-value">low</span>
                    </div>
                  </div>
                  
                  <div className="expected-impact">
                    <span className="impact-label">Expected Impact:</span>
                    <span className="impact-value positive">25% increase in platform usage</span>
                  </div>
                  
                  <button className="action-plan-btn">
                    Create Action Plan →
                  </button>
                </div>

                <div className="opportunity-card high-impact">
                  <div className="opportunity-header">
                    <div className="opportunity-number">#3</div>
                    <div className="impact-badge high">high impact</div>
                  </div>
                  <h4 className="opportunity-title">Optimize Course Scheduling</h4>
                  <p className="opportunity-description">Use AI to reduce conflicts and improve resource utilization</p>
                  
                  <div className="opportunity-details">
                    <div className="detail-row">
                      <span className="detail-label">Category:</span>
                      <span className="detail-value">Operations</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Timeline:</span>
                      <span className="detail-value">4 months</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Effort:</span>
                      <span className="detail-value effort-high">high</span>
                    </div>
                  </div>
                  
                  <div className="expected-impact">
                    <span className="impact-label">Expected Impact:</span>
                    <span className="impact-value positive">30% better resource efficiency</span>
                  </div>
                  
                  <button className="action-plan-btn">
                    Create Action Plan →
                  </button>
                </div>

                <div className="opportunity-card medium-impact">
                  <div className="opportunity-header">
                    <div className="opportunity-number">#4</div>
                    <div className="impact-badge medium">medium impact</div>
                  </div>
                  <h4 className="opportunity-title">Expand Popular Elective Courses</h4>
                  <p className="opportunity-description">Increase sections for high-demand AI/ML courses</p>
                  
                  <div className="opportunity-details">
                    <div className="detail-row">
                      <span className="detail-label">Category:</span>
                      <span className="detail-value">Curriculum</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Timeline:</span>
                      <span className="detail-value">2 months</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Effort:</span>
                      <span className="detail-value">medium</span>
                    </div>
                  </div>
                  
                  <div className="expected-impact">
                    <span className="impact-label">Expected Impact:</span>
                    <span className="impact-value positive">40% more student satisfaction</span>
                  </div>
                  
                  <button className="action-plan-btn">
                    Create Action Plan →
                  </button>
                </div>

                <div className="opportunity-card medium-impact">
                  <div className="opportunity-header">
                    <div className="opportunity-number">#5</div>
                    <div className="impact-badge medium">medium impact</div>
                  </div>
                  <h4 className="opportunity-title">Student Engagement Initiative</h4>
                  <p className="opportunity-description">Launch peer mentoring and study group programs</p>
                  
                  <div className="opportunity-details">
                    <div className="detail-row">
                      <span className="detail-label">Category:</span>
                      <span className="detail-value">Student Success</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Timeline:</span>
                      <span className="detail-value">8 weeks</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Effort:</span>
                      <span className="detail-value">low</span>
                    </div>
                  </div>
                  
                  <div className="expected-impact">
                    <span className="impact-label">Expected Impact:</span>
                    <span className="impact-value positive">20% improvement in retention</span>
                  </div>
                  
                  <button className="action-plan-btn">
                    Create Action Plan →
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Student & Faculty Management Section */}
          <div className="management-section">
            <h2 className="section-title">Student & Faculty Management</h2>
            
            <div className="at-risk-students">
              <div className="at-risk-header">
                <div className="at-risk-title">
                  <AlertTriangle className="warning-icon" />
                  <h3>At-Risk Students</h3>
                </div>
                <button className="export-btn">
                  Export
                </button>
              </div>
              
              <div className="students-table">
                <div className="table-header">
                  <div className="header-cell">Student</div>
                  <div className="header-cell">Department</div>
                  <div className="header-cell">GPA</div>
                  <div className="header-cell">Risk Level</div>
                  <div className="header-cell">Actions</div>
                </div>
                
                {atRiskStudents.slice(0, 4).map(student => (
                  <div key={student.id} className="table-row">
                    <div className="student-info">
                      <div className="student-name">
                        {student.name || `${student.first_name} ${student.last_name}`}
                      </div>
                      <div className="student-id">{student.student_id}</div>
                    </div>
                    <div className="department">{student.department}</div>
                    <div className="gpa">{student.gpa}</div>
                    <div className={`risk-level ${student.risk_level}`}>
                      {student.risk_level}
                    </div>
                    <div className="action-buttons">
                      <button className="contact-btn">✉</button>
                      <button className="call-btn">📞</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="faculty-course-grid">
              <div className="faculty-workload">
                <h3 className="card-title">Faculty Workload</h3>
                <div className="workload-table">
                  <div className="workload-header">
                    <div>Faculty</div>
                    <div>Courses</div>
                    <div>Students</div>
                    <div>Load</div>
                  </div>
                  
                  {facultyWorkload.slice(0, 3).map(faculty => (
                    <div key={faculty.faculty_id} className="workload-row">
                      <div className="faculty-info">
                        <div className="faculty-name">{faculty.name}</div>
                        <div className="faculty-dept">{faculty.department}</div>
                      </div>
                      <div>{faculty.sections_count}</div>
                      <div>{faculty.total_students}</div>
                      <div className={`load-badge ${faculty.utilization_percentage > 90 ? 'high' : 'normal'}`}>
                        {faculty.utilization_percentage > 90 ? 'high' : 'normal'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="course-enrollment">
                <h3 className="card-title">Course Enrollment</h3>
                <div className="enrollment-table">
                  <div className="enrollment-header">
                    <div>Course</div>
                    <div>Enrolled</div>
                    <div>Utilization</div>
                    <div>Status</div>
                  </div>
                  
                  {courseEnrollment.slice(0, 3).map(course => (
                    <div key={course.course_code} className="enrollment-row">
                      <div className="course-info">
                        <div className="course-code">{course.course_code}</div>
                        <div className="course-name">{course.course_title}</div>
                      </div>
                      <div>{course.total_enrolled}/{course.total_capacity}</div>
                      <div>{course.utilization_rate}%</div>
                      <div className={`status-badge ${course.utilization_rate > 90 ? 'full' : 'open'}`}>
                        {course.utilization_rate > 90 ? 'full' : 'open'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Reports & Compliance Section */}
          <div className="reports-section">
            <h2 className="section-title">Reports & Compliance</h2>
            
            <div className="reports-grid">
              <div className="report-templates">
                <div className="reports-header">
                  <div className="reports-title-section">
                    <FileText className="reports-icon" />
                    <h3>Report Templates</h3>
                  </div>
                  <select className="category-filter">
                    <option>All Categories</option>
                    <option>Academic</option>
                    <option>Financial</option>
                    <option>Administrative</option>
                  </select>
                </div>
                
                <div className="report-list">
                  <div className="report-item">
                    <div className="report-icon-wrapper">
                      <Users className="report-icon blue" />
                    </div>
                    <div className="report-content">
                      <h4 className="report-title">Student Performance Report</h4>
                      <p className="report-description">Comprehensive analysis of student academic performance</p>
                      <div className="report-meta">
                        <span>Last generated: 2024-01-15 • 5 recipients</span>
                      </div>
                    </div>
                    <div className="report-actions">
                      <span className="frequency-badge">Monthly</span>
                      <button className="generate-btn">Generate</button>
                    </div>
                  </div>
                  
                  <div className="report-item">
                    <div className="report-icon-wrapper">
                      <DollarSign className="report-icon green" />
                    </div>
                    <div className="report-content">
                      <h4 className="report-title">Financial Summary Report</h4>
                      <p className="report-description">Revenue, expenses, and budget analysis</p>
                      <div className="report-meta">
                        <span>Last generated: 2024-01-01 • 3 recipients</span>
                      </div>
                    </div>
                    <div className="report-actions">
                      <span className="frequency-badge">Quarterly</span>
                      <button className="generate-btn">Generate</button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="scheduled-reports">
                <div className="scheduled-header">
                  <h3 className="scheduled-title">Scheduled Reports</h3>
                </div>
                
                <div className="scheduled-list">
                  <div className="scheduled-item">
                    <div className="scheduled-content">
                      <h4>Weekly Performance Summary</h4>
                      <div className="scheduled-meta">
                        <span>Next: 2024-01-22 09:00</span>
                        <span>Frequency: Weekly</span>
                      </div>
                    </div>
                    <div className="scheduled-status active">active</div>
                  </div>
                  
                  <div className="scheduled-item">
                    <div className="scheduled-content">
                      <h4>Monthly Financial Report</h4>
                      <div className="scheduled-meta">
                        <span>Next: 2024-02-01 08:00</span>
                        <span>Frequency: Monthly</span>
                      </div>
                    </div>
                    <div className="scheduled-status active">active</div>
                  </div>
                </div>
                
                <div className="scheduled-actions">
                  <button className="schedule-new-btn">
                    📅 Schedule New Report
                  </button>
                  <button className="manage-recipients-btn">
                    ✉ Manage Recipients
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Financial Summary */}
          <div className="financial-summary">
            <div className="financial-header">
              <DollarSign className="dollar-icon-large" />
              <h3>Financial Report Summary</h3>
            </div>
            
            <div className="financial-table-header">
              <div>Category</div>
              <div>Amount</div>
              <div>Change</div>
              <div>Type</div>
            </div>

            <div className="financial-table-content">
              <div className="financial-row">
                <div className="financial-category">Tuition Revenue</div>
                <div className="financial-amount">$2,400,000</div>
                <div className="financial-change positive">+8.2%</div>
                <div className="financial-type income">income</div>
              </div>
              
              <div className="financial-row">
                <div className="financial-category">Faculty Salaries</div>
                <div className="financial-amount">$1,800,000</div>
                <div className="financial-change positive">+4.3%</div>
                <div className="financial-type expense">expense</div>
              </div>
              
              <div className="financial-row">
                <div className="financial-category">Infrastructure</div>
                <div className="financial-amount">$400,000</div>
                <div className="financial-change positive">+15.2%</div>
                <div className="financial-type expense">expense</div>
              </div>
            </div>
            
            <div className="financial-footer">
              <div className="financial-updated">
                Updated: {new Date().toLocaleDateString()} at {new Date().toLocaleTimeString()}
              </div>
              <div className="financial-export-buttons">
                <button className="export-pdf-btn">
                  📄 Export PDF
                </button>
                <button className="export-excel-btn">
                  📊 Export Excel
                </button>
              </div>
            </div>
          </div>

          {/* Alerts & Monitoring Section */}
          <div className="alerts-monitoring-section">
            <h2 className="section-title">Alerts & Monitoring</h2>
            
            <div className="alerts-grid">
              {/* System Alerts */}
              <div className="system-alerts-card">
                <div className="alerts-card-header">
                  <div className="alerts-title-section">
                    <Bell className="alerts-icon" />
                    <h3>System Alerts</h3>
                  </div>
                  <span className="active-alerts-count">{activeNotifications.length} active</span>
                </div>
                
                <div className="alerts-list">
                  {notifications.slice(0, 3).map(alert => (
                    <div key={alert.id} className={`alert-item ${alert.type}-priority`}>
                      <div className="alert-icon-wrapper">
                        {getIcon(alert.type)}
                      </div>
                      <div className="alert-content">
                        <h4 className="alert-item-title">{alert.title}</h4>
                        <p className="alert-description">{alert.message}</p>
                        <span className="alert-time">
                          {new Date(alert.time).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="alert-actions">
                        <span className={`alert-priority ${alert.type}`}>
                          {alert.type}
                        </span>
                        <button 
                          className="alert-dismiss"
                          onClick={() => removeNotification(alert.id)}
                        >
                          <X className="icon-small" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Threshold Monitoring */}
              <div className="threshold-monitoring-card">
                <div className="threshold-header">
                  <h3>System Performance</h3>
                </div>
                
                <div className="threshold-metrics">
                  <div className="threshold-metric">
                    <div className="metric-info">
                      <span className="metric-name">Server Uptime</span>
                      <span className="metric-status normal">99.9%</span>
                    </div>
                    <div className="metric-bar-container">
                      <div className="metric-progress-bar">
                        <div className="metric-fill normal" style={{width: '99.9%'}}></div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="threshold-metric">
                    <div className="metric-info">
                      <span className="metric-name">Database Performance</span>
                      <span className="metric-status normal">98.2%</span>
                    </div>
                    <div className="metric-bar-container">
                      <div className="metric-progress-bar">
                        <div className="metric-fill normal" style={{width: '98.2%'}}></div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="threshold-metric">
                    <div className="metric-info">
                      <span className="metric-name">Response Time</span>
                      <span className="metric-status normal">142ms</span>
                    </div>
                    <div className="metric-bar-container">
                      <div className="metric-progress-bar">
                        <div className="metric-fill normal" style={{width: '85%'}}></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default EduDashboard;