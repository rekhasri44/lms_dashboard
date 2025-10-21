import React, { useState, useCallback, useMemo, useRef } from 'react';
import { 
  FileText, Download, Plus, Calendar, AlertTriangle, 
  RefreshCw, Eye, Clock, CheckCircle, X, BarChart3, Users,
  BookOpen, GraduationCap, DollarSign
} from 'lucide-react';
import { reportsAPI, studentsAPI, coursesAPI, facultyAPI } from './services/api';
import useApi from './hooks/useApi';
import './Reports.css';

// Enterprise Configuration
const ENTERPRISE_CONFIG = {
  REPORT_TYPES: {
    ACADEMIC: 'academic',
    FINANCIAL: 'financial',
    HR: 'hr',
    SYSTEM: 'system',
    COMPLIANCE: 'compliance'
  },
  FREQUENCY_OPTIONS: ['daily', 'weekly', 'monthly', 'quarterly'],
  FORMAT_OPTIONS: ['pdf', 'excel', 'csv'],
  DETAIL_LEVELS: ['summary', 'detailed', 'comprehensive'],
  PERFORMANCE: {
    MAX_RETRY_ATTEMPTS: 3,
    CACHE_DURATION: 10 * 60 * 1000 // 10 minutes
  }
};

// Enhanced Error Boundary for Reports
class ReportsErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Reports Error Boundary:', error, errorInfo);
    if (window.monitoringService) {
      window.monitoringService.captureException(error, {
        component: 'Reports',
        errorInfo,
        timestamp: new Date().toISOString()
      });
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <div className="error-content">
            <AlertTriangle size={32} />
            <h3>Reports Module Error</h3>
            <p>We encountered an error while loading the reports module.</p>
            <button onClick={this.handleReset} className="btn-primary">
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

const Reports = () => {
  // State Management
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('templates');
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [operationInProgress, setOperationInProgress] = useState(false);

  // Refs for cleanup
  const mountedRef = useRef(true);

  // Report templates with enhanced metadata
  const reportTemplates = useMemo(() => [
    {
      id: 1,
      name: 'Student Performance Report',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC,
      description: 'Comprehensive analysis of student academic performance',
      icon: Users,
      parameters: ['timeframe', 'department', 'metrics'],
      estimatedTime: '2-5 minutes',
      accessLevel: 'faculty',
      dataSources: ['grades', 'attendance', 'assessments']
    },
    {
      id: 2,
      name: 'Financial Summary Report',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.FINANCIAL,
      description: 'Revenue, expenses and budget analysis',
      icon: DollarSign,
      parameters: ['period', 'detail_level', 'format'],
      estimatedTime: '1-3 minutes',
      accessLevel: 'admin',
      dataSources: ['tuition', 'expenses', 'budget']
    },
    {
      id: 3,
      name: 'Faculty Workload Analysis',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.HR,
      description: 'Teaching assignments and performance metrics',
      icon: GraduationCap,
      parameters: ['semester', 'department', 'metrics'],
      estimatedTime: '3-7 minutes',
      accessLevel: 'admin',
      dataSources: ['schedules', 'evaluations', 'research']
    },
    {
      id: 4,
      name: 'Course Enrollment Statistics',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC,
      description: 'Detailed enrollment trends and capacity analysis',
      icon: BookOpen,
      parameters: ['semester', 'courses', 'format'],
      estimatedTime: '1-4 minutes',
      accessLevel: 'faculty',
      dataSources: ['enrollments', 'capacity', 'waitlists']
    },
    {
      id: 5,
      name: 'System Usage Analytics',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.SYSTEM,
      description: 'Platform usage and engagement metrics',
      icon: BarChart3,
      parameters: ['timeframe', 'metrics', 'format'],
      estimatedTime: '2-4 minutes',
      accessLevel: 'admin',
      dataSources: ['logs', 'sessions', 'features']
    },
    {
      id: 6,
      name: 'Compliance Audit Report',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.COMPLIANCE,
      description: 'Regulatory compliance and audit readiness',
      icon: FileText,
      parameters: ['standards', 'timeframe', 'detail_level'],
      estimatedTime: '5-10 minutes',
      accessLevel: 'admin',
      dataSources: ['policies', 'procedures', 'audits']
    }
  ], []);

  // Form states with enhanced validation
  const [generateForm, setGenerateForm] = useState({
    title: '',
    report_type: '',
    parameters: {
      timeframe: 'current_semester',
      department: 'all',
      metrics: ['enrollment', 'performance'],
      format: 'pdf',
      detail_level: 'summary'
    }
  });

  const [scheduleForm, setScheduleForm] = useState({
    title: '',
    report_type: '',
    frequency: 'weekly',
    start_date: new Date().toISOString().split('T')[0],
    recipients: [],
    parameters: {}
  });

  // Real API integration with enhanced error handling
  const { refetch: refetchReports } = useApi(
    useCallback(() => reportsAPI.getReportTemplates(), []),
    {
      retry: ENTERPRISE_CONFIG.PERFORMANCE.MAX_RETRY_ATTEMPTS,
      cacheKey: 'report-templates',
      cacheTimeout: ENTERPRISE_CONFIG.PERFORMANCE.CACHE_DURATION
    }
  );

  const { refetch: refetchScheduled } = useApi(
    useCallback(() => reportsAPI.getScheduledReports(), []),
    {
      retry: ENTERPRISE_CONFIG.PERFORMANCE.MAX_RETRY_ATTEMPTS,
      cacheKey: 'scheduled-reports',
      cacheTimeout: ENTERPRISE_CONFIG.PERFORMANCE.CACHE_DURATION
    }
  );

  // Component Cleanup
  React.useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Enhanced Generate Report Function with Validation
  const handleGenerateReport = useCallback(async (template) => {
    if (!mountedRef.current) return;

    setOperationInProgress(true);
    setError('');

    try {
      const reportData = {
        title: generateForm.title || `${template.name} - ${new Date().toLocaleDateString()}`,
        report_type: template.type,
        parameters: generateForm.parameters,
        template_id: template.id,
        requested_at: new Date().toISOString()
      };

      const response = await reportsAPI.generateReport(reportData);
      
      if (response.success) {
        setShowGenerateModal(false);
        setSelectedTemplate(null);
        
        // Track successful generation
        if (window.analyticsService) {
          window.analyticsService.track('report_generated', {
            templateId: template.id,
            reportType: template.type,
            timestamp: new Date().toISOString()
          });
        }

        // Simulate report generation process
        setTimeout(() => {
          if (mountedRef.current) {
            alert(`Report "${reportData.title}" generated successfully!`);
            refetchReports();
          }
        }, 2000);
        
      } else {
        setError(response.error || 'Failed to generate report');
      }
    } catch (err) {
      const errorMsg = 'Failed to generate report. Please try again.';
      setError(errorMsg);
      console.error('Generate report error:', err);
      
      // Track generation failure
      if (window.analyticsService) {
        window.analyticsService.track('report_generation_failed', {
          templateId: template?.id,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    } finally {
      if (mountedRef.current) {
        setOperationInProgress(false);
      }
    }
  }, [generateForm, refetchReports]);

  // Enhanced Schedule Report Function
  const handleScheduleReport = useCallback(async (e) => {
    e.preventDefault();
    if (!mountedRef.current) return;

    setOperationInProgress(true);
    setError('');

    try {
      const response = await reportsAPI.scheduleReport(scheduleForm);
      
      if (response.success) {
        setShowScheduleModal(false);
        resetScheduleForm();
        await refetchScheduled();
        
        // Track successful scheduling
        if (window.analyticsService) {
          window.analyticsService.track('report_scheduled', {
            reportType: scheduleForm.report_type,
            frequency: scheduleForm.frequency,
            timestamp: new Date().toISOString()
          });
        }
        
        alert('Report scheduled successfully!');
      } else {
        setError(response.error || 'Failed to schedule report');
      }
    } catch (err) {
      const errorMsg = 'Failed to schedule report. Please try again.';
      setError(errorMsg);
      console.error('Schedule report error:', err);
    } finally {
      if (mountedRef.current) {
        setOperationInProgress(false);
      }
    }
  }, [scheduleForm, refetchScheduled]);

  // Enhanced Download Report Function
  const handleDownloadReport = useCallback(async (reportId) => {
    if (!mountedRef.current) return;

    setLoading(true);
    setError('');

    try {
      const response = await reportsAPI.downloadReport(reportId);
      
      if (response.success) {
        // Create secure file download
        const blob = new Blob([response.data], { 
          type: 'application/pdf',
          endings: 'native'
        });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `report_${reportId}_${new Date().toISOString().split('T')[0]}.pdf`;
        link.setAttribute('type', 'application/pdf');
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Cleanup URL
        setTimeout(() => window.URL.revokeObjectURL(url), 100);
        
        // Track successful download
        if (window.analyticsService) {
          window.analyticsService.track('report_downloaded', {
            reportId,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError('Failed to download report - no data received');
      }
    } catch (err) {
      const errorMsg = 'Failed to download report. Please try again.';
      setError(errorMsg);
      console.error('Download report error:', err);
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  // Enhanced Export Data Function
  const handleExportData = useCallback(async (type) => {
    if (!mountedRef.current) return;

    setLoading(true);
    setError('');

    try {
      let response;
      let apiMethod;
      
      switch(type) {
        case 'students':
          apiMethod = studentsAPI.exportStudents;
          break;
        case 'courses':
          apiMethod = coursesAPI.exportCourses;
          break;
        case 'faculty':
          apiMethod = facultyAPI.exportFaculty;
          break;
        default:
          throw new Error('Invalid export type');
      }

      response = await apiMethod();

      if (response.success && response.data) {
        // Create secure CSV download
        const blob = new Blob([response.data], { 
          type: 'text/csv; charset=utf-8',
          endings: 'native'
        });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${type}_export_${new Date().toISOString().split('T')[0]}.csv`;
        link.setAttribute('type', 'text/csv');
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Cleanup URL
        setTimeout(() => window.URL.revokeObjectURL(url), 100);
        
        // Track successful export
        if (window.analyticsService) {
          window.analyticsService.track('data_exported', {
            dataType: type,
            timestamp: new Date().toISOString(),
            recordCount: response.data.split('\n').length - 1 // Estimate record count
          });
        }
      } else {
        setError(`Failed to export ${type} data - no data received`);
      }
    } catch (err) {
      const errorMsg = `Failed to export ${type} data. Please try again.`;
      setError(errorMsg);
      console.error('Export error:', err);
    } finally {
      if (mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  // Form Management Functions
  const resetScheduleForm = useCallback(() => {
    setScheduleForm({
      title: '',
      report_type: '',
      frequency: 'weekly',
      start_date: new Date().toISOString().split('T')[0],
      recipients: [],
      parameters: {}
    });
  }, []);

  const handleTemplateSelect = useCallback((template) => {
    setSelectedTemplate(template);
    setGenerateForm(prev => ({
      ...prev,
      title: `${template.name} - ${new Date().toLocaleDateString()}`,
      report_type: template.type
    }));
    setShowGenerateModal(true);
  }, []);

  const handleRefresh = useCallback(() => {
    setError('');
    refetchReports();
    refetchScheduled();
  }, [refetchReports, refetchScheduled]);

  const handleCloseGenerateModal = useCallback(() => {
    setShowGenerateModal(false);
    setSelectedTemplate(null);
  }, []);

  const handleCloseScheduleModal = useCallback(() => {
    setShowScheduleModal(false);
    resetScheduleForm();
  }, [resetScheduleForm]);

  // Sample generated reports data
  const generatedReports = useMemo(() => [
    {
      id: 1,
      title: 'Student Performance Report - Q1 2024',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC,
      status: 'completed',
      generated_at: '2024-03-15T10:30:00Z',
      size: '2.4 MB',
      format: 'pdf',
      accessLevel: 'faculty'
    },
    {
      id: 2,
      title: 'Financial Summary - March 2024',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.FINANCIAL,
      status: 'completed',
      generated_at: '2024-03-10T14:20:00Z',
      size: '1.8 MB',
      format: 'pdf',
      accessLevel: 'admin'
    },
    {
      id: 3,
      title: 'Faculty Workload Analysis - Spring 2024',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.HR,
      status: 'processing',
      generated_at: '2024-03-20T09:15:00Z',
      size: 'N/A',
      format: 'pdf',
      accessLevel: 'admin'
    }
  ], []);

  // Sample scheduled reports data
  const scheduledReports = useMemo(() => [
    {
      id: 1,
      title: 'Weekly Performance Summary',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC,
      frequency: 'weekly',
      next_run: '2024-03-25T09:00:00Z',
      recipients: ['admin@university.edu', 'dean@university.edu'],
      status: 'active'
    },
    {
      id: 2,
      title: 'Monthly Financial Report',
      type: ENTERPRISE_CONFIG.REPORT_TYPES.FINANCIAL,
      frequency: 'monthly',
      next_run: '2024-04-01T08:00:00Z',
      recipients: ['finance@university.edu'],
      status: 'active'
    }
  ], []);

  return (
    <ReportsErrorBoundary>
      <div className="reports-container">
        {/* Header */}
        <header className="header" role="banner">
          <h1 className="header-title">Reports & Analytics</h1>
          <div className="header-actions">
            <button 
              className="btn-primary" 
              onClick={() => setShowScheduleModal(true)}
              aria-label="Schedule new report"
            >
              <Plus size={16} aria-hidden="true" />
              Schedule Report
            </button>
            <button 
              className="btn-secondary" 
              onClick={handleRefresh}
              disabled={loading}
              aria-label="Refresh reports data"
            >
              <RefreshCw size={16} aria-hidden="true" />
              Refresh
            </button>
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
              onClick={() => setError('')} 
              className="close-btn"
              aria-label="Dismiss error message"
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
        )}

        {/* Quick Export Section */}
        <section className="quick-export-section" aria-label="Quick data export options">
          <h3>Quick Data Export</h3>
          <div className="export-cards">
            <div 
              className="export-card" 
              onClick={() => handleExportData('students')}
              role="button"
              tabIndex={0}
              aria-label="Export student data"
              onKeyPress={(e) => e.key === 'Enter' && handleExportData('students')}
            >
              <Users size={24} aria-hidden="true" />
              <div className="export-info">
                <div className="export-title">Student Data</div>
                <div className="export-desc">Export all student records</div>
              </div>
              <Download size={16} aria-hidden="true" />
            </div>
            <div 
              className="export-card" 
              onClick={() => handleExportData('courses')}
              role="button"
              tabIndex={0}
              aria-label="Export course data"
              onKeyPress={(e) => e.key === 'Enter' && handleExportData('courses')}
            >
              <BookOpen size={24} aria-hidden="true" />
              <div className="export-info">
                <div className="export-title">Course Data</div>
                <div className="export-desc">Export course catalog</div>
              </div>
              <Download size={16} aria-hidden="true" />
            </div>
            <div 
              className="export-card" 
              onClick={() => handleExportData('faculty')}
              role="button"
              tabIndex={0}
              aria-label="Export faculty data"
              onKeyPress={(e) => e.key === 'Enter' && handleExportData('faculty')}
            >
              <GraduationCap size={24} aria-hidden="true" />
              <div className="export-info">
                <div className="export-title">Faculty Data</div>
                <div className="export-desc">Export faculty information</div>
              </div>
              <Download size={16} aria-hidden="true" />
            </div>
          </div>
        </section>

        {/* Navigation Tabs */}
        <nav className="reports-tabs" aria-label="Reports navigation">
          <button 
            className={`tab ${activeTab === 'templates' ? 'active' : ''}`}
            onClick={() => setActiveTab('templates')}
            aria-selected={activeTab === 'templates'}
            aria-controls="templates-content"
          >
            <FileText size={16} aria-hidden="true" />
            Report Templates
          </button>
          <button 
            className={`tab ${activeTab === 'generated' ? 'active' : ''}`}
            onClick={() => setActiveTab('generated')}
            aria-selected={activeTab === 'generated'}
            aria-controls="generated-content"
          >
            <Download size={16} aria-hidden="true" />
            Generated Reports
          </button>
          <button 
            className={`tab ${activeTab === 'scheduled' ? 'active' : ''}`}
            onClick={() => setActiveTab('scheduled')}
            aria-selected={activeTab === 'scheduled'}
            aria-controls="scheduled-content"
          >
            <Calendar size={16} aria-hidden="true" />
            Scheduled Reports
          </button>
        </nav>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'templates' && (
            <div id="templates-content" role="tabpanel" aria-labelledby="templates-tab">
              <div className="templates-grid">
                {reportTemplates.map(template => {
                  const IconComponent = template.icon;
                  return (
                    <div key={template.id} className="template-card" role="article">
                      <div className="template-header">
                        <div className="template-icon">
                          <IconComponent size={24} aria-hidden="true" />
                        </div>
                        <div className="template-info">
                          <h4 className="template-title">{template.name}</h4>
                          <p className="template-description">{template.description}</p>
                          <div className="template-meta">
                            <span className="access-level">{template.accessLevel}</span>
                            <span className="data-sources">
                              {template.dataSources.length} data sources
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="template-details">
                        <div className="template-parameters">
                          <span className="parameters-label">Parameters:</span>
                          <div className="parameters-list">
                            {template.parameters.map(param => (
                              <span key={param} className="parameter-tag">{param}</span>
                            ))}
                          </div>
                        </div>
                        <div className="template-time">
                          <Clock size={14} aria-hidden="true" />
                          {template.estimatedTime}
                        </div>
                      </div>
                      <div className="template-actions">
                        <button 
                          className="btn-primary"
                          onClick={() => handleTemplateSelect(template)}
                          aria-label={`Generate ${template.name} report`}
                        >
                          Generate Report
                        </button>
                        <button className="btn-secondary" aria-label={`Preview ${template.name} report`}>
                          <Eye size={14} aria-hidden="true" />
                          Preview
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {activeTab === 'generated' && (
            <div id="generated-content" role="tabpanel" aria-labelledby="generated-tab">
              <div className="reports-list">
                {generatedReports.map(report => (
                  <div key={report.id} className="report-item" role="article">
                    <div className="report-info">
                      <div className="report-icon">
                        <FileText size={20} aria-hidden="true" />
                      </div>
                      <div className="report-details">
                        <div className="report-title">{report.title}</div>
                        <div className="report-meta">
                          <span className="report-type">{report.type}</span>
                          <span className="report-date">
                            {new Date(report.generated_at).toLocaleDateString()}
                          </span>
                          <span className="report-size">{report.size}</span>
                          <span className="report-format">{report.format}</span>
                          <span className="report-access">{report.accessLevel}</span>
                        </div>
                      </div>
                    </div>
                    <div className="report-actions">
                      <div className={`report-status ${report.status}`}>
                        {report.status === 'completed' && <CheckCircle size={14} aria-hidden="true" />}
                        {report.status}
                      </div>
                      {report.status === 'completed' && (
                        <button 
                          className="btn-primary"
                          onClick={() => handleDownloadReport(report.id)}
                          aria-label={`Download ${report.title}`}
                        >
                          <Download size={14} aria-hidden="true" />
                          Download
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'scheduled' && (
            <div id="scheduled-content" role="tabpanel" aria-labelledby="scheduled-tab">
              <div className="scheduled-reports">
                {scheduledReports.length > 0 ? (
                  scheduledReports.map(scheduled => (
                    <div key={scheduled.id} className="scheduled-item" role="article">
                      <div className="scheduled-info">
                        <div className="scheduled-title">{scheduled.title}</div>
                        <div className="scheduled-details">
                          <span className="frequency">{scheduled.frequency}</span>
                          <span className="next-run">
                            Next: {new Date(scheduled.next_run).toLocaleDateString()}
                          </span>
                          <span className="recipients">
                            {scheduled.recipients.length} recipients
                          </span>
                          <span className="report-type">{scheduled.type}</span>
                        </div>
                      </div>
                      <div className="scheduled-actions">
                        <button className="btn-secondary" aria-label={`View ${scheduled.title} details`}>
                          <Eye size={14} aria-hidden="true" />
                          View
                        </button>
                        <button className="btn-danger" aria-label={`Cancel ${scheduled.title}`}>
                          <X size={14} aria-hidden="true" />
                          Cancel
                        </button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state" role="status" aria-live="polite">
                    <Calendar size={48} aria-hidden="true" />
                    <h3>No scheduled reports</h3>
                    <p>Schedule your first report to automate reporting</p>
                    <button 
                      className="btn-primary" 
                      onClick={() => setShowScheduleModal(true)}
                      aria-label="Schedule first report"
                    >
                      <Plus size={16} aria-hidden="true" />
                      Schedule Report
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Generate Report Modal */}
        {showGenerateModal && selectedTemplate && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="generate-report-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="generate-report-title">Generate {selectedTemplate.name}</h3>
                <button 
                  onClick={handleCloseGenerateModal} 
                  className="close-btn"
                  aria-label="Close generate report modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <div className="modal-content">
                <div className="form-group">
                  <label htmlFor="report-title">Report Title</label>
                  <input
                    id="report-title"
                    type="text"
                    value={generateForm.title}
                    onChange={(e) => setGenerateForm({...generateForm, title: e.target.value})}
                    placeholder="Enter report title"
                    aria-required="true"
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="timeframe">Timeframe</label>
                    <select
                      id="timeframe"
                      value={generateForm.parameters.timeframe}
                      onChange={(e) => setGenerateForm({
                        ...generateForm,
                        parameters: {...generateForm.parameters, timeframe: e.target.value}
                      })}
                    >
                      <option value="current_semester">Current Semester</option>
                      <option value="last_semester">Last Semester</option>
                      <option value="current_year">Current Year</option>
                      <option value="last_year">Last Year</option>
                      <option value="custom">Custom Range</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="department">Department</label>
                    <select
                      id="department"
                      value={generateForm.parameters.department}
                      onChange={(e) => setGenerateForm({
                        ...generateForm,
                        parameters: {...generateForm.parameters, department: e.target.value}
                      })}
                    >
                      <option value="all">All Departments</option>
                      <option value="computer_science">Computer Science</option>
                      <option value="engineering">Engineering</option>
                      <option value="mathematics">Mathematics</option>
                      <option value="physics">Physics</option>
                    </select>
                  </div>
                </div>

                <div className="form-group">
                  <label>Metrics to Include</label>
                  <div className="checkbox-group" role="group" aria-label="Report metrics selection">
                    <label className="checkbox">
                      <input type="checkbox" defaultChecked />
                      Enrollment Statistics
                    </label>
                    <label className="checkbox">
                      <input type="checkbox" defaultChecked />
                      Performance Metrics
                    </label>
                    <label className="checkbox">
                      <input type="checkbox" />
                      Attendance Data
                    </label>
                    <label className="checkbox">
                      <input type="checkbox" />
                      Financial Data
                    </label>
                  </div>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="format">Format</label>
                    <select
                      id="format"
                      value={generateForm.parameters.format}
                      onChange={(e) => setGenerateForm({
                        ...generateForm,
                        parameters: {...generateForm.parameters, format: e.target.value}
                      })}
                    >
                      {ENTERPRISE_CONFIG.FORMAT_OPTIONS.map(format => (
                        <option key={format} value={format}>{format.toUpperCase()}</option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="detail-level">Detail Level</label>
                    <select
                      id="detail-level"
                      value={generateForm.parameters.detail_level}
                      onChange={(e) => setGenerateForm({
                        ...generateForm,
                        parameters: {...generateForm.parameters, detail_level: e.target.value}
                      })}
                    >
                      {ENTERPRISE_CONFIG.DETAIL_LEVELS.map(level => (
                        <option key={level} value={level}>{level.charAt(0).toUpperCase() + level.slice(1)}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
              <div className="modal-actions">
                <button 
                  type="button" 
                  onClick={handleCloseGenerateModal} 
                  className="btn-secondary"
                  disabled={operationInProgress}
                >
                  Cancel
                </button>
                <button 
                  onClick={() => handleGenerateReport(selectedTemplate)}
                  className="btn-primary"
                  disabled={operationInProgress}
                >
                  {operationInProgress ? (
                    <>
                      <RefreshCw size={16} className="spinning" aria-hidden="true" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <FileText size={16} aria-hidden="true" />
                      Generate Report
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Schedule Report Modal */}
        {showScheduleModal && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="schedule-report-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="schedule-report-title">Schedule New Report</h3>
                <button 
                  onClick={handleCloseScheduleModal} 
                  className="close-btn"
                  aria-label="Close schedule report modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleScheduleReport} className="modal-form">
                <div className="form-group">
                  <label htmlFor="schedule-title">Report Title *</label>
                  <input
                    id="schedule-title"
                    type="text"
                    value={scheduleForm.title}
                    onChange={(e) => setScheduleForm({...scheduleForm, title: e.target.value})}
                    placeholder="Enter report title"
                    required
                    aria-required="true"
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="report-type">Report Type *</label>
                    <select
                      id="report-type"
                      value={scheduleForm.report_type}
                      onChange={(e) => setScheduleForm({...scheduleForm, report_type: e.target.value})}
                      required
                      aria-required="true"
                    >
                      <option value="">Select Report Type</option>
                      <option value={ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC}>Academic Performance</option>
                      <option value={ENTERPRISE_CONFIG.REPORT_TYPES.FINANCIAL}>Financial Summary</option>
                      <option value={ENTERPRISE_CONFIG.REPORT_TYPES.HR}>Faculty Workload</option>
                      <option value={ENTERPRISE_CONFIG.REPORT_TYPES.ACADEMIC}>Enrollment Statistics</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="frequency">Frequency *</label>
                    <select
                      id="frequency"
                      value={scheduleForm.frequency}
                      onChange={(e) => setScheduleForm({...scheduleForm, frequency: e.target.value})}
                      required
                      aria-required="true"
                    >
                      {ENTERPRISE_CONFIG.FREQUENCY_OPTIONS.map(freq => (
                        <option key={freq} value={freq}>{freq.charAt(0).toUpperCase() + freq.slice(1)}</option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="form-group">
                  <label htmlFor="start-date">Start Date *</label>
                  <input
                    id="start-date"
                    type="date"
                    value={scheduleForm.start_date}
                    onChange={(e) => setScheduleForm({...scheduleForm, start_date: e.target.value})}
                    required
                    aria-required="true"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="recipients">Recipients</label>
                  <input
                    id="recipients"
                    type="text"
                    placeholder="Enter email addresses (comma separated)"
                    onChange={(e) => setScheduleForm({
                      ...scheduleForm,
                      recipients: e.target.value.split(',').map(email => email.trim())
                    })}
                    aria-describedby="recipients-help"
                  />
                  <small id="recipients-help" className="help-text">
                    Separate multiple email addresses with commas
                  </small>
                </div>

                <div className="modal-actions">
                  <button 
                    type="button" 
                    onClick={handleCloseScheduleModal} 
                    className="btn-secondary"
                    disabled={operationInProgress}
                  >
                    Cancel
                  </button>
                  <button 
                    type="submit" 
                    className="btn-primary"
                    disabled={operationInProgress}
                  >
                    <Calendar size={16} aria-hidden="true" />
                    {operationInProgress ? 'Scheduling...' : 'Schedule Report'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </ReportsErrorBoundary>
  );
};

export default Reports;