import React, { useState, useEffect } from 'react';
import { 
  FileText, Download, Filter, Plus, Calendar, AlertTriangle, 
  RefreshCw, Eye, Clock, CheckCircle, X, BarChart3, Users,
  BookOpen, GraduationCap, DollarSign, TrendingUp
} from 'lucide-react';
import { reportsAPI, analyticsAPI, studentsAPI, coursesAPI, facultyAPI } from '../services/api';
import { useApi } from '../hooks/useApi';
import './Reports.css';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [scheduledReports, setScheduledReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('templates');
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(null);

  // Report templates
  const reportTemplates = [
    {
      id: 1,
      name: 'Student Performance Report',
      type: 'academic',
      description: 'Comprehensive analysis of student academic performance',
      icon: Users,
      parameters: ['timeframe', 'department', 'metrics'],
      estimatedTime: '2-5 minutes'
    },
    {
      id: 2,
      name: 'Financial Summary Report',
      type: 'financial',
      description: 'Revenue, expenses and budget analysis',
      icon: DollarSign,
      parameters: ['period', 'detail_level', 'format'],
      estimatedTime: '1-3 minutes'
    },
    {
      id: 3,
      name: 'Faculty Workload Analysis',
      type: 'hr',
      description: 'Teaching assignments and performance metrics',
      icon: GraduationCap,
      parameters: ['semester', 'department', 'metrics'],
      estimatedTime: '3-7 minutes'
    },
    {
      id: 4,
      name: 'Course Enrollment Statistics',
      type: 'academic',
      description: 'Detailed enrollment trends and capacity analysis',
      icon: BookOpen,
      parameters: ['semester', 'courses', 'format'],
      estimatedTime: '1-4 minutes'
    },
    {
      id: 5,
      name: 'System Usage Analytics',
      type: 'system',
      description: 'Platform usage and engagement metrics',
      icon: BarChart3,
      parameters: ['timeframe', 'metrics', 'format'],
      estimatedTime: '2-4 minutes'
    },
    {
      id: 6,
      name: 'Compliance Audit Report',
      type: 'compliance',
      description: 'Regulatory compliance and audit readiness',
      icon: FileText,
      parameters: ['standards', 'timeframe', 'detail_level'],
      estimatedTime: '5-10 minutes'
    }
  ];

  // Form states
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

  // Real API integration
  const { data: reportsData, refetch: refetchReports } = useApi(
    () => reportsAPI.getReportTemplates()
  );

  const { data: scheduledData, refetch: refetchScheduled } = useApi(
    () => reportsAPI.getScheduledReports()
  );

  // Generate report function
  const handleGenerateReport = async (template) => {
    try {
      setError('');
      setLoading(true);
      
      const reportData = {
        title: `${template.name} - ${new Date().toLocaleDateString()}`,
        report_type: template.type,
        parameters: generateForm.parameters
      };

      const response = await reportsAPI.generateReport(reportData);
      
      if (response.success) {
        setShowGenerateModal(false);
        setSelectedTemplate(null);
        
        // Simulate report generation process
        setTimeout(() => {
          alert(`Report "${reportData.title}" generated successfully!`);
          refetchReports();
        }, 2000);
        
      } else {
        setError(response.error || 'Failed to generate report');
      }
    } catch (err) {
      setError('Failed to generate report. Please try again.');
      console.error('Generate report error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Schedule report function
  const handleScheduleReport = async (e) => {
    e.preventDefault();
    try {
      setError('');
      const response = await reportsAPI.scheduleReport(scheduleForm);
      
      if (response.success) {
        setShowScheduleModal(false);
        resetScheduleForm();
        refetchScheduled();
        alert('Report scheduled successfully!');
      } else {
        setError(response.error || 'Failed to schedule report');
      }
    } catch (err) {
      setError('Failed to schedule report. Please try again.');
      console.error('Schedule report error:', err);
    }
  };

  // Download report function
  const handleDownloadReport = async (reportId) => {
    try {
      setError('');
      const response = await reportsAPI.downloadReport(reportId);
      
      if (response.success) {
        // Simulate file download
        const blob = new Blob([response.data], { type: 'application/pdf' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `report_${reportId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } else {
        setError('Failed to download report');
      }
    } catch (err) {
      setError('Failed to download report. Please try again.');
      console.error('Download report error:', err);
    }
  };

  // Export raw data
  const handleExportData = async (type) => {
    try {
      setError('');
      let response;
      
      switch(type) {
        case 'students':
          response = await studentsAPI.exportStudents();
          break;
        case 'courses':
          response = await coursesAPI.exportCourses();
          break;
        case 'faculty':
          response = await facultyAPI.exportFaculty();
          break;
        default:
          throw new Error('Invalid export type');
      }

      if (response.success && response.data) {
        const blob = new Blob([response.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${type}_export_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(`Failed to export ${type} data`);
      console.error('Export error:', err);
    }
  };

  const resetGenerateForm = () => {
    setGenerateForm({
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
  };

  const resetScheduleForm = () => {
    setScheduleForm({
      title: '',
      report_type: '',
      frequency: 'weekly',
      start_date: new Date().toISOString().split('T')[0],
      recipients: [],
      parameters: {}
    });
  };

  const handleTemplateSelect = (template) => {
    setSelectedTemplate(template);
    setGenerateForm(prev => ({
      ...prev,
      title: `${template.name} - ${new Date().toLocaleDateString()}`,
      report_type: template.type
    }));
    setShowGenerateModal(true);
  };

  const handleRefresh = () => {
    setError('');
    refetchReports();
    refetchScheduled();
  };

  // Sample generated reports data
  const generatedReports = [
    {
      id: 1,
      title: 'Student Performance Report - Q1 2024',
      type: 'academic',
      status: 'completed',
      generated_at: '2024-03-15T10:30:00Z',
      size: '2.4 MB',
      format: 'pdf'
    },
    {
      id: 2,
      title: 'Financial Summary - March 2024',
      type: 'financial',
      status: 'completed',
      generated_at: '2024-03-10T14:20:00Z',
      size: '1.8 MB',
      format: 'pdf'
    },
    {
      id: 3,
      title: 'Faculty Workload Analysis - Spring 2024',
      type: 'hr',
      status: 'processing',
      generated_at: '2024-03-20T09:15:00Z',
      size: 'N/A',
      format: 'pdf'
    }
  ];

  return (
    <div className="reports-container">
      {/* Header */}
      <div className="header">
        <h1 className="header-title">Reports & Analytics</h1>
        <div className="header-actions">
          <button 
            className="btn-primary" 
            onClick={() => setShowScheduleModal(true)}
          >
            <Plus size={16} />
            Schedule Report
          </button>
          <button className="btn-secondary" onClick={handleRefresh}>
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <AlertTriangle size={16} />
          <span>{error}</span>
          <button onClick={() => setError('')} className="close-btn">
            <X size={16} />
          </button>
        </div>
      )}

      {/* Quick Export Section */}
      <div className="quick-export-section">
        <h3>Quick Data Export</h3>
        <div className="export-cards">
          <div className="export-card" onClick={() => handleExportData('students')}>
            <Users size={24} />
            <div className="export-info">
              <div className="export-title">Student Data</div>
              <div className="export-desc">Export all student records</div>
            </div>
            <Download size={16} />
          </div>
          <div className="export-card" onClick={() => handleExportData('courses')}>
            <BookOpen size={24} />
            <div className="export-info">
              <div className="export-title">Course Data</div>
              <div className="export-desc">Export course catalog</div>
            </div>
            <Download size={16} />
          </div>
          <div className="export-card" onClick={() => handleExportData('faculty')}>
            <GraduationCap size={24} />
            <div className="export-info">
              <div className="export-title">Faculty Data</div>
              <div className="export-desc">Export faculty information</div>
            </div>
            <Download size={16} />
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="reports-tabs">
        <button 
          className={`tab ${activeTab === 'templates' ? 'active' : ''}`}
          onClick={() => setActiveTab('templates')}
        >
          <FileText size={16} />
          Report Templates
        </button>
        <button 
          className={`tab ${activeTab === 'generated' ? 'active' : ''}`}
          onClick={() => setActiveTab('generated')}
        >
          <Download size={16} />
          Generated Reports
        </button>
        <button 
          className={`tab ${activeTab === 'scheduled' ? 'active' : ''}`}
          onClick={() => setActiveTab('scheduled')}
        >
          <Calendar size={16} />
          Scheduled Reports
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'templates' && (
        <div className="tab-content">
          <div className="templates-grid">
            {reportTemplates.map(template => {
              const IconComponent = template.icon;
              return (
                <div key={template.id} className="template-card">
                  <div className="template-header">
                    <div className="template-icon">
                      <IconComponent size={24} />
                    </div>
                    <div className="template-info">
                      <h4 className="template-title">{template.name}</h4>
                      <p className="template-description">{template.description}</p>
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
                      <Clock size={14} />
                      {template.estimatedTime}
                    </div>
                  </div>
                  <div className="template-actions">
                    <button 
                      className="btn-primary"
                      onClick={() => handleTemplateSelect(template)}
                    >
                      Generate Report
                    </button>
                    <button className="btn-secondary">
                      <Eye size={14} />
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
        <div className="tab-content">
          <div className="reports-list">
            {generatedReports.map(report => (
              <div key={report.id} className="report-item">
                <div className="report-info">
                  <div className="report-icon">
                    <FileText size={20} />
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
                    </div>
                  </div>
                </div>
                <div className="report-actions">
                  <div className={`report-status ${report.status}`}>
                    {report.status === 'completed' && <CheckCircle size={14} />}
                    {report.status}
                  </div>
                  {report.status === 'completed' && (
                    <button 
                      className="btn-primary"
                      onClick={() => handleDownloadReport(report.id)}
                    >
                      <Download size={14} />
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
        <div className="tab-content">
          <div className="scheduled-reports">
            {scheduledData && scheduledData.length > 0 ? (
              scheduledData.map(scheduled => (
                <div key={scheduled.id} className="scheduled-item">
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
                    </div>
                  </div>
                  <div className="scheduled-actions">
                    <button className="btn-secondary">
                      <Eye size={14} />
                      View
                    </button>
                    <button className="btn-danger">
                      <X size={14} />
                      Cancel
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <Calendar size={48} />
                <h3>No scheduled reports</h3>
                <p>Schedule your first report to automate reporting</p>
                <button 
                  className="btn-primary" 
                  onClick={() => setShowScheduleModal(true)}
                >
                  <Plus size={16} />
                  Schedule Report
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Generate Report Modal */}
      {showGenerateModal && selectedTemplate && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Generate {selectedTemplate.name}</h3>
              <button onClick={() => setShowGenerateModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <div className="modal-content">
              <div className="form-group">
                <label>Report Title</label>
                <input
                  type="text"
                  value={generateForm.title}
                  onChange={(e) => setGenerateForm({...generateForm, title: e.target.value})}
                  placeholder="Enter report title"
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Timeframe</label>
                  <select
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
                  <label>Department</label>
                  <select
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
                <div className="checkbox-group">
                  <label className="checkbox">
                    <input type="checkbox" checked />
                    Enrollment Statistics
                  </label>
                  <label className="checkbox">
                    <input type="checkbox" checked />
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
                  <label>Format</label>
                  <select
                    value={generateForm.parameters.format}
                    onChange={(e) => setGenerateForm({
                      ...generateForm,
                      parameters: {...generateForm.parameters, format: e.target.value}
                    })}
                  >
                    <option value="pdf">PDF</option>
                    <option value="excel">Excel</option>
                    <option value="csv">CSV</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Detail Level</label>
                  <select
                    value={generateForm.parameters.detail_level}
                    onChange={(e) => setGenerateForm({
                      ...generateForm,
                      parameters: {...generateForm.parameters, detail_level: e.target.value}
                    })}
                  >
                    <option value="summary">Summary</option>
                    <option value="detailed">Detailed</option>
                    <option value="comprehensive">Comprehensive</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="modal-actions">
              <button 
                type="button" 
                onClick={() => setShowGenerateModal(false)} 
                className="btn-secondary"
              >
                Cancel
              </button>
              <button 
                onClick={() => handleGenerateReport(selectedTemplate)}
                className="btn-primary"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <RefreshCw size={16} className="spinning" />
                    Generating...
                  </>
                ) : (
                  <>
                    <FileText size={16} />
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
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Schedule New Report</h3>
              <button onClick={() => setShowScheduleModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleScheduleReport} className="modal-form">
              <div className="form-group">
                <label>Report Title *</label>
                <input
                  type="text"
                  value={scheduleForm.title}
                  onChange={(e) => setScheduleForm({...scheduleForm, title: e.target.value})}
                  placeholder="Enter report title"
                  required
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Report Type *</label>
                  <select
                    value={scheduleForm.report_type}
                    onChange={(e) => setScheduleForm({...scheduleForm, report_type: e.target.value})}
                    required
                  >
                    <option value="">Select Report Type</option>
                    <option value="academic">Academic Performance</option>
                    <option value="financial">Financial Summary</option>
                    <option value="hr">Faculty Workload</option>
                    <option value="enrollment">Enrollment Statistics</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Frequency *</label>
                  <select
                    value={scheduleForm.frequency}
                    onChange={(e) => setScheduleForm({...scheduleForm, frequency: e.target.value})}
                    required
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                    <option value="quarterly">Quarterly</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Start Date *</label>
                <input
                  type="date"
                  value={scheduleForm.start_date}
                  onChange={(e) => setScheduleForm({...scheduleForm, start_date: e.target.value})}
                  required
                />
              </div>

              <div className="form-group">
                <label>Recipients</label>
                <input
                  type="text"
                  placeholder="Enter email addresses (comma separated)"
                  onChange={(e) => setScheduleForm({
                    ...scheduleForm,
                    recipients: e.target.value.split(',').map(email => email.trim())
                  })}
                />
              </div>

              <div className="modal-actions">
                <button 
                  type="button" 
                  onClick={() => setShowScheduleModal(false)} 
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Calendar size={16} />
                  Schedule Report
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;