import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { 
  Users, Search, Plus, Edit, Trash2, Download, 
  AlertTriangle, X, Save, GraduationCap, BookOpen, TrendingUp, RefreshCw
} from 'lucide-react';
import { facultyAPI } from './services/api';
import useApi from './hooks/useApi';
import './FacultyManagement.css';

// Enterprise Configuration
const ENTERPRISE_CONFIG = {
  VALIDATION: {
    MAX_WORKLOAD_HOURS: 60,
    MIN_SALARY: 0,
    MAX_SCORE: 5,
    MIN_SCORE: 0,
    EMAIL_PATTERN: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  PERFORMANCE: {
    SEARCH_DEBOUNCE: 300,
    MAX_RETRY_ATTEMPTS: 3,
    CACHE_DURATION: 5 * 60 * 1000 // 5 minutes
  },
  WORKLOAD_THRESHOLDS: {
    HIGH: 35,
    MEDIUM: 25,
    LOW: 0
  }
};

// Enhanced Error Boundary for Faculty Management
class FacultyErrorBoundary extends React.Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Faculty Management Error:', error, errorInfo);
    if (window.monitoringService) {
      window.monitoringService.captureException(error, {
        component: 'FacultyManagement',
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
            <h3>Faculty Management Error</h3>
            <p>We encountered an error while loading faculty data.</p>
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

// Enhanced Memoized Faculty Row with Accessibility
const FacultyRow = React.memo(({ member, onEdit, onDelete }) => {
  const getPositionLabel = useCallback((position) => {
    const positions = {
      'assistant_professor': 'Assistant Professor',
      'associate_professor': 'Associate Professor', 
      'professor': 'Professor',
      'lecturer': 'Lecturer',
      'instructor': 'Instructor'
    };
    return positions[position] || position;
  }, []);

  const getStatusClass = useCallback((status) => {
    const statusMap = {
      'active': 'active',
      'inactive': 'inactive',
      'on_leave': 'on-leave'
    };
    return statusMap[status] || 'active';
  }, []);

  const getWorkloadStatus = useCallback((hours) => {
    if (hours > ENTERPRISE_CONFIG.WORKLOAD_THRESHOLDS.HIGH) return 'high';
    if (hours > ENTERPRISE_CONFIG.WORKLOAD_THRESHOLDS.MEDIUM) return 'medium';
    return 'low';
  }, []);

  const workloadPercentage = Math.min((member.workload_hours || 0) / 40 * 100, 100);
  const workloadStatus = getWorkloadStatus(member.workload_hours);

  return (
    <tr className="faculty-row" role="row">
      <td role="cell">
        <div className="employee-id">
          <Users size={16} aria-hidden="true" />
          <span>{member.employee_id || 'N/A'}</span>
        </div>
      </td>
      <td role="cell">
        <div className="faculty-info">
          <strong>{member.name || 'Unnamed Faculty'}</strong>
          <span className="faculty-email">{member.email || 'No email'}</span>
        </div>
      </td>
      <td role="cell">{member.department || 'N/A'}</td>
      <td role="cell">
        <span className="position-badge">
          {getPositionLabel(member.position)}
        </span>
      </td>
      <td role="cell">
        <div className="workload-info">
          <span className="workload-hours">{member.workload_hours || 0}h</span>
          <div 
            className="workload-bar" 
            role="progressbar" 
            aria-valuenow={workloadPercentage} 
            aria-valuemin="0" 
            aria-valuemax="100"
          >
            <div 
              className={`workload-fill ${workloadStatus}`}
              style={{width: `${workloadPercentage}%`}}
            ></div>
          </div>
        </div>
      </td>
      <td role="cell">
        <span className={`score-badge ${(member.research_score || 0) >= 4 ? 'high' : (member.research_score || 0) >= 3 ? 'medium' : 'low'}`}>
          {member.research_score || 'N/A'}
        </span>
      </td>
      <td role="cell">
        <span className={`score-badge ${(member.student_satisfaction_score || 0) >= 4 ? 'high' : (member.student_satisfaction_score || 0) >= 3 ? 'medium' : 'low'}`}>
          {member.student_satisfaction_score || 'N/A'}
        </span>
      </td>
      <td role="cell">
        <span className={`status-badge ${getStatusClass(member.status)}`}>
          {member.status || 'active'}
        </span>
      </td>
      <td role="cell">
        <div className="action-buttons">
          <button 
            className="btn-icon primary"
            onClick={() => onEdit(member)}
            title="Edit Faculty"
            aria-label={`Edit ${member.name}`}
          >
            <Edit size={14} aria-hidden="true" />
          </button>
          <button 
            className="btn-icon danger"
            onClick={() => onDelete(member.id)}
            title="Archive Faculty"
            aria-label={`Archive ${member.name}`}
          >
            <Trash2 size={14} aria-hidden="true" />
          </button>
        </div>
      </td>
    </tr>
  );
});

const FacultyManagement = () => {
  // State Management
  const [faculty, setFaculty] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    department: '',
    status: ''
  });
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedFaculty, setSelectedFaculty] = useState(null);
  const [formData, setFormData] = useState({
    employee_id: '',
    first_name: '',
    last_name: '',
    email: '',
    department_id: '',
    position: 'assistant_professor',
    salary: '',
    workload_hours: '',
    research_score: '',
    student_satisfaction_score: '',
    status: 'active'
  });
  const [formErrors, setFormErrors] = useState({});
  const [operationInProgress, setOperationInProgress] = useState(false);

  // Refs for cleanup
  const searchTimeoutRef = useRef(null);
  const mountedRef = useRef(true);

  // Real API integration with enhanced error handling
  const { 
    data: facultyData, 
    loading: facultyLoading, 
    error: facultyError, 
    refetch: refetchFaculty 
  } = useApi(
    useCallback(() => facultyAPI.getFaculty(filters), [filters]),
    {
      retry: ENTERPRISE_CONFIG.PERFORMANCE.MAX_RETRY_ATTEMPTS,
      cacheKey: 'faculty-data',
      cacheTimeout: ENTERPRISE_CONFIG.PERFORMANCE.CACHE_DURATION
    }
  );

  // Data Synchronization
  useEffect(() => {
    if (facultyData) {
      setFaculty(facultyData);
      setLoading(false);
    }
  }, [facultyData]);

  // Error Handling
  useEffect(() => {
    if (facultyError && mountedRef.current) {
      setError(`Failed to load faculty data: ${facultyError.message}`);
      setLoading(false);
    }
  }, [facultyError]);

  // Component Cleanup
  useEffect(() => {
    mountedRef.current = true;
    
    return () => {
      mountedRef.current = false;
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, []);

  // Enhanced Search Handler with Debouncing
  const handleSearch = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    
    searchTimeoutRef.current = setTimeout(() => {
      // Search logic handled in filteredFaculty memo
      if (window.analyticsService && value.length > 2) {
        window.analyticsService.track('faculty_search', {
          searchTerm: value,
          resultCount: filteredFaculty.length,
          timestamp: new Date().toISOString()
        });
      }
    }, ENTERPRISE_CONFIG.PERFORMANCE.SEARCH_DEBOUNCE);
  }, []);

  // Memoized Filtered Faculty
  const filteredFaculty = useMemo(() => {
    if (!searchTerm.trim()) return faculty;
    
    const term = searchTerm.toLowerCase().trim();
    return faculty.filter(member => 
      member.name?.toLowerCase().includes(term) ||
      member.email?.toLowerCase().includes(term) ||
      member.employee_id?.toLowerCase().includes(term) ||
      member.department?.toLowerCase().includes(term)
    );
  }, [faculty, searchTerm]);

  // Enhanced Form Validation
  const validateForm = useCallback((data) => {
    const errors = {};

    if (!data.employee_id?.trim()) {
      errors.employee_id = 'Employee ID is required';
    }

    if (!data.first_name?.trim()) {
      errors.first_name = 'First name is required';
    }

    if (!data.last_name?.trim()) {
      errors.last_name = 'Last name is required';
    }

    if (!data.email?.trim()) {
      errors.email = 'Email is required';
    } else if (!ENTERPRISE_CONFIG.VALIDATION.EMAIL_PATTERN.test(data.email)) {
      errors.email = 'Please enter a valid email address';
    }

    if (data.workload_hours && data.workload_hours > ENTERPRISE_CONFIG.VALIDATION.MAX_WORKLOAD_HOURS) {
      errors.workload_hours = `Workload cannot exceed ${ENTERPRISE_CONFIG.VALIDATION.MAX_WORKLOAD_HOURS} hours`;
    }

    if (data.salary && data.salary < ENTERPRISE_CONFIG.VALIDATION.MIN_SALARY) {
      errors.salary = `Salary must be at least $${ENTERPRISE_CONFIG.VALIDATION.MIN_SALARY}`;
    }

    if (data.research_score && (data.research_score < ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE || data.research_score > ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE)) {
      errors.research_score = `Research score must be between ${ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE} and ${ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}`;
    }

    if (data.student_satisfaction_score && (data.student_satisfaction_score < ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE || data.student_satisfaction_score > ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE)) {
      errors.student_satisfaction_score = `Satisfaction score must be between ${ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE} and ${ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}`;
    }

    return errors;
  }, []);

  // Prepare Backend Data
  const prepareBackendData = useCallback((formData) => {
    return {
      employee_id: formData.employee_id,
      first_name: formData.first_name,
      last_name: formData.last_name,
      email: formData.email,
      department: formData.department_id,  
      position: formData.position,
      salary: parseFloat(formData.salary) || 0,
      workload_hours: parseInt(formData.workload_hours) || 0,
      research_score: parseFloat(formData.research_score) || 0,
      student_satisfaction_score: parseFloat(formData.student_satisfaction_score) || 0,
      status: formData.status
    };
  }, []);

  // Enhanced CRUD Operations with Error Handling
  const handleAddFaculty = useCallback(async (e) => {
    e.preventDefault();
    
    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    setOperationInProgress(true);
    setFormErrors({});

    try {
      setError('');
      const backendData = prepareBackendData(formData);
      const response = await facultyAPI.createFaculty(backendData);
      
      if (response.success) {
        setShowAddModal(false);
        resetForm();
        await refetchFaculty();
        
        // Track successful creation
        if (window.analyticsService) {
          window.analyticsService.track('faculty_created', {
            employeeId: formData.employee_id,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to create faculty member');
      }
    } catch (err) {
      const errorMsg = 'Failed to add faculty member. Please try again.';
      setError(errorMsg);
      console.error('Add faculty error:', err);
      
      // Track creation failure
      if (window.analyticsService) {
        window.analyticsService.track('faculty_creation_failed', {
          employeeId: formData.employee_id,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    } finally {
      setOperationInProgress(false);
    }
  }, [formData, refetchFaculty, validateForm, prepareBackendData]);

  const handleEditFaculty = useCallback(async (e) => {
    e.preventDefault();
    
    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    setOperationInProgress(true);
    setFormErrors({});

    try {
      setError('');
      const backendData = prepareBackendData(formData);
      const response = await facultyAPI.updateFaculty(selectedFaculty.id, backendData);
      
      if (response.success) {
        setShowEditModal(false);
        setSelectedFaculty(null);
        resetForm();
        await refetchFaculty();
        
        // Track successful update
        if (window.analyticsService) {
          window.analyticsService.track('faculty_updated', {
            facultyId: selectedFaculty.id,
            employeeId: formData.employee_id,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to update faculty member');
      }
    } catch (err) {
      const errorMsg = 'Failed to update faculty member. Please try again.';
      setError(errorMsg);
      console.error('Update faculty error:', err);
    } finally {
      setOperationInProgress(false);
    }
  }, [selectedFaculty, formData, refetchFaculty, validateForm, prepareBackendData]);

  const handleDeleteFaculty = useCallback(async (facultyId) => {
    if (!window.confirm('Are you sure you want to archive this faculty member? This action cannot be undone.')) {
      return;
    }

    try {
      setError('');
      const response = await facultyAPI.deleteFaculty(facultyId);
      
      if (response.success) {
        await refetchFaculty();
        
        // Track successful archive
        if (window.analyticsService) {
          window.analyticsService.track('faculty_archived', {
            facultyId,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to archive faculty member');
      }
    } catch (err) {
      const errorMsg = 'Failed to archive faculty member. Please try again.';
      setError(errorMsg);
      console.error('Delete faculty error:', err);
    }
  }, [refetchFaculty]);

  // Form Management Functions
  const resetForm = useCallback(() => {
    setFormData({
      employee_id: '',
      first_name: '',
      last_name: '',
      email: '',
      department_id: '',
      position: 'assistant_professor',
      salary: '',
      workload_hours: '',
      research_score: '',
      student_satisfaction_score: '',
      status: 'active'
    });
    setFormErrors({});
  }, []);

  const handleEditClick = useCallback((member) => {
    setSelectedFaculty(member);
    const nameParts = member.name?.split(' ') || [];
    setFormData({
      employee_id: member.employee_id || '',
      first_name: nameParts[0] || '',
      last_name: nameParts.slice(1).join(' ') || '',
      email: member.email || '',
      department_id: member.department_id || '',
      position: member.position || 'assistant_professor',
      salary: member.salary?.toString() || '',
      workload_hours: member.workload_hours?.toString() || '',
      research_score: member.research_score?.toString() || '',
      student_satisfaction_score: member.student_satisfaction_score?.toString() || '',
      status: member.status || 'active'
    });
    setFormErrors({});
    setShowEditModal(true);
  }, []);

  // Enhanced Export Functionality
  const handleExport = useCallback(async () => {
    try {
      setError('');
      if (facultyAPI.exportFaculty) {
        const response = await facultyAPI.exportFaculty();
        
        if (response.success && response.data) {
          // Create secure download
          const blob = new Blob([response.data], { 
            type: 'text/csv; charset=utf-8',
            endings: 'native'
          });
          const url = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `faculty_export_${new Date().toISOString().split('T')[0]}.csv`;
          link.setAttribute('type', 'text/csv');
          
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          
          // Cleanup URL
          setTimeout(() => window.URL.revokeObjectURL(url), 100);
          
          // Track successful export
          if (window.analyticsService) {
            window.analyticsService.track('faculty_exported', {
              timestamp: new Date().toISOString(),
              recordCount: faculty.length
            });
          }
        }
      } else {
        setError('Export functionality not available');
      }
    } catch (err) {
      const errorMsg = 'Failed to export faculty data. Please try again.';
      setError(errorMsg);
      console.error('Export error:', err);
    }
  }, [faculty.length]);

  // Memoized Stats Calculations
  const stats = useMemo(() => {
    try {
      const totalFaculty = faculty.length;
      const avgSatisfaction = totalFaculty > 0 
        ? (faculty.reduce((sum, f) => sum + (f.student_satisfaction_score || 0), 0) / totalFaculty).toFixed(1)
        : '0.0';
      const avgResearch = totalFaculty > 0 
        ? (faculty.reduce((sum, f) => sum + (f.research_score || 0), 0) / totalFaculty).toFixed(1)
        : '0.0';
      const highWorkload = faculty.filter(f => (f.workload_hours || 0) > ENTERPRISE_CONFIG.WORKLOAD_THRESHOLDS.HIGH).length;

      return { totalFaculty, avgSatisfaction, avgResearch, highWorkload };
    } catch (error) {
      console.error('Stats calculation error:', error);
      return { totalFaculty: 0, avgSatisfaction: '0.0', avgResearch: '0.0', highWorkload: 0 };
    }
  }, [faculty]);

  const handleRefresh = useCallback(() => {
    setLoading(true);
    setError('');
    refetchFaculty();
  }, [refetchFaculty]);

  const handleFilterChange = useCallback((key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    
    // Track filter usage
    if (window.analyticsService) {
      window.analyticsService.track('faculty_filter_applied', {
        filter: key,
        value,
        timestamp: new Date().toISOString()
      });
    }
  }, []);

  const handleCloseAddModal = useCallback(() => {
    setShowAddModal(false);
    resetForm();
  }, [resetForm]);

  const handleCloseEditModal = useCallback(() => {
    setShowEditModal(false);
    setSelectedFaculty(null);
    resetForm();
  }, [resetForm]);

  // Loading State with Accessibility
  if (loading && faculty.length === 0) {
    return (
      <div className="faculty-management-container">
        <div className="loading-container" role="status" aria-live="polite">
          <div className="loading-spinner" aria-hidden="true"></div>
          <p>Loading faculty data...</p>
        </div>
      </div>
    );
  }

  return (
    <FacultyErrorBoundary>
      <div className="faculty-management-container">
        {/* Header */}
        <header className="header" role="banner">
          <h1 className="header-title">Faculty Management</h1>
          <div className="header-actions">
            <button 
              className="btn-primary" 
              onClick={() => setShowAddModal(true)}
              aria-label="Add new faculty member"
            >
              <Plus size={16} aria-hidden="true" />
              Add Faculty
            </button>
            <button 
              className="btn-secondary" 
              onClick={handleExport}
              disabled={faculty.length === 0}
              aria-label="Export faculty data"
            >
              <Download size={16} aria-hidden="true" />
              Export
            </button>
            <button 
              className="btn-icon" 
              onClick={handleRefresh} 
              disabled={facultyLoading}
              aria-label="Refresh faculty data"
            >
              <RefreshCw size={16} className={facultyLoading ? 'spinning' : ''} aria-hidden="true" />
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

        {/* Stats Cards */}
        <section className="stats-grid" aria-label="Faculty statistics">
          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Total Faculty</span>
              <Users className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.totalFaculty}</div>
            <div className="stat-change neutral">Across all departments</div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Avg Satisfaction</span>
              <TrendingUp className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.avgSatisfaction}</div>
            <div className="stat-change positive">Out of 5.0</div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Avg Research Score</span>
              <BookOpen className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.avgResearch}</div>
            <div className="stat-change neutral">Research performance</div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">High Workload</span>
              <AlertTriangle className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.highWorkload}</div>
            <div className="stat-change warning">Need attention</div>
          </div>
        </section>

        {/* Controls */}
        <section className="controls-section" aria-label="Faculty search and filters">
          <div className="search-box">
            <Search size={18} aria-hidden="true" />
            <input
              type="text"
              placeholder="Search faculty by name, email, or ID..."
              value={searchTerm}
              onChange={handleSearch}
              aria-label="Search faculty members"
            />
          </div>
          
          <div className="filters">
            <select 
              value={filters.department}
              onChange={(e) => handleFilterChange('department', e.target.value)}
              aria-label="Filter by department"
            >
              <option value="">All Departments</option>
              <option value="Computer Science">Computer Science</option>
              <option value="Mathematics">Mathematics</option>
              <option value="Engineering">Engineering</option>
              <option value="Physics">Physics</option>
            </select>
            
            <select 
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              aria-label="Filter by status"
            >
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="on_leave">On Leave</option>
            </select>
          </div>
        </section>

        {/* Faculty Table */}
        <section className="table-section" aria-label="Faculty members list">
          <div className="table-container">
            <table className="faculty-table" aria-label="Faculty data">
              <thead>
                <tr>
                  <th scope="col">Employee ID</th>
                  <th scope="col">Name</th>
                  <th scope="col">Department</th>
                  <th scope="col">Position</th>
                  <th scope="col">Workload</th>
                  <th scope="col">Research Score</th>
                  <th scope="col">Satisfaction</th>
                  <th scope="col">Status</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredFaculty.map((member) => (
                  <FacultyRow 
                    key={member.id}
                    member={member}
                    onEdit={handleEditClick}
                    onDelete={handleDeleteFaculty}
                  />
                ))}
              </tbody>
            </table>
            
            {filteredFaculty.length === 0 && !facultyLoading && (
              <div className="empty-state" role="status" aria-live="polite">
                <GraduationCap size={48} aria-hidden="true" />
                <h3>No faculty members found</h3>
                <p>Try adjusting your search or filters, or add a new faculty member</p>
                <button 
                  className="btn-primary" 
                  onClick={() => setShowAddModal(true)}
                  aria-label="Add first faculty member"
                >
                  <Plus size={16} aria-hidden="true" />
                  Add First Faculty Member
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Add Faculty Modal */}
        {showAddModal && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="add-faculty-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="add-faculty-title">Add New Faculty Member</h3>
                <button 
                  onClick={handleCloseAddModal} 
                  className="close-btn"
                  aria-label="Close add faculty modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleAddFaculty} className="modal-form">
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="employee-id">Employee ID *</label>
                    <input
                      id="employee-id"
                      type="text"
                      value={formData.employee_id}
                      onChange={(e) => setFormData({...formData, employee_id: e.target.value})}
                      placeholder="e.g., F001"
                      required
                      className={formErrors.employee_id ? 'error' : ''}
                    />
                    {formErrors.employee_id && <span className="error-message">{formErrors.employee_id}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="position">Position *</label>
                    <select
                      id="position"
                      value={formData.position}
                      onChange={(e) => setFormData({...formData, position: e.target.value})}
                      required
                    >
                      <option value="assistant_professor">Assistant Professor</option>
                      <option value="associate_professor">Associate Professor</option>
                      <option value="professor">Professor</option>
                      <option value="lecturer">Lecturer</option>
                      <option value="instructor">Instructor</option>
                    </select>
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="first-name">First Name *</label>
                    <input
                      id="first-name"
                      type="text"
                      value={formData.first_name}
                      onChange={(e) => setFormData({...formData, first_name: e.target.value})}
                      placeholder="John"
                      required
                      className={formErrors.first_name ? 'error' : ''}
                    />
                    {formErrors.first_name && <span className="error-message">{formErrors.first_name}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="last-name">Last Name *</label>
                    <input
                      id="last-name"
                      type="text"
                      value={formData.last_name}
                      onChange={(e) => setFormData({...formData, last_name: e.target.value})}
                      placeholder="Doe"
                      required
                      className={formErrors.last_name ? 'error' : ''}
                    />
                    {formErrors.last_name && <span className="error-message">{formErrors.last_name}</span>}
                  </div>
                </div>
                
                <div className="form-group">
                  <label htmlFor="email">Email *</label>
                  <input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    placeholder="john.doe@university.edu"
                    required
                    className={formErrors.email ? 'error' : ''}
                  />
                  {formErrors.email && <span className="error-message">{formErrors.email}</span>}
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="department">Department</label>
                    <select
                      id="department"
                      value={formData.department_id}
                      onChange={(e) => setFormData({...formData, department_id: e.target.value})}
                    >
                      <option value="">Select Department</option>
                      <option value="1">Computer Science</option>
                      <option value="2">Mathematics</option>
                      <option value="3">Engineering</option>
                      <option value="4">Physics</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="status">Status *</label>
                    <select
                      id="status"
                      value={formData.status}
                      onChange={(e) => setFormData({...formData, status: e.target.value})}
                      required
                    >
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                      <option value="on_leave">On Leave</option>
                    </select>
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="salary">Salary ($)</label>
                    <input
                      id="salary"
                      type="number"
                      value={formData.salary}
                      onChange={(e) => setFormData({...formData, salary: e.target.value})}
                      placeholder="75000"
                      min="0"
                      className={formErrors.salary ? 'error' : ''}
                    />
                    {formErrors.salary && <span className="error-message">{formErrors.salary}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="workload-hours">Workload Hours</label>
                    <input
                      id="workload-hours"
                      type="number"
                      value={formData.workload_hours}
                      onChange={(e) => setFormData({...formData, workload_hours: e.target.value})}
                      placeholder="20"
                      min="0"
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_WORKLOAD_HOURS}
                      className={formErrors.workload_hours ? 'error' : ''}
                    />
                    {formErrors.workload_hours && <span className="error-message">{formErrors.workload_hours}</span>}
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="research-score">Research Score</label>
                    <input
                      id="research-score"
                      type="number"
                      step="0.1"
                      min={ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE}
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}
                      value={formData.research_score}
                      onChange={(e) => setFormData({...formData, research_score: e.target.value})}
                      placeholder="4.2"
                      className={formErrors.research_score ? 'error' : ''}
                    />
                    {formErrors.research_score && <span className="error-message">{formErrors.research_score}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="satisfaction-score">Satisfaction Score</label>
                    <input
                      id="satisfaction-score"
                      type="number"
                      step="0.1"
                      min={ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE}
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}
                      value={formData.student_satisfaction_score}
                      onChange={(e) => setFormData({...formData, student_satisfaction_score: e.target.value})}
                      placeholder="4.5"
                      className={formErrors.student_satisfaction_score ? 'error' : ''}
                    />
                    {formErrors.student_satisfaction_score && <span className="error-message">{formErrors.student_satisfaction_score}</span>}
                  </div>
                </div>
                
                <div className="modal-actions">
                  <button 
                    type="button" 
                    onClick={handleCloseAddModal} 
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
                    <Save size={16} aria-hidden="true" />
                    {operationInProgress ? 'Adding...' : 'Add Faculty Member'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Edit Faculty Modal */}
        {showEditModal && selectedFaculty && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="edit-faculty-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="edit-faculty-title">Edit Faculty Member</h3>
                <button 
                  onClick={handleCloseEditModal} 
                  className="close-btn"
                  aria-label="Close edit faculty modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleEditFaculty} className="modal-form">
                <div className="form-row">
                  <div className="form-group">
                    <label>Employee ID</label>
                    <input
                      type="text"
                      value={formData.employee_id}
                      disabled
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-position">Position *</label>
                    <select
                      id="edit-position"
                      value={formData.position}
                      onChange={(e) => setFormData({...formData, position: e.target.value})}
                      required
                    >
                      <option value="assistant_professor">Assistant Professor</option>
                      <option value="associate_professor">Associate Professor</option>
                      <option value="professor">Professor</option>
                      <option value="lecturer">Lecturer</option>
                      <option value="instructor">Instructor</option>
                    </select>
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-first-name">First Name *</label>
                    <input
                      id="edit-first-name"
                      type="text"
                      value={formData.first_name}
                      onChange={(e) => setFormData({...formData, first_name: e.target.value})}
                      required
                      className={formErrors.first_name ? 'error' : ''}
                    />
                    {formErrors.first_name && <span className="error-message">{formErrors.first_name}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-last-name">Last Name *</label>
                    <input
                      id="edit-last-name"
                      type="text"
                      value={formData.last_name}
                      onChange={(e) => setFormData({...formData, last_name: e.target.value})}
                      required
                      className={formErrors.last_name ? 'error' : ''}
                    />
                    {formErrors.last_name && <span className="error-message">{formErrors.last_name}</span>}
                  </div>
                </div>
                
                <div className="form-group">
                  <label htmlFor="edit-email">Email *</label>
                  <input
                    id="edit-email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    required
                    className={formErrors.email ? 'error' : ''}
                  />
                  {formErrors.email && <span className="error-message">{formErrors.email}</span>}
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-department">Department</label>
                    <select
                      id="edit-department"
                      value={formData.department_id}
                      onChange={(e) => setFormData({...formData, department_id: e.target.value})}
                    >
                      <option value="1">Computer Science</option>
                      <option value="2">Mathematics</option>
                      <option value="3">Engineering</option>
                      <option value="4">Physics</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-status">Status *</label>
                    <select
                      id="edit-status"
                      value={formData.status}
                      onChange={(e) => setFormData({...formData, status: e.target.value})}
                      required
                    >
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                      <option value="on_leave">On Leave</option>
                    </select>
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-salary">Salary ($)</label>
                    <input
                      id="edit-salary"
                      type="number"
                      value={formData.salary}
                      onChange={(e) => setFormData({...formData, salary: e.target.value})}
                      min="0"
                      className={formErrors.salary ? 'error' : ''}
                    />
                    {formErrors.salary && <span className="error-message">{formErrors.salary}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-workload-hours">Workload Hours</label>
                    <input
                      id="edit-workload-hours"
                      type="number"
                      value={formData.workload_hours}
                      onChange={(e) => setFormData({...formData, workload_hours: e.target.value})}
                      min="0"
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_WORKLOAD_HOURS}
                      className={formErrors.workload_hours ? 'error' : ''}
                    />
                    {formErrors.workload_hours && <span className="error-message">{formErrors.workload_hours}</span>}
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-research-score">Research Score</label>
                    <input
                      id="edit-research-score"
                      type="number"
                      step="0.1"
                      min={ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE}
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}
                      value={formData.research_score}
                      onChange={(e) => setFormData({...formData, research_score: e.target.value})}
                      className={formErrors.research_score ? 'error' : ''}
                    />
                    {formErrors.research_score && <span className="error-message">{formErrors.research_score}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-satisfaction-score">Satisfaction Score</label>
                    <input
                      id="edit-satisfaction-score"
                      type="number"
                      step="0.1"
                      min={ENTERPRISE_CONFIG.VALIDATION.MIN_SCORE}
                      max={ENTERPRISE_CONFIG.VALIDATION.MAX_SCORE}
                      value={formData.student_satisfaction_score}
                      onChange={(e) => setFormData({...formData, student_satisfaction_score: e.target.value})}
                      className={formErrors.student_satisfaction_score ? 'error' : ''}
                    />
                    {formErrors.student_satisfaction_score && <span className="error-message">{formErrors.student_satisfaction_score}</span>}
                  </div>
                </div>
                
                <div className="modal-actions">
                  <button 
                    type="button" 
                    onClick={handleCloseEditModal} 
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
                    <Save size={16} aria-hidden="true" />
                    {operationInProgress ? 'Updating...' : 'Update Faculty Member'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </FacultyErrorBoundary>
  );
};

export default FacultyManagement;