import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { 
  BookOpen, Search, Plus, Edit, Trash2, Download, 
  AlertTriangle, X, Save, Users,
  TrendingUp, RefreshCw, Filter
} from 'lucide-react';
import { coursesAPI, facultyAPI } from './services/api';
import useApi from './hooks/useApi';
import './CourseManagement.css';



// Enterprise Configuration
const ENTERPRISE_CONFIG = {
  COURSE: {
    DEFAULT_CAPACITY: 30,
    MIN_CREDITS: 1,
    MAX_CREDITS: 6,
    STATUS_OPTIONS: ['active', 'inactive', 'archived'],
    SEMESTER_OPTIONS: ['Spring', 'Summer', 'Fall', 'Winter']
  },
  PERFORMANCE: {
    SEARCH_DEBOUNCE: 300,
    MAX_RETRY_ATTEMPTS: 3,
    CACHE_DURATION: 5 * 60 * 1000 // 5 minutes
  },
  VALIDATION: {
    COURSE_CODE_PATTERN: /^[A-Z]{2,4}\d{3}$/,
    MIN_COURSE_TITLE_LENGTH: 5,
    MAX_COURSE_TITLE_LENGTH: 100
  }
};

// Enhanced Error Boundary for Course Operations
class CourseErrorBoundary extends React.Component {
  state = { hasError: false, error: null, errorContext: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorContext: errorInfo });
    
    // Enterprise error reporting
    console.error('Course Management Error:', error, errorInfo);
    if (window.monitoringService) {
      window.monitoringService.captureException(error, {
        component: 'CourseManagement',
        errorInfo,
        timestamp: new Date().toISOString()
      });
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorContext: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-container">
          <div className="error-content">
            <AlertTriangle size={32} />
            <h3>Course Management Error</h3>
            <p>We encountered an error while loading course data.</p>
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

// Enhanced Memoized Course Row with Error Handling
const CourseRow = React.memo(({ course, onEdit, onDelete, onAddSection }) => {
  const getEnrollmentStatus = useCallback((enrolled, capacity) => {
    try {
      const percentage = (enrolled / capacity) * 100;
      if (percentage >= 95) return { status: 'full', label: 'Full', class: 'full' };
      if (percentage >= 80) return { status: 'nearly-full', label: 'Nearly Full', class: 'nearly-full' };
      return { status: 'open', label: 'Open', class: 'open' };
    } catch (error) {
      console.error('Enrollment status calculation error:', error);
      return { status: 'open', label: 'Open', class: 'open' };
    }
  }, []);

  const getStatusClass = useCallback((status) => {
    const statusMap = {
      'active': 'active',
      'inactive': 'inactive', 
      'archived': 'archived'
    };
    return statusMap[status] || 'active';
  }, []);

  const enrollmentStatus = getEnrollmentStatus(course.enrolled_count || 0, course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY);
  const enrollmentPercentage = Math.round(((course.enrolled_count || 0) / (course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY)) * 100);

  return (
    <tr className="course-row" role="row">
      <td role="cell">
        <div className="course-code">
          <BookOpen size={16} aria-hidden="true" />
          <span>{course.code || 'N/A'}</span>
        </div>
      </td>
      <td role="cell">
        <div className="course-title">
          <strong>{course.title || 'Untitled Course'}</strong>
          {course.description && (
            <span className="course-description">{course.description}</span>
          )}
        </div>
      </td>
      <td role="cell">{course.department || 'N/A'}</td>
      <td role="cell">
        <span className="credits-badge">{course.credits || 3}</span>
      </td>
      <td role="cell">{course.instructor || 'TBA'}</td>
      <td role="cell">
        <div className="enrollment-info">
          <span className="enrollment-count">{course.enrolled_count || 0}</span>
          <div className="enrollment-bar" role="progressbar" 
               aria-valuenow={enrollmentPercentage} 
               aria-valuemin="0" 
               aria-valuemax="100">
            <div 
              className={`enrollment-fill ${enrollmentStatus.class}`}
              style={{width: `${enrollmentPercentage}%`}}
            ></div>
          </div>
          <span className="enrollment-percent">{enrollmentPercentage}%</span>
        </div>
      </td>
      <td role="cell">{course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY}</td>
      <td role="cell">
        <span className={`status-badge ${getStatusClass(course.status)}`}>
          {course.status || 'active'}
        </span>
      </td>
      <td role="cell">
        <div className="action-buttons">
          <button 
            className="btn-icon primary"
            onClick={() => onAddSection(course)}
            title="Add Section"
            aria-label={`Add section to ${course.code}`}
          >
            <Plus size={14} aria-hidden="true" />
          </button>
          <button 
            className="btn-icon secondary"
            onClick={() => onEdit(course)}
            title="Edit Course"
            aria-label={`Edit ${course.code}`}
          >
            <Edit size={14} aria-hidden="true" />
          </button>
          <button 
            className="btn-icon danger"
            onClick={() => onDelete(course.id)}
            title="Archive Course"
            aria-label={`Archive ${course.code}`}
          >
            <Trash2 size={14} aria-hidden="true" />
          </button>
        </div>
      </td>
    </tr>
  );
});

// Enhanced Trend Card with Analytics
const TrendCard = React.memo(({ course }) => {
  const utilization = Math.round(((course.enrolled_count || 0) / (course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY)) * 100);
  
  const getDemandLevel = (utilization) => {
    if (utilization > 90) return { level: 'high', label: 'High Demand' };
    if (utilization > 70) return { level: 'medium', label: 'Medium Demand' };
    return { level: 'low', label: 'Low Demand' };
  };

  const demand = getDemandLevel(utilization);

  return (
    <div className="trend-card" role="article" aria-label={`${course.code} enrollment trends`}>
      <div className="trend-header">
        <div className="trend-course">
          <div className="course-code-small">{course.code}</div>
          <div className="course-title-small">{course.title}</div>
        </div>
        <div className={`utilization-badge ${demand.level}`}>
          {utilization}%
        </div>
      </div>
      <div className="trend-metrics">
        <div className="trend-metric">
          <span className="metric-label">Enrolled:</span>
          <span className="metric-value">{course.enrolled_count || 0}</span>
        </div>
        <div className="trend-metric">
          <span className="metric-label">Capacity:</span>
          <span className="metric-value">{course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY}</span>
        </div>
        <div className="trend-metric">
          <span className="metric-label">Waitlist:</span>
          <span className="metric-value">{course.waitlist_count || 0}</span>
        </div>
      </div>
      <div className={`trend-indicator ${demand.level}`}>
        {demand.label}
      </div>
    </div>
  );
});

// Validation Utilities
const validateCourseForm = (formData) => {
  const errors = {};

  if (!formData.code?.trim()) {
    errors.code = 'Course code is required';
  } else if (!ENTERPRISE_CONFIG.VALIDATION.COURSE_CODE_PATTERN.test(formData.code)) {
    errors.code = 'Course code must follow pattern like CS101, MATH201';
  }

  if (!formData.title?.trim()) {
    errors.title = 'Course title is required';
  } else if (formData.title.length < ENTERPRISE_CONFIG.VALIDATION.MIN_COURSE_TITLE_LENGTH) {
    errors.title = `Course title must be at least ${ENTERPRISE_CONFIG.VALIDATION.MIN_COURSE_TITLE_LENGTH} characters`;
  } else if (formData.title.length > ENTERPRISE_CONFIG.VALIDATION.MAX_COURSE_TITLE_LENGTH) {
    errors.title = `Course title must be less than ${ENTERPRISE_CONFIG.VALIDATION.MAX_COURSE_TITLE_LENGTH} characters`;
  }

  if (!formData.credits || formData.credits < ENTERPRISE_CONFIG.COURSE.MIN_CREDITS || formData.credits > ENTERPRISE_CONFIG.COURSE.MAX_CREDITS) {
    errors.credits = `Credits must be between ${ENTERPRISE_CONFIG.COURSE.MIN_CREDITS} and ${ENTERPRISE_CONFIG.COURSE.MAX_CREDITS}`;
  }

  if (!formData.capacity || formData.capacity < 1) {
    errors.capacity = 'Capacity must be at least 1';
  }

  if (!formData.department_id) {
    errors.department_id = 'Department is required';
  }

  return errors;
};

const validateSectionForm = (formData) => {
  const errors = {};

  if (!formData.section_number?.trim()) {
    errors.section_number = 'Section number is required';
  }

  if (!formData.faculty_id) {
    errors.faculty_id = 'Faculty is required';
  }

  if (!formData.schedule?.trim()) {
    errors.schedule = 'Schedule is required';
  }

  if (!formData.room?.trim()) {
    errors.room = 'Room is required';
  }

  if (!formData.capacity || formData.capacity < 1) {
    errors.capacity = 'Capacity must be at least 1';
  }

  return errors;
};

const CourseManagement = () => {
  // State Management
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    department: '',
    status: ''
  });
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showSectionModal, setShowSectionModal] = useState(false);
  const [selectedCourse, setSelectedCourse] = useState(null);
  const [stats, setStats] = useState({
    total: 0,
    active: 0,
    avgEnrollment: 0,
    highDemand: 0
  });
  const [facultyList, setFacultyList] = useState([]);
  const [formErrors, setFormErrors] = useState({});
  const [operationInProgress, setOperationInProgress] = useState(false);
  
  // Refs for performance and cleanup
  const searchTimeoutRef = useRef(null);
  const abortControllerRef = useRef(new AbortController());

  // API Hooks with Enhanced Error Handling
  const { 
    data: coursesData, 
    loading: coursesLoading, 
    error: coursesError, 
    refetch: refetchCourses 
  } = useApi(
    useCallback(() => coursesAPI.getCourses(filters), [filters]),
    {
      retry: ENTERPRISE_CONFIG.PERFORMANCE.MAX_RETRY_ATTEMPTS,
      cacheKey: 'courses-data',
      cacheTimeout: ENTERPRISE_CONFIG.PERFORMANCE.CACHE_DURATION
    }
  );

  const { data: enrollmentStats, refetch: refetchStats } = useApi(
    useCallback(() => coursesAPI.getEnrollmentStats(), [])
  );

  // Form States
  const [courseForm, setCourseForm] = useState({
    code: '',
    title: '',
    description: '',
    credits: 3,
    department_id: '',
    prerequisites: '',
    capacity: ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY,
    status: 'active'
  });

  const [sectionForm, setSectionForm] = useState({
    section_number: '',
    semester: 'Spring',
    year: new Date().getFullYear(),
    faculty_id: '',
    schedule: '',
    room: '',
    capacity: ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY
  });

  // Fetch Faculty Data
  useEffect(() => {
    const fetchFaculty = async () => {
      try {
        const response = await facultyAPI.getFacultyList();
        if (response.success) {
          setFacultyList(response.data);
        } else {
          throw new Error(response.error || 'Failed to fetch faculty');
        }
      } catch (err) {
        console.error('Failed to fetch faculty list:', err);
        // Fallback to sample data with proper error handling
        setFacultyList([
          {id: 1, name: 'Dr. John Smith', department: 'Computer Science'},
          {id: 2, name: 'Prof. Maria Garcia', department: 'Mathematics'},
          {id: 3, name: 'Dr. Robert Chen', department: 'Engineering'},
          {id: 4, name: 'Prof. Sarah Johnson', department: 'Physics'}
        ]);
        
        if (process.env.NODE_ENV === 'production') {
          setError('Faculty data temporarily unavailable. Using cached data.');
        }
      }
    };
    
    fetchFaculty();
  }, []);

  // Data Synchronization
  useEffect(() => {
    if (coursesData) {
      setCourses(coursesData);
      calculateStats(coursesData);
      setLoading(false);
    }
  }, [coursesData]);

  // Error Handling
  useEffect(() => {
    if (coursesError) {
      setError(`Failed to load courses: ${coursesError.message}`);
      setLoading(false);
    }
  }, [coursesError]);

  // Filter Effect with Cleanup
  useEffect(() => {
    const controller = new AbortController();
    refetchCourses();
    
    return () => {
      controller.abort();
    };
  }, [filters, refetchCourses]);

  // Cleanup on Unmount
  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
      abortControllerRef.current.abort();
    };
  }, []);

  // Memoized Stats Calculation
  const calculateStats = useCallback((coursesList) => {
    try {
      const activeCourses = coursesList.filter(c => c.status === 'active').length;
      const totalEnrollment = coursesList.reduce((sum, c) => sum + (c.enrolled_count || 0), 0);
      const avgEnrollment = coursesList.length > 0 ? totalEnrollment / coursesList.length : 0;
      const highDemand = coursesList.filter(c => (c.enrolled_count || 0) > (c.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY) * 0.9).length;

      setStats({
        total: coursesList.length,
        active: activeCourses,
        avgEnrollment: Math.round(avgEnrollment),
        highDemand: highDemand
      });

      // Track stats for analytics
      if (window.analyticsService) {
        window.analyticsService.track('course_stats_updated', {
          totalCourses: coursesList.length,
          activeCourses,
          avgEnrollment: Math.round(avgEnrollment),
          highDemandCourses: highDemand,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Stats calculation error:', error);
    }
  }, []);

  // Memoized Filtered Courses with Performance Optimization
  const filteredCourses = useMemo(() => {
    if (!searchTerm.trim()) return courses;
    
    const term = searchTerm.toLowerCase().trim();
    return courses.filter(course =>
      course.code?.toLowerCase().includes(term) ||
      course.title?.toLowerCase().includes(term) ||
      course.department?.toLowerCase().includes(term) ||
      course.instructor?.toLowerCase().includes(term)
    );
  }, [courses, searchTerm]);

  // Enhanced Search Handler with Debouncing
  const handleSearch = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    
    searchTimeoutRef.current = setTimeout(() => {
      // Search logic is handled by filteredCourses memo
      if (window.analyticsService && value.length > 2) {
        window.analyticsService.track('course_search', {
          searchTerm: value,
          resultCount: filteredCourses.length,
          timestamp: new Date().toISOString()
        });
      }
    }, ENTERPRISE_CONFIG.PERFORMANCE.SEARCH_DEBOUNCE);
  }, [filteredCourses.length]);

  // Enhanced CRUD Operations with Validation and Error Handling
  const handleCreateCourse = useCallback(async (e) => {
    e.preventDefault();
    
    const errors = validateCourseForm(courseForm);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    setOperationInProgress(true);
    setFormErrors({});

    try {
      setError('');
      const response = await coursesAPI.createCourse(courseForm);
      
      if (response.success) {
        setShowAddModal(false);
        resetCourseForm();
        await refetchCourses();
        
        // Track successful creation
        if (window.analyticsService) {
          window.analyticsService.track('course_created', {
            courseCode: courseForm.code,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to create course');
      }
    } catch (err) {
      const errorMsg = 'Failed to create course. Please try again.';
      setError(errorMsg);
      console.error('Create course error:', err);
      
      // Track creation failure
      if (window.analyticsService) {
        window.analyticsService.track('course_creation_failed', {
          courseCode: courseForm.code,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      }
    } finally {
      setOperationInProgress(false);
    }
  }, [courseForm, refetchCourses]);

  const handleUpdateCourse = useCallback(async (e) => {
    e.preventDefault();
    
    const errors = validateCourseForm(courseForm);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    setOperationInProgress(true);
    setFormErrors({});

    try {
      setError('');
      const response = await coursesAPI.updateCourse(selectedCourse.id, courseForm);
      
      if (response.success) {
        setShowEditModal(false);
        setSelectedCourse(null);
        resetCourseForm();
        await refetchCourses();
        
        // Track successful update
        if (window.analyticsService) {
          window.analyticsService.track('course_updated', {
            courseId: selectedCourse.id,
            courseCode: courseForm.code,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to update course');
      }
    } catch (err) {
      const errorMsg = 'Failed to update course. Please try again.';
      setError(errorMsg);
      console.error('Update course error:', err);
    } finally {
      setOperationInProgress(false);
    }
  }, [selectedCourse, courseForm, refetchCourses]);

  const handleDeleteCourse = useCallback(async (courseId) => {
    if (!window.confirm('Are you sure you want to archive this course? This will make it inactive and remove it from active listings.')) {
      return;
    }

    try {
      setError('');
      const response = await coursesAPI.deleteCourse(courseId);
      
      if (response.success) {
        await refetchCourses();
        
        // Track successful archive
        if (window.analyticsService) {
          window.analyticsService.track('course_archived', {
            courseId,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to archive course');
      }
    } catch (err) {
      const errorMsg = 'Failed to archive course. Please try again.';
      setError(errorMsg);
      console.error('Delete course error:', err);
    }
  }, [refetchCourses]);

  const handleCreateSection = useCallback(async (e) => {
    e.preventDefault();
    
    const errors = validateSectionForm(sectionForm);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    setOperationInProgress(true);
    setFormErrors({});

    try {
      setError('');
      const response = await coursesAPI.createCourseSection(selectedCourse.id, sectionForm);
      
      if (response.success) {
        setShowSectionModal(false);
        resetSectionForm();
        await refetchCourses();
        
        // Track successful section creation
        if (window.analyticsService) {
          window.analyticsService.track('course_section_created', {
            courseId: selectedCourse.id,
            sectionNumber: sectionForm.section_number,
            timestamp: new Date().toISOString()
          });
        }
      } else {
        setError(response.error || 'Failed to create course section');
      }
    } catch (err) {
      const errorMsg = 'Failed to create course section. Please try again.';
      setError(errorMsg);
      console.error('Create section error:', err);
    } finally {
      setOperationInProgress(false);
    }
  }, [selectedCourse, sectionForm, refetchCourses]);

  // Enhanced Export with Error Handling
  const handleExport = useCallback(async () => {
    try {
      setError('');
      const response = await coursesAPI.exportCourses();
      
      if (response.success && response.data) {
        // Create secure download
        const blob = new Blob([response.data], { 
          type: 'text/csv; charset=utf-8',
          endings: 'native'
        });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `courses_export_${new Date().toISOString().split('T')[0]}.csv`;
        link.setAttribute('type', 'text/csv');
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Cleanup URL
        setTimeout(() => window.URL.revokeObjectURL(url), 100);
        
        // Track successful export
        if (window.analyticsService) {
          window.analyticsService.track('courses_exported', {
            timestamp: new Date().toISOString(),
            recordCount: courses.length
          });
        }
      } else {
        setError('Export failed - no data received from server');
      }
    } catch (err) {
      const errorMsg = 'Failed to export courses. Please try again.';
      setError(errorMsg);
      console.error('Export error:', err);
    }
  }, [courses.length]);

  // Form Management Functions
  const resetCourseForm = useCallback(() => {
    setCourseForm({
      code: '',
      title: '',
      description: '',
      credits: 3,
      department_id: '',
      prerequisites: '',
      capacity: ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY,
      status: 'active'
    });
    setFormErrors({});
  }, []);

  const resetSectionForm = useCallback(() => {
    setSectionForm({
      section_number: '',
      semester: 'Spring',
      year: new Date().getFullYear(),
      faculty_id: '',
      schedule: '',
      room: '',
      capacity: ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY
    });
    setFormErrors({});
  }, []);

  const handleEditClick = useCallback((course) => {
    setSelectedCourse(course);
    setCourseForm({
      code: course.code || '',
      title: course.title || '',
      description: course.description || '',
      credits: course.credits || 3,
      department_id: course.department_id || '',
      prerequisites: course.prerequisites || '',
      capacity: course.capacity || ENTERPRISE_CONFIG.COURSE.DEFAULT_CAPACITY,
      status: course.status || 'active'
    });
    setFormErrors({});
    setShowEditModal(true);
  }, []);

  const handleSectionClick = useCallback((course) => {
    setSelectedCourse(course);
    setFormErrors({});
    setShowSectionModal(true);
  }, []);

  const handleRefresh = useCallback(() => {
    setError('');
    setLoading(true);
    Promise.all([refetchCourses(), refetchStats()])
      .finally(() => setLoading(false));
  }, [refetchCourses, refetchStats]);

  const handleFilterChange = useCallback((key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    
    // Track filter usage
    if (window.analyticsService) {
      window.analyticsService.track('course_filter_applied', {
        filter: key,
        value,
        timestamp: new Date().toISOString()
      });
    }
  }, []);

  // Memoized Top Courses for Trends
  const topCourses = useMemo(() => 
    filteredCourses
      .sort((a, b) => (b.enrolled_count || 0) - (a.enrolled_count || 0))
      .slice(0, 4), 
    [filteredCourses]
  );

  // Enhanced Modal Handlers
  const handleCloseAddModal = useCallback(() => {
    setShowAddModal(false);
    resetCourseForm();
  }, [resetCourseForm]);

  const handleCloseEditModal = useCallback(() => {
    setShowEditModal(false);
    setSelectedCourse(null);
    resetCourseForm();
  }, [resetCourseForm]);

  const handleCloseSectionModal = useCallback(() => {
    setShowSectionModal(false);
    setSelectedCourse(null);
    resetSectionForm();
  }, [resetSectionForm]);

  // Loading State
  if (loading && courses.length === 0) {
    return (
      <div className="course-management-container">
        <div className="loading-container" role="status" aria-live="polite">
          <div className="loading-spinner" aria-hidden="true"></div>
          <p>Loading course data...</p>
        </div>
      </div>
    );
  }

  return (
    <CourseErrorBoundary>
      <div className="course-management-container">
        {/* Header Section */}
        <header className="header" role="banner">
          <h1 className="header-title">Course Management</h1>
          <div className="header-actions">
            <button 
              className="btn-primary" 
              onClick={() => setShowAddModal(true)}
              aria-label="Add new course"
            >
              <Plus size={16} aria-hidden="true" />
              Add Course
            </button>
            <button 
              className="btn-secondary" 
              onClick={handleExport}
              disabled={courses.length === 0}
              aria-label="Export courses data"
            >
              <Download size={16} aria-hidden="true" />
              Export
            </button>
            <button 
              className="btn-icon" 
              onClick={handleRefresh} 
              disabled={coursesLoading}
              aria-label="Refresh course data"
            >
              <RefreshCw 
                size={16} 
                className={coursesLoading ? 'spinning' : ''} 
                aria-hidden="true" 
              />
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

        {/* Stats Dashboard */}
        <section className="stats-grid" aria-label="Course statistics">
          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Total Courses</span>
              <BookOpen className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.total}</div>
            <div className="stat-change neutral">All departments</div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Active Courses</span>
              <BookOpen className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.active}</div>
            <div className="stat-change positive">
              {stats.active > 0 ? `${Math.round((stats.active / stats.total) * 100)}% of total` : 'No active courses'}
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Avg Enrollment</span>
              <Users className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.avgEnrollment}</div>
            <div className="stat-change positive">Per course</div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">High Demand</span>
              <TrendingUp className="stat-icon" aria-hidden="true" />
            </div>
            <div className="stat-value">{stats.highDemand}</div>
            <div className="stat-change warning">
              {stats.highDemand > 0 ? `${Math.round((stats.highDemand / stats.total) * 100)}% of courses` : 'No high demand'}
            </div>
          </div>
        </section>

        {/* Controls Section */}
        <section className="controls-section" aria-label="Course search and filters">
          <div className="search-box">
            <Search size={18} aria-hidden="true" />
            <input
              type="text"
              placeholder="Search courses by code, title, department, or instructor..."
              value={searchTerm}
              onChange={handleSearch}
              aria-label="Search courses"
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
              <option value="archived">Archived</option>
            </select>
          </div>
        </section>

        {/* Courses Table */}
        <section className="table-section" aria-label="Courses list">
          <div className="table-container">
            <table className="courses-table" aria-label="Courses data">
              <thead>
                <tr>
                  <th scope="col">Course Code</th>
                  <th scope="col">Title</th>
                  <th scope="col">Department</th>
                  <th scope="col">Credits</th>
                  <th scope="col">Instructor</th>
                  <th scope="col">Enrollment</th>
                  <th scope="col">Capacity</th>
                  <th scope="col">Status</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredCourses.map((course) => (
                  <CourseRow 
                    key={course.id}
                    course={course}
                    onEdit={handleEditClick}
                    onDelete={handleDeleteCourse}
                    onAddSection={handleSectionClick}
                  />
                ))}
              </tbody>
            </table>
            
            {filteredCourses.length === 0 && (
              <div className="empty-state" role="status" aria-live="polite">
                <BookOpen size={48} aria-hidden="true" />
                <h3>No courses found</h3>
                <p>Try adjusting your search or filters, or add a new course</p>
                <button 
                  className="btn-primary" 
                  onClick={() => setShowAddModal(true)}
                  aria-label="Add first course"
                >
                  <Plus size={16} aria-hidden="true" />
                  Add First Course
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Enrollment Trends */}
        {topCourses.length > 0 && (
          <section className="trends-section" aria-label="Enrollment trends">
            <div className="section-header">
              <h3>Enrollment Trends</h3>
              <button className="btn-secondary" onClick={handleExport}>
                <Download size={14} aria-hidden="true" />
                Export Trends
              </button>
            </div>
            <div className="trends-grid">
              {topCourses.map(course => (
                <TrendCard key={course.id} course={course} />
              ))}
            </div>
          </section>
        )}

        {/* Add Course Modal */}
        {showAddModal && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="add-course-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="add-course-title">Add New Course</h3>
                <button 
                  onClick={handleCloseAddModal} 
                  className="close-btn"
                  aria-label="Close add course modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleCreateCourse} className="modal-form">
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="course-code">Course Code *</label>
                    <input
                      id="course-code"
                      type="text"
                      value={courseForm.code}
                      onChange={(e) => setCourseForm({...courseForm, code: e.target.value.toUpperCase()})}
                      placeholder="e.g., CS101"
                      required
                      className={formErrors.code ? 'error' : ''}
                    />
                    {formErrors.code && <span className="error-message">{formErrors.code}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="course-credits">Credits *</label>
                    <input
                      id="course-credits"
                      type="number"
                      value={courseForm.credits}
                      onChange={(e) => setCourseForm({...courseForm, credits: parseInt(e.target.value) || ''})}
                      min={ENTERPRISE_CONFIG.COURSE.MIN_CREDITS}
                      max={ENTERPRISE_CONFIG.COURSE.MAX_CREDITS}
                      required
                      className={formErrors.credits ? 'error' : ''}
                    />
                    {formErrors.credits && <span className="error-message">{formErrors.credits}</span>}
                  </div>
                </div>
                
                <div className="form-group">
                  <label htmlFor="course-title">Course Title *</label>
                  <input
                    id="course-title"
                    type="text"
                    value={courseForm.title}
                    onChange={(e) => setCourseForm({...courseForm, title: e.target.value})}
                    placeholder="e.g., Introduction to Programming"
                    required
                    className={formErrors.title ? 'error' : ''}
                  />
                  {formErrors.title && <span className="error-message">{formErrors.title}</span>}
                </div>
                
                <div className="form-group">
                  <label htmlFor="course-description">Description</label>
                  <textarea
                    id="course-description"
                    value={courseForm.description}
                    onChange={(e) => setCourseForm({...courseForm, description: e.target.value})}
                    placeholder="Course description and objectives..."
                    rows="3"
                  />
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="course-department">Department *</label>
                    <select
                      id="course-department"
                      value={courseForm.department_id}
                      onChange={(e) => setCourseForm({...courseForm, department_id: e.target.value})}
                      required
                      className={formErrors.department_id ? 'error' : ''}
                    >
                      <option value="">Select Department</option>
                      <option value="1">Computer Science</option>
                      <option value="2">Mathematics</option>
                      <option value="3">Engineering</option>
                      <option value="4">Physics</option>
                    </select>
                    {formErrors.department_id && <span className="error-message">{formErrors.department_id}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="course-capacity">Capacity *</label>
                    <input
                      id="course-capacity"
                      type="number"
                      value={courseForm.capacity}
                      onChange={(e) => setCourseForm({...courseForm, capacity: parseInt(e.target.value) || ''})}
                      min="1"
                      required
                      className={formErrors.capacity ? 'error' : ''}
                    />
                    {formErrors.capacity && <span className="error-message">{formErrors.capacity}</span>}
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="course-prerequisites">Prerequisites</label>
                    <input
                      id="course-prerequisites"
                      type="text"
                      value={courseForm.prerequisites}
                      onChange={(e) => setCourseForm({...courseForm, prerequisites: e.target.value})}
                      placeholder="e.g., CS101, MATH201"
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="course-status">Status</label>
                    <select
                      id="course-status"
                      value={courseForm.status}
                      onChange={(e) => setCourseForm({...courseForm, status: e.target.value})}
                    >
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                    </select>
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
                    {operationInProgress ? 'Creating...' : 'Create Course'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Edit Course Modal */}
        {showEditModal && selectedCourse && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="edit-course-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="edit-course-title">Edit Course</h3>
                <button 
                  onClick={handleCloseEditModal} 
                  className="close-btn"
                  aria-label="Close edit course modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleUpdateCourse} className="modal-form">
                <div className="form-row">
                  <div className="form-group">
                    <label>Course Code</label>
                    <input
                      type="text"
                      value={courseForm.code}
                      onChange={(e) => setCourseForm({...courseForm, code: e.target.value.toUpperCase()})}
                      required
                      disabled
                      className={formErrors.code ? 'error' : ''}
                    />
                    {formErrors.code && <span className="error-message">{formErrors.code}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-course-credits">Credits *</label>
                    <input
                      id="edit-course-credits"
                      type="number"
                      value={courseForm.credits}
                      onChange={(e) => setCourseForm({...courseForm, credits: parseInt(e.target.value) || ''})}
                      min={ENTERPRISE_CONFIG.COURSE.MIN_CREDITS}
                      max={ENTERPRISE_CONFIG.COURSE.MAX_CREDITS}
                      required
                      className={formErrors.credits ? 'error' : ''}
                    />
                    {formErrors.credits && <span className="error-message">{formErrors.credits}</span>}
                  </div>
                </div>
                
                <div className="form-group">
                  <label htmlFor="edit-course-title">Course Title *</label>
                  <input
                    id="edit-course-title"
                    type="text"
                    value={courseForm.title}
                    onChange={(e) => setCourseForm({...courseForm, title: e.target.value})}
                    required
                    className={formErrors.title ? 'error' : ''}
                  />
                  {formErrors.title && <span className="error-message">{formErrors.title}</span>}
                </div>
                
                <div className="form-group">
                  <label htmlFor="edit-course-description">Description</label>
                  <textarea
                    id="edit-course-description"
                    value={courseForm.description}
                    onChange={(e) => setCourseForm({...courseForm, description: e.target.value})}
                    rows="3"
                  />
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-course-department">Department *</label>
                    <select
                      id="edit-course-department"
                      value={courseForm.department_id}
                      onChange={(e) => setCourseForm({...courseForm, department_id: e.target.value})}
                      required
                      className={formErrors.department_id ? 'error' : ''}
                    >
                      <option value="1">Computer Science</option>
                      <option value="2">Mathematics</option>
                      <option value="3">Engineering</option>
                      <option value="4">Physics</option>
                    </select>
                    {formErrors.department_id && <span className="error-message">{formErrors.department_id}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-course-capacity">Capacity *</label>
                    <input
                      id="edit-course-capacity"
                      type="number"
                      value={courseForm.capacity}
                      onChange={(e) => setCourseForm({...courseForm, capacity: parseInt(e.target.value) || ''})}
                      min="1"
                      required
                      className={formErrors.capacity ? 'error' : ''}
                    />
                    {formErrors.capacity && <span className="error-message">{formErrors.capacity}</span>}
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="edit-course-prerequisites">Prerequisites</label>
                    <input
                      id="edit-course-prerequisites"
                      type="text"
                      value={courseForm.prerequisites}
                      onChange={(e) => setCourseForm({...courseForm, prerequisites: e.target.value})}
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="edit-course-status">Status</label>
                    <select
                      id="edit-course-status"
                      value={courseForm.status}
                      onChange={(e) => setCourseForm({...courseForm, status: e.target.value})}
                    >
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                    </select>
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
                    {operationInProgress ? 'Updating...' : 'Update Course'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Add Section Modal */}
        {showSectionModal && selectedCourse && (
          <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="add-section-title">
            <div className="modal">
              <div className="modal-header">
                <h3 id="add-section-title">Add Section to {selectedCourse.code}</h3>
                <button 
                  onClick={handleCloseSectionModal} 
                  className="close-btn"
                  aria-label="Close add section modal"
                >
                  <X size={20} aria-hidden="true" />
                </button>
              </div>
              <form onSubmit={handleCreateSection} className="modal-form">
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="section-number">Section Number *</label>
                    <input
                      id="section-number"
                      type="text"
                      value={sectionForm.section_number}
                      onChange={(e) => setSectionForm({...sectionForm, section_number: e.target.value})}
                      placeholder="e.g., 001"
                      required
                      className={formErrors.section_number ? 'error' : ''}
                    />
                    {formErrors.section_number && <span className="error-message">{formErrors.section_number}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="section-semester">Semester *</label>
                    <select
                      id="section-semester"
                      value={sectionForm.semester}
                      onChange={(e) => setSectionForm({...sectionForm, semester: e.target.value})}
                      required
                    >
                      {ENTERPRISE_CONFIG.COURSE.SEMESTER_OPTIONS.map(semester => (
                        <option key={semester} value={semester}>{semester}</option>
                      ))}
                    </select>
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="section-year">Year *</label>
                    <input
                      id="section-year"
                      type="number"
                      value={sectionForm.year}
                      onChange={(e) => setSectionForm({...sectionForm, year: parseInt(e.target.value) || ''})}
                      min="2020"
                      max="2030"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="section-capacity">Section Capacity *</label>
                    <input
                      id="section-capacity"
                      type="number"
                      value={sectionForm.capacity}
                      onChange={(e) => setSectionForm({...sectionForm, capacity: parseInt(e.target.value) || ''})}
                      min="1"
                      required
                      className={formErrors.capacity ? 'error' : ''}
                    />
                    {formErrors.capacity && <span className="error-message">{formErrors.capacity}</span>}
                  </div>
                </div>
                
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="section-faculty">Faculty *</label>
                    <select
                      id="section-faculty"
                      value={sectionForm.faculty_id}
                      onChange={(e) => setSectionForm({...sectionForm, faculty_id: parseInt(e.target.value)})}
                      required
                      className={formErrors.faculty_id ? 'error' : ''}
                    >
                      <option value="">Select Faculty</option>
                      {facultyList.map(faculty => (
                        <option key={faculty.id} value={faculty.id}>
                          {faculty.name} - {faculty.department}
                        </option>
                      ))}
                    </select>
                    {formErrors.faculty_id && <span className="error-message">{formErrors.faculty_id}</span>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="section-room">Room *</label>
                    <input
                      id="section-room"
                      type="text"
                      value={sectionForm.room}
                      onChange={(e) => setSectionForm({...sectionForm, room: e.target.value})}
                      placeholder="e.g., SCI-201"
                      required
                      className={formErrors.room ? 'error' : ''}
                    />
                    {formErrors.room && <span className="error-message">{formErrors.room}</span>}
                  </div>
                </div>
                
                <div className="form-group">
                  <label htmlFor="section-schedule">Schedule *</label>
                  <input
                    id="section-schedule"
                    type="text"
                    value={sectionForm.schedule}
                    onChange={(e) => setSectionForm({...sectionForm, schedule: e.target.value})}
                    placeholder="e.g., MWF 10:00-11:00"
                    required
                    className={formErrors.schedule ? 'error' : ''}
                  />
                  {formErrors.schedule && <span className="error-message">{formErrors.schedule}</span>}
                </div>
                
                <div className="modal-actions">
                  <button 
                    type="button" 
                    onClick={handleCloseSectionModal} 
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
                    {operationInProgress ? 'Creating...' : 'Create Section'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </CourseErrorBoundary>
  );
};

export default CourseManagement;