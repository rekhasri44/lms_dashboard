import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  BookOpen, Search, Filter, Plus, Edit, Trash2, Download, 
  AlertTriangle, X, Save, Users, Calendar, Clock, Eye,
  GraduationCap, BarChart3, TrendingUp, RefreshCw
} from 'lucide-react';
import { coursesAPI, analyticsAPI } from '../services/api';
import { useApi } from '../hooks/useApi';
import './CourseManagement.css';

// Memoized course row component
const CourseRow = React.memo(({ course, onEdit, onDelete, onAddSection }) => {
  const getEnrollmentStatus = useCallback((enrolled, capacity) => {
    const percentage = (enrolled / capacity) * 100;
    if (percentage >= 95) return { status: 'full', label: 'Full', class: 'full' };
    if (percentage >= 80) return { status: 'nearly-full', label: 'Nearly Full', class: 'nearly-full' };
    return { status: 'open', label: 'Open', class: 'open' };
  }, []);

  const getStatusClass = useCallback((status) => {
    switch(status) {
      case 'active': return 'active';
      case 'inactive': return 'inactive';
      case 'archived': return 'archived';
      default: return 'active';
    }
  }, []);

  const enrollmentStatus = getEnrollmentStatus(course.enrolled_count || 0, course.capacity || 30);
  const enrollmentPercentage = Math.round(((course.enrolled_count || 0) / (course.capacity || 30)) * 100);

  return (
    <tr key={course.id}>
      <td>
        <div className="course-code">
          <BookOpen size={16} />
          {course.code}
        </div>
      </td>
      <td>
        <div className="course-title">
          <strong>{course.title}</strong>
          {course.description && (
            <span className="course-description">{course.description}</span>
          )}
        </div>
      </td>
      <td>{course.department || 'N/A'}</td>
      <td>
        <span className="credits-badge">{course.credits}</span>
      </td>
      <td>{course.instructor || 'TBA'}</td>
      <td>
        <div className="enrollment-info">
          <span className="enrollment-count">{course.enrolled_count || 0}</span>
          <div className="enrollment-bar">
            <div 
              className={`enrollment-fill ${enrollmentStatus.class}`}
              style={{width: `${enrollmentPercentage}%`}}
            ></div>
          </div>
          <span className="enrollment-percent">{enrollmentPercentage}%</span>
        </div>
      </td>
      <td>{course.capacity || 30}</td>
      <td>
        <span className={`status-badge ${getStatusClass(course.status)}`}>
          {course.status}
        </span>
      </td>
      <td>
        <div className="action-buttons">
          <button 
            className="btn-icon primary"
            onClick={() => onAddSection(course)}
            title="Add Section"
          >
            <Plus size={14} />
          </button>
          <button 
            className="btn-icon secondary"
            onClick={() => onEdit(course)}
            title="Edit Course"
          >
            <Edit size={14} />
          </button>
          <button 
            className="btn-icon danger"
            onClick={() => onDelete(course.id)}
            title="Archive Course"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </td>
    </tr>
  );
});

// Memoized trend card component
const TrendCard = React.memo(({ course }) => {
  const utilization = Math.round(((course.enrolled_count || 0) / (course.capacity || 30)) * 100);
  
  return (
    <div className="trend-card">
      <div className="trend-header">
        <div className="trend-course">
          <div className="course-code-small">{course.code}</div>
          <div className="course-title-small">{course.title}</div>
        </div>
        <div className={`utilization-badge ${utilization > 90 ? 'high' : utilization > 70 ? 'medium' : 'low'}`}>
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
          <span className="metric-value">{course.capacity || 30}</span>
        </div>
        <div className="trend-metric">
          <span className="metric-label">Waitlist:</span>
          <span className="metric-value">{course.waitlist_count || 0}</span>
        </div>
      </div>
      <div className="trend-indicator">
        {utilization > 90 ? 'High Demand' : utilization > 70 ? 'Medium Demand' : 'Low Demand'}
      </div>
    </div>
  );
});

const CourseManagement = () => {
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
  
  // Debounced search
  const [searchTimeout, setSearchTimeout] = useState(null);

  // Form states
  const [courseForm, setCourseForm] = useState({
    code: '',
    title: '',
    description: '',
    credits: 3,
    department_id: '',
    prerequisites: '',
    capacity: 30,
    status: 'active'
  });

  const [sectionForm, setSectionForm] = useState({
    section_number: '',
    semester: 'Spring',
    year: new Date().getFullYear(),
    faculty_id: '',
    schedule: '',
    room: '',
    capacity: 30
  });

  // Real API integration with useCallback
  const [facultyList, setFacultyList] = useState([]);

// Fetch real faculty
useEffect(() => {
  const fetchFaculty = async () => {
    try {
      const response = await facultyAPI.getFacultyList();
      if (response.success) {
        setFacultyList(response.data);
      }
    } catch (err) {
      console.error('Failed to fetch faculty list:', err);
      // Fallback to sample data
      setFacultyList([
        {id: 1, name: 'Dr. John Smith', department: 'Computer Science'},
        {id: 2, name: 'Prof. Maria Garcia', department: 'Mathematics'}
      ]);
    }
  };
  fetchFaculty();
}, []);

// In the section modal form:
<div className="form-group">
  <label>Faculty *</label>
  <select
  value={sectionForm.faculty_id}
  onChange={(e) => setSectionForm({...sectionForm, faculty_id: parseInt(e.target.value)})}
  required
>
  <option value="">Select Faculty</option>
  {facultyList.map(faculty => (
    <option key={faculty.id} value={faculty.id}>
      {faculty.name} - {faculty.department}
    </option>
  ))}
</select>

</div>

  const { data: coursesData, loading: coursesLoading, error: coursesError, refetch: refetchCourses } = useApi(
    useCallback(() => coursesAPI.getCourses(filters), [filters])
  );

  const { data: enrollmentStats, refetch: refetchStats } = useApi(
    useCallback(() => coursesAPI.getEnrollmentStats(), [])
  );

  useEffect(() => {
    if (coursesData) {
      setCourses(coursesData);
      calculateStats(coursesData);
    }
  }, [coursesData]);

  useEffect(() => {
    if (coursesError) {
      setError(coursesError);
    }
  }, [coursesError]);

  useEffect(() => {
    refetchCourses();
  }, [filters]);

  // Memoized stats calculation
  const calculateStats = useCallback((coursesList) => {
    const activeCourses = coursesList.filter(c => c.status === 'active').length;
    const totalEnrollment = coursesList.reduce((sum, c) => sum + (c.enrolled_count || 0), 0);
    const avgEnrollment = coursesList.length > 0 ? totalEnrollment / coursesList.length : 0;
    const highDemand = coursesList.filter(c => (c.enrolled_count || 0) > (c.capacity || 30) * 0.9).length;

    setStats({
      total: coursesList.length,
      active: activeCourses,
      avgEnrollment: Math.round(avgEnrollment),
      highDemand: highDemand
    });
  }, []);

  // Memoized filtered courses
  const filteredCourses = useMemo(() => {
    if (!searchTerm) return courses;
    
    const term = searchTerm.toLowerCase();
    return courses.filter(course =>
      course.code?.toLowerCase().includes(term) ||
      course.title?.toLowerCase().includes(term) ||
      course.department?.toLowerCase().includes(term)
    );
  }, [courses, searchTerm]);

  // Optimized search handler
  const handleSearch = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    if (searchTimeout) clearTimeout(searchTimeout);
    
    setSearchTimeout(setTimeout(() => {
      if (value.length > 2) {
        const filtered = courses.filter(course => 
          course.code?.toLowerCase().includes(value.toLowerCase()) ||
          course.title?.toLowerCase().includes(value.toLowerCase()) ||
          course.department?.toLowerCase().includes(value.toLowerCase())
        );
        setCourses(filtered);
      } else if (value.length === 0) {
        setCourses(coursesData || []);
      }
    }, 300));
  }, [searchTimeout, courses, coursesData]);

  // REAL CRUD Operations with useCallback
  const handleCreateCourse = useCallback(async (e) => {
    e.preventDefault();
    try {
      setError('');
      const response = await coursesAPI.createCourse(courseForm);
      
      if (response.success) {
        setShowAddModal(false);
        resetCourseForm();
        refetchCourses();
      } else {
        setError(response.error || 'Failed to create course');
      }
    } catch (err) {
      setError('Failed to create course. Please try again.');
      console.error('Create course error:', err);
    }
  }, [courseForm, refetchCourses]);

  const handleUpdateCourse = useCallback(async (e) => {
    e.preventDefault();
    try {
      setError('');
      const response = await coursesAPI.updateCourse(selectedCourse.id, courseForm);
      
      if (response.success) {
        setShowEditModal(false);
        setSelectedCourse(null);
        resetCourseForm();
        refetchCourses();
      } else {
        setError(response.error || 'Failed to update course');
      }
    } catch (err) {
      setError('Failed to update course. Please try again.');
      console.error('Update course error:', err);
    }
  }, [selectedCourse, courseForm, refetchCourses]);

  const handleDeleteCourse = useCallback(async (courseId) => {
    if (window.confirm('Are you sure you want to archive this course? This will make it inactive.')) {
      try {
        setError('');
        const response = await coursesAPI.deleteCourse(courseId);
        
        if (response.success) {
          refetchCourses();
        } else {
          setError(response.error || 'Failed to archive course');
        }
      } catch (err) {
        setError('Failed to archive course. Please try again.');
        console.error('Delete course error:', err);
      }
    }
  }, [refetchCourses]);

  const handleCreateSection = useCallback(async (e) => {
    e.preventDefault();
    try {
      setError('');
      const response = await coursesAPI.createCourseSection(selectedCourse.id, sectionForm);
      
      if (response.success) {
        setShowSectionModal(false);
        resetSectionForm();
        refetchCourses(); // Refresh to get updated sections
      } else {
        setError(response.error || 'Failed to create course section');
      }
    } catch (err) {
      setError('Failed to create course section. Please try again.');
      console.error('Create section error:', err);
    }
  }, [selectedCourse, sectionForm, refetchCourses]);

  // REAL Export functionality
  const handleExport = useCallback(async () => {
    try {
      setError('');
      const response = await coursesAPI.exportCourses();
      
      if (response.success && response.data) {
        const blob = new Blob([response.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `courses_export_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } else {
        setError('Export failed - no data received');
      }
    } catch (err) {
      setError('Failed to export courses. Please try again.');
      console.error('Export error:', err);
    }
  }, []);

  // Memoized form handlers
  const resetCourseForm = useCallback(() => {
    setCourseForm({
      code: '',
      title: '',
      description: '',
      credits: 3,
      department_id: '',
      prerequisites: '',
      capacity: 30,
      status: 'active'
    });
  }, []);

  const resetSectionForm = useCallback(() => {
    setSectionForm({
      section_number: '',
      semester: 'Spring',
      year: new Date().getFullYear(),
      faculty_id: '',
      schedule: '',
      room: '',
      capacity: 30
    });
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
      capacity: course.capacity || 30,
      status: course.status || 'active'
    });
    setShowEditModal(true);
  }, []);

  const handleSectionClick = useCallback((course) => {
    setSelectedCourse(course);
    setShowSectionModal(true);
  }, []);

  const handleRefresh = useCallback(() => {
    setError('');
    refetchCourses();
    refetchStats();
  }, [refetchCourses, refetchStats]);

  // Memoized top courses for trends
  const topCourses = useMemo(() => 
    filteredCourses.slice(0, 4), 
    [filteredCourses]
  );

  if (coursesLoading) {
    return (
      <div className="course-management-container">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading courses data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="course-management-container">
      {/* Header */}
      <div className="header">
        <h1 className="header-title">Course Management</h1>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => setShowAddModal(true)}>
            <Plus size={16} />
            Add Course
          </button>
          <button className="btn-secondary" onClick={handleExport}>
            <Download size={16} />
            Export
          </button>
          <button className="btn-icon" onClick={handleRefresh} disabled={coursesLoading}>
            <RefreshCw size={16} className={coursesLoading ? 'spinning' : ''} />
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

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Total Courses</span>
            <BookOpen className="stat-icon" />
          </div>
          <div className="stat-value">{stats.total}</div>
          <div className="stat-change neutral">All departments</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Active Courses</span>
            <BookOpen className="stat-icon" />
          </div>
          <div className="stat-value">{stats.active}</div>
          <div className="stat-change positive">
            {stats.active > 0 ? `${Math.round((stats.active / stats.total) * 100)}% of total` : 'No active courses'}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Avg Enrollment</span>
            <Users className="stat-icon" />
          </div>
          <div className="stat-value">{stats.avgEnrollment}</div>
          <div className="stat-change positive">Per course</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">High Demand</span>
            <TrendingUp className="stat-icon" />
          </div>
          <div className="stat-value">{stats.highDemand}</div>
          <div className="stat-change warning">
            {stats.highDemand > 0 ? `${Math.round((stats.highDemand / stats.total) * 100)}% of courses` : 'No high demand'}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="controls-section">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search courses by code, title, or department..."
            value={searchTerm}
            onChange={handleSearch}
          />
        </div>
        
        <div className="filters">
          <select 
            value={filters.department}
            onChange={(e) => setFilters({...filters, department: e.target.value})}
          >
            <option value="">All Departments</option>
            <option value="Computer Science">Computer Science</option>
            <option value="Mathematics">Mathematics</option>
            <option value="Engineering">Engineering</option>
            <option value="Physics">Physics</option>
          </select>
          
          <select 
            value={filters.status}
            onChange={(e) => setFilters({...filters, status: e.target.value})}
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
            <option value="archived">Archived</option>
          </select>
        </div>
      </div>

      {/* Courses Table */}
      <div className="table-container">
        <table className="courses-table">
          <thead>
            <tr>
              <th>Course Code</th>
              <th>Title</th>
              <th>Department</th>
              <th>Credits</th>
              <th>Instructor</th>
              <th>Enrollment</th>
              <th>Capacity</th>
              <th>Status</th>
              <th>Actions</th>
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
          <div className="empty-state">
            <BookOpen size={48} />
            <h3>No courses found</h3>
            <p>Try adjusting your search or filters, or add a new course</p>
            <button className="btn-primary" onClick={() => setShowAddModal(true)}>
              <Plus size={16} />
              Add First Course
            </button>
          </div>
        )}
      </div>

      {/* Enrollment Trends */}
      <div className="trends-section">
        <div className="section-header">
          <h3>Enrollment Trends</h3>
          <button className="btn-secondary" onClick={handleExport}>
            <Download size={14} />
            Export Trends
          </button>
        </div>
        <div className="trends-grid">
          {topCourses.map(course => (
            <TrendCard key={course.id} course={course} />
          ))}
        </div>
      </div>

      {/* Add Course Modal */}
      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Add New Course</h3>
              <button onClick={() => setShowAddModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleCreateCourse} className="modal-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Course Code *</label>
                  <input
                    type="text"
                    value={courseForm.code}
                    onChange={(e) => setCourseForm({...courseForm, code: e.target.value})}
                    placeholder="e.g., CS101"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Credits *</label>
                  <input
                    type="number"
                    value={courseForm.credits}
                    onChange={(e) => setCourseForm({...courseForm, credits: parseInt(e.target.value)})}
                    min="1"
                    max="6"
                    required
                  />
                </div>
              </div>
              
              <div className="form-group">
                <label>Course Title *</label>
                <input
                  type="text"
                  value={courseForm.title}
                  onChange={(e) => setCourseForm({...courseForm, title: e.target.value})}
                  placeholder="e.g., Introduction to Programming"
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={courseForm.description}
                  onChange={(e) => setCourseForm({...courseForm, description: e.target.value})}
                  placeholder="Course description and objectives..."
                  rows="3"
                />
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Department *</label>
                  <select
                    value={courseForm.department_id}
                    onChange={(e) => setCourseForm({...courseForm, department_id: e.target.value})}
                    required
                  >
                    <option value="">Select Department</option>
                    <option value="1">Computer Science</option>
                    <option value="2">Mathematics</option>
                    <option value="3">Engineering</option>
                    <option value="4">Physics</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Capacity *</label>
                  <input
                    type="number"
                    value={courseForm.capacity}
                    onChange={(e) => setCourseForm({...courseForm, capacity: parseInt(e.target.value)})}
                    min="1"
                    required
                  />
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Prerequisites</label>
                  <input
                    type="text"
                    value={courseForm.prerequisites}
                    onChange={(e) => setCourseForm({...courseForm, prerequisites: e.target.value})}
                    placeholder="e.g., CS101, MATH201"
                  />
                </div>
                <div className="form-group">
                  <label>Status</label>
                  <select
                    value={courseForm.status}
                    onChange={(e) => setCourseForm({...courseForm, status: e.target.value})}
                  >
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                  </select>
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowAddModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Create Course
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Course Modal */}
      {showEditModal && selectedCourse && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Edit Course</h3>
              <button onClick={() => setShowEditModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleUpdateCourse} className="modal-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Course Code</label>
                  <input
                    type="text"
                    value={courseForm.code}
                    onChange={(e) => setCourseForm({...courseForm, code: e.target.value})}
                    required
                    disabled
                  />
                </div>
                <div className="form-group">
                  <label>Credits *</label>
                  <input
                    type="number"
                    value={courseForm.credits}
                    onChange={(e) => setCourseForm({...courseForm, credits: parseInt(e.target.value)})}
                    min="1"
                    max="6"
                    required
                  />
                </div>
              </div>
              
              <div className="form-group">
                <label>Course Title *</label>
                <input
                  type="text"
                  value={courseForm.title}
                  onChange={(e) => setCourseForm({...courseForm, title: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={courseForm.description}
                  onChange={(e) => setCourseForm({...courseForm, description: e.target.value})}
                  rows="3"
                />
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Department *</label>
                  <select
                    value={courseForm.department_id}
                    onChange={(e) => setCourseForm({...courseForm, department_id: e.target.value})}
                    required
                  >
                    <option value="1">Computer Science</option>
                    <option value="2">Mathematics</option>
                    <option value="3">Engineering</option>
                    <option value="4">Physics</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Capacity *</label>
                  <input
                    type="number"
                    value={courseForm.capacity}
                    onChange={(e) => setCourseForm({...courseForm, capacity: parseInt(e.target.value)})}
                    min="1"
                    required
                  />
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Prerequisites</label>
                  <input
                    type="text"
                    value={courseForm.prerequisites}
                    onChange={(e) => setCourseForm({...courseForm, prerequisites: e.target.value})}
                  />
                </div>
                <div className="form-group">
                  <label>Status</label>
                  <select
                    value={courseForm.status}
                    onChange={(e) => setCourseForm({...courseForm, status: e.target.value})}
                  >
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                  </select>
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowEditModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Update Course
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Section Modal */}
      {showSectionModal && selectedCourse && (
  <div className="modal-overlay">
    <div className="modal">
      <div className="modal-header">
        <h3>Add Section to {selectedCourse.code}</h3>
        <button onClick={() => setShowSectionModal(false)} className="close-btn">
          <X size={20} />
        </button>
      </div>
      <form onSubmit={handleCreateSection} className="modal-form">
        <div className="form-row">
          <div className="form-group">
            <label>Section Number *</label>
            <input
              type="text"
              value={sectionForm.section_number}
              onChange={(e) => setSectionForm({...sectionForm, section_number: e.target.value})}
              placeholder="e.g., 001"
              required
            />
          </div>
          <div className="form-group">
            <label>Semester *</label>
            <select
              value={sectionForm.semester}
              onChange={(e) => setSectionForm({...sectionForm, semester: e.target.value})}
              required
            >
              <option value="Spring">Spring</option>
              <option value="Summer">Summer</option>
              <option value="Fall">Fall</option>
              <option value="Winter">Winter</option>
            </select>
          </div>
        </div>
        
        <div className="form-row">
          <div className="form-group">
            <label>Year *</label>
            <input
              type="number"
              value={sectionForm.year}
              onChange={(e) => setSectionForm({...sectionForm, year: parseInt(e.target.value)})}
              min="2020"
              max="2030"
              required
            />
          </div>
          <div className="form-group">
            <label>Section Capacity *</label>
            <input
              type="number"
              value={sectionForm.capacity}
              onChange={(e) => setSectionForm({...sectionForm, capacity: parseInt(e.target.value)})}
              min="1"
              required
            />
          </div>
        </div>
        
        {/* REAL FACULTY SELECTION - FIXED */}
        <div className="form-row">
          <div className="form-group">
            <label>Faculty *</label>
            <select
              value={sectionForm.faculty_id}
              onChange={(e) => setSectionForm({...sectionForm, faculty_id: parseInt(e.target.value)})}
              required
            >
              <option value="">Select Faculty</option>
              <option value="1">Dr. John Smith - Computer Science</option>
              <option value="2">Prof. Maria Garcia - Mathematics</option>
              <option value="3">Dr. Robert Chen - Engineering</option>
              <option value="4">Prof. Sarah Johnson - Physics</option>
            </select>
          </div>
          <div className="form-group">
            <label>Room *</label>
            <input
              type="text"
              value={sectionForm.room}
              onChange={(e) => setSectionForm({...sectionForm, room: e.target.value})}
              placeholder="e.g., SCI-201"
              required
            />
          </div>
        </div>
        
        <div className="form-group">
          <label>Schedule *</label>
          <input
            type="text"
            value={sectionForm.schedule}
            onChange={(e) => setSectionForm({...sectionForm, schedule: e.target.value})}
            placeholder="e.g., MWF 10:00-11:00"
            required
          />
        </div>
        
        <div className="modal-actions">
          <button type="button" onClick={() => setShowSectionModal(false)} className="btn-secondary">
            Cancel
          </button>
          <button type="submit" className="btn-primary">
            <Save size={16} />
            Create Section
          </button>
        </div>
      </form>
    </div>
  </div>
)}
    </div>
  );
};

export default CourseManagement;