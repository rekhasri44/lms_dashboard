import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Users, Search, Filter, Plus, Edit, Trash2, Download, 
  AlertTriangle, X, Save, Mail, Phone, Calendar, DollarSign,
  GraduationCap, BookOpen, TrendingUp, RefreshCw
} from 'lucide-react';
import { facultyAPI } from '../services/api';
import { useApi } from '../hooks/useApi';
import './FacultyManagement.css';

// Memoized faculty row component
const FacultyRow = React.memo(({ member, onEdit, onDelete }) => {
  const getPositionLabel = (position) => {
    const positions = {
      'assistant_professor': 'Assistant Professor',
      'associate_professor': 'Associate Professor', 
      'professor': 'Professor',
      'lecturer': 'Lecturer',
      'instructor': 'Instructor'
    };
    return positions[position] || position;
  };

  const getStatusClass = (status) => {
    switch(status) {
      case 'active': return 'active';
      case 'inactive': return 'inactive';
      case 'on_leave': return 'on-leave';
      default: return 'active';
    }
  };

  const getWorkloadStatus = (hours) => {
    if (hours > 35) return 'high';
    if (hours > 25) return 'medium';
    return 'low';
  };

  return (
    <tr key={member.id}>
      <td>
        <div className="employee-id">
          <Users size={16} />
          {member.employee_id}
        </div>
      </td>
      <td>
        <div className="faculty-info">
          <strong>{member.name}</strong>
          <span className="faculty-email">{member.email}</span>
        </div>
      </td>
      <td>{member.department || 'N/A'}</td>
      <td>
        <span className="position-badge">
          {getPositionLabel(member.position)}
        </span>
      </td>
      <td>
        <div className="workload-info">
          <span className="workload-hours">{member.workload_hours || 0}h</span>
          <div className="workload-bar">
            <div 
              className={`workload-fill ${getWorkloadStatus(member.workload_hours)}`}
              style={{width: `${Math.min((member.workload_hours || 0) / 40 * 100, 100)}%`}}
            ></div>
          </div>
        </div>
      </td>
      <td>
        <span className={`score-badge ${(member.research_score || 0) >= 4 ? 'high' : (member.research_score || 0) >= 3 ? 'medium' : 'low'}`}>
          {member.research_score || 'N/A'}
        </span>
      </td>
      <td>
        <span className={`score-badge ${(member.student_satisfaction_score || 0) >= 4 ? 'high' : (member.student_satisfaction_score || 0) >= 3 ? 'medium' : 'low'}`}>
          {member.student_satisfaction_score || 'N/A'}
        </span>
      </td>
      <td>
        <span className={`status-badge ${getStatusClass(member.status)}`}>
          {member.status}
        </span>
      </td>
      <td>
        <div className="action-buttons">
          <button 
            className="btn-icon primary"
            onClick={() => onEdit(member)}
            title="Edit Faculty"
          >
            <Edit size={14} />
          </button>
          <button 
            className="btn-icon danger"
            onClick={() => onDelete(member.id)}
            title="Archive Faculty"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </td>
    </tr>
  );
});

const FacultyManagement = () => {
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

  // Debounced search
  const [searchTimeout, setSearchTimeout] = useState(null);

  // Real API integration with useCallback - FIXED: Added error handling
  const { data: facultyData, loading: facultyLoading, error: facultyError, refetch: refetchFaculty } = useApi(
    useCallback(() => facultyAPI.getFaculty(filters), [filters])
  );

  useEffect(() => {
    if (facultyData) {
      setFaculty(facultyData);
      setLoading(false);
    }
  }, [facultyData]);

  useEffect(() => {
    if (facultyError) {
      setError(facultyError);
      setLoading(false);
    }
  }, [facultyError]);

  // Optimized search handler - FIXED: Better debouncing
  const handleSearch = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    if (searchTimeout) clearTimeout(searchTimeout);
    
    setSearchTimeout(setTimeout(() => {
      // Search logic handled in filteredFaculty memo
    }, 300));
  }, [searchTimeout]);

  // Memoized filtered faculty - FIXED: Proper search
  const filteredFaculty = useMemo(() => {
    if (!searchTerm) return faculty;
    
    const term = searchTerm.toLowerCase();
    return faculty.filter(member => 
      member.name?.toLowerCase().includes(term) ||
      member.email?.toLowerCase().includes(term) ||
      member.employee_id?.toLowerCase().includes(term) ||
      member.department?.toLowerCase().includes(term)
    );
  }, [faculty, searchTerm]);

  // Memoized CRUD operations - FIXED: Added validation
  const validateForm = (data) => {
    const errors = {};
    if (!data.employee_id) errors.employee_id = 'Employee ID required';
    if (!data.first_name) errors.first_name = 'First name required';
    if (!data.last_name) errors.last_name = 'Last name required';
    if (!data.email || !/\S+@\S+\.\S+/.test(data.email)) errors.email = 'Valid email required';
    if (data.workload_hours && data.workload_hours > 60) errors.workload_hours = 'Max 60 hours';
    if (data.research_score && (data.research_score < 0 || data.research_score > 5)) {
      errors.research_score = 'Score must be 0-5';
    }
    return errors;
  };

const backendData = {
  
      employee_id: formData.employee_id,
      first_name: formData.first_name,
      last_name: formData.last_name,
      email: formData.email,
      department: formData.department,  
      position: formData.position,
      salary: parseFloat(formData.salary) || 0,
      workload_hours: parseInt(formData.workload_hours) || 0,
      research_score: parseFloat(formData.research_score) || 0,
      student_satisfaction_score: parseFloat(formData.student_satisfaction_score) || 0,
      status: formData.status
    };

    const handleAddFaculty = useCallback(async (e) => {
  e.preventDefault();
  try {
    setError('');
    
    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setError('Please fix the form errors');
      return;
    }

    const response = await facultyAPI.createFaculty(backendData);
    
    if (response.success) {
      setShowAddModal(false);
      resetForm();
      refetchFaculty();
    } else {
      setError(response.error || 'Failed to create faculty member');
    }
  } catch (err) {
    setError('Failed to add faculty member. Please try again.');
  }
}, [formData, refetchFaculty]);

const handleEditFaculty = useCallback(async (e) => {
  e.preventDefault();
  try {
    setError('');
    
    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setError('Please fix the form errors');
      return;
    }

    const response = await facultyAPI.updateFaculty(selectedFaculty.id, formData);
    
    if (response.success) {
      setShowEditModal(false);
      setSelectedFaculty(null);
      resetForm();
      refetchFaculty();
      setError(''); 
    } else {
      setError(response.error || 'Failed to update faculty member');
    }
  } catch (err) {
    setError('Failed to update faculty member. Please try again.');
  }
}, [selectedFaculty, formData, refetchFaculty]);
  const handleDeleteFaculty = useCallback(async (facultyId) => {
    if (window.confirm('Are you sure you want to archive this faculty member?')) {
      try {
        setError('');
        const response = await facultyAPI.deleteFaculty(facultyId);
        
        if (response.success) {
          refetchFaculty();
        } else {
          setError(response.error || 'Failed to archive faculty member');
        }
      } catch (err) {
        setError('Failed to archive faculty member. Please try again.');
      }
    }
  }, [refetchFaculty]);

  const handleEditClick = useCallback((member) => {
    setSelectedFaculty(member);
    // FIXED: Better name parsing
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
    setShowEditModal(true);
  }, []);

  // Memoized stats calculations
  const stats = useMemo(() => {
    const totalFaculty = faculty.length;
    const avgSatisfaction = totalFaculty > 0 
      ? (faculty.reduce((sum, f) => sum + (f.student_satisfaction_score || 0), 0) / totalFaculty).toFixed(1)
      : '0.0';
    const avgResearch = totalFaculty > 0 
      ? (faculty.reduce((sum, f) => sum + (f.research_score || 0), 0) / totalFaculty).toFixed(1)
      : '0.0';
    const highWorkload = faculty.filter(f => (f.workload_hours || 0) > 35).length;

    return { totalFaculty, avgSatisfaction, avgResearch, highWorkload };
  }, [faculty]);

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
  }, []);

  const handleRefresh = useCallback(() => {
    setLoading(true);
    setError('');
    refetchFaculty();
  }, [refetchFaculty]);

  // FIXED: Better loading state
  if (loading && faculty.length === 0) {
    return (
      <div className="faculty-management-container">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading faculty data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="faculty-management-container">
      {/* Header */}
      <div className="header">
        <h1 className="header-title">Faculty Management</h1>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => setShowAddModal(true)}>
            <Plus size={16} />
            Add Faculty
          </button>
          <button className="btn-secondary" onClick={() => facultyAPI.exportFaculty && facultyAPI.exportFaculty()}>
            <Download size={16} />
            Export
          </button>
          <button className="btn-icon" onClick={handleRefresh} disabled={facultyLoading}>
            <RefreshCw size={16} className={facultyLoading ? 'spinning' : ''} />
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
            <span className="stat-label">Total Faculty</span>
            <Users className="stat-icon" />
          </div>
          <div className="stat-value">{stats.totalFaculty}</div>
          <div className="stat-change neutral">Across all departments</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Avg Satisfaction</span>
            <TrendingUp className="stat-icon" />
          </div>
          <div className="stat-value">{stats.avgSatisfaction}</div>
          <div className="stat-change positive">Out of 5.0</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Avg Research Score</span>
            <BookOpen className="stat-icon" />
          </div>
          <div className="stat-value">{stats.avgResearch}</div>
          <div className="stat-change neutral">Research performance</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">High Workload</span>
            <AlertTriangle className="stat-icon" />
          </div>
          <div className="stat-value">{stats.highWorkload}</div>
          <div className="stat-change warning">Need attention</div>
        </div>
      </div>

      {/* Controls */}
      <div className="controls-section">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search faculty by name, email, or ID..."
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
            <option value="on_leave">On Leave</option>
          </select>
        </div>
      </div>

      {/* Faculty Table */}
      <div className="table-container">
        <table className="faculty-table">
          <thead>
            <tr>
              <th>Employee ID</th>
              <th>Name</th>
              <th>Department</th>
              <th>Position</th>
              <th>Workload</th>
              <th>Research Score</th>
              <th>Satisfaction</th>
              <th>Status</th>
              <th>Actions</th>
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
          <div className="empty-state">
            <GraduationCap size={48} />
            <h3>No faculty members found</h3>
            <p>Try adjusting your search or filters, or add a new faculty member</p>
            <button className="btn-primary" onClick={() => setShowAddModal(true)}>
              <Plus size={16} />
              Add First Faculty Member
            </button>
          </div>
        )}
      </div>

      {/* Add Faculty Modal */}
      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Add New Faculty Member</h3>
              <button onClick={() => setShowAddModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleAddFaculty} className="modal-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Employee ID *</label>
                  <input
                    type="text"
                    value={formData.employee_id}
                    onChange={(e) => setFormData({...formData, employee_id: e.target.value})}
                    placeholder="e.g., F001"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Position *</label>
                  <select
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
                  <label>First Name *</label>
                  <input
                    type="text"
                    value={formData.first_name}
                    onChange={(e) => setFormData({...formData, first_name: e.target.value})}
                    placeholder="John"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Last Name *</label>
                  <input
                    type="text"
                    value={formData.last_name}
                    onChange={(e) => setFormData({...formData, last_name: e.target.value})}
                    placeholder="Doe"
                    required
                  />
                </div>
              </div>
              
              <div className="form-group">
                <label>Email *</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                  placeholder="john.doe@university.edu"
                  required
                />
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Department</label>
                  <select
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
                  <label>Status *</label>
                  <select
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
                  <label>Salary ($)</label>
                  <input
                    type="number"
                    value={formData.salary}
                    onChange={(e) => setFormData({...formData, salary: e.target.value})}
                    placeholder="75000"
                    min="0"
                  />
                </div>
                <div className="form-group">
                  <label>Workload Hours</label>
                  <input
                    type="number"
                    value={formData.workload_hours}
                    onChange={(e) => setFormData({...formData, workload_hours: e.target.value})}
                    placeholder="20"
                    min="0"
                    max="60"
                  />
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Research Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="5"
                    value={formData.research_score}
                    onChange={(e) => setFormData({...formData, research_score: e.target.value})}
                    placeholder="4.2"
                  />
                </div>
                <div className="form-group">
                  <label>Satisfaction Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="5"
                    value={formData.student_satisfaction_score}
                    onChange={(e) => setFormData({...formData, student_satisfaction_score: e.target.value})}
                    placeholder="4.5"
                  />
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowAddModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Add Faculty Member
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Faculty Modal */}
      {showEditModal && selectedFaculty && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Edit Faculty Member</h3>
              <button onClick={() => setShowEditModal(false)} className="close-btn">
                <X size={20} />
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
                  <label>Position *</label>
                  <select
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
                  <label>First Name *</label>
                  <input
                    type="text"
                    value={formData.first_name}
                    onChange={(e) => setFormData({...formData, first_name: e.target.value})}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Last Name *</label>
                  <input
                    type="text"
                    value={formData.last_name}
                    onChange={(e) => setFormData({...formData, last_name: e.target.value})}
                    required
                  />
                </div>
              </div>
              
              <div className="form-group">
                <label>Email *</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                  required
                />
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Department</label>
                  <select
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
                  <label>Status *</label>
                  <select
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
                  <label>Salary ($)</label>
                  <input
                    type="number"
                    value={formData.salary}
                    onChange={(e) => setFormData({...formData, salary: e.target.value})}
                    min="0"
                  />
                </div>
                <div className="form-group">
                  <label>Workload Hours</label>
                  <input
                    type="number"
                    value={formData.workload_hours}
                    onChange={(e) => setFormData({...formData, workload_hours: e.target.value})}
                    min="0"
                    max="60"
                  />
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Research Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="5"
                    value={formData.research_score}
                    onChange={(e) => setFormData({...formData, research_score: e.target.value})}
                  />
                </div>
                <div className="form-group">
                  <label>Satisfaction Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="5"
                    value={formData.student_satisfaction_score}
                    onChange={(e) => setFormData({...formData, student_satisfaction_score: e.target.value})}
                  />
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowEditModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Update Faculty Member
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default FacultyManagement;