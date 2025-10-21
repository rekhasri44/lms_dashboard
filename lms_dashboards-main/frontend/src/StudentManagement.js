import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Users, Search, Filter, Plus, Edit, Trash2, Download, 
  Upload, Eye, AlertTriangle, CheckCircle, X, Save, 
  GraduationCap, User, Mail, BookOpen, Calendar 
} from 'lucide-react';
import { studentsAPI, analyticsAPI } from './services/api';
import useApi from './hooks/useApi';
import './StudentManagement.css';

// Memoized student row component
const StudentRow = React.memo(({ student, onEdit, onDelete }) => {
  const getRiskLevelClass = (riskLevel) => {
    switch(riskLevel) {
      case 'high': return 'high';
      case 'medium': return 'medium'; 
      case 'low': return 'low';
      default: return 'low';
    }
  };

  const getStatusClass = (status) => {
    switch(status) {
      case 'enrolled': return 'enrolled';
      case 'graduated': return 'graduated';
      case 'dropped': return 'dropped';
      default: return 'enrolled';
    }
  };
  const testIntervention = async (studentId) => {
  try {
    const response = await studentsAPI.createIntervention(studentId, {
      intervention_type: 'Academic Counseling',
      description: 'Initial assessment meeting',
      priority: 'medium'
    });
    console.log('Intervention test:', response);
  } catch (err) {
    console.error('Intervention broken:', err);
  }
};

  return (
    <tr key={student.id}>
      <td>{student.student_id}</td>
      <td>
        <div className="student-info">
          <User size={16} />
          {student.name}
        </div>
      </td>
      <td>{student.email}</td>
      <td>{student.department}</td>
      <td>
        <span className={`gpa-badge ${student.gpa >= 3.5 ? 'high' : student.gpa >= 2.5 ? 'medium' : 'low'}`}>
          {student.gpa}
        </span>
      </td>
      <td>
        <span className={`status-badge ${getStatusClass(student.status)}`}>
          {student.status}
        </span>
      </td>
      <td>
        <span className={`risk-badge ${getRiskLevelClass(student.risk_level)}`}>
          {student.risk_level}
        </span>
      </td>
      <td>
        <div className="action-buttons">
          <button 
            className="btn-icon view"
            onClick={() => onEdit(student)}
          >
            <Edit size={14} />
          </button>
          <button 
            className="btn-icon delete"
            onClick={() => onDelete(student.id)}
          >
            <Trash2 size={14} />
          </button>
        </div>
      </td>
    </tr>
  );
});

const StudentManagement = () => {
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    department: '',
    status: '',
    risk_level: ''
  });
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedStudent, setSelectedStudent] = useState(null);
  const [formData, setFormData] = useState({
    student_id: '',
    first_name: '',
    last_name: '',
    email: '',
    department: '',
    gpa: '',
    status: 'enrolled',
    risk_level: 'low',
    financial_status: 'paid'
  });

  // Debounced search - ADD THIS
  const [searchTimeout, setSearchTimeout] = useState(null);

  // Memoized filtered students
  const filteredStudents = useMemo(() => {
    if (!searchTerm) return students;
    
    const term = searchTerm.toLowerCase();
    return students.filter(student => 
      student.name.toLowerCase().includes(term) ||
      student.email.toLowerCase().includes(term) ||
      student.student_id.toLowerCase().includes(term)
    );
  }, [students, searchTerm]);

  // Fetch students with useCallback
  const fetchStudents = useCallback(async () => {
    try {
      setLoading(true);
      const response = await studentsAPI.getStudents(filters);
      
      if (response.success) {
        setStudents(response.data);
      } else {
        setError(response.error);
        setStudents(getStaticStudents());
      }
    } catch (err) {
      setError('Failed to fetch students');
      setStudents(getStaticStudents());
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchStudents();
  }, [fetchStudents]);

  // Optimized search handler - REPLACE OLD ONE
  const handleSearch = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    
    // Clear existing timeout
    if (searchTimeout) clearTimeout(searchTimeout);
    
    // Set new timeout for debouncing
    setSearchTimeout(setTimeout(() => {
      if (value.length > 2) {
        // Client-side filtering for demo
        const filtered = students.filter(student => 
          student.name.toLowerCase().includes(value.toLowerCase()) ||
          student.email.toLowerCase().includes(value.toLowerCase()) ||
          student.student_id.toLowerCase().includes(value.toLowerCase())
        );
        setStudents(filtered);
      } else if (value.length === 0) {
        fetchStudents();
      }
    }, 300));
  }, [searchTimeout, students, fetchStudents]);

  // Memoized handlers
  const handleAddStudent = useCallback(async (e) => {
    e.preventDefault();
    try {
      const response = await studentsAPI.createStudent(formData);
      if (response.success) {
        setShowAddModal(false);
        setFormData({
          student_id: '', first_name: '', last_name: '', email: '',
          department: '', gpa: '', status: 'enrolled', risk_level: 'low', financial_status: 'paid'
        });
        fetchStudents();
      } else {
        setError(response.error);
      }
    } catch (err) {
      setError('Failed to add student');
    }
  }, [formData, fetchStudents]);

  const handleEditStudent = useCallback(async (e) => {
    e.preventDefault();
    try {
      const response = await studentsAPI.updateStudent(selectedStudent.id, formData);
      if (response.success) {
        setShowEditModal(false);
        setSelectedStudent(null);
        fetchStudents();
      } else {
        setError(response.error);
      }
    } catch (err) {
      setError('Failed to update student');
    }
  }, [selectedStudent, formData, fetchStudents]);

  const handleDeleteStudent = useCallback(async (studentId) => {
    if (window.confirm('Are you sure you want to delete this student?')) {
      try {
        const response = await studentsAPI.deleteStudent(studentId);
        if (response.success) {
          fetchStudents();
        } else {
          setError(response.error);
        }
      } catch (err) {
        setError('Failed to delete student');
      }
    }
  }, [fetchStudents]);

  const handleEditClick = useCallback((student) => {
    setSelectedStudent(student);
    setFormData({
      student_id: student.student_id,
      first_name: student.name.split(' ')[0],
      last_name: student.name.split(' ')[1] || '',
      email: student.email,
      department: student.department,
      gpa: student.gpa.toString(),
      status: student.status,
      risk_level: student.risk_level,
      financial_status: student.financial_status
    });
    setShowEditModal(true);
  }, []);

  // Static data fallback
  const getStaticStudents = () => [
    {
      id: 1, student_id: 'S001', name: 'John Smith', email: 'john.smith@university.edu',
      department: 'Computer Science', gpa: 3.8, status: 'enrolled', risk_level: 'low',
      financial_status: 'paid', enrollment_date: '2023-09-01'
    },
    {
      id: 2, student_id: 'S002', name: 'Maria Garcia', email: 'maria.garcia@university.edu',
      department: 'Mathematics', gpa: 2.1, status: 'enrolled', risk_level: 'high',
      financial_status: 'pending', enrollment_date: '2023-09-01'
    }
  ];

  if (loading) {
    return (
      <div className="student-management-container">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading students...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="student-management-container">
      {/* Header */}
      <div className="header">
        <h1 className="header-title">Student Management</h1>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => setShowAddModal(true)}>
            <Plus size={16} />
            Add Student
          </button>
          <button className="btn-secondary" onClick={() => studentsAPI.exportStudents()}>
            <Download size={16} />
            Export
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

      {/* Controls */}
      <div className="controls-section">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search students..."
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
          </select>
          
          <select 
            value={filters.status}
            onChange={(e) => setFilters({...filters, status: e.target.value})}
          >
            <option value="">All Status</option>
            <option value="enrolled">Enrolled</option>
            <option value="graduated">Graduated</option>
            <option value="dropped">Dropped</option>
          </select>
          
          <select 
            value={filters.risk_level}
            onChange={(e) => setFilters({...filters, risk_level: e.target.value})}
          >
            <option value="">All Risk Levels</option>
            <option value="low">Low Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="high">High Risk</option>
          </select>
        </div>
      </div>

      {/* Students Table */}
      <div className="table-container">
        <table className="students-table">
          <thead>
            <tr>
              <th>Student ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Department</th>
              <th>GPA</th>
              <th>Status</th>
              <th>Risk Level</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredStudents.map((student) => (
              <StudentRow 
                key={student.id}
                student={student}
                onEdit={handleEditClick}
                onDelete={handleDeleteStudent}
              />
            ))}
          </tbody>
        </table>
        
        {filteredStudents.length === 0 && (
          <div className="empty-state">
            <Users size={48} />
            <h3>No students found</h3>
            <p>Try adjusting your search or filters</p>
          </div>
        )}
      </div>

      {/* Add Student Modal */}
      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Add New Student</h3>
              <button onClick={() => setShowAddModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleAddStudent} className="modal-form">
              {/* FORM CONTENT REMAINS SAME */}
              <div className="form-row">
                <div className="form-group">
                  <label>Student ID *</label>
                  <input
                    type="text"
                    value={formData.student_id}
                    onChange={(e) => setFormData({...formData, student_id: e.target.value})}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>GPA *</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="4.0"
                    value={formData.gpa}
                    onChange={(e) => setFormData({...formData, gpa: e.target.value})}
                    required
                  />
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
                  <label>Department *</label>
                  <select
                    value={formData.department}
                    onChange={(e) => setFormData({...formData, department: e.target.value})}
                    required
                  >
                    <option value="">Select Department</option>
                    <option value="Computer Science">Computer Science</option>
                    <option value="Mathematics">Mathematics</option>
                    <option value="Engineering">Engineering</option>
                    <option value="Physics">Physics</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Status *</label>
                  <select
                    value={formData.status}
                    onChange={(e) => setFormData({...formData, status: e.target.value})}
                    required
                  >
                    <option value="enrolled">Enrolled</option>
                    <option value="graduated">Graduated</option>
                    <option value="dropped">Dropped</option>
                  </select>
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Risk Level</label>
                  <select
                    value={formData.risk_level}
                    onChange={(e) => setFormData({...formData, risk_level: e.target.value})}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Financial Status</label>
                  <select
                    value={formData.financial_status}
                    onChange={(e) => setFormData({...formData, financial_status: e.target.value})}
                  >
                    <option value="paid">Paid</option>
                    <option value="pending">Pending</option>
                    <option value="overdue">Overdue</option>
                  </select>
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowAddModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Add Student
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Student Modal - KEEP EXISTING */}
      {showEditModal && selectedStudent && (
        <div className="modal-overlay">
          <div className="modal">
            <div className="modal-header">
              <h3>Edit Student</h3>
              <button onClick={() => setShowEditModal(false)} className="close-btn">
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleEditStudent} className="modal-form">
              {/* KEEP EXISTING EDIT FORM */}
              <div className="form-row">
                <div className="form-group">
                  <label>Student ID</label>
                  <input
                    type="text"
                    value={formData.student_id}
                    disabled
                  />
                </div>
                <div className="form-group">
                  <label>GPA *</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="4.0"
                    value={formData.gpa}
                    onChange={(e) => setFormData({...formData, gpa: e.target.value})}
                    required
                  />
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
                  <label>Department *</label>
                  <select
                    value={formData.department}
                    onChange={(e) => setFormData({...formData, department: e.target.value})}
                    required
                  >
                    <option value="Computer Science">Computer Science</option>
                    <option value="Mathematics">Mathematics</option>
                    <option value="Engineering">Engineering</option>
                    <option value="Physics">Physics</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Status *</label>
                  <select
                    value={formData.status}
                    onChange={(e) => setFormData({...formData, status: e.target.value})}
                    required
                  >
                    <option value="enrolled">Enrolled</option>
                    <option value="graduated">Graduated</option>
                    <option value="dropped">Dropped</option>
                  </select>
                </div>
              </div>
              
              <div className="form-row">
                <div className="form-group">
                  <label>Risk Level</label>
                  <select
                    value={formData.risk_level}
                    onChange={(e) => setFormData({...formData, risk_level: e.target.value})}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Financial Status</label>
                  <select
                    value={formData.financial_status}
                    onChange={(e) => setFormData({...formData, financial_status: e.target.value})}
                  >
                    <option value="paid">Paid</option>
                    <option value="pending">Pending</option>
                    <option value="overdue">Overdue</option>
                  </select>
                </div>
              </div>
              
              <div className="modal-actions">
                <button type="button" onClick={() => setShowEditModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  <Save size={16} />
                  Update Student
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default StudentManagement;
