import { useAuth } from '../context/AuthContext';

// Base API configuration
const API_CONFIG = {
  BASE_URL: process.env.REACT_APP_API_URL || 'https://dashboard-backend-qmy9.onrender.com',
  TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3
};

// Enhanced API service with proper error handling
class ApiService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
  }

  // Enhanced request method with authentication
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const token = localStorage.getItem('access_token');
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` }),
        ...options.headers,
      },
      timeout: API_CONFIG.TIMEOUT,
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      // Handle authentication errors
      if (response.status === 401) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        throw new Error('Authentication required');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API call failed: ${endpoint}`, error);
      throw error;
    }
  }

  // Generic CRUD operations
  async get(endpoint) {
    return this.request(endpoint);
  }

  async post(endpoint, data) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async put(endpoint, data) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async delete(endpoint) {
    return this.request(endpoint, {
      method: 'DELETE',
    });
  }
}

// Create API service instance
const apiService = new ApiService();

// Analytics API - FIXED ENDPOINTS
export const analyticsAPI = {
  getDashboardOverview: () => 
    apiService.get('/api/v1/analytics/dashboard/overview'),

  getPerformanceAnalytics: () =>
    apiService.get('/api/v1/analytics/performance/grade-distribution'),

  getStudentRetention: () =>
    apiService.get('/api/v1/analytics/performance/student-retention'),

  getRiskAssessment: () =>
    apiService.get('/api/v1/analytics/risk/assessment'),

  getFinancialOverview: () =>
    apiService.get('/api/v1/analytics/financial/overview'),

  getResourceUtilization: () =>
    apiService.get('/api/v1/analytics/resource/utilization'),

  getPredictiveInsights: () =>
    apiService.get('/api/v1/analytics/predictive/insights')
};

// Students API - FIXED ENDPOINTS
export const studentsAPI = {
  getStudents: (filters = {}) => {
    const queryParams = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) queryParams.append(key, value);
    });
    const queryString = queryParams.toString();
    return apiService.get(`/api/v1/students${queryString ? `?${queryString}` : ''}`);
  },

  getStudentDetails: (studentId) =>
    apiService.get(`/api/v1/students/${studentId}`),

  createStudent: (studentData) =>
    apiService.post('/api/v1/students', studentData),

  updateStudent: (studentId, studentData) =>
    apiService.put(`/api/v1/students/${studentId}`, studentData),

  deleteStudent: (studentId) =>
    apiService.delete(`/api/v1/students/${studentId}`),

  getAtRiskStudents: () =>
    apiService.get('/api/v1/students/at-risk'),

  exportStudents: () =>
    apiService.get('/api/v1/students/export'),

  createIntervention: (studentId, interventionData) =>
    apiService.post(`/api/v1/students/${studentId}/interventions`, interventionData)
};

// Faculty API - FIXED ENDPOINTS
export const facultyAPI = {
  getFaculty: (filters = {}) => {
    const queryParams = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) queryParams.append(key, value);
    });
    const queryString = queryParams.toString();
    return apiService.get(`/api/v1/faculty${queryString ? `?${queryString}` : ''}`);
  },

  getFacultyDetails: (facultyId) =>
    apiService.get(`/api/v1/faculty/${facultyId}`),

  createFaculty: (facultyData) =>
    apiService.post('/api/v1/faculty', facultyData),

  updateFaculty: (facultyId, facultyData) =>
    apiService.put(`/api/v1/faculty/${facultyId}`, facultyData),

  deleteFaculty: (facultyId) =>
    apiService.delete(`/api/v1/faculty/${facultyId}`),

  getFacultyWorkload: () =>
    apiService.get('/api/v1/faculty/workload'),

  exportFaculty: () =>
    apiService.get('/api/v1/faculty/export')
};

// Courses API - FIXED ENDPOINTS
export const coursesAPI = {
  getCourses: (filters = {}) => {
    const queryParams = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) queryParams.append(key, value);
    });
    const queryString = queryParams.toString();
    return apiService.get(`/api/v1/courses${queryString ? `?${queryString}` : ''}`);
  },

  getCourseSections: (filters = {}) => {
    const queryParams = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value) queryParams.append(key, value);
    });
    const queryString = queryParams.toString();
    return apiService.get(`/api/v1/courses/sections${queryString ? `?${queryString}` : ''}`);
  },

  getEnrollmentStats: () =>
    apiService.get('/api/v1/courses/enrollment-stats'),

  createCourse: (courseData) =>
    apiService.post('/api/v1/courses', courseData),

  updateCourse: (courseId, courseData) =>
    apiService.put(`/api/v1/courses/${courseId}`, courseData),

  deleteCourse: (courseId) =>
    apiService.delete(`/api/v1/courses/${courseId}`)
};

// System API - FIXED ENDPOINTS
export const systemAPI = {
  getAlerts: () =>
    apiService.get('/api/v1/system/alerts'),

  getAnnouncements: () =>
    apiService.get('/api/v1/system/announcements'),

  createAlert: (alertData) =>
    apiService.post('/api/v1/system/alerts', alertData),

  getSystemHealth: () =>
    apiService.get('/api/v1/system/monitoring/health'),

  getComplianceStatus: () =>
    apiService.get('/api/v1/system/monitoring/compliance'),

  getSystemSettings: () =>
    apiService.get('/api/v1/system/settings'),

  updateSystemSettings: (settings) =>
    apiService.put('/api/v1/system/settings', { settings })
};

// Reports API - FIXED ENDPOINTS
export const reportsAPI = {
  getReports: () =>
    apiService.get('/api/v1/reports'),

  generateReport: (reportData) =>
    apiService.post('/api/v1/reports/generate', reportData),

  getReportTemplates: () =>
    apiService.get('/api/v1/reports/templates')
};

// Authentication API - FIXED ENDPOINTS
export const authAPI = {
  login: (credentials) =>
    apiService.post('/api/v1/auth/login', credentials),

  logout: () =>
    apiService.post('/api/v1/auth/logout'),

  refreshToken: () =>
    apiService.post('/api/v1/auth/refresh'),

  getCurrentUser: () =>
    apiService.get('/api/v1/auth/me'),

  changePassword: (passwordData) =>
    apiService.put('/api/v1/auth/password', passwordData),

  updateProfile: (profileData) =>
    apiService.put('/api/v1/auth/profile', profileData)
};

// Legacy endpoints for backward compatibility
export const legacyAPI = {
  login: (credentials) =>
    apiService.post('/api/auth/login', credentials),

  logout: () =>
    apiService.post('/api/auth/logout'),

  getProfile: () =>
    apiService.get('/api/auth/profile')
};

export default apiService;