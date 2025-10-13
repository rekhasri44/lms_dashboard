import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response cache for GET requests
const responseCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Cache helper functions
const getCacheKey = (url, params) => {
  const paramString = params ? JSON.stringify(params) : '';
  return `${url}-${paramString}`;
};

const setCache = (key, data) => {
  responseCache.set(key, {
    data,
    timestamp: Date.now()
  });
};

const getCache = (key) => {
  const cached = responseCache.get(key);
  if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
    return cached.data;
  }
  responseCache.delete(key);
  return null;
};

// Request interceptor - Add token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor - Handle caching and errors
api.interceptors.response.use(
  (response) => {
    // Cache successful GET responses
    if (response.config.method === 'get') {
      const cacheKey = getCacheKey(response.config.url, response.config.params);
      setCache(cacheKey, response.data);
    }
    return response;
  },
  async (error) => {
    // Handle 401 Unauthorized
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
    
    // Handle network errors
    if (!error.response) {
      console.error('Network error:', error.message);
      
      // Try to return cached data if available
      const cacheKey = getCacheKey(error.config.url, error.config.params);
      const cachedData = getCache(cacheKey);
      if (cachedData) {
        console.log('Returning cached data due to network error');
        return Promise.resolve({ data: cachedData });
      }
      
      return Promise.reject(new Error('Network connection failed. Please check your connection.'));
    }
    
    // Handle server errors
    if (error.response.status >= 500) {
      console.error('Server error:', error.response.data);
      
      // Try cache for GET requests
      if (error.config.method === 'get') {
        const cacheKey = getCacheKey(error.config.url, error.config.params);
        const cachedData = getCache(cacheKey);
        if (cachedData) {
          console.log('Returning cached data due to server error');
          return Promise.resolve({ data: cachedData });
        }
      }
      
      return Promise.reject(new Error('Server error. Please try again later.'));
    }
    
    return Promise.reject(error);
  }
);

// Enhanced API methods with proper error handling
export const authAPI = {
  login: async (credentials) => {
    try {
      const response = await api.post('/auth/login', credentials);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Login failed' 
      };
    }
  },
  
  logout: async () => {
    try {
      await api.post('/auth/logout');
      return { success: true };
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: error.message };
    }
  },
  
  getProfile: async () => {
    try {
      const response = await api.get('/auth/profile');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch profile' 
      };
    }
  },
  
  updateProfile: async (data) => {
    try {
      const response = await api.put('/auth/profile', data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to update profile' 
      };
    }
  }
};

// Students API
export const studentsAPI = {
  getStudents: async (params = {}) => {
    try {
      // Check cache first
      const cacheKey = getCacheKey('/students', params);
      const cachedData = getCache(cacheKey);
      
      if (cachedData) {
        console.log('Returning cached students data');
        return { success: true, data: cachedData, cached: true };
      }

      const response = await api.get('/students', { params });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch students' 
      };
    }
  },
  
  getStudent: async (id) => {
    try {
      const response = await api.get(`/students/${id}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch student' 
      };
    }
  },
  
  createStudent: async (data) => {
    try {
      const response = await api.post('/students', data);
      // Invalidate students cache
      responseCache.clear();
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to create student' 
      };
    }
  },
  
  updateStudent: async (id, data) => {
    try {
      const response = await api.put(`/students/${id}`, data);
      // Invalidate students cache
      responseCache.clear();
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to update student' 
      };
    }
  },
  
  deleteStudent: async (id) => {
    try {
      const response = await api.delete(`/students/${id}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to delete student' 
      };
    }
  },
  
  getAtRiskStudents: async () => {
    try {
      const response = await api.get('/students/at-risk');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch at-risk students' 
      };
    }
  },
  
  createIntervention: async (studentId, data) => {
    try {
      const response = await api.post(`/students/${studentId}/interventions`, data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to create intervention' 
      };
    }
  },
  
  getStudentPerformance: async (studentId) => {
    try {
      const response = await api.get(`/students/${studentId}/performance`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch student performance' 
      };
    }
  },
  
  exportStudents: async () => {
    try {
      const response = await api.get('/students/export', { responseType: 'blob' });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to export students' 
      };
    }
  },
  
  // New endpoints for enhanced analytics
  getStudentEngagement: async (studentId) => {
    try {
      const response = await api.get(`/students/${studentId}/engagement`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch student engagement' 
      };
    }
  },
  
  getStudentAttendance: async (studentId) => {
    try {
      const response = await api.get(`/students/${studentId}/attendance`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch student attendance' 
      };
    }
  }
};

// Faculty API
export const facultyAPI = {
  getFaculty: async (params = {}) => {
    try {
      const response = await api.get('/faculty', { params });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty' 
      };
    }
  },
  
  getFacultyMember: async (id) => {
    try {
      const response = await api.get(`/faculty/${id}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty member' 
      };
    }
  },
  
  updateFaculty: async (id, data) => {
    try {
      const response = await api.put(`/faculty/${id}`, data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to update faculty' 
      };
    }
  },
  
  getFacultyWorkload: async () => {
    try {
      const response = await api.get('/faculty/workload');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty workload' 
      };
    }
  },
  
  getFacultyCourses: async (id) => {
    try {
      const response = await api.get(`/faculty/${id}/courses`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty courses' 
      };
    }
  },
  
  // New endpoints for enhanced analytics
  getFacultyPerformance: async (id) => {
    try {
      const response = await api.get(`/faculty/${id}/performance`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty performance' 
      };
    }
  },
  
  getFacultyList: async () => {
    try {
      const response = await api.get('/faculty/list');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Failed to fetch faculty list' 
      };
    }
  },
  
  getFacultyAnalytics: async () => {
    try {
      const response = await api.get('/faculty/analytics');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch faculty analytics' 
      };
    }
  }
};

// Courses API
export const coursesAPI = {
  getCourses: async (params = {}) => {
    try {
      const response = await api.get('/courses', { params });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch courses' 
      };
    }
  },
  
  createCourse: async (data) => {
    try {
      const response = await api.post('/courses', data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to create course' 
      };
    }
  },
  
  getCourse: async (id) => {
    try {
      const response = await api.get(`/courses/${id}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch course' 
      };
    }
  },
  
  updateCourse: async (id, data) => {
    try {
      const response = await api.put(`/courses/${id}`, data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to update course' 
      };
    }
  },
  
  deleteCourse: async (id) => {
    try {
      const response = await api.delete(`/courses/${id}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to delete course' 
      };
    }
  },
  
  getCourseSections: async (id) => {
    try {
      const response = await api.get(`/courses/${id}/sections`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch course sections' 
      };
    }
  },
  
  createCourseSection: async (courseId, data) => {
    try {
      const response = await api.post('/courses/sections', { ...data, course_id: courseId });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to create course section' 
      };
    }
  },
  
  getEnrollmentStats: async () => {
    try {
      const response = await api.get('/courses/enrollment-stats');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch enrollment stats' 
      };
    }
  },
  
  exportCourses: async () => {
    try {
      const response = await api.get('/courses/export', { responseType: 'blob' });
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to export courses' 
      };
    }
  },
  
  // New endpoints for enhanced analytics
  getCourseAnalytics: async (id) => {
    try {
      const response = await api.get(`/courses/${id}/analytics`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch course analytics' 
      };
    }
  },
  
  getCourseDemand: async () => {
    try {
      const response = await api.get('/courses/demand-forecast');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch course demand' 
      };
    }
  },
  
  getCoursePerformance: async (id) => {
    try {
      const response = await api.get(`/courses/${id}/performance`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch course performance' 
      };
    }
  }
};

// Departments API
export const departmentsAPI = {
  getDepartments: async () => {
    try {
      const response = await api.get('/departments/stats');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch departments' 
      };
    }
  },
  
  getDepartmentStats: async (departmentId) => {
    try {
      const response = await api.get(`/departments/${departmentId}/stats`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch department stats' 
      };
    }
  }
};

// Analytics API - Enhanced with comprehensive endpoints
export const analyticsAPI = {
  getDashboardOverview: async () => {
    try {
      const response = await api.get('/dashboard/overview');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch dashboard overview' 
      };
    }
  },
  
  getPerformanceAnalytics: async () => {
    try {
      const response = await api.get('/dashboard/analytics/performance');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch performance analytics' 
      };
    }
  },
  
  getEngagementAnalytics: async () => {
    try {
      const response = await api.get('/dashboard/analytics/engagement');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch engagement analytics' 
      };
    }
  },
  
  getForecastingAnalytics: async () => {
    try {
      const response = await api.get('/dashboard/analytics/forecasting');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch forecasting analytics' 
      };
    }
  },
  
  getBenchmarkingAnalytics: async () => {
    try {
      const response = await api.get('/dashboard/analytics/benchmarking');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch benchmarking analytics' 
      };
    }
  },
  
  // New comprehensive analytics endpoints
  getResourceUtilization: async () => {
    try {
      const response = await api.get('/analytics/resource-utilization');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch resource utilization' 
      };
    }
  },
  
  getGradeDistribution: async () => {
    try {
      const response = await api.get('/analytics/grade-distribution');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch grade distribution' 
      };
    }
  },
  
  getDepartmentAnalytics: async () => {
    try {
      const response = await api.get('/analytics/departments');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch department analytics' 
      };
    }
  },
  
  getStudentRetention: async () => {
    try {
      const response = await api.get('/analytics/student-retention');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch student retention' 
      };
    }
  },
  
  getPredictiveInsights: async () => {
    try {
      const response = await api.get('/analytics/predictive-insights');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch predictive insights' 
      };
    }
  },
  
  getRiskAssessment: async () => {
    try {
      const response = await api.get('/analytics/risk-assessment');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch risk assessment' 
      };
    }
  },
  
  getFinancialAnalytics: async () => {
    try {
      const response = await api.get('/analytics/financial');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch financial analytics' 
      };
    }
  },
  
  getAttendanceAnalytics: async () => {
    try {
      const response = await api.get('/analytics/attendance');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch attendance analytics' 
      };
    }
  }
};

// Reports API
export const reportsAPI = {
  getReportTemplates: async () => {
    try {
      const response = await api.get('/reports');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch report templates' 
      };
    }
  },
  
  generateReport: async (data) => {
    try {
      const response = await api.post('/reports/generate', data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to generate report' 
      };
    }
  },
  
  getReportStatus: async (id) => {
    try {
      const response = await api.get(`/reports/${id}/status`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch report status' 
      };
    }
  },
  
  scheduleReport: async (data) => {
    try {
      const response = await api.post('/reports/schedule', data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to schedule report' 
      };
    }
  },
  
  getScheduledReports: async () => {
    try {
      const response = await api.get('/reports/scheduled');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch scheduled reports' 
      };
    }
  },
  
  // New endpoints for enhanced reporting
  getFinancialReports: async () => {
    try {
      const response = await api.get('/reports/financial');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch financial reports' 
      };
    }
  },
  
  getAcademicReports: async () => {
    try {
      const response = await api.get('/reports/academic');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch academic reports' 
      };
    }
  },
  
  getComplianceReports: async () => {
    try {
      const response = await api.get('/reports/compliance');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch compliance reports' 
      };
    }
  }
};

// System API
export const systemAPI = {
  getAlerts: async () => {
    try {
      const response = await api.get('/alerts');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch alerts' 
      };
    }
  },
  
  createAlert: async (data) => {
    try {
      const response = await api.post('/alerts', data);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to create alert' 
      };
    }
  },
  
  dismissAlert: async (id) => {
    try {
      const response = await api.put(`/alerts/${id}/dismiss`);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to dismiss alert' 
      };
    }
  },
  
  getSystemMetrics: async () => {
    try {
      const response = await api.get('/monitoring/metrics');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch system metrics' 
      };
    }
  },
  
  getComplianceStatus: async () => {
    try {
      const response = await api.get('/monitoring/compliance');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch compliance status' 
      };
    }
  },
  
  // New endpoints for enhanced system monitoring
  getSystemHealth: async () => {
    try {
      const response = await api.get('/monitoring/health');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch system health' 
      };
    }
  },
  
  getPerformanceMetrics: async () => {
    try {
      const response = await api.get('/monitoring/performance');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch performance metrics' 
      };
    }
  },
  
  getThresholdMonitoring: async () => {
    try {
      const response = await api.get('/monitoring/thresholds');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch threshold monitoring' 
      };
    }
  }
};

// Financial API - New comprehensive financial endpoints
export const financialAPI = {
  getFinancialOverview: async () => {
    try {
      const response = await api.get('/financial/overview');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch financial overview' 
      };
    }
  },
  
  getFeeCollection: async () => {
    try {
      const response = await api.get('/financial/fee-collection');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch fee collection data' 
      };
    }
  },
  
  // Additional financial endpoints from original
  getRevenueAnalytics: async () => {
    try {
      const response = await api.get('/financial/revenue');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch revenue analytics' 
      };
    }
  },
  
  getExpenseAnalytics: async () => {
    try {
      const response = await api.get('/financial/expenses');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch expense analytics' 
      };
    }
  },
  
  getBudgetAnalytics: async () => {
    try {
      const response = await api.get('/financial/budget');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || error.message || 'Failed to fetch budget analytics' 
      };
    }
  }
};

export default api;