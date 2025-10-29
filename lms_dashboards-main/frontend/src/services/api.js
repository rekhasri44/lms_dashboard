import { useAuth } from '../context/AuthContext';

// Cache configuration
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

// Base API configuration
const API_CONFIG = {
  BASE_URL: process.env.REACT_APP_API_BASE_URL || process.env.REACT_APP_API_URL || 'https://dashboard-backend-qmy9.onrender.com',
  TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3
};

// Enterprise API Error Class
class EnterpriseApiError extends Error {
  constructor(message, status, details = null) {
    super(message);
    this.name = 'EnterpriseApiError';
    this.status = status;
    this.details = details;
    this.timestamp = new Date().toISOString();
  }

  toJSON() {
    return {
      error: this.message,
      status: this.status,
      details: this.details,
      timestamp: this.timestamp,
    };
  }
}

// Enhanced Enterprise API service with proper error handling, caching, and retry mechanism
class EnterpriseApiService {
  constructor() {
    let base = API_CONFIG.BASE_URL;
    base = base.replace(/\/$/, '');
    this.baseURL = base;
    console.log('Production API Base URL:', this.baseURL);
  }

  async request(endpoint, options = {}) {
    const token = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token') || localStorage.getItem('token');
    
    const defaultHeaders = {
      'Content-Type': 'application/json',
    };

    if (token) {
      defaultHeaders['Authorization'] = `Bearer ${token}`;
    }

    const config = {
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
      timeout: API_CONFIG.TIMEOUT,
      ...options,
    };

    // Handle request body
    if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
      config.body = JSON.stringify(config.body);
    } else if (options.data && (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH')) {
      config.body = JSON.stringify(options.data);
    }

    // Check cache for GET requests
    if ((config.method === 'GET' || !config.method) && options.useCache !== false) {
      const cacheKey = getCacheKey(endpoint, config.params || options.params);
      const cachedData = getCache(cacheKey);
      if (cachedData) {
        console.log('Returning cached data for:', endpoint);
        return { success: true, data: cachedData, cached: true };
      }
    }

    try {
      const url = `${this.baseURL}${endpoint}`;
      console.log(`Making API call to: ${url}`, config);
      
      const response = await fetch(url, config);
      
      // Handle 401 Unauthorized with token refresh
      if (response.status === 401) {
        try {
          await this.refreshToken();
          // Retry the original request with new token
          const newToken = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token');
          if (newToken) {
            config.headers.Authorization = `Bearer ${newToken}`;
            const retryResponse = await fetch(url, config);
            
            if (!retryResponse.ok) {
              throw new Error(`Retry failed with status: ${retryResponse.status}`);
            }
            
            const retryData = await retryResponse.json();
            
            // Cache successful GET responses after retry
            if ((config.method === 'GET' || !config.method) && options.useCache !== false) {
              const cacheKey = getCacheKey(endpoint, config.params || options.params);
              setCache(cacheKey, retryData);
            }
            
            return { success: true, data: retryData };
          }
        } catch (refreshError) {
          // Token refresh failed, clear storage and redirect
          localStorage.removeItem('enterprise_access_token');
          localStorage.removeItem('enterprise_refresh_token');
          localStorage.removeItem('access_token');
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          window.location.href = '/login';
          throw new EnterpriseApiError('Unauthorized - Please login again', 401);
        }
      }
      
      if (!response.ok) {
        // Try to parse error response
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorDetails = null;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
          errorDetails = errorData.details || null;
        } catch {
          // If response is not JSON, use status text
          errorMessage = response.statusText || errorMessage;
        }
        throw new EnterpriseApiError(errorMessage, response.status, errorDetails);
      }

      // Handle empty responses
      const contentType = response.headers.get('content-type');
      let data;
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = { success: true, status: response.status };
      }
      
      // Cache successful GET responses
      if ((config.method === 'GET' || !config.method) && options.useCache !== false) {
        const cacheKey = getCacheKey(endpoint, config.params || options.params);
        setCache(cacheKey, data);
      }
      
      return { success: true, data };
    } catch (error) {
      console.error('Enterprise API request failed:', error);
      
      // Enhanced error messages for better user experience
      if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
        error.message = 'Network error: Unable to connect to the server. Please check your internet connection.';
      }
      
      // Handle network errors - try cache for GET requests
      if ((config.method === 'GET' || !config.method) && options.useCache !== false && 
          (error.message.includes('Failed to fetch') || error.message.includes('Network'))) {
        const cacheKey = getCacheKey(endpoint, config.params || options.params);
        const cachedData = getCache(cacheKey);
        if (cachedData) {
          console.log('Returning cached data due to network error');
          return { data: cachedData, success: true, cached: true };
        }
      }
      
      if (error instanceof EnterpriseApiError) {
        return { 
          success: false, 
          error: error.message,
          status: error.status,
          details: error.details,
          data: null
        };
      }
      
      return { 
        success: false, 
        error: error.message || 'Network request failed',
        data: null
      };
    }
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('enterprise_refresh_token') || localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new EnterpriseApiError('No refresh token available', 401);
    }

    const response = await fetch(`${this.baseURL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${refreshToken}`,
      },
    });

    if (!response.ok) {
      localStorage.removeItem('enterprise_access_token');
      localStorage.removeItem('enterprise_refresh_token');
      localStorage.removeItem('access_token');
      throw new EnterpriseApiError('Token refresh failed', 401);
    }

    const data = await response.json();
    if (data.access_token) {
      localStorage.setItem('enterprise_access_token', data.access_token);
    }
    return data.access_token;
  }

  // Generic CRUD operations with enhanced caching
  async get(endpoint, params = {}, options = {}) {
    const queryString = Object.keys(params).length 
      ? `?${new URLSearchParams(params).toString()}`
      : '';
    return this.request(`${endpoint}${queryString}`, { ...options, method: 'GET' });
  }

  async post(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'POST',
      data,
      ...options
    });
  }

  async put(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      data,
      ...options
    });
  }

  async patch(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'PATCH',
      data,
      ...options
    });
  }

  async delete(endpoint, options = {}) {
    return this.request(endpoint, {
      method: 'DELETE',
      ...options
    });
  }

  // Additional method for file uploads/blobs
  async getBlob(endpoint) {
    try {
      const token = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token') || localStorage.getItem('token');
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        headers: {
          ...(token && { Authorization: `Bearer ${token}` }),
        },
      });
      
      if (!response.ok) throw new EnterpriseApiError('Failed to fetch blob', response.status);
      return { success: true, data: await response.blob() };
    } catch (error) {
      if (error instanceof EnterpriseApiError) {
        return { success: false, error: error.message, status: error.status };
      }
      return { success: false, error: error.message };
    }
  }

  // File upload method with progress support
  async uploadFile(endpoint, formData, options = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: formData,
      ...options,
      headers: {
        // Don't set Content-Type for FormData, let browser set it
      }
    });
  }

  // Enhanced file upload with progress tracking
  async upload(endpoint, file, onProgress = null) {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token');
    
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      
      xhr.upload.addEventListener('progress', (e) => {
        if (onProgress && e.lengthComputable) {
          onProgress((e.loaded / e.total) * 100);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
          try {
            const data = JSON.parse(xhr.responseText);
            resolve({ success: true, data });
          } catch (error) {
            resolve({ success: true, data: xhr.responseText });
          }
        } else {
          reject(new EnterpriseApiError('Upload failed', xhr.status));
        }
      });

      xhr.addEventListener('error', () => {
        reject(new EnterpriseApiError('Upload failed', 0));
      });

      xhr.open('POST', `${this.baseURL}${endpoint}`);
      if (token) {
        xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      }
      xhr.send(formData);
    });
  }

  // Clear cache utility
  clearCache() {
    responseCache.clear();
    console.log('Enterprise API cache cleared');
  }

  // Clear specific cache entries
  clearCacheForEndpoint(endpoint) {
    let clearedCount = 0;
    for (const [key] of responseCache) {
      if (key.startsWith(endpoint)) {
        responseCache.delete(key);
        clearedCount++;
      }
    }
    console.log(`Cleared ${clearedCount} cache entries for endpoint: ${endpoint}`);
  }

  // Get cache statistics
  getCacheStats() {
    return {
      size: responseCache.size,
      entries: Array.from(responseCache.keys())
    };
  }
}

// Create API instance
const api = new EnterpriseApiService();

// Enhanced API methods with proper error handling and fixed endpoints
const authAPI = {
  login: async (credentials) => {
    try {
      // Try new endpoint first, then fallback to legacy
      let result = await api.post('/api/v1/auth/login', credentials);
      
      if (!result.success) {
        // Fallback to legacy endpoint
        result = await api.post('/api/auth/login', credentials);
      }
      
      if (result.success && result.data) {
        // Handle different response formats from backend
        const responseData = result.data;
        
        if (responseData.access_token) {
          // Format 1: { access_token, user, refresh_token }
          localStorage.setItem('enterprise_access_token', responseData.access_token);
          if (responseData.refresh_token) {
            localStorage.setItem('enterprise_refresh_token', responseData.refresh_token);
          }
          if (responseData.user) {
            localStorage.setItem('user', JSON.stringify(responseData.user));
          }
          return { 
            success: true, 
            data: {
              token: responseData.access_token,
              refresh_token: responseData.refresh_token,
              user: responseData.user
            }
          };
        } else if (responseData.token) {
          // Format 2: { token, user }
          localStorage.setItem('enterprise_access_token', responseData.token);
          if (responseData.user) {
            localStorage.setItem('user', JSON.stringify(responseData.user));
          }
          return { 
            success: true, 
            data: responseData 
          };
        } else {
          return { 
            success: false, 
            error: 'Invalid response format from server' 
          };
        }
      } else {
        return { 
          success: false, 
          error: result.error || 'Login failed' 
        };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Login failed' 
      };
    }
  },

  logout: async () => {
    try {
      localStorage.removeItem('enterprise_access_token');
      localStorage.removeItem('enterprise_refresh_token');
      localStorage.removeItem('access_token');
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      
      // Try to call logout endpoint
      try {
        await api.post('/api/v1/auth/logout');
      } catch (e) {
        // Silently fail logout API call
        console.log('Logout API call failed, continuing with client cleanup');
      }
      
      return { success: true };
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: error.message };
    }
  },

  getProfile: async () => {
    try {
      // Try multiple endpoints
      let result = await api.get('/api/v1/auth/me');
      
      if (!result.success) {
        result = await api.get('/api/auth/profile');
      }
      
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch profile' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch profile' 
      };
    }
  },

  updateProfile: async (data) => {
    try {
      let result = await api.put('/api/v1/auth/profile', data);
      
      if (!result.success) {
        result = await api.put('/api/auth/profile', data);
      }
      
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to update profile' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to update profile' 
      };
    }
  },

  refreshToken: async () => {
    try {
      const result = await api.post('/api/v1/auth/refresh');
      if (result.success && result.data) {
        if (result.data.access_token) {
          localStorage.setItem('enterprise_access_token', result.data.access_token);
        }
        return { success: true, data: result.data };
      }
      return { success: false, error: result.error || 'Token refresh failed' };
    } catch (error) {
      return { success: false, error: error.message };
    }
  },

  changePassword: async (data) => {
    try {
      let result = await api.put('/api/v1/auth/password', data);
      
      if (!result.success) {
        result = await api.put('/api/auth/change-password', data);
      }
      
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to change password' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to change password' 
      };
    }
  },

  getCurrentUser: async () => {
    try {
      const result = await api.get('/api/v1/auth/me');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch current user' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch current user' 
      };
    }
  }
};

// Students API with fixed endpoints
const studentsAPI = {
  getStudents: async (params = {}) => {
    try {
      const result = await api.get('/api/v1/students', params);
      return result.success
        ? { success: true, data: result.data, cached: result.cached || false }
        : { success: false, error: result.error || 'Failed to fetch students' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch students' 
      };
    }
  },
  
  getStudent: async (id) => {
    try {
      const result = await api.get(`/api/v1/students/${id}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student' 
      };
    }
  },

  getStudentDetails: async (studentId) => {
    try {
      const result = await api.get(`/api/v1/students/${studentId}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student details' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student details' 
      };
    }
  },
  
  createStudent: async (data) => {
    try {
      const result = await api.post('/api/v1/students', data);
      // Invalidate students cache
      api.clearCacheForEndpoint('/api/v1/students');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create student' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create student' 
      };
    }
  },
  
  updateStudent: async (id, data) => {
    try {
      const result = await api.put(`/api/v1/students/${id}`, data);
      // Invalidate students cache
      api.clearCacheForEndpoint('/api/v1/students');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to update student' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to update student' 
      };
    }
  },
  
  deleteStudent: async (id) => {
    try {
      const result = await api.delete(`/api/v1/students/${id}`);
      // Invalidate students cache
      api.clearCacheForEndpoint('/api/v1/students');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to delete student' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to delete student' 
      };
    }
  },
  
  getAtRiskStudents: async () => {
    try {
      const result = await api.get('/api/v1/students/at-risk');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch at-risk students' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch at-risk students' 
      };
    }
  },
  
  createIntervention: async (studentId, data) => {
    try {
      const result = await api.post(`/api/v1/students/${studentId}/interventions`, data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create intervention' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create intervention' 
      };
    }
  },
  
  getStudentPerformance: async (studentId) => {
    try {
      const result = await api.get(`/api/v1/students/${studentId}/performance`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student performance' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student performance' 
      };
    }
  },
  
  exportStudents: async () => {
    try {
      const result = await api.getBlob('/api/v1/students/export');
      return result;
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to export students' 
      };
    }
  },
  
  getStudentEngagement: async (studentId) => {
    try {
      const result = await api.get(`/api/v1/students/${studentId}/engagement`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student engagement' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student engagement' 
      };
    }
  },
  
  getStudentAttendance: async (studentId) => {
    try {
      const result = await api.get(`/api/v1/students/${studentId}/attendance`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student attendance' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student attendance' 
      };
    }
  },

  uploadStudentPhoto: async (studentId, file, onProgress = null) => {
    try {
      if (onProgress) {
        const result = await api.upload(`/api/v1/students/${studentId}/photo`, file, onProgress);
        return result;
      } else {
        const formData = new FormData();
        formData.append('photo', file);
        const result = await api.uploadFile(`/api/v1/students/${studentId}/photo`, formData);
        return result;
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

// Faculty API with fixed endpoints
const facultyAPI = {
  getFaculty: async (params = {}) => {
    try {
      const result = await api.get('/api/v1/faculty', params);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty' 
      };
    }
  },
  
  getFacultyMember: async (id) => {
    try {
      const result = await api.get(`/api/v1/faculty/${id}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty member' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty member' 
      };
    }
  },

  getFacultyDetails: async (facultyId) => {
    try {
      const result = await api.get(`/api/v1/faculty/${facultyId}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty details' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty details' 
      };
    }
  },
  
  createFaculty: async (data) => {
    try {
      const result = await api.post('/api/v1/faculty', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create faculty' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create faculty' 
      };
    }
  },
  
  updateFaculty: async (id, data) => {
    try {
      const result = await api.put(`/api/v1/faculty/${id}`, data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to update faculty' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to update faculty' 
      };
    }
  },
  
  deleteFaculty: async (id) => {
    try {
      const result = await api.delete(`/api/v1/faculty/${id}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to delete faculty' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to delete faculty' 
      };
    }
  },
  
  getFacultyWorkload: async () => {
    try {
      const result = await api.get('/api/v1/faculty/workload');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty workload' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty workload' 
      };
    }
  },
  
  getFacultyCourses: async (id) => {
    try {
      const result = await api.get(`/api/v1/faculty/${id}/courses`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty courses' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty courses' 
      };
    }
  },
  
  getFacultyPerformance: async (id) => {
    try {
      const result = await api.get(`/api/v1/faculty/${id}/performance`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty performance' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty performance' 
      };
    }
  },
  
  getFacultyList: async () => {
    try {
      const result = await api.get('/api/v1/faculty/list');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty list' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty list' 
      };
    }
  },
  
  getFacultyAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/faculty/analytics');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty analytics' 
      };
    }
  },

  exportFaculty: async () => {
    try {
      const result = await api.getBlob('/api/v1/faculty/export');
      return result;
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to export faculty' 
      };
    }
  }
};

// Courses API with fixed endpoints
const coursesAPI = {
  getCourses: async (params = {}) => {
    try {
      const result = await api.get('/api/v1/courses', params);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch courses' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch courses' 
      };
    }
  },
  
  createCourse: async (data) => {
    try {
      const result = await api.post('/api/v1/courses', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create course' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create course' 
      };
    }
  },
  
  getCourse: async (id) => {
    try {
      const result = await api.get(`/api/v1/courses/${id}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch course' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch course' 
      };
    }
  },
  
  updateCourse: async (id, data) => {
    try {
      const result = await api.put(`/api/v1/courses/${id}`, data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to update course' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to update course' 
      };
    }
  },
  
  deleteCourse: async (id) => {
    try {
      const result = await api.delete(`/api/v1/courses/${id}`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to delete course' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to delete course' 
      };
    }
  },
  
  getCourseSections: async (params = {}) => {
    try {
      const result = await api.get('/api/v1/courses/sections', params);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch course sections' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch course sections' 
      };
    }
  },
  
  createCourseSection: async (courseId, data) => {
    try {
      const result = await api.post('/api/v1/courses/sections', { ...data, course_id: courseId });
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create course section' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create course section' 
      };
    }
  },
  
  getEnrollmentStats: async () => {
    try {
      const result = await api.get('/api/v1/courses/enrollment-stats');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch enrollment stats' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch enrollment stats' 
      };
    }
  },
  
  exportCourses: async () => {
    try {
      const result = await api.getBlob('/api/v1/courses/export');
      return result;
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to export courses' 
      };
    }
  },
  
  getCourseAnalytics: async (id) => {
    try {
      const result = await api.get(`/api/v1/courses/${id}/analytics`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch course analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch course analytics' 
      };
    }
  },
  
  getCourseDemand: async () => {
    try {
      const result = await api.get('/api/v1/courses/demand-forecast');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch course demand' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch course demand' 
      };
    }
  },
  
  getCoursePerformance: async (id) => {
    try {
      const result = await api.get(`/api/v1/courses/${id}/performance`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch course performance' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch course performance' 
      };
    }
  }
};

// Departments API
const departmentsAPI = {
  getDepartments: async () => {
    try {
      const result = await api.get('/api/v1/departments/stats');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch departments' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch departments' 
      };
    }
  },
  
  getDepartmentStats: async (departmentId) => {
    try {
      const result = await api.get(`/api/v1/departments/${departmentId}/stats`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch department stats' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch department stats' 
      };
    }
  }
};

// Analytics API with fixed endpoints
const analyticsAPI = {
  getDashboardOverview: async () => {
    try {
      const result = await api.get('/api/v1/analytics/dashboard/overview');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch dashboard overview' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch dashboard overview' 
      };
    }
  },
  
  getPerformanceAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/performance/grade-distribution');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch performance analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch performance analytics' 
      };
    }
  },
  
  getEngagementAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/engagement');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch engagement analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch engagement analytics' 
      };
    }
  },
  
  getForecastingAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/forecasting');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch forecasting analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch forecasting analytics' 
      };
    }
  },
  
  getBenchmarkingAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/benchmarking');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch benchmarking analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch benchmarking analytics' 
      };
    }
  },
  
  getResourceUtilization: async () => {
    try {
      const result = await api.get('/api/v1/analytics/resource/utilization');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch resource utilization' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch resource utilization' 
      };
    }
  },
  
  getGradeDistribution: async () => {
    try {
      const result = await api.get('/api/v1/analytics/grade-distribution');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch grade distribution' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch grade distribution' 
      };
    }
  },
  
  getDepartmentAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/departments');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch department analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch department analytics' 
      };
    }
  },
  
  getStudentRetention: async () => {
    try {
      const result = await api.get('/api/v1/analytics/performance/student-retention');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch student retention' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch student retention' 
      };
    }
  },
  
  getPredictiveInsights: async () => {
    try {
      const result = await api.get('/api/v1/analytics/predictive/insights');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch predictive insights' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch predictive insights' 
      };
    }
  },
  
  getRiskAssessment: async () => {
    try {
      const result = await api.get('/api/v1/analytics/risk/assessment');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch risk assessment' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch risk assessment' 
      };
    }
  },
  
  getFinancialAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/financial/overview');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch financial analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch financial analytics' 
      };
    }
  },
  
  getAttendanceAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/analytics/attendance');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch attendance analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch attendance analytics' 
      };
    }
  }
};

// Reports API with fixed endpoints
const reportsAPI = {
  getReports: async (filters = {}) => {
    try {
      const result = await api.get('/api/v1/reports', filters);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch reports' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch reports' 
      };
    }
  },

  getReportTemplates: async () => {
    try {
      const result = await api.get('/api/v1/reports/templates');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch report templates' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch report templates' 
      };
    }
  },
  
  generateReport: async (data) => {
    try {
      const result = await api.post('/api/v1/reports/generate', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to generate report' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to generate report' 
      };
    }
  },
  
  getReportStatus: async (id) => {
    try {
      const result = await api.get(`/api/v1/reports/${id}/status`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch report status' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch report status' 
      };
    }
  },
  
  scheduleReport: async (data) => {
    try {
      const result = await api.post('/api/v1/reports/schedule', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to schedule report' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to schedule report' 
      };
    }
  },
  
  getScheduledReports: async () => {
    try {
      const result = await api.get('/api/v1/reports/scheduled');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch scheduled reports' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch scheduled reports' 
      };
    }
  },
  
  getFinancialReports: async () => {
    try {
      const result = await api.get('/api/v1/reports/financial');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch financial reports' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch financial reports' 
      };
    }
  },
  
  getAcademicReports: async () => {
    try {
      const result = await api.get('/api/v1/reports/academic');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch academic reports' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch academic reports' 
      };
    }
  },
  
  getComplianceReports: async () => {
    try {
      const result = await api.get('/api/v1/reports/compliance');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch compliance reports' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch compliance reports' 
      };
    }
  }
};

// System API with fixed endpoints
const systemAPI = {
  getAlerts: async (filters = {}) => {
    try {
      const result = await api.get('/api/v1/system/alerts', filters);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch alerts' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch alerts' 
      };
    }
  },

  getAnnouncements: async (filters = {}) => {
    try {
      const result = await api.get('/api/v1/system/announcements', filters);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch announcements' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch announcements' 
      };
    }
  },
  
  createAlert: async (data) => {
    try {
      const result = await api.post('/api/v1/system/alerts', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to create alert' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to create alert' 
      };
    }
  },
  
  dismissAlert: async (id) => {
    try {
      const result = await api.put(`/api/v1/system/alerts/${id}/dismiss`);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to dismiss alert' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to dismiss alert' 
      };
    }
  },
  
  getSystemMetrics: async () => {
    try {
      const result = await api.get('/api/v1/system/monitoring/metrics');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch system metrics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch system metrics' 
      };
    }
  },
  
  getComplianceStatus: async () => {
    try {
      const result = await api.get('/api/v1/system/monitoring/compliance');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch compliance status' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch compliance status' 
      };
    }
  },
  
  getSystemHealth: async () => {
    try {
      const result = await api.get('/api/v1/system/monitoring/health');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch system health' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch system health' 
      };
    }
  },
  
  getPerformanceMetrics: async () => {
    try {
      const result = await api.get('/api/v1/system/monitoring/performance');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch performance metrics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch performance metrics' 
      };
    }
  },
  
  getThresholdMonitoring: async () => {
    try {
      const result = await api.get('/api/v1/system/monitoring/thresholds');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch threshold monitoring' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch threshold monitoring' 
      };
    }
  },

  getSystemSettings: async () => {
    try {
      const result = await api.get('/api/v1/system/settings');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch system settings' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch system settings' 
      };
    }
  },

  updateSystemSettings: async (settings) => {
    try {
      const result = await api.put('/api/v1/system/settings', { settings });
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to update system settings' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to update system settings' 
      };
    }
  }
};

// Financial API
const financialAPI = {
  getFinancialOverview: async () => {
    try {
      const result = await api.get('/api/v1/financial/overview');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch financial overview' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch financial overview' 
      };
    }
  },
  
  getFeeCollection: async () => {
    try {
      const result = await api.get('/api/v1/financial/fee-collection');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch fee collection data' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch fee collection data' 
      };
    }
  },
  
  getRevenueAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/financial/revenue');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch revenue analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch revenue analytics' 
      };
    }
  },
  
  getExpenseAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/financial/expenses');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch expense analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch expense analytics' 
      };
    }
  },
  
  getBudgetAnalytics: async () => {
    try {
      const result = await api.get('/api/v1/financial/budget');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch budget analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch budget analytics' 
      };
    }
  }
};

// Legacy endpoints for backward compatibility
const legacyAPI = {
  login: (credentials) =>
    api.post('/api/auth/login', credentials),

  logout: () =>
    api.post('/api/auth/logout'),

  getProfile: () =>
    api.get('/api/auth/profile'),

  updateProfile: (profileData) =>
    api.put('/api/auth/profile', profileData)
};

// Export singleton instance and error class
const apiService = api;
export { EnterpriseApiError };

// Export all APIs for easy access
export {
  authAPI,
  studentsAPI,
  facultyAPI,
  coursesAPI,
  departmentsAPI,
  analyticsAPI,
  reportsAPI,
  systemAPI,
  financialAPI,
  legacyAPI
};

export default api;