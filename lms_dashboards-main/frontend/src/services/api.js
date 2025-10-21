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
    // FIXED: Remove any trailing slashes and ensure /api/v1 path
    let base = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000';
    base = base.replace(/\/$/, ''); // Remove trailing slash
    this.baseURL = `${base}/api/v1`; // Always add /api/v1 for enterprise
    this.defaultHeaders = {
      'Content-Type': 'application/json',
    };
    console.log('Enterprise API Base URL configured:', this.baseURL);
  }

  async request(endpoint, options = {}) {
    const token = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token') || localStorage.getItem('token');
    
    const config = {
      headers: {
        ...this.defaultHeaders,
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    // Handle request body
    if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
      config.body = JSON.stringify(config.body);
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
      const response = await fetch(`${this.baseURL}${endpoint}`, config);
      
      // Handle 401 Unauthorized with token refresh
      if (response.status === 401) {
        try {
          await this.refreshToken();
          // Retry the original request with new token
          const newToken = localStorage.getItem('enterprise_access_token') || localStorage.getItem('access_token');
          if (newToken) {
            config.headers.Authorization = `Bearer ${newToken}`;
            const retryResponse = await fetch(`${this.baseURL}${endpoint}`, config);
            
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
      
      const data = await response.json();
      
      // Cache successful GET responses
      if ((config.method === 'GET' || !config.method) && options.useCache !== false) {
        const cacheKey = getCacheKey(endpoint, config.params || options.params);
        setCache(cacheKey, data);
      }
      
      return { success: true, data };
    } catch (error) {
      console.error('Enterprise API request failed:', error);
      
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

    const response = await fetch(`${this.baseURL}/auth/refresh`, {
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

  get(endpoint, params = {}, options = {}) {
    const queryString = Object.keys(params).length 
      ? `?${new URLSearchParams(params).toString()}`
      : '';
    return this.request(`${endpoint}${queryString}`, { ...options, method: 'GET' });
  }

  post(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: data,
      ...options
    });
  }

  put(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      body: data,
      ...options
    });
  }

  patch(endpoint, data, options = {}) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: data,
      ...options
    });
  }

  delete(endpoint, options = {}) {
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
      ...options
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

// Enhanced API methods with proper error handling
export const authAPI = {
  login: async (credentials) => {
    try {
      const result = await api.post('/auth/login', credentials);
      
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
      await api.post('/auth/logout');
      return { success: true };
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: error.message };
    }
  },

  getProfile: async () => {
    try {
      const result = await api.get('/auth/profile');
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
      const result = await api.put('/auth/profile', data);
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
      const result = await api.post('/auth/refresh');
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
      const result = await api.put('/auth/change-password', data);
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to change password' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to change password' 
      };
    }
  }
};

// Students API
export const studentsAPI = {
  getStudents: async (params = {}) => {
    try {
      const result = await api.get('/students', params);
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
      const result = await api.get(`/students/${id}`);
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
  
  createStudent: async (data) => {
    try {
      const result = await api.post('/students', data);
      // Invalidate students cache
      api.clearCacheForEndpoint('/students');
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
      const result = await api.put(`/students/${id}`, data);
      // Invalidate students cache
      api.clearCacheForEndpoint('/students');
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
      const result = await api.delete(`/students/${id}`);
      // Invalidate students cache
      api.clearCacheForEndpoint('/students');
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
      const result = await api.get('/students/at-risk');
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
      const result = await api.post(`/students/${studentId}/interventions`, data);
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
      const result = await api.get(`/students/${studentId}/performance`);
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
      const result = await api.getBlob('/students/export');
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
      const result = await api.get(`/students/${studentId}/engagement`);
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
      const result = await api.get(`/students/${studentId}/attendance`);
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
        const result = await api.upload(`/students/${studentId}/photo`, file, onProgress);
        return result;
      } else {
        const formData = new FormData();
        formData.append('photo', file);
        const result = await api.uploadFile(`/students/${studentId}/photo`, formData);
        return result;
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
};

// Faculty API
export const facultyAPI = {
  getFaculty: async (params = {}) => {
    try {
      const result = await api.get('/faculty', params);
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
      const result = await api.get(`/faculty/${id}`);
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
  
  updateFaculty: async (id, data) => {
    try {
      const result = await api.put(`/faculty/${id}`, data);
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
  
  getFacultyWorkload: async () => {
    try {
      const result = await api.get('/faculty/workload');
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
      const result = await api.get(`/faculty/${id}/courses`);
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
      const result = await api.get(`/faculty/${id}/performance`);
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
      const result = await api.get('/faculty/list');
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
      const result = await api.get('/faculty/analytics');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch faculty analytics' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch faculty analytics' 
      };
    }
  }
};

// Courses API
export const coursesAPI = {
  getCourses: async (params = {}) => {
    try {
      const result = await api.get('/courses', params);
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
      const result = await api.post('/courses', data);
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
      const result = await api.get(`/courses/${id}`);
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
      const result = await api.put(`/courses/${id}`, data);
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
      const result = await api.delete(`/courses/${id}`);
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
  
  getCourseSections: async (id) => {
    try {
      const result = await api.get(`/courses/${id}/sections`);
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
      const result = await api.post('/courses/sections', { ...data, course_id: courseId });
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
      const result = await api.get('/courses/enrollment-stats');
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
      const result = await api.getBlob('/courses/export');
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
      const result = await api.get(`/courses/${id}/analytics`);
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
      const result = await api.get('/courses/demand-forecast');
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
      const result = await api.get(`/courses/${id}/performance`);
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
export const departmentsAPI = {
  getDepartments: async () => {
    try {
      const result = await api.get('/departments/stats');
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
      const result = await api.get(`/departments/${departmentId}/stats`);
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

// Analytics API
export const analyticsAPI = {
  getDashboardOverview: async () => {
    try {
      const result = await api.get('/dashboard/overview');
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
      const result = await api.get('/dashboard/analytics/performance');
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
      const result = await api.get('/dashboard/analytics/engagement');
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
      const result = await api.get('/dashboard/analytics/forecasting');
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
      const result = await api.get('/dashboard/analytics/benchmarking');
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
      const result = await api.get('/analytics/resource-utilization');
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
      const result = await api.get('/analytics/grade-distribution');
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
      const result = await api.get('/analytics/departments');
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
      const result = await api.get('/analytics/student-retention');
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
      const result = await api.get('/analytics/predictive-insights');
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
      const result = await api.get('/analytics/risk-assessment');
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
      const result = await api.get('/analytics/financial');
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
      const result = await api.get('/analytics/attendance');
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

// Reports API
export const reportsAPI = {
  getReportTemplates: async () => {
    try {
      const result = await api.get('/reports');
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
      const result = await api.post('/reports/generate', data);
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
      const result = await api.get(`/reports/${id}/status`);
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
      const result = await api.post('/reports/schedule', data);
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
      const result = await api.get('/reports/scheduled');
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
      const result = await api.get('/reports/financial');
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
      const result = await api.get('/reports/academic');
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
      const result = await api.get('/reports/compliance');
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

// System API
export const systemAPI = {
  getAlerts: async () => {
    try {
      const result = await api.get('/alerts');
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
  
  createAlert: async (data) => {
    try {
      const result = await api.post('/alerts', data);
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
      const result = await api.put(`/alerts/${id}/dismiss`);
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
      const result = await api.get('/monitoring/metrics');
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
      const result = await api.get('/monitoring/compliance');
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
      const result = await api.get('/monitoring/health');
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
      const result = await api.get('/monitoring/performance');
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
      const result = await api.get('/monitoring/thresholds');
      return result.success
        ? { success: true, data: result.data }
        : { success: false, error: result.error || 'Failed to fetch threshold monitoring' };
    } catch (error) {
      return { 
        success: false, 
        error: error.message || 'Failed to fetch threshold monitoring' 
      };
    }
  }
};

// Financial API
export const financialAPI = {
  getFinancialOverview: async () => {
    try {
      const result = await api.get('/financial/overview');
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
      const result = await api.get('/financial/fee-collection');
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
      const result = await api.get('/financial/revenue');
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
      const result = await api.get('/financial/expenses');
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
      const result = await api.get('/financial/budget');
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

// Simple API service for basic operations (from modifications)
export const simpleApiService = {
  async login(email, password) {
    const response = await fetch(`${api.baseURL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
  },
  
  async getProfile(token) {
    const response = await fetch(`${api.baseURL}/users/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
  }
};

// Export singleton instance and error class
export const apiService = api;
export { EnterpriseApiError };

export default api;