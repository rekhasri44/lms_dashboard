

export const validationService = {
  
  validateEmail(email) {
    if (!email) {
      return { isValid: false, error: 'Email address is required' };
    }

    // Trim and lowercase email
    const cleanEmail = email.trim().toLowerCase();

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      return { isValid: false, error: 'Please enter a valid email address format (e.g., user@university.edu)' };
    }

    // Check for disposable email domains
    if (this.isDisposableEmail(cleanEmail)) {
      return { 
        isValid: false, 
        error: 'Disposable email addresses are not allowed. Please use your institutional email.' 
      };
    }

    // Institutional domain validation
    const institutionalDomains = [
      'edu', 'ac', 'school', 'college', 'university', 
      'institute', 'academy', 'k12', 'campus'
    ];
    
    const domainParts = cleanEmail.split('@')[1].split('.');
    const topLevelDomain = domainParts[domainParts.length - 1].toLowerCase();
    const secondLevelDomain = domainParts[domainParts.length - 2].toLowerCase();

    const isInstitutional = institutionalDomains.includes(topLevelDomain) || 
                           institutionalDomains.includes(secondLevelDomain) ||
                           cleanEmail.includes('@university.') ||
                           cleanEmail.includes('@college.') ||
                           cleanEmail.includes('@school.');

    if (!isInstitutional) {
      return { 
        isValid: false, 
        error: 'Please use your institutional email address (e.g., .edu, .ac, university domains)' 
      };
    }

    // Email length validation
    if (cleanEmail.length > 254) {
      return { isValid: false, error: 'Email address is too long' };
    }

    return { 
      isValid: true, 
      data: { 
        cleanEmail,
        domain: cleanEmail.split('@')[1],
        isInstitutional: true
      }
    };
  },

  /**
   * Validate password with enterprise security requirements
   */
  validatePassword(password) {
    if (!password) {
      return { isValid: false, error: 'Password is required' };
    }

    // Basic length check
    if (password.length < 8) {
      return { isValid: false, error: 'Password must be at least 8 characters long' };
    }

    if (password.length > 128) {
      return { isValid: false, error: 'Password is too long (maximum 128 characters)' };
    }

    // Security requirements
    const requirements = {
      hasUpperCase: /[A-Z]/.test(password),
      hasLowerCase: /[a-z]/.test(password),
      hasNumbers: /\d/.test(password),
      hasSpecialChar: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
    };

    const missingRequirements = [];
    if (!requirements.hasUpperCase) missingRequirements.push('uppercase letter');
    if (!requirements.hasLowerCase) missingRequirements.push('lowercase letter');
    if (!requirements.hasNumbers) missingRequirements.push('number');
    if (!requirements.hasSpecialChar) missingRequirements.push('special character');

    if (missingRequirements.length > 0) {
      return {
        isValid: false,
        error: `Password must contain at least: ${missingRequirements.join(', ')}`,
        requirements: requirements
      };
    }

    // Common weak password check
    if (this.isWeakPassword(password)) {
      return {
        isValid: false,
        error: 'This password is too common or weak. Please choose a stronger password.',
        requirements: requirements
      };
    }

    // Sequential character check
    if (this.hasSequentialChars(password)) {
      return {
        isValid: false,
        error: 'Password contains sequential characters. Please avoid patterns like "123" or "abc".',
        requirements: requirements
      };
    }

    return {
      isValid: true,
      data: {
        strength: this.calculatePasswordStrength(password),
        requirements: requirements
      }
    };
  },

  /**
   * Validate full name with proper formatting
   */
  validateFullName(fullName) {
    if (!fullName) {
      return { isValid: false, error: 'Full name is required' };
    }

    const cleanName = fullName.trim().replace(/\s+/g, ' ');

    // Length validation
    if (cleanName.length < 2) {
      return { isValid: false, error: 'Full name is too short' };
    }

    if (cleanName.length > 100) {
      return { isValid: false, error: 'Full name is too long' };
    }

    // Character validation - allow letters, spaces, hyphens, apostrophes
    const nameRegex = /^[a-zA-Z\s\-'.]+$/;
    if (!nameRegex.test(cleanName)) {
      return { isValid: false, error: 'Name can only contain letters, spaces, hyphens, and apostrophes' };
    }

    // Check for at least first and last name
    const nameParts = cleanName.split(' ').filter(part => part.length > 0);
    if (nameParts.length < 2) {
      return { isValid: false, error: 'Please enter both first and last name' };
    }

    // Check for reasonable name parts (not too short/long)
    for (const part of nameParts) {
      if (part.length < 1) {
        return { isValid: false, error: 'Name parts cannot be empty' };
      }
      if (part.length > 25) {
        return { isValid: false, error: 'Name parts are too long' };
      }
    }

    return {
      isValid: true,
      data: {
        cleanName,
        firstName: nameParts[0],
        lastName: nameParts[nameParts.length - 1],
        nameParts: nameParts
      }
    };
  },

  /**
   * Validate phone number with international support
   */
  validatePhoneNumber(phone) {
    if (!phone) {
      return { isValid: false, error: 'Phone number is required' };
    }

    const cleanPhone = phone.replace(/\s+/g, '').replace(/[^\d+]/g, '');

    // Basic length check
    if (cleanPhone.length < 10) {
      return { isValid: false, error: 'Phone number is too short' };
    }

    if (cleanPhone.length > 15) {
      return { isValid: false, error: 'Phone number is too long' };
    }

    // International format validation
    const phoneRegex = /^\+?[\d\s\-\(\)]{10,}$/;
    if (!phoneRegex.test(cleanPhone)) {
      return { isValid: false, error: 'Please enter a valid phone number format' };
    }

    return {
      isValid: true,
      data: {
        cleanPhone,
        isInternational: cleanPhone.startsWith('+'),
        formatted: this.formatPhoneNumber(cleanPhone)
      }
    };
  },

  /**
   * Validate user role selection
   */
  validateUserRole(role, allowedRoles = ['student', 'faculty', 'staff', 'admin']) {
    if (!role) {
      return { isValid: false, error: 'User role is required' };
    }

    const cleanRole = role.trim().toLowerCase();

    if (!allowedRoles.includes(cleanRole)) {
      return {
        isValid: false,
        error: `Invalid user role. Allowed roles: ${allowedRoles.join(', ')}`
      };
    }

    return {
      isValid: true,
      data: { role: cleanRole }
    };
  },

  /**
   * Comprehensive form validation for user registration
   */
  validateRegistrationForm(formData) {
    const errors = {};
    const validatedData = {};

    // Validate email
    const emailValidation = this.validateEmail(formData.email);
    if (!emailValidation.isValid) {
      errors.email = emailValidation.error;
    } else {
      validatedData.email = emailValidation.data.cleanEmail;
    }

    // Validate password
    const passwordValidation = this.validatePassword(formData.password);
    if (!passwordValidation.isValid) {
      errors.password = passwordValidation.error;
    } else {
      validatedData.passwordStrength = passwordValidation.data.strength;
    }

    // Validate full name
    const nameValidation = this.validateFullName(formData.fullName);
    if (!nameValidation.isValid) {
      errors.fullName = nameValidation.error;
    } else {
      validatedData.fullName = nameValidation.data.cleanName;
      validatedData.firstName = nameValidation.data.firstName;
      validatedData.lastName = nameValidation.data.lastName;
    }

    // Validate phone (optional)
    if (formData.phone) {
      const phoneValidation = this.validatePhoneNumber(formData.phone);
      if (!phoneValidation.isValid) {
        errors.phone = phoneValidation.error;
      } else {
        validatedData.phone = phoneValidation.data.cleanPhone;
      }
    }

    // Validate role
    const roleValidation = this.validateUserRole(formData.role);
    if (!roleValidation.isValid) {
      errors.role = roleValidation.error;
    } else {
      validatedData.role = roleValidation.data.role;
    }

    // Validate terms acceptance
    if (!formData.agreeToTerms) {
      errors.agreeToTerms = 'You must accept the terms and conditions';
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors,
      data: validatedData
    };
  },

  /**
   * Validate login form inputs
   */
  validateLoginForm(email, password) {
    const errors = {};

    const emailValidation = this.validateEmail(email);
    if (!emailValidation.isValid) {
      errors.email = emailValidation.error;
    }

    const passwordValidation = this.validatePassword(password);
    if (!passwordValidation.isValid) {
      errors.password = passwordValidation.error;
    }

    return {
      isValid: Object.keys(errors).length === 0,
      errors,
      data: {
        email: emailValidation.isValid ? emailValidation.data.cleanEmail : null,
        passwordStrength: passwordValidation.isValid ? passwordValidation.data.strength : null
      }
    };
  },

  /**
   * Check if email is from disposable email service
   */
  isDisposableEmail(email) {
    const disposableDomains = [
      'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
      'throwaway.com', 'fakeinbox.com', 'yopmail.com', 'trashmail.com',
      'temp-mail.org', 'disposable.com', 'tmpmail.org'
    ];

    const domain = email.split('@')[1].toLowerCase();
    return disposableDomains.some(disposable => domain.includes(disposable));
  },

  /**
   * Check for weak/common passwords
   */
  isWeakPassword(password) {
    const weakPasswords = [
      'password', '12345678', 'admin123', 'welcome1', 'password1',
      'qwerty123', 'letmein', 'monkey', 'sunshine', 'princess',
      'admin', '1234567890', 'passw0rd', 'university', 'college'
    ];

    const lowerPassword = password.toLowerCase();
    return weakPasswords.some(weak => lowerPassword.includes(weak));
  },

  /**
   * Check for sequential characters
   */
  hasSequentialChars(password) {
    const sequences = [
      '123', '234', '345', '456', '567', '678', '789', '890',
      'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
      'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs',
      'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz'
    ];

    const lowerPassword = password.toLowerCase();
    return sequences.some(seq => lowerPassword.includes(seq));
  },

  /**
   * Calculate password strength score (0-100)
   */
  calculatePasswordStrength(password) {
    let score = 0;

    // Length contribution (max 40 points)
    score += Math.min(password.length * 4, 40);

    // Character variety (max 40 points)
    const hasUpper = /[A-Z]/.test(password) ? 10 : 0;
    const hasLower = /[a-z]/.test(password) ? 10 : 0;
    const hasNumber = /\d/.test(password) ? 10 : 0;
    const hasSpecial = /[^A-Za-z0-9]/.test(password) ? 10 : 0;
    score += hasUpper + hasLower + hasNumber + hasSpecial;

    // Deductions for weak patterns (max -20 points)
    if (this.isWeakPassword(password)) score -= 20;
    if (this.hasSequentialChars(password)) score -= 10;

    return Math.max(0, Math.min(100, score));
  },

  /**
   * Format phone number for display
   */
  formatPhoneNumber(phone) {
    const numbers = phone.replace(/\D/g, '');

    if (numbers.length === 10) {
      return numbers.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
    } else if (numbers.length === 11 && numbers.startsWith('1')) {
      return numbers.replace(/(\d{1})(\d{3})(\d{3})(\d{4})/, '+$1 ($2) $3-$4');
    }

    return phone;
  },

  /**
   * Sanitize user input to prevent XSS
   */
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    return input
      .trim()
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  /**
   * Validate file upload (for profile pictures, documents, etc.)
   */
  validateFile(file, options = {}) {
    const {
      maxSize = 5 * 1024 * 1024, // 5MB default
      allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'],
      allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf']
    } = options;

    const errors = [];

    // Check file existence
    if (!file) {
      return { isValid: false, error: 'No file selected' };
    }

    // Check file size
    if (file.size > maxSize) {
      errors.push(`File size must be less than ${maxSize / 1024 / 1024}MB`);
    }

    // Check file type
    if (!allowedTypes.includes(file.type)) {
      errors.push(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`);
    }

    // Check file extension
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    if (!allowedExtensions.includes(fileExtension)) {
      errors.push(`File extension not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`);
    }

    // Check for potentially dangerous file names
    const dangerousPatterns = /\.\.\/|\.\.\\|\/etc\/|\/bin\//i;
    if (dangerousPatterns.test(file.name)) {
      errors.push('Invalid file name');
    }

    return {
      isValid: errors.length === 0,
      errors: errors.length > 0 ? errors : null,
      data: {
        name: file.name,
        size: file.size,
        type: file.type,
        extension: fileExtension
      }
    };
  }
};

export default validationService;