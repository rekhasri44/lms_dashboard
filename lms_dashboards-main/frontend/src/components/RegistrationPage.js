
import React, { useState } from 'react';
import validationService from '../services/validationService';

const RegistrationPage = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    fullName: '',
    phone: '',
    role: 'student',
    agreeToTerms: false
  });
  const [errors, setErrors] = useState({});

  const handleSubmit = (e) => {
    e.preventDefault();
    
    
    const validation = validationService.validateRegistrationForm(formData);
    
    if (!validation.isValid) {
      setErrors(validation.errors);
      return;
    }
    
    // Clear errors and proceed with registration
    setErrors({});
    handleRegistration(validation.data);
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Clear individual field error when user types
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Email Field */}
      <input
        type="email"
        value={formData.email}
        onChange={(e) => handleInputChange('email', e.target.value)}
        placeholder="john.doe@university.edu"
      />
      {errors.email && <div className="error">{errors.email}</div>}

      {/* Password Field */}
      <input
        type="password"
        value={formData.password}
        onChange={(e) => handleInputChange('password', e.target.value)}
        placeholder="SecurePass123!"
      />
      {errors.password && <div className="error">{errors.password}</div>}

      {/* Full Name Field */}
      <input
        type="text"
        value={formData.fullName}
        onChange={(e) => handleInputChange('fullName', e.target.value)}
        placeholder="John Doe"
      />
      {errors.fullName && <div className="error">{errors.fullName}</div>}

      <button type="submit">Register</button>
    </form>
  );
};