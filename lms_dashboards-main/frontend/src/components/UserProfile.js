
import React, { useState } from 'react';
import validationService from '../services/validationService';

const UserProfile = () => {
  const [profileData, setProfileData] = useState({
    fullName: '',
    phone: '',
    email: ''
  });
  const [errors, setErrors] = useState({});

  const validateProfile = () => {
    const errors = {};

    const nameValidation = validationService.validateFullName(profileData.fullName);
    if (!nameValidation.isValid) {
      errors.fullName = nameValidation.error;
    }

    if (profileData.phone) {
      const phoneValidation = validationService.validatePhoneNumber(profileData.phone);
      if (!phoneValidation.isValid) {
        errors.phone = phoneValidation.error;
      }
    }

    const emailValidation = validationService.validateEmail(profileData.email);
    if (!emailValidation.isValid) {
      errors.email = emailValidation.error;
    }

    return errors;
  };

  const handleSave = () => {
    const validationErrors = validateProfile();
    
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }
    
    // Save profile data
    saveProfile(profileData);
  };

  return (
    <div>
      {/* Profile form fields */}
      <button onClick={handleSave}>Save Profile</button>
    </div>
  );
};