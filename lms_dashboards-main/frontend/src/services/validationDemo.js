
import validationService from './validationService';

export const runValidationExamples = () => {
  console.log('=== Validation Service Demo ===');

  // Basic email validation
  const emailResult = validationService.validateEmail('user@university.edu');
  if (!emailResult.isValid) {
    console.error('Email Error:', emailResult.error);
  } else {
    console.log('✅ Email is valid:', emailResult.data.cleanEmail);
  }

  // Comprehensive form validation
  const formValidation = validationService.validateRegistrationForm({
    email: 'john.doe@university.edu',
    password: 'SecurePass123!',
    fullName: 'John Doe',
    phone: '+1234567890',
    role: 'student',
    agreeToTerms: true
  });

  if (!formValidation.isValid) {
    console.log('❌ Form errors:', formValidation.errors);
  } else {
    console.log('✅ Form is valid:', formValidation.data);
  }

  // Password strength check
  const passwordStrength = validationService.calculatePasswordStrength('MySecurePass123!');
  console.log(`🔐 Password strength: ${passwordStrength}%`);
};

// Export for use in development
export default runValidationExamples;