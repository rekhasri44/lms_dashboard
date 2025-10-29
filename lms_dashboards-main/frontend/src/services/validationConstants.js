
export const VALIDATION_CONSTANTS = {
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true
  },
  EMAIL: {
    MAX_LENGTH: 254,
    INSTITUTIONAL_DOMAINS: [
      'edu', 'ac', 'school', 'college', 'university',
      'institute', 'academy', 'k12', 'campus'
    ],
    DISPOSABLE_DOMAINS: [
      'tempmail.com', 'guerrillamail.com', 'mailinator.com',
      '10minutemail.com', 'throwaway.com', 'fakeinbox.com',
      'yopmail.com', 'trashmail.com', 'temp-mail.org'
    ]
  },
  NAME: {
    MIN_LENGTH: 2,
    MAX_LENGTH: 100,
    MIN_PARTS: 2
  },
  PHONE: {
    MIN_LENGTH: 10,
    MAX_LENGTH: 15
  },
  FILE: {
    MAX_SIZE: 5 * 1024 * 1024, // 5MB
    ALLOWED_TYPES: [
      'image/jpeg',
      'image/png', 
      'image/gif',
      'application/pdf'
    ]
  }
};

export const VALIDATION_MESSAGES = {
  REQUIRED: 'This field is required',
  INVALID_EMAIL: 'Please enter a valid email address',
  INSTITUTIONAL_EMAIL_REQUIRED: 'Please use your institutional email address',
  DISPOSABLE_EMAIL: 'Disposable email addresses are not allowed',
  PASSWORD_TOO_WEAK: 'Password does not meet security requirements',
  PASSWORD_TOO_SHORT: 'Password must be at least 8 characters long',
  PASSWORD_TOO_LONG: 'Password is too long (maximum 128 characters)',
  NAME_TOO_SHORT: 'Name is too short',
  NAME_TOO_LONG: 'Name is too long',
  NAME_INVALID_CHARS: 'Name contains invalid characters',
  PHONE_INVALID: 'Please enter a valid phone number',
  FILE_TOO_LARGE: 'File is too large',
  FILE_TYPE_NOT_ALLOWED: 'File type is not allowed'
};