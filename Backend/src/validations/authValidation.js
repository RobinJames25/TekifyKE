import Joi from 'joi';
import SecurityService from '../modules/auth/services/securityService.js';

export const registerSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .custom((value, helpers) => {
      const validatedEmail = SecurityService.validateEmail(value);
      if (!validatedEmail) {
        return helpers.error('any.invalid', { message: 'Please provide a valid email address' });
      }
      return validatedEmail;
    })
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.empty': 'Email is required',
      'any.required': 'Email is required',
      'any.invalid': '{{#error.message}}'
    }),
  
  password: Joi.string()
    .min(SecurityService.PASSWORD_MIN_LENGTH)
    .required()
    .custom((value, helpers) => {
      const validation = SecurityService.validatePasswordStrength(value);
      if (!validation.isValid) {
        return helpers.error('any.invalid', { message: validation.errors[0] });
      }
      return value;
    })
    .messages({
      'string.min': `Password must be at least ${SecurityService.PASSWORD_MIN_LENGTH} characters`,
      'string.empty': 'Password is required',
      'any.required': 'Password is required',
      'any.invalid': '{{#error.message}}'
    }),
  
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match',
      'any.required': 'Please confirm your password'
    }),
  
  name: Joi.string()
    .min(2)
    .max(50)
    .required()
    .pattern(/^[a-zA-Z\s'-]+$/)
    .messages({
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name cannot exceed 50 characters',
      'string.empty': 'Name is required',
      'string.pattern.base': 'Name can only contain letters, spaces, hyphens, and apostrophes'
    }),
  
  phone: Joi.string()
    .custom((value, helpers) => {
      if (value && !SecurityService.validatePhone(value)) {
        return helpers.error('any.invalid', { 
          message: 'Please provide a valid Kenyan phone number (e.g., 0712345678 or +254712345678)' 
        });
      }
      return value;
    })
    .messages({
      'any.invalid': '{{#error.message}}'
    }),
  
  acceptTerms: Joi.boolean()
    .valid(true)
    .required()
    .messages({
      'any.only': 'You must accept the terms and conditions',
      'any.required': 'You must accept the terms and conditions'
    })
});

export const loginSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .custom((value, helpers) => {
      const validatedEmail = SecurityService.validateEmail(value);
      if (!validatedEmail) {
        return helpers.error('any.invalid', { message: 'Please provide a valid email address' });
      }
      return validatedEmail;
    })
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.empty': 'Email is required',
      'any.required': 'Email is required',
      'any.invalid': '{{#error.message}}'
    }),
  
  password: Joi.string()
    .required()
    .messages({
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
  
  rememberMe: Joi.boolean().default(false),
  twoFactorCode: Joi.string()
    .length(6)
    .pattern(/^\d+$/)
    .optional()
    .messages({
      'string.length': 'Two-factor code must be 6 digits',
      'string.pattern.base': 'Two-factor code must contain only numbers'
    })
});

export const forgotPasswordSchema = Joi.object({
  email: Joi.string()
    .email()
    .required()
    .messages({
      'string.email': 'Please provide a valid email address',
      'string.empty': 'Email is required',
      'any.required': 'Email is required'
    })
});

export const resetPasswordSchema = Joi.object({
  password: Joi.string()
    .min(SecurityService.PASSWORD_MIN_LENGTH)
    .required()
    .custom((value, helpers) => {
      const validation = SecurityService.validatePasswordStrength(value);
      if (!validation.isValid) {
        return helpers.error('any.invalid', { message: validation.errors[0] });
      }
      return value;
    })
    .messages({
      'string.min': `Password must be at least ${SecurityService.PASSWORD_MIN_LENGTH} characters`,
      'string.empty': 'Password is required',
      'any.required': 'Password is required',
      'any.invalid': '{{#error.message}}'
    }),
  
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({
      'any.only': 'Passwords do not match',
      'any.required': 'Please confirm your password'
    })
});

export const updateProfileSchema = Joi.object({
  name: Joi.string()
    .min(2)
    .max(50)
    .pattern(/^[a-zA-Z\s'-]+$/)
    .messages({
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name cannot exceed 50 characters',
      'string.pattern.base': 'Name can only contain letters, spaces, hyphens, and apostrophes'
    }),
  
  phone: Joi.string()
    .custom((value, helpers) => {
      if (value && !SecurityService.validatePhone(value)) {
        return helpers.error('any.invalid', { 
          message: 'Please provide a valid Kenyan phone number' 
        });
      }
      return value;
    })
    .messages({
      'any.invalid': '{{#error.message}}'
    }),
  
  avatar: Joi.string()
    .uri()
    .messages({
      'string.uri': 'Please provide a valid URL for avatar'
    })
});

export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string()
    .required()
    .messages({
      'string.empty': 'Current password is required',
      'any.required': 'Current password is required'
    }),
  
  newPassword: Joi.string()
    .min(SecurityService.PASSWORD_MIN_LENGTH)
    .required()
    .custom((value, helpers) => {
      const validation = SecurityService.validatePasswordStrength(value);
      if (!validation.isValid) {
        return helpers.error('any.invalid', { message: validation.errors[0] });
      }
      return value;
    })
    .messages({
      'string.min': `Password must be at least ${SecurityService.PASSWORD_MIN_LENGTH} characters`,
      'string.empty': 'New password is required',
      'any.required': 'New password is required',
      'any.invalid': '{{#error.message}}'
    }),
  
  confirmPassword: Joi.string()
    .valid(Joi.ref('newPassword'))
    .required()
    .messages({
      'any.only': 'Passwords do not match',
      'any.required': 'Please confirm your new password'
    })
});

export const twoFactorSchema = Joi.object({
  code: Joi.string()
    .length(6)
    .pattern(/^\d+$/)
    .required()
    .messages({
      'string.length': 'Two-factor code must be 6 digits',
      'string.pattern.base': 'Two-factor code must contain only numbers',
      'string.empty': 'Two-factor code is required',
      'any.required': 'Two-factor code is required'
    })
});

export const deleteAccountSchema = Joi.object({
  password: Joi.string()
    .required()
    .messages({
      'string.empty': 'Password is required',
      'any.required': 'Password is required'
    }),
  
  confirmText: Joi.string()
    .valid('DELETE MY ACCOUNT')
    .required()
    .messages({
      'any.only': 'Please type "DELETE MY ACCOUNT" to confirm',
      'any.required': 'Confirmation text is required'
    })
});

// Custom validation middleware
export const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
      errors: {
        wrap: {
          label: ''
        }
      }
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }
    
    // Sanitize inputs
    req.body = SecurityService.sanitizeInput(value);
    next();
  };
};