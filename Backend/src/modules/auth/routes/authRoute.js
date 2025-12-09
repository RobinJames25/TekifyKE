import express from 'express';
import {
  register,
  login,
  logout,
  refreshToken,
  verifyEmail,
  resendVerification,
  forgotPassword,
  resetPassword,
  changePassword,
  getProfile,
  updateProfile,
  setupTwoFactor,
  verifyTwoFactor,
  disableTwoFactor,
  getSessions,
  revokeSession,
  revokeAllSessions,
  deleteAccount
} from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validation.js';
import {
  registerSchema,
  loginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  updateProfileSchema,
  changePasswordSchema,
  twoFactorSchema,
  deleteAccountSchema
} from '../../../validations/utils/authValidation.js';
import {
  authRateLimiter,
  registerRateLimiter,
  passwordResetRateLimiter,
  verifyEmailRateLimiter
} from '../middleware/rateLimiter.js';

const router = express.Router();

// Public routes
router.post('/register', 
  registerRateLimiter,
  validate(registerSchema), 
  register
);

router.post('/login', 
  authRateLimiter,
  validate(loginSchema), 
  login
);

router.post('/refresh-token', refreshToken);

router.post('/forgot-password',
  passwordResetRateLimiter,
  validate(forgotPasswordSchema),
  forgotPassword
);

router.post('/reset-password/:token',
  validate(resetPasswordSchema),
  resetPassword
);

router.get('/verify-email/:token',
  verifyEmailRateLimiter,
  verifyEmail
);

router.post('/resend-verification',
  verifyEmailRateLimiter,
  validate(forgotPasswordSchema),
  resendVerification
);

// Protected routes (require authentication)
router.use(authenticate);

router.post('/logout', logout);
router.get('/profile', getProfile);
router.put('/profile', validate(updateProfileSchema), updateProfile);
router.put('/change-password', validate(changePasswordSchema), changePassword);

// Two-Factor Authentication routes
router.post('/two-factor/setup', setupTwoFactor);
router.post('/two-factor/verify', validate(twoFactorSchema), verifyTwoFactor);
router.post('/two-factor/disable', validate(changePasswordSchema), disableTwoFactor);

// Session management
router.get('/sessions', getSessions);
router.delete('/sessions/:sessionId', revokeSession);
router.delete('/sessions', revokeAllSessions);

// Account deletion
router.delete('/account', validate(deleteAccountSchema), deleteAccount);

export default router;