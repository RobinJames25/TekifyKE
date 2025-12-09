import prisma from '../../lib/prisma.js';
import TokenService from '../services/tokenService.js';
import SecurityService from '../services/securityService.js';
import EmailService from '../services/emailService.js';
import {
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  ValidationError
} from '../utils/errors.js';
import logger from '../utils/logger.js';
import { validateEmail, validatePhone } from '../utils/validators.js';

class AuthController {
  /**
   * Register a new user
   */
  static async register(req, res, next) {
    const transactionStart = Date.now();
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    try {
      const { email, password, name, phone, acceptTerms } = req.body;
      
      // Validate inputs
      if (!acceptTerms) {
        throw new BadRequestError('You must accept the terms and conditions');
      }
      
      const validatedEmail = SecurityService.validateEmail(email);
      if (!validatedEmail) {
        throw new BadRequestError('Please provide a valid email address');
      }
      
      if (phone && !SecurityService.validatePhone(phone)) {
        throw new BadRequestError('Please provide a valid Kenyan phone number');
      }
      
      // Check password strength
      const passwordValidation = SecurityService.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        throw new ValidationError('Password validation failed', passwordValidation.errors);
      }
      
      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email: validatedEmail }
      });
      
      if (existingUser) {
        throw new ConflictError('Email already registered');
      }
      
      // Check for suspicious registration patterns
      const recentRegistrations = await prisma.user.count({
        where: {
          createdAt: {
            gte: new Date(Date.now() - 3600000) // Last hour
          },
          ipAddress: ipAddress
        }
      });
      
      if (recentRegistrations >= 3) {
        logger.warn(`Suspicious registration pattern from IP: ${ipAddress}`);
        throw new ForbiddenError('Registration limit exceeded. Please try again later.');
      }
      
      // Hash password
      const hashedPassword = await SecurityService.hashPassword(password);
      
      // Generate verification token
      const verificationToken = TokenService.generateSecureToken();
      
      // Start transaction
      const result = await prisma.$transaction(async (tx) => {
        // Create user
        const user = await tx.user.create({
          data: {
            email: validatedEmail,
            password: hashedPassword,
            name: SecurityService.sanitizeInput(name),
            phone: phone ? SecurityService.formatPhone(phone) : null,
            verificationToken,
            ipAddress,
            lastLogin: new Date(),
            cart: {
              create: {}
            }
          },
          select: {
            id: true,
            email: true,
            name: true,
            role: true,
            emailVerified: true,
            createdAt: true
          }
        });
        
        // Save password to history
        await tx.$executeRaw`
          INSERT INTO password_history (user_id, password, created_at)
          VALUES (${user.id}, ${hashedPassword}, NOW())
        `;
        
        // Store verification token
        await TokenService.storeEmailVerificationToken(user.id, verificationToken);
        
        // Log audit
        await tx.auditLog.create({
          data: {
            userId: user.id,
            action: 'REGISTER',
            ipAddress,
            userAgent,
            metadata: {
              userAgent,
              ipAddress
            }
          }
        });
        
        return user;
      });
      
      // Send verification email (async - don't block response)
      EmailService.sendVerificationEmail(validatedEmail, verificationToken, result.name)
        .catch(error => {
          logger.error('Failed to send verification email:', error);
        });
      
      // Send welcome email
      EmailService.sendWelcomeEmail(validatedEmail, result.name)
        .catch(error => {
          logger.error('Failed to send welcome email:', error);
        });
      
      // Generate tokens
      const deviceInfo = { ipAddress, userAgent };
      const tokens = TokenService.generateTokens(result, deviceInfo);
      
      // Create session
      const session = await TokenService.createSession(
        result.id,
        tokens.refreshToken,
        deviceInfo
      );
      
      // Set secure cookies
      this.setAuthCookies(res, tokens, session.sessionToken);
      
      logger.info(`User registered successfully: ${result.id}`, {
        userId: result.id,
        email: result.email,
        duration: Date.now() - transactionStart
      });
      
      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email to verify your account.',
        data: {
          user: result,
          accessToken: tokens.accessToken,
          expiresIn: parseInt(process.env.JWT_ACCESS_EXPIRY || '900'),
          requiresEmailVerification: true
        }
      });
      
    } catch (error) {
      logger.error('Registration failed:', {
        error: error.message,
        email: req.body.email,
        ipAddress,
        duration: Date.now() - transactionStart
      });
      
      next(error);
    }
  }
  
  /**
   * Login user
   */
  static async login(req, res, next) {
    const transactionStart = Date.now();
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    try {
      const { email, password, rememberMe, twoFactorCode } = req.body;
      
      // Validate email
      const validatedEmail = SecurityService.validateEmail(email);
      if (!validatedEmail) {
        await SecurityService.trackLoginAttempt(email, ipAddress, userAgent, false);
        throw new UnauthorizedError('Invalid email or password');
      }
      
      // Check if account is locked
      const isLocked = await SecurityService.isAccountLocked(validatedEmail);
      if (isLocked) {
        await SecurityService.trackLoginAttempt(validatedEmail, ipAddress, userAgent, false);
        throw new ForbiddenError(
          'Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.'
        );
      }
      
      // Find user with sensitive data
      const user = await prisma.user.findUnique({
        where: { email: validatedEmail },
        include: {
          cart: true
        }
      });
      
      // User not found or inactive
      if (!user || !user.isActive || user.status !== 'ACTIVE') {
        await SecurityService.trackLoginAttempt(validatedEmail, ipAddress, userAgent, false);
        throw new UnauthorizedError('Invalid email or password');
      }
      
      // Check if email is verified
      if (!user.emailVerified) {
        // Allow login but restrict certain actions
        logger.warn(`Login attempt with unverified email: ${validatedEmail}`);
      }
      
      // Verify password
      const isValidPassword = await SecurityService.verifyPassword(password, user.password);
      
      if (!isValidPassword) {
        await SecurityService.trackLoginAttempt(validatedEmail, ipAddress, userAgent, false);
        
        const failedCount = await SecurityService.getFailedAttemptsCount(validatedEmail);
        const remainingAttempts = SecurityService.MAX_LOGIN_ATTEMPTS - failedCount - 1;
        
        if (remainingAttempts > 0) {
          throw new UnauthorizedError(
            `Invalid email or password. ${remainingAttempts} attempt(s) remaining.`
          );
        } else {
          // Send account locked email
          EmailService.sendAccountLockedEmail(validatedEmail, user.name, new Date(Date.now() + SecurityService.LOCKOUT_DURATION))
            .catch(error => logger.error('Failed to send account locked email:', error));
          
          throw new ForbiddenError(
            'Account locked due to too many failed attempts. Please try again in 15 minutes or reset your password.'
          );
        }
      }
      
      // Check if 2FA is enabled
      if (user.twoFactorEnabled && !twoFactorCode) {
        // Generate and send 2FA code
        const twoFactorToken = TokenService.generateSecureToken(6);
        // Store token temporarily (in practice, use Redis or database)
        
        // Send 2FA email
        await EmailService.sendTwoFactorEmail(validatedEmail, user.name, twoFactorToken);
        
        return res.json({
          success: true,
          requiresTwoFactor: true,
          message: 'Two-factor authentication required. Check your email for the verification code.',
          twoFactorToken: twoFactorToken // In production, don't send token in response
        });
      }
      
      // Verify 2FA code if enabled
      if (user.twoFactorEnabled && twoFactorCode) {
        const isValid2FA = SecurityService.verifyTwoFactorToken(user.twoFactorSecret, twoFactorCode);
        if (!isValid2FA) {
          await SecurityService.trackLoginAttempt(validatedEmail, ipAddress, userAgent, false);
          throw new UnauthorizedError('Invalid two-factor authentication code');
        }
      }
      
      // Successful login
      await SecurityService.trackLoginAttempt(validatedEmail, ipAddress, userAgent, true);
      
      // Clear failed attempts
      await SecurityService.clearFailedAttempts(validatedEmail);
      
      // Update user last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLogin: new Date() }
      });
      
      // Generate tokens
      const deviceInfo = {
        ipAddress,
        userAgent,
        deviceInfo: {
          browser: this.parseUserAgent(userAgent)
        }
      };
      
      const tokens = TokenService.generateTokens(user, deviceInfo);
      
      // Create or update session
      let session = await prisma.session.findFirst({
        where: {
          userId: user.id,
          ipAddress,
          userAgent,
          isActive: true
        }
      });
      
      if (session && rememberMe) {
        // Update existing session
        session = await prisma.session.update({
          where: { id: session.id },
          data: {
            refreshToken: TokenService.hashToken(tokens.refreshToken),
            expiresAt: new Date(tokens.refreshTokenExpiry),
            lastUsedAt: new Date()
          }
        });
      } else {
        // Create new session
        session = await TokenService.createSession(
          user.id,
          tokens.refreshToken,
          deviceInfo
        );
      }
      
      // Set secure cookies
      this.setAuthCookies(res, tokens, session.sessionToken, rememberMe);
      
      // Log audit
      await SecurityService.logAudit(user.id, 'LOGIN', {
        ipAddress,
        userAgent,
        metadata: { twoFactorUsed: user.twoFactorEnabled }
      });
      
      // Remove sensitive data from response
      const { password: _, verificationToken, resetToken, twoFactorSecret, ...userWithoutSensitive } = user;
      
      logger.info(`User logged in successfully: ${user.id}`, {
        userId: user.id,
        email: user.email,
        twoFactor: user.twoFactorEnabled,
        duration: Date.now() - transactionStart
      });
      
      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: userWithoutSensitive,
          accessToken: tokens.accessToken,
          expiresIn: parseInt(process.env.JWT_ACCESS_EXPIRY || '900'),
          requiresEmailVerification: !user.emailVerified
        }
      });
      
    } catch (error) {
      logger.error('Login failed:', {
        error: error.message,
        email: req.body.email,
        ipAddress,
        duration: Date.now() - transactionStart
      });
      
      next(error);
    }
  }
  
  /**
   * Logout user
   */
  static async logout(req, res, next) {
    try {
      const userId = req.user?.id;
      const sessionToken = req.cookies.sessionToken;
      const refreshToken = req.cookies.refreshToken;
      const ipAddress = req.ip;
      const userAgent = req.headers['user-agent'];
      
      // Clear cookies
      this.clearAuthCookies(res);
      
      // Invalidate session if exists
      if (sessionToken) {
        await TokenService.invalidateSession(sessionToken);
      }
      
      // Invalidate refresh token
      if (refreshToken) {
        try {
          const hashedToken = TokenService.hashToken(refreshToken);
          await prisma.session.updateMany({
            where: {
              refreshToken: hashedToken,
              isActive: true
            },
            data: { isActive: false }
          });
        } catch (error) {
          // Token might already be invalid
        }
      }
      
      // Log audit
      if (userId) {
        await SecurityService.logAudit(userId, 'LOGOUT', {
          ipAddress,
          userAgent
        });
        
        logger.info(`User logged out: ${userId}`);
      }
      
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Refresh access token
   */
  static async refreshToken(req, res, next) {
    try {
      const refreshToken = req.cookies.refreshToken;
      const sessionToken = req.cookies.sessionToken;
      
      if (!refreshToken || !sessionToken) {
        throw new UnauthorizedError('Refresh token required');
      }
      
      // Validate session
      const session = await TokenService.validateSession(sessionToken, refreshToken);
      if (!session) {
        this.clearAuthCookies(res);
        throw new UnauthorizedError('Invalid or expired session');
      }
      
      // Generate new tokens
      const deviceInfo = {
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        deviceInfo: session.deviceInfo
      };
      
      const newTokens = TokenService.generateTokens(session.user, deviceInfo);
      
      // Update session with new refresh token
      await prisma.session.update({
        where: { id: session.id },
        data: {
          refreshToken: TokenService.hashToken(newTokens.refreshToken),
          expiresAt: new Date(newTokens.refreshTokenExpiry),
          lastUsedAt: new Date()
        }
      });
      
      // Set new cookies
      this.setAuthCookies(res, newTokens, session.sessionToken);
      
      res.json({
        success: true,
        message: 'Token refreshed',
        data: {
          accessToken: newTokens.accessToken,
          expiresIn: parseInt(process.env.JWT_ACCESS_EXPIRY || '900')
        }
      });
      
    } catch (error) {
      this.clearAuthCookies(res);
      next(error);
    }
  }
  
  /**
   * Verify email address
   */
  static async verifyEmail(req, res, next) {
    try {
      const { token } = req.params;
      
      if (!token) {
        throw new BadRequestError('Verification token required');
      }
      
      // Validate token
      const user = await TokenService.validateEmailVerificationToken(token);
      
      if (!user) {
        throw new BadRequestError('Invalid or expired verification token');
      }
      
      // Update user as verified
      await prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerified: true,
          verificationToken: null
        }
      });
      
      // Log audit
      await SecurityService.logAudit(user.id, 'EMAIL_VERIFIED', {
        metadata: { verificationMethod: 'email' }
      });
      
      logger.info(`Email verified for user: ${user.id}`);
      
      res.json({
        success: true,
        message: 'Email verified successfully. Your account is now fully activated.'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Resend verification email
   */
  static async resendVerification(req, res, next) {
    try {
      const { email } = req.body;
      
      if (!email) {
        throw new BadRequestError('Email is required');
      }
      
      const user = await prisma.user.findUnique({
        where: { email }
      });
      
      if (!user) {
        // Don't reveal if user exists
        return res.json({
          success: true,
          message: 'If an account exists with this email, a verification link has been sent.'
        });
      }
      
      if (user.emailVerified) {
        throw new BadRequestError('Email is already verified');
      }
      
      // Check rate limit
      const recentAttempts = await prisma.auditLog.count({
        where: {
          userId: user.id,
          action: 'EMAIL_VERIFICATION_RESEND',
          createdAt: {
            gte: new Date(Date.now() - 3600000) // Last hour
          }
        }
      });
      
      if (recentAttempts >= 3) {
        throw new ForbiddenError('Too many verification requests. Please try again later.');
      }
      
      // Generate new verification token
      const verificationToken = TokenService.generateSecureToken();
      
      // Store token
      await TokenService.storeEmailVerificationToken(user.id, verificationToken);
      
      // Update user's verification token
      await prisma.user.update({
        where: { id: user.id },
        data: { verificationToken }
      });
      
      // Send verification email
      await EmailService.sendVerificationEmail(email, verificationToken, user.name);
      
      // Log audit
      await SecurityService.logAudit(user.id, 'EMAIL_VERIFICATION_RESEND', {
        metadata: { attempts: recentAttempts + 1 }
      });
      
      logger.info(`Verification email resent to: ${email}`);
      
      res.json({
        success: true,
        message: 'Verification email sent. Please check your inbox.'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Forgot password - send reset email
   */
  static async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;
      const ipAddress = req.ip;
      
      if (!email) {
        throw new BadRequestError('Email is required');
      }
      
      // Rate limiting
      const recentRequests = await prisma.passwordResetToken.count({
        where: {
          user: { email },
          createdAt: {
            gte: new Date(Date.now() - 3600000) // Last hour
          },
          used: false
        }
      });
      
      if (recentRequests >= 3) {
        throw new ForbiddenError('Too many password reset requests. Please try again later.');
      }
      
      const user = await prisma.user.findUnique({
        where: { 
          email,
          isActive: true,
          status: 'ACTIVE'
        }
      });
      
      if (!user) {
        // Don't reveal if user exists
        return res.json({
          success: true,
          message: 'If an account exists with this email, a password reset link has been sent.'
        });
      }
      
      // Generate reset token
      const resetToken = TokenService.generateSecureToken();
      
      // Store token
      await TokenService.storePasswordResetToken(user.id, resetToken, ipAddress);
      
      // Send reset email
      await EmailService.sendPasswordResetEmail(email, resetToken, user.name);
      
      // Log audit
      await SecurityService.logAudit(user.id, 'PASSWORD_RESET_REQUESTED', {
        ipAddress,
        metadata: { requests: recentRequests + 1 }
      });
      
      logger.info(`Password reset email sent to: ${email}`);
      
      res.json({
        success: true,
        message: 'Password reset email sent. Please check your inbox.'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Reset password with token
   */
  static async resetPassword(req, res, next) {
    try {
      const { token } = req.params;
      const { password, confirmPassword } = req.body;
      const ipAddress = req.ip;
      
      if (!token) {
        throw new BadRequestError('Reset token required');
      }
      
      if (password !== confirmPassword) {
        throw new BadRequestError('Passwords do not match');
      }
      
      // Validate password strength
      const passwordValidation = SecurityService.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        throw new ValidationError('Password validation failed', passwordValidation.errors);
      }
      
      // Validate token
      const user = await TokenService.validatePasswordResetToken(token);
      
      if (!user) {
        throw new BadRequestError('Invalid or expired reset token');
      }
      
      // Check if password was previously used
      const isPasswordInHistory = await SecurityService.isPasswordInHistory(user.id, password);
      if (isPasswordInHistory) {
        throw new BadRequestError('You cannot reuse a previous password');
      }
      
      // Hash new password
      const hashedPassword = await SecurityService.hashPassword(password);
      
      // Update user password
      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          resetToken: null,
          resetTokenExpiry: null,
          lastPasswordChange: new Date()
        }
      });
      
      // Save to password history
      await SecurityService.savePasswordToHistory(user.id, password);
      
      // Invalidate all user sessions
      await TokenService.invalidateAllUserSessions(user.id);
      
      // Send password changed email
      await EmailService.sendPasswordChangedEmail(user.email, user.name);
      
      // Clear any existing auth cookies
      this.clearAuthCookies(res);
      
      // Log audit
      await SecurityService.logAudit(user.id, 'PASSWORD_RESET', {
        ipAddress,
        metadata: { method: 'email_token' }
      });
      
      logger.info(`Password reset for user: ${user.id}`);
      
      res.json({
        success: true,
        message: 'Password reset successful. Please log in with your new password.'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Change password (authenticated)
   */
  static async changePassword(req, res, next) {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword, confirmPassword } = req.body;
      const ipAddress = req.ip;
      
      if (newPassword !== confirmPassword) {
        throw new BadRequestError('New passwords do not match');
      }
      
      // Validate new password strength
      const passwordValidation = SecurityService.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new ValidationError('Password validation failed', passwordValidation.errors);
      }
      
      // Get user with current password
      const user = await prisma.user.findUnique({
        where: { id: userId }
      });
      
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Verify current password
      const isValidPassword = await SecurityService.verifyPassword(currentPassword, user.password);
      
      if (!isValidPassword) {
        throw new UnauthorizedError('Current password is incorrect');
      }
      
      // Check if new password is same as current
      const isSamePassword = await SecurityService.verifyPassword(newPassword, user.password);
      
      if (isSamePassword) {
        throw new BadRequestError('New password must be different from current password');
      }
      
      // Check if password was previously used
      const isPasswordInHistory = await SecurityService.isPasswordInHistory(userId, newPassword);
      if (isPasswordInHistory) {
        throw new BadRequestError('You cannot reuse a previous password');
      }
      
      // Hash new password
      const hashedPassword = await SecurityService.hashPassword(newPassword);
      
      // Update password
      await prisma.user.update({
        where: { id: userId },
        data: {
          password: hashedPassword,
          lastPasswordChange: new Date()
        }
      });
      
      // Save to password history
      await SecurityService.savePasswordToHistory(userId, newPassword);
      
      // Invalidate all sessions except current
      const sessionToken = req.cookies.sessionToken;
      await TokenService.invalidateAllUserSessions(userId, sessionToken);
      
      // Send password changed email
      await EmailService.sendPasswordChangedEmail(user.email, user.name);
      
      // Log audit
      await SecurityService.logAudit(userId, 'PASSWORD_CHANGED', {
        ipAddress,
        metadata: { method: 'authenticated' }
      });
      
      logger.info(`Password changed for user: ${userId}`);
      
      res.json({
        success: true,
        message: 'Password changed successfully'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Get current user profile
   */
  static async getProfile(req, res, next) {
    try {
      const userId = req.user.id;
      
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          name: true,
          phone: true,
          avatar: true,
          role: true,
          emailVerified: true,
          twoFactorEnabled: true,
          status: true,
          isActive: true,
          lastLogin: true,
          lastPasswordChange: true,
          createdAt: true,
          updatedAt: true,
          addresses: {
            where: { isDefault: true },
            take: 1
          }
        }
      });
      
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Get security health
      const securityHealth = await SecurityService.checkSecurityHealth(userId);
      
      res.json({
        success: true,
        data: {
          ...user,
          securityHealth
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Update user profile
   */
  static async updateProfile(req, res, next) {
    try {
      const userId = req.user.id;
      const { name, phone, avatar } = req.body;
      const ipAddress = req.ip;
      
      const updateData = {};
      
      if (name) {
        updateData.name = SecurityService.sanitizeInput(name);
      }
      
      if (phone) {
        if (!SecurityService.validatePhone(phone)) {
          throw new BadRequestError('Please provide a valid Kenyan phone number');
        }
        updateData.phone = SecurityService.formatPhone(phone);
      }
      
      if (avatar) {
        updateData.avatar = avatar;
      }
      
      const oldUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { name: true, phone: true, avatar: true }
      });
      
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
        select: {
          id: true,
          email: true,
          name: true,
          phone: true,
          avatar: true,
          role: true,
          updatedAt: true
        }
      });
      
      // Log audit
      const changes = {};
      if (name && oldUser.name !== name) changes.name = { old: oldUser.name, new: name };
      if (phone && oldUser.phone !== phone) changes.phone = { old: oldUser.phone, new: phone };
      if (avatar && oldUser.avatar !== avatar) changes.avatar = { old: oldUser.avatar, new: avatar };
      
      if (Object.keys(changes).length > 0) {
        await SecurityService.logAudit(userId, 'PROFILE_UPDATED', {
          ipAddress,
          oldData: oldUser,
          newData: updatedUser,
          metadata: { changes }
        });
      }
      
      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: updatedUser
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Setup Two-Factor Authentication
   */
  static async setupTwoFactor(req, res, next) {
    try {
      const userId = req.user.id;
      const ipAddress = req.ip;
      
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, twoFactorEnabled: true }
      });
      
      if (user.twoFactorEnabled) {
        throw new BadRequestError('Two-factor authentication is already enabled');
      }
      
      // Generate 2FA secret
      const { secret, otpauthUrl } = SecurityService.generateTwoFactorSecret(user.email);
      
      // Generate QR code
      const qrCodeDataUrl = await SecurityService.generateQRCodeDataURL(otpauthUrl);
      
      // Generate backup codes
      const { codes, hashedCodes } = SecurityService.generateBackupCodes();
      
      // Store secret and backup codes temporarily
      // In production, use Redis or encrypted session
      const tempData = {
        secret,
        backupCodes: hashedCodes,
        expiresAt: Date.now() + 600000 // 10 minutes
      };
      
      // Store in database temporarily (or use Redis)
      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorSecret: secret,
          // Store backup codes encrypted
        }
      });
      
      // Log audit
      await SecurityService.logAudit(userId, '2FA_SETUP_INITIATED', {
        ipAddress,
        metadata: { method: 'TOTP' }
      });
      
      res.json({
        success: true,
        message: 'Two-factor authentication setup initiated',
        data: {
          secret,
          qrCodeDataUrl,
          backupCodes: codes, // Send only once!
          instructions: 'Scan the QR code with your authenticator app and enter the code below to verify.'
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Verify and enable Two-Factor Authentication
   */
  static async verifyTwoFactor(req, res, next) {
    try {
      const userId = req.user.id;
      const { code } = req.body;
      const ipAddress = req.ip;
      
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { twoFactorSecret: true, twoFactorEnabled: true }
      });
      
      if (user.twoFactorEnabled) {
        throw new BadRequestError('Two-factor authentication is already enabled');
      }
      
      if (!user.twoFactorSecret) {
        throw new BadRequestError('Two-factor setup not initiated');
      }
      
      // Verify code
      const isValid = SecurityService.verifyTwoFactorToken(user.twoFactorSecret, code);
      
      if (!isValid) {
        throw new BadRequestError('Invalid verification code');
      }
      
      // Enable 2FA
      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: true
        }
      });
      
      // Log audit
      await SecurityService.logAudit(userId, '2FA_ENABLED', {
        ipAddress,
        metadata: { method: 'TOTP' }
      });
      
      logger.info(`Two-factor authentication enabled for user: ${userId}`);
      
      res.json({
        success: true,
        message: 'Two-factor authentication enabled successfully',
        data: {
          enabled: true,
          backupCodesWarning: 'Make sure to save your backup codes in a secure place.'
        }
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Disable Two-Factor Authentication
   */
  static async disableTwoFactor(req, res, next) {
    try {
      const userId = req.user.id;
      const { password } = req.body;
      const ipAddress = req.ip;
      
      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId }
      });
      
      const isValidPassword = await SecurityService.verifyPassword(password, user.password);
      if (!isValidPassword) {
        throw new UnauthorizedError('Password is incorrect');
      }
      
      // Disable 2FA
      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null
        }
      });
      
      // Log audit
      await SecurityService.logAudit(userId, '2FA_DISABLED', {
        ipAddress,
        metadata: { method: 'password_verified' }
      });
      
      logger.info(`Two-factor authentication disabled for user: ${userId}`);
      
      res.json({
        success: true,
        message: 'Two-factor authentication disabled successfully'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Get active sessions
   */
  static async getSessions(req, res, next) {
    try {
      const userId = req.user.id;
      
      const sessions = await prisma.session.findMany({
        where: {
          userId,
          isActive: true,
          expiresAt: { gt: new Date() }
        },
        orderBy: {
          lastUsedAt: 'desc'
        },
        select: {
          id: true,
          ipAddress: true,
          userAgent: true,
          deviceInfo: true,
          lastUsedAt: true,
          createdAt: true,
          expiresAt: true
        }
      });
      
      // Parse device info for better display
      const formattedSessions = sessions.map(session => ({
        ...session,
        device: this.parseDeviceInfo(session.userAgent, session.deviceInfo),
        isCurrent: session.id === req.cookies.sessionId
      }));
      
      res.json({
        success: true,
        data: formattedSessions
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Revoke session
   */
  static async revokeSession(req, res, next) {
    try {
      const userId = req.user.id;
      const { sessionId } = req.params;
      const ipAddress = req.ip;
      
      // Verify session belongs to user
      const session = await prisma.session.findFirst({
        where: {
          id: sessionId,
          userId,
          isActive: true
        }
      });
      
      if (!session) {
        throw new NotFoundError('Session not found');
      }
      
      // Revoke session
      await TokenService.invalidateSession(session.sessionToken);
      
      // Log audit
      await SecurityService.logAudit(userId, 'SESSION_REVOKED', {
        ipAddress,
        metadata: { sessionId }
      });
      
      res.json({
        success: true,
        message: 'Session revoked successfully'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Revoke all sessions except current
   */
  static async revokeAllSessions(req, res, next) {
    try {
      const userId = req.user.id;
      const currentSessionToken = req.cookies.sessionToken;
      const ipAddress = req.ip;
      
      await TokenService.invalidateAllUserSessions(userId, currentSessionToken);
      
      // Log audit
      await SecurityService.logAudit(userId, 'ALL_SESSIONS_REVOKED', {
        ipAddress,
        metadata: { exceptCurrent: true }
      });
      
      logger.info(`All sessions revoked for user: ${userId}`);
      
      res.json({
        success: true,
        message: 'All other sessions have been revoked'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Delete account
   */
  static async deleteAccount(req, res, next) {
    try {
      const userId = req.user.id;
      const { password, confirmText } = req.body;
      const ipAddress = req.ip;
      
      if (confirmText !== 'DELETE MY ACCOUNT') {
        throw new BadRequestError('Please type "DELETE MY ACCOUNT" to confirm');
      }
      
      // Verify password
      const user = await prisma.user.findUnique({
        where: { id: userId }
      });
      
      const isValidPassword = await SecurityService.verifyPassword(password, user.password);
      if (!isValidPassword) {
        throw new UnauthorizedError('Password is incorrect');
      }
      
      // Check for active orders
      const activeOrders = await prisma.order.count({
        where: {
          userId,
          status: { not: 'DELIVERED' }
        }
      });
      
      if (activeOrders > 0) {
        throw new BadRequestError('Cannot delete account with active orders. Please contact support.');
      }
      
      // Soft delete - anonymize user data
      await prisma.$transaction(async (tx) => {
        // Anonymize user
        await tx.user.update({
          where: { id: userId },
          data: {
            email: `deleted_${Date.now()}_${user.email}`,
            name: 'Deleted User',
            phone: null,
            avatar: null,
            isActive: false,
            status: 'DEACTIVATED'
          }
        });
        
        // Invalidate all sessions
        await tx.session.updateMany({
          where: { userId },
          data: { isActive: false }
        });
        
        // Log audit
        await tx.auditLog.create({
          data: {
            userId,
            action: 'ACCOUNT_DELETED',
            ipAddress,
            oldData: { email: user.email, name: user.name },
            metadata: { method: 'user_requested' }
          }
        });
      });
      
      // Clear cookies
      this.clearAuthCookies(res);
      
      // Send goodbye email
      EmailService.sendEmail(
        user.email,
        'Account Deleted - Electronics Shop',
        this.getAccountDeletedEmail(user.name)
      ).catch(error => logger.error('Failed to send account deleted email:', error));
      
      logger.info(`Account deleted: ${userId}`);
      
      res.json({
        success: true,
        message: 'Account deleted successfully'
      });
      
    } catch (error) {
      next(error);
    }
  }
  
  /**
   * Helper: Set authentication cookies
   */
  static setAuthCookies(res, tokens, sessionToken, rememberMe = false) {
    const isProduction = process.env.NODE_ENV === 'production';
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      path: '/'
    };
    
    // Access token cookie (short-lived)
    res.cookie('accessToken', tokens.accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });
    
    // Refresh token cookie
    res.cookie('refreshToken', tokens.refreshToken, {
      ...cookieOptions,
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000, // 30 days or 7 days
      path: '/api/auth/refresh'
    });
    
    // Session token cookie
    res.cookie('sessionToken', sessionToken, {
      ...cookieOptions,
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000,
    });
    
    // CSRF protection token (for forms)
    const csrfToken = TokenService.generateSecureToken();
    res.cookie('XSRF-TOKEN', csrfToken, {
      secure: isProduction,
      sameSite: 'strict'
    });
  }
  
  /**
   * Helper: Clear authentication cookies
   */
  static clearAuthCookies(res) {
    const cookies = ['accessToken', 'refreshToken', 'sessionToken', 'XSRF-TOKEN'];
    
    cookies.forEach(cookieName => {
      res.clearCookie(cookieName, {
        path: '/',
        httpOnly: cookieName !== 'XSRF-TOKEN'
      });
      
      if (cookieName === 'refreshToken') {
        res.clearCookie(cookieName, {
          path: '/api/auth/refresh',
          httpOnly: true
        });
      }
    });
  }
  
  /**
   * Helper: Parse user agent
   */
  static parseUserAgent(userAgent) {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('Opera')) return 'Opera';
    
    return 'Other';
  }
  
  /**
   * Helper: Parse device info
   */
  static parseDeviceInfo(userAgent, deviceInfo) {
    const device = {
      browser: this.parseUserAgent(userAgent),
      os: 'Unknown',
      device: 'Desktop'
    };
    
    if (userAgent.includes('Windows')) device.os = 'Windows';
    else if (userAgent.includes('Mac')) device.os = 'macOS';
    else if (userAgent.includes('Linux')) device.os = 'Linux';
    else if (userAgent.includes('Android')) device.os = 'Android';
    else if (userAgent.includes('iOS') || userAgent.includes('iPhone')) device.os = 'iOS';
    
    if (userAgent.includes('Mobile')) device.device = 'Mobile';
    else if (userAgent.includes('Tablet')) device.device = 'Tablet';
    
    return device;
  }
  
  /**
   * Helper: Get account deleted email template
   */
  static getAccountDeletedEmail(name) {
    return `
      <h2>Account Deleted</h2>
      <p>Dear ${name},</p>
      <p>Your account has been successfully deleted from Electronics Shop.</p>
      <p>We're sorry to see you go. If this was a mistake or you change your mind, 
      you can create a new account anytime.</p>
      <p>Thank you for being part of our community.</p>
      <p>Best regards,<br>The Electronics Shop Team</p>
    `;
  }
}

// Export all methods
export const register = AuthController.register;
export const login = AuthController.login;
export const logout = AuthController.logout;
export const refreshToken = AuthController.refreshToken;
export const verifyEmail = AuthController.verifyEmail;
export const resendVerification = AuthController.resendVerification;
export const forgotPassword = AuthController.forgotPassword;
export const resetPassword = AuthController.resetPassword;
export const changePassword = AuthController.changePassword;
export const getProfile = AuthController.getProfile;
export const updateProfile = AuthController.updateProfile;
export const setupTwoFactor = AuthController.setupTwoFactor;
export const verifyTwoFactor = AuthController.verifyTwoFactor;
export const disableTwoFactor = AuthController.disableTwoFactor;
export const getSessions = AuthController.getSessions;
export const revokeSession = AuthController.revokeSession;
export const revokeAllSessions = AuthController.revokeAllSessions;
export const deleteAccount = AuthController.deleteAccount;