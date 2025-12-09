import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import validator from 'validator';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import prisma from '../../lib/prisma.js';
import logger from '../utils/logger.js';
import { BadRequestError, ForbiddenError } from '../utils/errors.js';

class SecurityService {
  static SALT_ROUNDS = 12;
  static PASSWORD_MIN_LENGTH = 8;
  static MAX_PASSWORD_HISTORY = 5;
  static MAX_LOGIN_ATTEMPTS = 5;
  static LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
  static SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  
  /**
   * Hash password with bcrypt
   */
  static async hashPassword(password) {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }
  
  /**
   * Verify password
   */
  static async verifyPassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  }
  
  /**
   * Validate password strength
   */
  static validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < this.PASSWORD_MIN_LENGTH) {
      errors.push(`Password must be at least ${this.PASSWORD_MIN_LENGTH} characters`);
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    // Check for common passwords
    const commonPasswords = [
      'password', '123456', 'qwerty', 'admin', 'welcome',
      'password123', 'letmein', 'monkey', 'dragon', 'sunshine'
    ];
    
    if (commonPasswords.includes(password.toLowerCase())) {
      errors.push('Password is too common');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
  
  /**
   * Check if password was previously used
   */
  static async isPasswordInHistory(userId, newPassword) {
    const recentPasswords = await prisma.$queryRaw`
      SELECT password 
      FROM password_history 
      WHERE user_id = ${userId} 
      ORDER BY created_at DESC 
      LIMIT ${this.MAX_PASSWORD_HISTORY}
    `;
    
    for (const record of recentPasswords) {
      const isMatch = await bcrypt.compare(newPassword, record.password);
      if (isMatch) return true;
    }
    
    return false;
  }
  
  /**
   * Save password to history
   */
  static async savePasswordToHistory(userId, password) {
    const hashedPassword = await this.hashPassword(password);
    
    await prisma.$executeRaw`
      INSERT INTO password_history (user_id, password, created_at)
      VALUES (${userId}, ${hashedPassword}, NOW())
    `;
    
    // Clean up old passwords
    await prisma.$executeRaw`
      DELETE FROM password_history 
      WHERE id IN (
        SELECT id FROM (
          SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) as rn
          FROM password_history 
          WHERE user_id = ${userId}
        ) t 
        WHERE rn > ${this.MAX_PASSWORD_HISTORY}
      )
    `;
  }
  
  /**
   * Track login attempt
   */
  static async trackLoginAttempt(email, ipAddress, userAgent, success) {
    try {
      await prisma.loginAttempt.create({
        data: {
          email,
          ipAddress,
          userAgent,
          success
        }
      });
      
      // If failed, check for suspicious activity
      if (!success) {
        await this.checkSuspiciousActivity(email, ipAddress);
      }
    } catch (error) {
      logger.error('Failed to track login attempt:', error);
    }
  }
  
  /**
   * Check if account is locked
   */
  static async isAccountLocked(email) {
    const recentFailedAttempts = await prisma.loginAttempt.count({
      where: {
        email,
        success: false,
        createdAt: {
          gte: new Date(Date.now() - this.LOCKOUT_DURATION)
        }
      }
    });
    
    return recentFailedAttempts >= this.MAX_LOGIN_ATTEMPTS;
  }
  
  /**
   * Get failed login attempts count
   */
  static async getFailedAttemptsCount(email, minutes = 15) {
    const count = await prisma.loginAttempt.count({
      where: {
        email,
        success: false,
        createdAt: {
          gte: new Date(Date.now() - minutes * 60 * 1000)
        }
      }
    });
    
    return count;
  }
  
  /**
   * Clear failed attempts
   */
  static async clearFailedAttempts(email) {
    await prisma.loginAttempt.deleteMany({
      where: { email }
    });
  }
  
  /**
   * Check for suspicious activity
   */
  static async checkSuspiciousActivity(email, ipAddress) {
    // Check for multiple failed attempts from different IPs
    const recentAttempts = await prisma.loginAttempt.findMany({
      where: {
        email,
        success: false,
        createdAt: {
          gte: new Date(Date.now() - 5 * 60 * 1000) // Last 5 minutes
        }
      },
      select: {
        ipAddress: true
      },
      distinct: ['ipAddress']
    });
    
    if (recentAttempts.length >= 3) {
      // Multiple IPs in short time - possible attack
      logger.warn(`Suspicious activity detected for email: ${email} from multiple IPs`);
      
      // You could trigger additional security measures here
      // - Send alert email to user
      // - Temporarily disable account
      // - Require additional verification
    }
  }
  
  /**
   * Sanitize user input
   */
  static sanitizeInput(input) {
    if (typeof input === 'string') {
      // Remove potential XSS
      let sanitized = validator.escape(validator.trim(input));
      // Remove extra whitespace
      sanitized = sanitized.replace(/\s+/g, ' ');
      return sanitized;
    }
    return input;
  }
  
  /**
   * Validate email
   */
  static validateEmail(email) {
    if (!validator.isEmail(email)) {
      return false;
    }
    
    // Normalize email
    const normalizedEmail = validator.normalizeEmail(email);
    if (!normalizedEmail) {
      return false;
    }
    
    // Check for disposable emails
    const disposableDomains = [
      'tempmail.com', 'guerrillamail.com', 'mailinator.com',
      '10minutemail.com', 'throwawaymail.com', 'fakeinbox.com'
    ];
    
    const domain = normalizedEmail.split('@')[1];
    if (disposableDomains.includes(domain.toLowerCase())) {
      return false;
    }
    
    return normalizedEmail;
  }
  
  /**
   * Validate phone number (Kenya)
   */
  static validatePhone(phone) {
    // Remove all non-digits
    const cleaned = phone.replace(/\D/g, '');
    
    // Kenyan phone patterns
    const patterns = [
      /^2547\d{8}$/,     // +2547XXXXXXXX
      /^07\d{8}$/,       // 07XXXXXXXX
      /^7\d{8}$/         // 7XXXXXXXX (without prefix)
    ];
    
    return patterns.some(pattern => pattern.test(cleaned));
  }
  
  /**
   * Format phone to international format
   */
  static formatPhone(phone) {
    const cleaned = phone.replace(/\D/g, '');
    
    if (cleaned.startsWith('254')) {
      return `+${cleaned}`;
    } else if (cleaned.startsWith('0')) {
      return `+254${cleaned.substring(1)}`;
    } else if (cleaned.startsWith('7')) {
      return `+254${cleaned}`;
    }
    
    return phone;
  }
  
  /**
   * Generate Two-Factor Authentication secret
   */
  static generateTwoFactorSecret(email) {
    const secret = speakeasy.generateSecret({
      name: `Electronics Shop:${email}`,
      length: 20
    });
    
    return {
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url
    };
  }
  
  /**
   * Generate QR code for 2FA
   */
  static async generateQRCodeDataURL(otpauthUrl) {
    try {
      return await qrcode.toDataURL(otpauthUrl);
    } catch (error) {
      logger.error('Failed to generate QR code:', error);
      throw new Error('Failed to generate QR code');
    }
  }
  
  /**
   * Verify Two-Factor Authentication token
   */
  static verifyTwoFactorToken(secret, token) {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1 // Allow 30 seconds before/after
    });
  }
  
  /**
   * Generate backup codes for 2FA
   */
  static generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    
    // Hash codes for storage
    const hashedCodes = codes.map(code => 
      crypto.createHash('sha256').update(code).digest('hex')
    );
    
    return { codes, hashedCodes };
  }
  
  /**
   * Verify backup code
   */
  static verifyBackupCode(backupCodes, code) {
    const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
    const index = backupCodes.indexOf(hashedCode);
    
    if (index === -1) {
      return false;
    }
    
    // Remove used code
    backupCodes.splice(index, 1);
    return true;
  }
  
  /**
   * Check for weak security indicators
   */
  static async checkSecurityHealth(userId) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        emailVerified: true,
        lastPasswordChange: true,
        twoFactorEnabled: true,
        lastLogin: true
      }
    });
    
    const warnings = [];
    
    // Check if email is verified
    if (!user.emailVerified) {
      warnings.push('Email not verified');
    }
    
    // Check password age (90 days)
    if (user.lastPasswordChange) {
      const passwordAge = Date.now() - new Date(user.lastPasswordChange).getTime();
      const ninetyDays = 90 * 24 * 60 * 60 * 1000;
      
      if (passwordAge > ninetyDays) {
        warnings.push('Password is older than 90 days');
      }
    }
    
    // Check 2FA
    if (!user.twoFactorEnabled) {
      warnings.push('Two-factor authentication not enabled');
    }
    
    // Check last login (30 days)
    if (user.lastLogin) {
      const lastLoginAge = Date.now() - new Date(user.lastLogin).getTime();
      const thirtyDays = 30 * 24 * 60 * 60 * 1000;
      
      if (lastLoginAge > thirtyDays) {
        warnings.push('Account inactive for more than 30 days');
      }
    }
    
    return {
      score: 100 - (warnings.length * 25), // Simple scoring
      warnings,
      recommendations: warnings.map(warning => ({
        issue: warning,
        action: this.getSecurityRecommendation(warning)
      }))
    };
  }
  
  static getSecurityRecommendation(issue) {
    const recommendations = {
      'Email not verified': 'Verify your email address in account settings',
      'Password is older than 90 days': 'Change your password',
      'Two-factor authentication not enabled': 'Enable 2FA in security settings',
      'Account inactive for more than 30 days': 'Consider updating security settings'
    };
    
    return recommendations[issue] || 'Review account security';
  }
  
  /**
   * Log security audit
   */
  static async logAudit(userId, action, metadata = {}) {
    try {
      await prisma.auditLog.create({
        data: {
          userId,
          action,
          entityType: metadata.entityType,
          entityId: metadata.entityId,
          oldData: metadata.oldData,
          newData: metadata.newData,
          ipAddress: metadata.ipAddress,
          userAgent: metadata.userAgent,
          metadata: metadata.metadata
        }
      });
    } catch (error) {
      logger.error('Failed to log audit:', error);
    }
  }
}

export default SecurityService;