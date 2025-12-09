import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import ms from 'ms';
import prisma from '../../lib/prisma.js';
import logger from '../utils/logger.js';
import { UnauthorizedError, ForbiddenError } from '../utils/errors.js';

class TokenService {
  static ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_SECRET;
  static REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET;
  static ACCESS_TOKEN_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '15m';
  static REFRESH_TOKEN_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';
  
  /**
   * Generate JWT tokens
   */
  static generateTokens(user, deviceInfo = {}) {
    const accessTokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      tokenType: 'access'
    };
    
    const refreshTokenPayload = {
      userId: user.id,
      tokenType: 'refresh'
    };
    
    const accessToken = jwt.sign(
      accessTokenPayload,
      this.ACCESS_TOKEN_SECRET,
      {
        expiresIn: this.ACCESS_TOKEN_EXPIRY,
        issuer: 'electronics-ecommerce',
        audience: 'web-client',
        jwtid: crypto.randomBytes(16).toString('hex')
      }
    );
    
    const refreshToken = jwt.sign(
      refreshTokenPayload,
      this.REFRESH_TOKEN_SECRET,
      {
        expiresIn: this.REFRESH_TOKEN_EXPIRY,
        issuer: 'electronics-ecommerce',
        audience: 'web-client',
        jwtid: crypto.randomBytes(16).toString('hex')
      }
    );
    
    return {
      accessToken,
      refreshToken,
      accessTokenExpiry: Date.now() + ms(this.ACCESS_TOKEN_EXPIRY),
      refreshTokenExpiry: Date.now() + ms(this.REFRESH_TOKEN_EXPIRY)
    };
  }
  
  /**
   * Verify access token
   */
  static verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, this.ACCESS_TOKEN_SECRET, {
        issuer: 'electronics-ecommerce',
        audience: 'web-client'
      });
      
      if (decoded.tokenType !== 'access') {
        throw new UnauthorizedError('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Access token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedError('Invalid access token');
      }
      throw error;
    }
  }
  
  /**
   * Verify refresh token
   */
  static verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, this.REFRESH_TOKEN_SECRET, {
        issuer: 'electronics-ecommerce',
        audience: 'web-client'
      });
      
      if (decoded.tokenType !== 'refresh') {
        throw new UnauthorizedError('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError('Refresh token expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedError('Invalid refresh token');
      }
      throw error;
    }
  }
  
  /**
   * Generate secure random token for email/password reset
   */
  static generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
  
  /**
   * Hash token for storage
   */
  static hashToken(token) {
    return crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
  }
  
  /**
   * Create and store session
   */
  static async createSession(userId, refreshToken, deviceInfo) {
    const hashedRefreshToken = this.hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + ms(this.REFRESH_TOKEN_EXPIRY));
    
    const session = await prisma.session.create({
      data: {
        userId,
        sessionToken: crypto.randomBytes(32).toString('hex'),
        refreshToken: hashedRefreshToken,
        ipAddress: deviceInfo.ipAddress,
        userAgent: deviceInfo.userAgent,
        deviceInfo: deviceInfo.deviceInfo || {},
        expiresAt,
        lastUsedAt: new Date()
      }
    });
    
    return session;
  }
  
  /**
   * Validate session
   */
  static async validateSession(sessionToken, refreshToken) {
    const session = await prisma.session.findFirst({
      where: {
        sessionToken,
        isActive: true,
        expiresAt: { gt: new Date() }
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            role: true,
            status: true,
            isActive: true
          }
        }
      }
    });
    
    if (!session) {
      return null;
    }
    
    // Verify refresh token matches
    const hashedToken = this.hashToken(refreshToken);
    if (session.refreshToken !== hashedToken) {
      await this.invalidateSession(sessionToken);
      return null;
    }
    
    // Check user status
    if (!session.user.isActive || session.user.status !== 'ACTIVE') {
      await this.invalidateSession(sessionToken);
      return null;
    }
    
    // Update last used
    await prisma.session.update({
      where: { id: session.id },
      data: { lastUsedAt: new Date() }
    });
    
    return session;
  }
  
  /**
   * Invalidate session
   */
  static async invalidateSession(sessionToken) {
    try {
      await prisma.session.update({
        where: { sessionToken },
        data: { isActive: false }
      });
    } catch (error) {
      logger.warn(`Failed to invalidate session: ${error.message}`);
    }
  }
  
  /**
   * Invalidate all user sessions
   */
  static async invalidateAllUserSessions(userId, excludeSessionToken = null) {
    const where = {
      userId,
      isActive: true
    };
    
    if (excludeSessionToken) {
      where.sessionToken = { not: excludeSessionToken };
    }
    
    await prisma.session.updateMany({
      where,
      data: { isActive: false }
    });
  }
  
  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions() {
    const result = await prisma.session.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { isActive: false }
        ]
      }
    });
    
    logger.info(`Cleaned up ${result.count} expired sessions`);
    return result.count;
  }
  
  /**
   * Store password reset token
   */
  static async storePasswordResetToken(userId, token, ipAddress = null) {
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour
    
    // Invalidate previous tokens
    await prisma.passwordResetToken.updateMany({
      where: { userId, used: false },
      data: { used: true }
    });
    
    return prisma.passwordResetToken.create({
      data: {
        userId,
        token: this.hashToken(token),
        expiresAt,
        ipAddress
      }
    });
  }
  
  /**
   * Validate password reset token
   */
  static async validatePasswordResetToken(token) {
    const hashedToken = this.hashToken(token);
    
    const resetToken = await prisma.passwordResetToken.findFirst({
      where: {
        token: hashedToken,
        used: false,
        expiresAt: { gt: new Date() }
      },
      include: {
        user: true
      }
    });
    
    if (!resetToken) {
      return null;
    }
    
    // Mark as used
    await prisma.passwordResetToken.update({
      where: { id: resetToken.id },
      data: { used: true }
    });
    
    return resetToken.user;
  }
  
  /**
   * Store email verification token
   */
  static async storeEmailVerificationToken(userId, token) {
    const expiresAt = new Date(Date.now() + 86400000); // 24 hours
    
    // Invalidate previous tokens
    await prisma.emailVerificationToken.updateMany({
      where: { userId, used: false },
      data: { used: true }
    });
    
    return prisma.emailVerificationToken.create({
      data: {
        userId,
        token: this.hashToken(token),
        expiresAt
      }
    });
  }
  
  /**
   * Validate email verification token
   */
  static async validateEmailVerificationToken(token) {
    const hashedToken = this.hashToken(token);
    
    const verificationToken = await prisma.emailVerificationToken.findFirst({
      where: {
        token: hashedToken,
        used: false,
        expiresAt: { gt: new Date() }
      },
      include: {
        user: true
      }
    });
    
    if (!verificationToken) {
      return null;
    }
    
    // Mark as used
    await prisma.emailVerificationToken.update({
      where: { id: verificationToken.id },
      data: { used: true }
    });
    
    return verificationToken.user;
  }
}

export default TokenService;