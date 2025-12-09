import TokenService from '../services/tokenService.js';
import prisma from '../../lib/prisma.js';
import { UnauthorizedError, ForbiddenError } from '../utils/errors.js';
import logger from '../utils/logger.js';

export const authenticate = async (req, res, next) => {
  const startTime = Date.now();
  
  try {
    // Get token from Authorization header or cookie
    let token = req.headers.authorization;
    
    if (token && token.startsWith('Bearer ')) {
      token = token.substring(7);
    } else {
      token = req.cookies.accessToken;
    }
    
    if (!token) {
      throw new UnauthorizedError('Access token required');
    }
    
    // Verify token
    const decoded = TokenService.verifyAccessToken(token);
    
    // Get user with current status
    const user = await prisma.user.findUnique({
      where: { 
        id: decoded.userId,
        isActive: true
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        emailVerified: true,
        twoFactorEnabled: true,
        status: true,
        isActive: true,
        avatar: true
      }
    });
    
    if (!user) {
      throw new UnauthorizedError('User not found or deactivated');
    }
    
    // Check user status
    if (user.status !== 'ACTIVE') {
      throw new ForbiddenError(`Account is ${user.status.toLowerCase()}. Please contact support.`);
    }
    
    // Attach user to request
    req.user = user;
    
    // Add user info to response headers for logging
    res.setHeader('X-User-ID', user.id);
    res.setHeader('X-User-Role', user.role);
    
    logger.debug(`Authentication successful: ${user.id}`, {
      userId: user.id,
      email: user.email,
      role: user.role,
      duration: Date.now() - startTime
    });
    
    next();
    
  } catch (error) {
    logger.warn('Authentication failed:', {
      error: error.message,
      ip: req.ip,
      path: req.path,
      duration: Date.now() - startTime
    });
    
    // Clear invalid tokens from cookies
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
    }
    
    next(error);
  }
};

// Admin-only middleware
export const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') {
    throw new ForbiddenError('Admin access required');
  }
  next();
};

// Email verification required middleware
export const requireVerifiedEmail = (req, res, next) => {
  if (!req.user.emailVerified) {
    throw new ForbiddenError('Please verify your email address to access this resource');
  }
  next();
};

// Role-based access control
export const requireRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new ForbiddenError('Insufficient permissions');
    }
    next();
  };
};

// CSRF protection middleware
export const csrfProtection = (req, res, next) => {
  // Skip for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  // Check CSRF token
  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  const cookieToken = req.cookies['XSRF-TOKEN'];
  
  if (!csrfToken || !cookieToken || csrfToken !== cookieToken) {
    throw new ForbiddenError('Invalid CSRF token');
  }
  
  next();
};