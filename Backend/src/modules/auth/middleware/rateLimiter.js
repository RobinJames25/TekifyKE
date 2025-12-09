import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';
import logger from '../utils/logger.js';

// Create Redis client if available
let redisClient = null;

if (process.env.REDIS_URL) {
    try {
        redisClient = new Redis(process.env.REDIS_URL, {
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
            maxRetriesPerRequest: 3
        });

        redisClient.on('error', (error) => {
            logger.error('Redis connection error:', error);
        });

        redisClient.on('connect', () => {
            logger.info('✅ Redis connected for rate limiting');
        });
    } catch (error) {
        logger.error('Failed to connect to Redis:', error);
    }
}

const createRateLimiter = (options = {}) => {
    const store = redisClient
        ? new RedisStore({
            client: redisClient,
            prefix: 'rl:auth:',
            // @ts-ignore - sendCommand exists in ioredis
            sendCommand: (...args) => redisClient.call(...args)
        })
        : undefined;

    return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // Limit each IP to 100 requests per window
        message: {
            success: false,
            message: 'Too many requests from this IP, please try again later',
            retryAfter: '15 minutes'
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: false,
        keyGenerator: (req) => {
            // Use IP + user ID if available
            const ip = req.ip;
            const userId = req.user?.id || 'anonymous';
            return `${ip}:${userId}`;
        },
        skip: (req) => {
            // Skip rate limiting for admin users in development
            if (process.env.NODE_ENV === 'development' && req.user?.role === 'ADMIN') {
                return true;
            }
            return false;
        },
        ...options,
        store
    });
};

// Authentication-specific rate limiters
export const authRateLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per 15 minutes
    message: {
        success: false,
        message: 'Too many login attempts, please try again later',
        retryAfter: '15 minutes'
    },
    skipSuccessfulRequests: true
});

export const registerRateLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 registrations per hour per IP
    message: {
        success: false,
        message: 'Too many registration attempts from this IP',
        retryAfter: '1 hour'
    }
});

export const passwordResetRateLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 password reset requests per hour
    message: {
        success: false,
        message: 'Too many password reset attempts, please try again later',
        retryAfter: '1 hour'
    }
});

export const verifyEmailRateLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 verification attempts per hour
    message: {
        success: false,
        message: 'Too many verification attempts, please try again later',
        retryAfter: '1 hour'
    }
});

export const twoFactorRateLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 2FA attempts per 15 minutes
    message: {
        success: false,
        message: 'Too many two-factor authentication attempts',
        retryAfter: '15 minutes'
    }
});

// Global API rate limiter
export const apiRateLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 1000, // 1000 requests per 15 minutes per IP
    message: {
        success: false,
        message: 'Too many API requests, please try again later',
        retryAfter: '15 minutes'
    }
});