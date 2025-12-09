import logger from './logger.js';

export class AppError extends Error {
  constructor(message, statusCode, errors = null, isOperational = true) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errors = errors;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
    
    // Log error
    this.logError();
  }
  
  logError() {
    if (this.statusCode >= 500) {
      logger.error(this.message, {
        name: this.name,
        statusCode: this.statusCode,
        stack: this.stack,
        timestamp: this.timestamp
      });
    } else {
      logger.warn(this.message, {
        name: this.name,
        statusCode: this.statusCode,
        errors: this.errors
      });
    }
  }
  
  toJSON() {
    return {
      success: false,
      message: this.message,
      ...(this.errors && { errors: this.errors }),
      timestamp: this.timestamp,
      ...(process.env.NODE_ENV !== 'production' && { 
        stack: this.stack,
        name: this.name 
      })
    };
  }
}

export class BadRequestError extends AppError {
  constructor(message = 'Bad Request', errors = null) {
    super(message, 400, errors);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden') {
    super(message, 403);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Not Found') {
    super(message, 404);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Conflict') {
    super(message, 409);
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Validation Failed', errors = null) {
    super(message, 422, errors);
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Too Many Requests') {
    super(message, 429);
  }
}

export class DatabaseError extends AppError {
  constructor(message = 'Database Error') {
    super(message, 500);
  }
}

// Global error handler middleware
export const errorHandler = (err, req, res, next) => {
  // Set default status code
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';
  
  // Handle specific error types
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Invalid token';
  }
  
  if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Token expired';
  }
  
  if (err.name === 'SequelizeValidationError' || err.name === 'ValidationError') {
    statusCode = 422;
    message = 'Validation failed';
  }
  
  if (err.name === 'SequelizeUniqueConstraintError') {
    statusCode = 409;
    message = 'Duplicate entry';
  }
  
  // Log unexpected errors
  if (statusCode >= 500) {
    logger.error('Unexpected error:', {
      message: err.message,
      stack: err.stack,
      method: req.method,
      path: req.path,
      ip: req.ip,
      userId: req.user?.id,
      timestamp: new Date().toISOString()
    });
  }
  
  // Prepare response
  const response = {
    success: false,
    message,
    ...(err.errors && { errors: err.errors }),
    timestamp: new Date().toISOString()
  };
  
  // Add stack trace in development
  if (process.env.NODE_ENV !== 'production') {
    response.stack = err.stack;
    response.name = err.name;
  }
  
  // Don't expose internal errors in production
  if (process.env.NODE_ENV === 'production' && statusCode >= 500) {
    response.message = 'Something went wrong. Please try again later.';
  }
  
  res.status(statusCode).json(response);
};

// 404 handler
export const notFoundHandler = (req, res, next) => {
  const error = new NotFoundError(`Route ${req.originalUrl} not found`);
  next(error);
};