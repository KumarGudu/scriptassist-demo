import { 
  ExceptionFilter, 
  Catch, 
  ArgumentsHost, 
  HttpException, 
  Logger, 
  HttpStatus,
  BadRequestException,
  UnauthorizedException,
  ForbiddenException
} from '@nestjs/common';
import { Request, Response } from 'express';
import * as crypto from 'crypto';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);
  private readonly sensitiveKeys = [
    'password', 'token', 'key', 'secret', 'auth', 'credential',
    'email', 'phone', 'ssn', 'credit', 'card', 'account'
  ];

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    // Generate unique error ID for tracking
    const errorId = crypto.randomUUID();

    // Determine log level based on status code
    const logLevel = this.getLogLevel(status);
    
    // Sanitize request data before logging
    const sanitizedRequest = this.sanitizeObject({
      method: request.method,
      url: request.url,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      userId: request.user?.id,
    });

    // Log with appropriate level
    const logMessage = `[${errorId}] HTTP ${status} - ${exception.message}`;
    
    if (logLevel === 'error') {
      this.logger.error(
        logMessage,
        {
          errorId,
          status,
          request: sanitizedRequest,
          stack: exception.stack,
        }
      );
    } else if (logLevel === 'warn') {
      this.logger.warn(logMessage, {
        errorId,
        status,
        request: sanitizedRequest,
      });
    } else {
      this.logger.log(logMessage, {
        errorId,
        status,
        request: sanitizedRequest,
      });
    }

    // Create secure response based on error type and environment
    const secureResponse = this.createSecureResponse(
      exception, 
      status, 
      errorId, 
      request.url
    );

    response.status(status).json(secureResponse);
  }

  private getLogLevel(status: number): 'error' | 'warn' | 'log' {
    if (status >= 500) return 'error';
    if (status >= 400) return 'warn';
    return 'log';
  }

  private createSecureResponse(
    exception: HttpException, 
    status: number, 
    errorId: string, 
    path: string
  ) {
    const isProduction = process.env.NODE_ENV === 'production';
    const baseResponse = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path,
      errorId, // For support tracking
    };

    // Handle different error types with secure messaging
    if (exception instanceof UnauthorizedException) {
      return {
        ...baseResponse,
        message: 'Authentication required',
        error: 'Unauthorized',
      };
    }

    if (exception instanceof ForbiddenException) {
      return {
        ...baseResponse,
        message: 'Access denied',
        error: 'Forbidden',
      };
    }

    if (exception instanceof BadRequestException) {
      const response = exception.getResponse();
      return {
        ...baseResponse,
        message: 'Invalid request',
        error: 'Bad Request',
        // Only include validation details, not sensitive info
        ...(typeof response === 'object' && response !== null && 
            this.isSafeValidationError(response) ? { details: response } : {}),
      };
    }

    // For server errors (5xx), hide details in production
    if (status >= 500) {
      return {
        ...baseResponse,
        message: isProduction 
          ? 'Internal server error' 
          : this.sanitizeMessage(exception.message),
        error: 'Internal Server Error',
      };
    }

    // For client errors (4xx), provide safe message
    return {
      ...baseResponse,
      message: this.sanitizeMessage(exception.message),
      error: HttpStatus[status] || 'Client Error',
    };
  }

  private sanitizeObject(obj: any): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (this.isSensitiveKey(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeObject(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  private sanitizeMessage(message: string): string {
    // Remove potential sensitive information from error messages
    let sanitized = message;
    
    // Remove file paths
    sanitized = sanitized.replace(/\/(\w+\/)*\w+\.(js|ts|json)/g, '[FILE_PATH]');
    
    // Remove potential database connection strings
    sanitized = sanitized.replace(/postgresql:\/\/[^\s]+/g, '[DB_CONNECTION]');
    
    // Remove potential API keys or tokens
    sanitized = sanitized.replace(/[a-zA-Z0-9]{20,}/g, '[TOKEN]');
    
    // Remove IP addresses
    sanitized = sanitized.replace(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, '[IP_ADDRESS]');
    
    return sanitized;
  }

  private isSensitiveKey(key: string): boolean {
    const lowerKey = key.toLowerCase();
    return this.sensitiveKeys.some(sensitiveKey => 
      lowerKey.includes(sensitiveKey)
    );
  }

  private isSafeValidationError(response: any): boolean {
    // Check if the response contains only validation error information
    // and no sensitive data
    if (Array.isArray(response.message)) {
      return response.message.every((msg: string) => 
        typeof msg === 'string' && 
        !this.sensitiveKeys.some(key => msg.toLowerCase().includes(key))
      );
    }
    return false;
  }
} 