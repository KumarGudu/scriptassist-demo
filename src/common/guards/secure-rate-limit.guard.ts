import { 
  Injectable, 
  CanActivate, 
  ExecutionContext, 
  HttpException, 
  HttpStatus, 
  Logger 
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import * as crypto from 'crypto';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipIf?: (request: any) => boolean;
  keyGenerator?: (request: any) => string;
  message?: string;
}

const RATE_LIMIT_KEY = 'rate_limit_config';

@Injectable()
export class SecureRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(SecureRateLimitGuard.name);
  private readonly requestCounts = new Map<string, { count: number; resetTime: number }>();
  private readonly suspiciousIPs = new Set<string>();
  private lastCleanup = Date.now();
  private readonly cleanupInterval = 5 * 60 * 1000; // 5 minutes

  constructor(private readonly reflector: Reflector) {
    // Periodic cleanup to prevent memory leaks
    setInterval(() => this.cleanupExpiredEntries(), this.cleanupInterval);
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Get rate limit configuration from decorator or use defaults
    const config = this.getRateLimitConfig(context);
    
    if (!config) {
      return true; // No rate limiting configured
    }

    // Skip if condition is met
    if (config.skipIf && config.skipIf(request)) {
      return true;
    }

    const key = this.generateSecureKey(request, config);
    const now = Date.now();
    
    // Clean up expired entries periodically
    if (now - this.lastCleanup > this.cleanupInterval) {
      this.cleanupExpiredEntries();
      this.lastCleanup = now;
    }

    const record = this.requestCounts.get(key);
    const windowStart = now - config.windowMs;

    if (!record || record.resetTime <= windowStart) {
      // New window or expired record
      this.requestCounts.set(key, {
        count: 1,
        resetTime: now + config.windowMs,
      });
      
      this.setRateLimitHeaders(response, config, 1, now + config.windowMs);
      return true;
    }

    // Update existing record
    record.count += 1;

    // Set rate limit headers
    this.setRateLimitHeaders(response, config, record.count, record.resetTime);

    if (record.count > config.maxRequests) {
      // Track suspicious behavior
      const ip = this.getClientIP(request);
      this.handleRateLimit(ip, key, record.count, config);
      
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: config.message || 'Too many requests',
          retryAfter: Math.ceil((record.resetTime - now) / 1000),
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  private getRateLimitConfig(context: ExecutionContext): RateLimitConfig | null {
    return this.reflector.getAllAndOverride<RateLimitConfig>(RATE_LIMIT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
  }

  private generateSecureKey(request: any, config: RateLimitConfig): string {
    if (config.keyGenerator) {
      return this.hashKey(config.keyGenerator(request));
    }

    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'] || '';
    const userId = request.user?.id || '';
    
    // Create composite key for better security
    const keyData = `${ip}:${userAgent}:${userId}:${request.route?.path || request.url}`;
    
    return this.hashKey(keyData);
  }

  private hashKey(key: string): string {
    return crypto.createHash('sha256').update(key).digest('hex');
  }

  private getClientIP(request: any): string {
    // Handle various proxy configurations securely
    const xForwardedFor = request.headers['x-forwarded-for'];
    const xRealIP = request.headers['x-real-ip'];
    const cfConnectingIP = request.headers['cf-connecting-ip'];
    
    if (xForwardedFor) {
      // Take the first IP (client IP) from the chain
      return xForwardedFor.split(',')[0].trim();
    }
    
    if (xRealIP) {
      return xRealIP.trim();
    }
    
    if (cfConnectingIP) {
      return cfConnectingIP.trim();
    }
    
    return request.ip || request.connection?.remoteAddress || 'unknown';
  }

  private setRateLimitHeaders(
    response: any,
    config: RateLimitConfig,
    currentCount: number,
    resetTime: number,
  ): void {
    const remaining = Math.max(0, config.maxRequests - currentCount);
    const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);

    response.setHeader('X-RateLimit-Limit', config.maxRequests);
    response.setHeader('X-RateLimit-Remaining', remaining);
    response.setHeader('X-RateLimit-Reset', Math.ceil(resetTime / 1000));
    
    if (remaining === 0) {
      response.setHeader('Retry-After', retryAfter);
    }
  }

  private handleRateLimit(
    ip: string,
    key: string,
    count: number,
    config: RateLimitConfig,
  ): void {
    // Log security event
    this.logger.warn(
      `Rate limit exceeded: ${count}/${config.maxRequests} requests from IP ${ip}`
    );

    // Track suspicious IPs that consistently exceed limits
    if (count > config.maxRequests * 2) {
      this.suspiciousIPs.add(ip);
      this.logger.error(
        `Suspicious activity detected from IP ${ip}: ${count} requests in window`
      );
      
      // In production, implement additional security measures:
      // - Temporary IP blocking
      // - CAPTCHA challenges
      // - Notification to security team
    }
  }

  private cleanupExpiredEntries(): void {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, record] of this.requestCounts.entries()) {
      if (record.resetTime <= now) {
        this.requestCounts.delete(key);
        cleanedCount++;
      }
    }

    // Clean up suspicious IPs periodically (after 1 hour)
    const oneHour = 60 * 60 * 1000;
    if (this.suspiciousIPs.size > 0) {
      // In production, implement proper tracking with timestamps
      // For now, clear periodically
      if (cleanedCount > 0) {
        this.suspiciousIPs.clear();
      }
    }

    if (cleanedCount > 0) {
      this.logger.debug(`Cleaned up ${cleanedCount} expired rate limit entries`);
    }
  }

  // Method to check if IP is suspicious (for additional security measures)
  isSuspiciousIP(ip: string): boolean {
    return this.suspiciousIPs.has(ip);
  }

  // Method to manually add suspicious IP
  addSuspiciousIP(ip: string): void {
    this.suspiciousIPs.add(ip);
    this.logger.warn(`Manually marked IP as suspicious: ${ip}`);
  }

  // Method to get current rate limit status (for monitoring)
  getRateLimitStatus(request: any): { count: number; remaining: number; resetTime: number } | null {
    // This would need the same key generation logic
    // Implementation depends on requirements
    return null;
  }
}

// Secure Rate Limit Decorator
export const SecureRateLimit = (config: RateLimitConfig) => {
  return (target: any, propertyName?: string, descriptor?: PropertyDescriptor) => {
    if (descriptor) {
      // Method decorator
      Reflector.createDecorator<RateLimitConfig>()(config)(target, propertyName, descriptor);
    } else {
      // Class decorator
      Reflector.createDecorator<RateLimitConfig>()(config)(target);
    }
  };
};

// Predefined rate limit configurations
export const RateLimitPresets = {
  // Strict limits for auth endpoints
  AUTH: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    message: 'Too many authentication attempts. Please try again later.',
  },
  
  // Standard API limits
  API: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
    message: 'API rate limit exceeded. Please slow down your requests.',
  },
  
  // Generous limits for general use
  GENERAL: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 1000,
    message: 'Rate limit exceeded. Please try again in a minute.',
  },
  
  // Strict limits for sensitive operations
  SENSITIVE: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxRequests: 3,
    message: 'Too many attempts for sensitive operation. Please wait before trying again.',
  },
} as const;