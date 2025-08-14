import { Injectable, Logger } from '@nestjs/common';
import { RetryService } from './retry.service';
import { ResilientCacheService } from './resilient-cache.service';

export interface DegradationConfig {
  enableFallback: boolean;
  fallbackData?: any;
  timeoutMs?: number;
  retryConfig?: {
    maxAttempts: number;
    backoffMs: number;
  };
  cacheFallback?: {
    enabled: boolean;
    ttl: number;
    staleWhileRevalidate: boolean;
  };
}

export interface ServiceHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: number;
  errorRate: number;
  responseTime: number;
}

@Injectable()
export class GracefulDegradationService {
  private readonly logger = new Logger(GracefulDegradationService.name);
  private readonly serviceHealth = new Map<string, ServiceHealth>();
  private readonly fallbackData = new Map<string, any>();
  private readonly performanceMetrics = new Map<string, {
    calls: number;
    errors: number;
    totalResponseTime: number;
    lastUpdate: number;
  }>();

  constructor(
    private readonly retryService: RetryService,
    private readonly cacheService: ResilientCacheService,
  ) {
    // Start health monitoring
    setInterval(() => this.updateHealthMetrics(), 30000); // Every 30 seconds
  }

  async executeWithDegradation<T>(
    serviceName: string,
    primaryOperation: () => Promise<T>,
    config: DegradationConfig
  ): Promise<T> {
    const startTime = Date.now();
    const cacheKey = `degradation:${serviceName}:${this.hashOperation(primaryOperation.toString())}`;

    try {
      // Check if service is healthy enough to attempt primary operation
      const serviceHealth = this.getServiceHealth(serviceName);
      
      if (serviceHealth.status === 'unhealthy' && config.enableFallback) {
        this.logger.warn(`Service ${serviceName} is unhealthy, using fallback immediately`);
        return await this.executeFallback<T>(serviceName, cacheKey, config);
      }

      // Attempt primary operation with timeout and retries
      const result = await this.executeWithTimeout(
        () => this.executeWithRetryIfConfigured(primaryOperation, config),
        config.timeoutMs || 10000,
        serviceName
      );

      // Record success
      this.recordMetric(serviceName, Date.now() - startTime, false);
      
      // Cache successful result for future fallback use
      if (config.cacheFallback?.enabled) {
        await this.cacheService.set(cacheKey, result, {
          ttl: config.cacheFallback.ttl || 300,
          namespace: 'fallback',
        });
      }

      return result;

    } catch (error) {
      this.logger.error(`Primary operation failed for ${serviceName}:`, error);
      this.recordMetric(serviceName, Date.now() - startTime, true);

      // Attempt graceful degradation
      if (config.enableFallback) {
        return await this.executeFallback<T>(serviceName, cacheKey, config);
      }

      throw error;
    }
  }

  async executeWithFallbackChain<T>(
    serviceName: string,
    operations: Array<{
      name: string;
      operation: () => Promise<T>;
      priority: number;
    }>,
    config: DegradationConfig
  ): Promise<T> {
    // Sort operations by priority (higher number = higher priority)
    const sortedOperations = operations.sort((a, b) => b.priority - a.priority);
    
    let lastError: Error | null = null;

    for (const { name, operation, priority } of sortedOperations) {
      try {
        this.logger.debug(`Attempting ${name} (priority: ${priority}) for ${serviceName}`);
        
        const result = await this.executeWithDegradation(
          `${serviceName}:${name}`,
          operation,
          {
            ...config,
            enableFallback: false, // Don't cascade fallbacks in chain
          }
        );

        this.logger.log(`Successfully executed ${name} for ${serviceName}`);
        return result;

      } catch (error) {
        lastError = error as Error;
        this.logger.warn(`${name} failed for ${serviceName}, trying next fallback:`, error);
        continue;
      }
    }

    // All operations failed
    this.logger.error(`All fallback operations failed for ${serviceName}`);
    throw lastError || new Error('All fallback operations failed');
  }

  async executeWithPartialDegradation<T>(
    serviceName: string,
    operations: Map<string, () => Promise<any>>,
    combineResults: (results: Map<string, any>) => T,
    config: {
      minSuccessThreshold: number; // Minimum percentage of operations that must succeed
      timeout: number;
    }
  ): Promise<T> {
    const results = new Map<string, any>();
    const errors = new Map<string, Error>();
    const promises = new Map<string, Promise<any>>();

    // Start all operations concurrently
    for (const [operationName, operation] of operations.entries()) {
      promises.set(
        operationName,
        this.executeWithTimeout(operation, config.timeout, `${serviceName}:${operationName}`)
          .then(result => {
            results.set(operationName, result);
            return result;
          })
          .catch(error => {
            errors.set(operationName, error);
            this.logger.warn(`Partial operation ${operationName} failed:`, error);
            throw error;
          })
      );
    }

    // Wait for all operations to complete or fail
    const settledResults = await Promise.allSettled(Array.from(promises.values()));
    
    const successCount = settledResults.filter(result => result.status === 'fulfilled').length;
    const successRate = (successCount / operations.size) * 100;

    if (successRate >= config.minSuccessThreshold) {
      this.logger.log(
        `Partial degradation successful for ${serviceName}: ${successCount}/${operations.size} operations succeeded (${successRate.toFixed(1)}%)`
      );
      
      return combineResults(results);
    } else {
      this.logger.error(
        `Partial degradation failed for ${serviceName}: Only ${successCount}/${operations.size} operations succeeded (${successRate.toFixed(1)}%), below threshold of ${config.minSuccessThreshold}%`
      );
      
      throw new Error(
        `Insufficient successful operations: ${successRate.toFixed(1)}% < ${config.minSuccessThreshold}%`
      );
    }
  }

  registerFallbackData(serviceName: string, data: any): void {
    this.fallbackData.set(serviceName, data);
    this.logger.debug(`Registered fallback data for ${serviceName}`);
  }

  private async executeFallback<T>(
    serviceName: string,
    cacheKey: string,
    config: DegradationConfig
  ): Promise<T> {
    // Try cached fallback data first
    if (config.cacheFallback?.enabled) {
      const cachedData = await this.cacheService.get<T>(cacheKey, {
        namespace: 'fallback',
      });

      if (cachedData !== null) {
        this.logger.info(`Using cached fallback data for ${serviceName}`);
        return cachedData;
      }
    }

    // Try registered fallback data
    if (this.fallbackData.has(serviceName)) {
      const fallbackData = this.fallbackData.get(serviceName);
      this.logger.info(`Using registered fallback data for ${serviceName}`);
      return fallbackData as T;
    }

    // Use provided fallback data
    if (config.fallbackData !== undefined) {
      this.logger.info(`Using configured fallback data for ${serviceName}`);
      return config.fallbackData as T;
    }

    throw new Error(`No fallback data available for ${serviceName}`);
  }

  private async executeWithRetryIfConfigured<T>(
    operation: () => Promise<T>,
    config: DegradationConfig
  ): Promise<T> {
    if (config.retryConfig) {
      return await this.retryService.executeWithRetry(
        operation,
        {
          maxAttempts: config.retryConfig.maxAttempts,
          baseDelayMs: config.retryConfig.backoffMs,
        }
      );
    }

    return await operation();
  }

  private async executeWithTimeout<T>(
    operation: () => Promise<T>,
    timeoutMs: number,
    operationName: string
  ): Promise<T> {
    return Promise.race([
      operation(),
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Operation ${operationName} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  }

  private recordMetric(serviceName: string, responseTime: number, error: boolean): void {
    if (!this.performanceMetrics.has(serviceName)) {
      this.performanceMetrics.set(serviceName, {
        calls: 0,
        errors: 0,
        totalResponseTime: 0,
        lastUpdate: Date.now(),
      });
    }

    const metrics = this.performanceMetrics.get(serviceName)!;
    metrics.calls++;
    metrics.totalResponseTime += responseTime;
    metrics.lastUpdate = Date.now();

    if (error) {
      metrics.errors++;
    }
  }

  private getServiceHealth(serviceName: string): ServiceHealth {
    const metrics = this.performanceMetrics.get(serviceName);
    
    if (!metrics) {
      return {
        name: serviceName,
        status: 'healthy',
        lastCheck: Date.now(),
        errorRate: 0,
        responseTime: 0,
      };
    }

    const errorRate = (metrics.errors / metrics.calls) * 100;
    const avgResponseTime = metrics.totalResponseTime / metrics.calls;
    
    let status: 'healthy' | 'degraded' | 'unhealthy';
    
    if (errorRate > 50 || avgResponseTime > 10000) {
      status = 'unhealthy';
    } else if (errorRate > 20 || avgResponseTime > 5000) {
      status = 'degraded';
    } else {
      status = 'healthy';
    }

    const health: ServiceHealth = {
      name: serviceName,
      status,
      lastCheck: Date.now(),
      errorRate,
      responseTime: avgResponseTime,
    };

    this.serviceHealth.set(serviceName, health);
    return health;
  }

  private updateHealthMetrics(): void {
    for (const [serviceName, health] of this.serviceHealth.entries()) {
      const timeSinceLastCheck = Date.now() - health.lastCheck;
      
      // Mark services as unhealthy if they haven't been checked recently
      if (timeSinceLastCheck > 300000) { // 5 minutes
        health.status = 'unhealthy';
        this.logger.warn(`Service ${serviceName} marked as unhealthy due to inactivity`);
      }
    }
  }

  private hashOperation(operationStr: string): string {
    // Simple hash function for operation caching
    let hash = 0;
    for (let i = 0; i < operationStr.length; i++) {
      const char = operationStr.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  // Public API for monitoring and management
  getServiceHealthStatus(): Map<string, ServiceHealth> {
    return new Map(this.serviceHealth);
  }

  getPerformanceMetrics(): Map<string, any> {
    const metrics = new Map();
    
    for (const [serviceName, data] of this.performanceMetrics.entries()) {
      metrics.set(serviceName, {
        calls: data.calls,
        errors: data.errors,
        errorRate: (data.errors / data.calls) * 100,
        avgResponseTime: data.totalResponseTime / data.calls,
        lastUpdate: data.lastUpdate,
      });
    }
    
    return metrics;
  }

  async getOverallSystemHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'critical';
    services: ServiceHealth[];
    summary: {
      total: number;
      healthy: number;
      degraded: number;
      unhealthy: number;
    };
  }> {
    const services = Array.from(this.serviceHealth.values());
    const summary = {
      total: services.length,
      healthy: services.filter(s => s.status === 'healthy').length,
      degraded: services.filter(s => s.status === 'degraded').length,
      unhealthy: services.filter(s => s.status === 'unhealthy').length,
    };

    let overallStatus: 'healthy' | 'degraded' | 'critical';
    
    if (summary.unhealthy > summary.total * 0.5) {
      overallStatus = 'critical';
    } else if (summary.unhealthy > 0 || summary.degraded > summary.total * 0.3) {
      overallStatus = 'degraded';
    } else {
      overallStatus = 'healthy';
    }

    return {
      status: overallStatus,
      services,
      summary,
    };
  }
}