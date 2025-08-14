import { Injectable, Logger } from '@nestjs/common';

export interface RetryConfig {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  jitterMs?: number;
  retryableErrors?: (error: Error) => boolean;
  onRetry?: (attempt: number, error: Error) => void;
}

export interface CircuitBreakerConfig {
  failureThreshold: number;
  timeout: number;
  resetTimeout: number;
  monitoringPeriod: number;
}

export enum CircuitBreakerState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

@Injectable()
export class RetryService {
  private readonly logger = new Logger(RetryService.name);
  private readonly circuitBreakers = new Map<string, {
    state: CircuitBreakerState;
    failures: number;
    lastFailureTime: number;
    successCount: number;
  }>();

  // Default retry configuration
  private readonly defaultRetryConfig: RetryConfig = {
    maxAttempts: 3,
    baseDelayMs: 1000,
    maxDelayMs: 30000,
    backoffMultiplier: 2,
    jitterMs: 100,
    retryableErrors: (error: Error) => {
      // Retry on network errors, timeouts, and 5xx server errors
      return error.message.includes('ECONNRESET') ||
             error.message.includes('ENOTFOUND') ||
             error.message.includes('timeout') ||
             error.message.includes('503') ||
             error.message.includes('502') ||
             error.message.includes('504');
    },
  };

  async executeWithRetry<T>(
    operation: () => Promise<T>,
    config?: Partial<RetryConfig>
  ): Promise<T> {
    const finalConfig = { ...this.defaultRetryConfig, ...config };
    let lastError: Error;

    for (let attempt = 1; attempt <= finalConfig.maxAttempts; attempt++) {
      try {
        const result = await operation();
        
        if (attempt > 1) {
          this.logger.log(`Operation succeeded on attempt ${attempt}`);
        }
        
        return result;
      } catch (error) {
        lastError = error as Error;
        
        // Check if error is retryable
        if (!finalConfig.retryableErrors!(lastError)) {
          this.logger.warn(`Non-retryable error: ${lastError.message}`);
          throw lastError;
        }

        // Don't retry on last attempt
        if (attempt === finalConfig.maxAttempts) {
          break;
        }

        // Calculate delay with exponential backoff and jitter
        const delay = this.calculateDelay(attempt, finalConfig);
        
        // Call retry callback if provided
        if (finalConfig.onRetry) {
          finalConfig.onRetry(attempt, lastError);
        }

        this.logger.warn(
          `Attempt ${attempt}/${finalConfig.maxAttempts} failed: ${lastError.message}. ` +
          `Retrying in ${delay}ms...`
        );

        await this.sleep(delay);
      }
    }

    this.logger.error(
      `Operation failed after ${finalConfig.maxAttempts} attempts: ${lastError.message}`
    );
    throw lastError;
  }

  async executeWithCircuitBreaker<T>(
    operation: () => Promise<T>,
    circuitName: string,
    config?: Partial<CircuitBreakerConfig>
  ): Promise<T> {
    const circuitConfig: CircuitBreakerConfig = {
      failureThreshold: 5,
      timeout: 60000,
      resetTimeout: 300000, // 5 minutes
      monitoringPeriod: 10000, // 10 seconds
      ...config,
    };

    const circuit = this.getOrCreateCircuit(circuitName);
    
    // Check circuit state
    if (circuit.state === CircuitBreakerState.OPEN) {
      const timeSinceLastFailure = Date.now() - circuit.lastFailureTime;
      
      if (timeSinceLastFailure < circuitConfig.resetTimeout) {
        throw new Error(`Circuit breaker ${circuitName} is OPEN. Failing fast.`);
      } else {
        // Transition to half-open
        circuit.state = CircuitBreakerState.HALF_OPEN;
        circuit.successCount = 0;
        this.logger.warn(`Circuit breaker ${circuitName} transitioning to HALF_OPEN`);
      }
    }

    try {
      const result = await Promise.race([
        operation(),
        this.timeoutPromise(circuitConfig.timeout),
      ]);

      // Success - handle circuit breaker state
      if (circuit.state === CircuitBreakerState.HALF_OPEN) {
        circuit.successCount++;
        if (circuit.successCount >= 3) { // Require 3 successes to close
          circuit.state = CircuitBreakerState.CLOSED;
          circuit.failures = 0;
          this.logger.log(`Circuit breaker ${circuitName} is now CLOSED`);
        }
      } else {
        circuit.failures = Math.max(0, circuit.failures - 1); // Gradual recovery
      }

      return result;
    } catch (error) {
      // Failure - increment failure count
      circuit.failures++;
      circuit.lastFailureTime = Date.now();

      if (circuit.failures >= circuitConfig.failureThreshold) {
        circuit.state = CircuitBreakerState.OPEN;
        this.logger.error(
          `Circuit breaker ${circuitName} is now OPEN after ${circuit.failures} failures`
        );
      }

      throw error;
    }
  }

  async executeWithBulkhead<T>(
    operation: () => Promise<T>,
    maxConcurrentOperations: number,
    operationName: string
  ): Promise<T> {
    // Simple bulkhead implementation using a semaphore-like pattern
    const semaphoreKey = `bulkhead_${operationName}`;
    
    if (!this.semaphores.has(semaphoreKey)) {
      this.semaphores.set(semaphoreKey, {
        current: 0,
        max: maxConcurrentOperations,
        queue: [],
      });
    }

    const semaphore = this.semaphores.get(semaphoreKey)!;

    return new Promise((resolve, reject) => {
      const executeOperation = async () => {
        semaphore.current++;
        
        try {
          const result = await operation();
          resolve(result);
        } catch (error) {
          reject(error);
        } finally {
          semaphore.current--;
          
          // Process next item in queue
          if (semaphore.queue.length > 0) {
            const nextOperation = semaphore.queue.shift()!;
            setImmediate(nextOperation);
          }
        }
      };

      if (semaphore.current < semaphore.max) {
        executeOperation();
      } else {
        // Queue the operation
        semaphore.queue.push(executeOperation);
        
        this.logger.debug(
          `Operation queued for ${operationName}. Queue length: ${semaphore.queue.length}`
        );
      }
    });
  }

  private readonly semaphores = new Map<string, {
    current: number;
    max: number;
    queue: (() => void)[];
  }>();

  private calculateDelay(attempt: number, config: RetryConfig): number {
    const exponentialDelay = Math.min(
      config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt - 1),
      config.maxDelayMs
    );

    // Add jitter to prevent thundering herd
    const jitter = config.jitterMs ? Math.random() * config.jitterMs : 0;
    
    return Math.floor(exponentialDelay + jitter);
  }

  private getOrCreateCircuit(name: string) {
    if (!this.circuitBreakers.has(name)) {
      this.circuitBreakers.set(name, {
        state: CircuitBreakerState.CLOSED,
        failures: 0,
        lastFailureTime: 0,
        successCount: 0,
      });
    }
    return this.circuitBreakers.get(name)!;
  }

  private async timeoutPromise<T>(timeoutMs: number): Promise<T> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Health monitoring
  getCircuitBreakerStatus(): Record<string, any> {
    const status: Record<string, any> = {};
    
    for (const [name, circuit] of this.circuitBreakers.entries()) {
      status[name] = {
        state: circuit.state,
        failures: circuit.failures,
        lastFailureTime: circuit.lastFailureTime,
        successCount: circuit.successCount,
      };
    }
    
    return status;
  }

  getBulkheadStatus(): Record<string, any> {
    const status: Record<string, any> = {};
    
    for (const [name, semaphore] of this.semaphores.entries()) {
      status[name] = {
        current: semaphore.current,
        max: semaphore.max,
        queueLength: semaphore.queue.length,
        utilization: (semaphore.current / semaphore.max) * 100,
      };
    }
    
    return status;
  }
}