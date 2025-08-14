import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RetryService } from './retry.service';
import Redis from 'ioredis';

export interface CacheOptions {
  ttl?: number; // Time to live in seconds
  namespace?: string;
  fallbackToMemory?: boolean;
  compression?: boolean;
  retries?: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  errors: number;
  operations: number;
  memoryFallbacks: number;
  redisConnected: boolean;
}

@Injectable()
export class ResilientCacheService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ResilientCacheService.name);
  private redis: Redis | null = null;
  private readonly fallbackCache = new Map<string, { value: any; expiresAt: number }>();
  private readonly stats: CacheStats = {
    hits: 0,
    misses: 0,
    errors: 0,
    operations: 0,
    memoryFallbacks: 0,
    redisConnected: false,
  };
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(
    private readonly configService: ConfigService,
    private readonly retryService: RetryService,
  ) {}

  async onModuleInit() {
    await this.initializeRedis();
    this.startMemoryCleanup();
  }

  async onModuleDestroy() {
    if (this.redis) {
      await this.redis.quit();
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }

  private async initializeRedis(): Promise<void> {
    try {
      const redisConfig = {
        host: this.configService.get('REDIS_HOST', 'localhost'),
        port: this.configService.get('REDIS_PORT', 6379),
        password: this.configService.get('REDIS_PASSWORD'),
        db: this.configService.get('REDIS_DB', 0),
        retryDelayOnFailover: 100,
        retryDelayMs: 1000,
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        // Connection pooling and health checks
        connectTimeout: 10000,
        commandTimeout: 5000,
        family: 4, // Use IPv4
      };

      this.redis = new Redis(redisConfig);

      // Event handlers for connection monitoring
      this.redis.on('connect', () => {
        this.logger.log('Redis connected successfully');
        this.stats.redisConnected = true;
      });

      this.redis.on('error', (error) => {
        this.logger.error('Redis connection error:', error.message);
        this.stats.redisConnected = false;
        this.stats.errors++;
      });

      this.redis.on('close', () => {
        this.logger.warn('Redis connection closed');
        this.stats.redisConnected = false;
      });

      this.redis.on('reconnecting', (time) => {
        this.logger.log(`Redis reconnecting in ${time}ms`);
      });

      // Test the connection
      await this.redis.ping();
      this.logger.log('Redis connection established and tested');
    } catch (error) {
      this.logger.error('Failed to initialize Redis:', error);
      this.redis = null;
    }
  }

  async set(key: string, value: any, options: CacheOptions = {}): Promise<boolean> {
    this.stats.operations++;
    
    const finalOptions = {
      ttl: 300, // 5 minutes default
      namespace: 'default',
      fallbackToMemory: true,
      compression: false,
      retries: 2,
      ...options,
    };

    const namespacedKey = this.createNamespacedKey(key, finalOptions.namespace!);
    const serializedValue = this.serializeValue(value, finalOptions.compression);

    // Try Redis first with retry mechanism
    if (this.redis && this.stats.redisConnected) {
      try {
        const success = await this.retryService.executeWithRetry(
          async () => {
            if (finalOptions.ttl > 0) {
              await this.redis!.setex(namespacedKey, finalOptions.ttl, serializedValue);
            } else {
              await this.redis!.set(namespacedKey, serializedValue);
            }
            return true;
          },
          {
            maxAttempts: finalOptions.retries + 1,
            baseDelayMs: 500,
            onRetry: (attempt, error) => {
              this.logger.warn(`Cache SET retry ${attempt} for key ${key}: ${error.message}`);
            },
          }
        );

        if (success && finalOptions.fallbackToMemory) {
          // Also store in memory for redundancy
          this.setMemoryCache(namespacedKey, value, finalOptions.ttl);
        }

        return success;
      } catch (error) {
        this.logger.error(`Failed to set Redis cache for key ${key}:`, error);
        this.stats.errors++;
      }
    }

    // Fallback to memory cache
    if (finalOptions.fallbackToMemory) {
      this.stats.memoryFallbacks++;
      return this.setMemoryCache(namespacedKey, value, finalOptions.ttl);
    }

    return false;
  }

  async get<T>(key: string, options: CacheOptions = {}): Promise<T | null> {
    this.stats.operations++;
    
    const finalOptions = {
      namespace: 'default',
      fallbackToMemory: true,
      compression: false,
      retries: 2,
      ...options,
    };

    const namespacedKey = this.createNamespacedKey(key, finalOptions.namespace!);

    // Try Redis first with circuit breaker
    if (this.redis && this.stats.redisConnected) {
      try {
        const result = await this.retryService.executeWithCircuitBreaker(
          async () => {
            const value = await this.redis!.get(namespacedKey);
            return value ? this.deserializeValue(value, finalOptions.compression) : null;
          },
          `cache_get_${finalOptions.namespace}`,
          {
            failureThreshold: 5,
            timeout: 3000,
            resetTimeout: 60000,
          }
        );

        if (result !== null) {
          this.stats.hits++;
          return result as T;
        }
      } catch (error) {
        this.logger.error(`Failed to get Redis cache for key ${key}:`, error);
        this.stats.errors++;
      }
    }

    // Fallback to memory cache
    if (finalOptions.fallbackToMemory) {
      const memoryResult = this.getMemoryCache<T>(namespacedKey);
      if (memoryResult !== null) {
        this.stats.hits++;
        this.stats.memoryFallbacks++;
        return memoryResult;
      }
    }

    this.stats.misses++;
    return null;
  }

  async delete(key: string, options: CacheOptions = {}): Promise<boolean> {
    this.stats.operations++;
    
    const finalOptions = {
      namespace: 'default',
      fallbackToMemory: true,
      ...options,
    };

    const namespacedKey = this.createNamespacedKey(key, finalOptions.namespace!);
    let redisDeleted = false;

    // Delete from Redis
    if (this.redis && this.stats.redisConnected) {
      try {
        const result = await this.redis.del(namespacedKey);
        redisDeleted = result > 0;
      } catch (error) {
        this.logger.error(`Failed to delete Redis cache for key ${key}:`, error);
        this.stats.errors++;
      }
    }

    // Delete from memory cache
    const memoryDeleted = this.deleteMemoryCache(namespacedKey);

    return redisDeleted || memoryDeleted;
  }

  async mget<T>(keys: string[], options: CacheOptions = {}): Promise<Map<string, T>> {
    this.stats.operations++;
    
    const finalOptions = {
      namespace: 'default',
      fallbackToMemory: true,
      compression: false,
      ...options,
    };

    const namespacedKeys = keys.map(key => 
      this.createNamespacedKey(key, finalOptions.namespace!)
    );
    const results = new Map<string, T>();

    // Try Redis bulk get
    if (this.redis && this.stats.redisConnected) {
      try {
        const values = await this.redis.mget(...namespacedKeys);
        
        for (let i = 0; i < keys.length; i++) {
          if (values[i] !== null) {
            const deserialized = this.deserializeValue(values[i]!, finalOptions.compression);
            results.set(keys[i], deserialized as T);
            this.stats.hits++;
          }
        }
      } catch (error) {
        this.logger.error('Failed to execute Redis MGET:', error);
        this.stats.errors++;
      }
    }

    // Fallback to memory for missing keys
    if (finalOptions.fallbackToMemory) {
      for (let i = 0; i < keys.length; i++) {
        if (!results.has(keys[i])) {
          const memoryResult = this.getMemoryCache<T>(namespacedKeys[i]);
          if (memoryResult !== null) {
            results.set(keys[i], memoryResult);
            this.stats.hits++;
            this.stats.memoryFallbacks++;
          } else {
            this.stats.misses++;
          }
        }
      }
    }

    return results;
  }

  async mset(entries: Map<string, any>, options: CacheOptions = {}): Promise<boolean> {
    this.stats.operations++;
    
    const finalOptions = {
      ttl: 300,
      namespace: 'default',
      fallbackToMemory: true,
      compression: false,
      ...options,
    };

    const pipeline = this.redis?.pipeline();
    const namespacedEntries = new Map<string, any>();

    // Prepare namespaced entries
    for (const [key, value] of entries.entries()) {
      const namespacedKey = this.createNamespacedKey(key, finalOptions.namespace!);
      const serializedValue = this.serializeValue(value, finalOptions.compression);
      namespacedEntries.set(namespacedKey, value);

      if (pipeline) {
        if (finalOptions.ttl > 0) {
          pipeline.setex(namespacedKey, finalOptions.ttl, serializedValue);
        } else {
          pipeline.set(namespacedKey, serializedValue);
        }
      }
    }

    // Execute Redis pipeline
    if (pipeline && this.stats.redisConnected) {
      try {
        await pipeline.exec();
      } catch (error) {
        this.logger.error('Failed to execute Redis MSET:', error);
        this.stats.errors++;
      }
    }

    // Fallback to memory
    if (finalOptions.fallbackToMemory) {
      for (const [namespacedKey, value] of namespacedEntries.entries()) {
        this.setMemoryCache(namespacedKey, value, finalOptions.ttl);
      }
      this.stats.memoryFallbacks++;
    }

    return true;
  }

  async clear(namespace?: string): Promise<boolean> {
    const pattern = namespace 
      ? this.createNamespacedKey('*', namespace)
      : '*';

    // Clear Redis
    if (this.redis && this.stats.redisConnected) {
      try {
        const keys = await this.redis.keys(pattern);
        if (keys.length > 0) {
          await this.redis.del(...keys);
        }
      } catch (error) {
        this.logger.error('Failed to clear Redis cache:', error);
        this.stats.errors++;
      }
    }

    // Clear memory cache
    if (namespace) {
      const prefix = `${namespace}:`;
      for (const key of this.fallbackCache.keys()) {
        if (key.startsWith(prefix)) {
          this.fallbackCache.delete(key);
        }
      }
    } else {
      this.fallbackCache.clear();
    }

    return true;
  }

  // Memory cache operations
  private setMemoryCache(key: string, value: any, ttl: number): boolean {
    const expiresAt = ttl > 0 ? Date.now() + (ttl * 1000) : 0;
    this.fallbackCache.set(key, { value, expiresAt });
    return true;
  }

  private getMemoryCache<T>(key: string): T | null {
    const item = this.fallbackCache.get(key);
    
    if (!item) {
      return null;
    }

    if (item.expiresAt > 0 && item.expiresAt < Date.now()) {
      this.fallbackCache.delete(key);
      return null;
    }

    return item.value as T;
  }

  private deleteMemoryCache(key: string): boolean {
    return this.fallbackCache.delete(key);
  }

  private createNamespacedKey(key: string, namespace: string): string {
    return `${namespace}:${key}`;
  }

  private serializeValue(value: any, compression: boolean): string {
    const serialized = JSON.stringify(value);
    
    if (compression && serialized.length > 1024) {
      // In production, implement actual compression (zlib, etc.)
      return `compressed:${serialized}`;
    }
    
    return serialized;
  }

  private deserializeValue(value: string, compression: boolean): any {
    if (compression && value.startsWith('compressed:')) {
      // In production, implement actual decompression
      return JSON.parse(value.substring(11));
    }
    
    return JSON.parse(value);
  }

  private startMemoryCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      let cleanedCount = 0;

      for (const [key, item] of this.fallbackCache.entries()) {
        if (item.expiresAt > 0 && item.expiresAt < now) {
          this.fallbackCache.delete(key);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        this.logger.debug(`Cleaned up ${cleanedCount} expired memory cache entries`);
      }
    }, 60000); // Run every minute
  }

  // Health and monitoring
  getStats(): CacheStats & { memorySize: number } {
    return {
      ...this.stats,
      memorySize: this.fallbackCache.size,
    };
  }

  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    redis: boolean;
    memory: boolean;
    details: any;
  }> {
    const redisHealthy = this.redis && this.stats.redisConnected;
    const memoryHealthy = this.fallbackCache.size < 10000; // Arbitrary threshold

    let status: 'healthy' | 'degraded' | 'unhealthy';
    
    if (redisHealthy && memoryHealthy) {
      status = 'healthy';
    } else if (redisHealthy || memoryHealthy) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }

    return {
      status,
      redis: !!redisHealthy,
      memory: memoryHealthy,
      details: {
        redisConnected: this.stats.redisConnected,
        memorySize: this.fallbackCache.size,
        stats: this.stats,
      },
    };
  }
}