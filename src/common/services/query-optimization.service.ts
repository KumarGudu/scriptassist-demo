import { Injectable, Logger } from '@nestjs/common';
import { DataSource } from 'typeorm';

export interface QueryPerformanceMetrics {
  query: string;
  executionTime: number;
  rowsAffected?: number;
  parameters?: any[];
  timestamp: Date;
}

export interface QueryOptimizationOptions {
  enableLogging?: boolean;
  slowQueryThreshold?: number;
  trackParameters?: boolean;
}

@Injectable()
export class QueryOptimizationService {
  private readonly logger = new Logger(QueryOptimizationService.name);
  private readonly queryMetrics = new Map<string, QueryPerformanceMetrics[]>();
  private readonly slowQueryThreshold = 1000; // 1 second

  constructor(private readonly dataSource: DataSource) {}

  async executeOptimizedQuery<T>(
    queryFn: () => Promise<T>,
    queryName: string,
    options: QueryOptimizationOptions = {}
  ): Promise<T> {
    const startTime = Date.now();
    
    try {
      const result = await queryFn();
      const executionTime = Date.now() - startTime;

      // Track performance metrics
      this.trackQueryMetrics(queryName, executionTime, options);

      // Log slow queries
      if (executionTime > (options.slowQueryThreshold || this.slowQueryThreshold)) {
        this.logger.warn(`Slow query detected: ${queryName} took ${executionTime}ms`);
      }

      return result;
    } catch (error) {
      const executionTime = Date.now() - startTime;
      this.logger.error(`Query failed: ${queryName} after ${executionTime}ms`, error);
      throw error;
    }
  }

  private trackQueryMetrics(
    queryName: string,
    executionTime: number,
    options: QueryOptimizationOptions
  ): void {
    if (!this.queryMetrics.has(queryName)) {
      this.queryMetrics.set(queryName, []);
    }

    const metrics = this.queryMetrics.get(queryName)!;
    metrics.push({
      query: queryName,
      executionTime,
      timestamp: new Date(),
    });

    // Keep only last 100 metrics per query to prevent memory leaks
    if (metrics.length > 100) {
      metrics.shift();
    }
  }

  getQueryMetrics(queryName?: string): QueryPerformanceMetrics[] | Map<string, QueryPerformanceMetrics[]> {
    if (queryName) {
      return this.queryMetrics.get(queryName) || [];
    }
    return new Map(this.queryMetrics);
  }

  getSlowQueries(thresholdMs: number = this.slowQueryThreshold): QueryPerformanceMetrics[] {
    const slowQueries: QueryPerformanceMetrics[] = [];
    
    for (const [queryName, metrics] of this.queryMetrics.entries()) {
      const slowMetrics = metrics.filter(metric => metric.executionTime > thresholdMs);
      slowQueries.push(...slowMetrics);
    }

    return slowQueries.sort((a, b) => b.executionTime - a.executionTime);
  }

  getQueryStatistics(queryName: string): {
    totalExecutions: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    slowExecutions: number;
  } | null {
    const metrics = this.queryMetrics.get(queryName);
    if (!metrics || !metrics.length) return null;

    const executionTimes = metrics.map(m => m.executionTime);
    const slowExecutions = executionTimes.filter(time => time > this.slowQueryThreshold).length;

    return {
      totalExecutions: metrics.length,
      averageTime: Math.round(executionTimes.reduce((sum, time) => sum + time, 0) / metrics.length),
      minTime: Math.min(...executionTimes),
      maxTime: Math.max(...executionTimes),
      slowExecutions,
    };
  }

  async analyzeTableStatistics(tableName: string): Promise<{
    rowCount: number;
    tableSize: string;
    indexCount: number;
    lastAnalyzed?: Date;
  }> {
    const result = await this.dataSource.query(`
      SELECT 
        schemaname,
        tablename,
        attname,
        n_distinct,
        correlation
      FROM pg_stats 
      WHERE tablename = $1
    `, [tableName]);

    const tableInfo = await this.dataSource.query(`
      SELECT 
        COUNT(*) as row_count,
        pg_size_pretty(pg_total_relation_size(c.oid)) as table_size,
        (SELECT COUNT(*) FROM pg_indexes WHERE tablename = $1) as index_count
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relname = $1 AND n.nspname = 'public'
    `, [tableName]);

    return {
      rowCount: parseInt(tableInfo[0]?.row_count || '0'),
      tableSize: tableInfo[0]?.table_size || '0 bytes',
      indexCount: parseInt(tableInfo[0]?.index_count || '0'),
    };
  }

  async suggestIndexes(tableName: string): Promise<string[]> {
    // Analyze query patterns to suggest missing indexes
    const suggestions: string[] = [];

    // This is a simplified implementation - in production, you'd analyze
    // actual query logs and execution plans
    const queryLogs = await this.dataSource.query(`
      SELECT 
        query,
        calls,
        total_time,
        mean_time
      FROM pg_stat_statements 
      WHERE query LIKE '%${tableName}%'
      ORDER BY total_time DESC
      LIMIT 10
    `).catch(() => []); // pg_stat_statements may not be enabled

    // Basic suggestions based on common patterns
    if (tableName === 'tasks') {
      suggestions.push(
        'Consider adding composite index on (user_id, status, due_date) for user task queries',
        'Full-text search index on title and description for search functionality',
        'Partial index on overdue tasks: (status, due_date) WHERE due_date < NOW()'
      );
    }

    if (tableName === 'users') {
      suggestions.push(
        'Consider adding index on (email, role) for authentication queries',
        'Add index on created_at for time-based queries'
      );
    }

    return suggestions;
  }

  async explainQuery(query: string, parameters?: any[]): Promise<any[]> {
    const explainQuery = `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${query}`;
    
    try {
      const result = await this.dataSource.query(explainQuery, parameters);
      return result[0]['QUERY PLAN'];
    } catch (error) {
      this.logger.error('Failed to explain query:', error);
      throw error;
    }
  }

  clearMetrics(queryName?: string): void {
    if (queryName) {
      this.queryMetrics.delete(queryName);
    } else {
      this.queryMetrics.clear();
    }
  }

  // Utility methods for common optimization patterns
  async withPagination<T>(
    queryBuilder: any,
    page: number,
    limit: number,
    countQuery?: any
  ): Promise<{ data: T[]; total: number; page: number; totalPages: number }> {
    const skip = (page - 1) * limit;
    
    // Execute count query in parallel with data query for better performance
    const [data, total] = await Promise.all([
      queryBuilder.skip(skip).take(limit).getMany(),
      countQuery ? countQuery.getCount() : queryBuilder.getCount()
    ]);

    return {
      data,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    };
  }

  createSearchCondition(fields: string[], searchTerm: string, alias?: string): string {
    const prefix = alias ? `${alias}.` : '';
    const conditions = fields.map(field => 
      `${prefix}${field} ILIKE :searchTerm`
    ).join(' OR ');
    
    return `(${conditions})`;
  }

  createDateRangeCondition(
    field: string, 
    startDate?: Date, 
    endDate?: Date, 
    alias?: string
  ): { condition: string; parameters: Record<string, any> } {
    const prefix = alias ? `${alias}.` : '';
    const conditions: string[] = [];
    const parameters: Record<string, any> = {};

    if (startDate) {
      conditions.push(`${prefix}${field} >= :startDate`);
      parameters.startDate = startDate;
    }

    if (endDate) {
      conditions.push(`${prefix}${field} <= :endDate`);
      parameters.endDate = endDate;
    }

    return {
      condition: conditions.join(' AND '),
      parameters,
    };
  }
}