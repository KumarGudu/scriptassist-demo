import { Injectable, Logger } from '@nestjs/common';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { TasksService } from '../../modules/tasks/tasks.service';
import { RetryService } from '../../common/services/retry.service';
import { GracefulDegradationService } from '../../common/services/graceful-degradation.service';

@Injectable()
@Processor('task-processing')
export class TaskProcessorService extends WorkerHost {
  private readonly logger = new Logger(TaskProcessorService.name);

  constructor(
    private readonly tasksService: TasksService,
    private readonly retryService: RetryService,
    private readonly degradationService: GracefulDegradationService,
  ) {
    super();
  }

  async process(job: Job): Promise<any> {
    this.logger.debug(`Processing job ${job.id} of type ${job.name}`);
    
    return await this.degradationService.executeWithDegradation(
      `job-${job.name}`,
      async () => {
        return await this.retryService.executeWithCircuitBreaker(
          async () => {
            switch (job.name) {
              case 'task-status-update':
                return await this.handleStatusUpdate(job);
              case 'overdue-tasks-notification':
                return await this.handleOverdueTasks(job);
              case 'task-batch-processing':
                return await this.handleBatchProcessing(job);
              default:
                this.logger.warn(`Unknown job type: ${job.name}`);
                throw new Error(`Unknown job type: ${job.name}`);
            }
          },
          `job-processor-${job.name}`,
          {
            failureThreshold: 3,
            timeout: 30000,
            resetTimeout: 120000,
          }
        );
      },
      {
        enableFallback: true,
        timeoutMs: 45000,
        retryConfig: {
          maxAttempts: 2,
          backoffMs: 1000,
        },
        cacheFallback: {
          enabled: true,
          ttl: 60,
          staleWhileRevalidate: false,
        },
        fallbackData: { success: false, error: 'Service temporarily unavailable' },
      }
    );
  }

  private async handleStatusUpdate(job: Job) {
    const { taskId, status } = job.data;
    
    if (!taskId || !status) {
      throw new Error('Missing required data: taskId and status are required');
    }

    const validStatuses = ['pending', 'in_progress', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      throw new Error(`Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
    }

    return await this.retryService.executeWithBulkhead(
      async () => {
        const task = await this.tasksService.updateStatus(taskId, status);
        
        this.logger.log(`Successfully updated task ${taskId} status to ${status}`);
        return { 
          success: true,
          taskId: task.id,
          newStatus: task.status,
          updatedAt: new Date().toISOString(),
        };
      },
      5,
      'task-status-update'
    );
  }

  private async handleOverdueTasks(job: Job) {
    this.logger.debug('Processing overdue tasks notification with batching');
    
    const { batchSize = 50 } = job.data;
    
    return await this.retryService.executeWithBulkhead(
      async () => {
        const overdueTasks = await this.tasksService.findOverdueTasks(batchSize);
        
        if (overdueTasks.length === 0) {
          return { 
            success: true, 
            message: 'No overdue tasks found',
            processed: 0 
          };
        }

        let processed = 0;
        const errors: string[] = [];

        for (const task of overdueTasks) {
          try {
            await this.tasksService.sendOverdueNotification(task.id);
            processed++;
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            errors.push(`Task ${task.id}: ${errorMessage}`);
            this.logger.warn(`Failed to send notification for task ${task.id}: ${errorMessage}`);
          }
        }

        this.logger.log(`Processed ${processed}/${overdueTasks.length} overdue task notifications`);
        
        return { 
          success: errors.length < overdueTasks.length / 2,
          message: `Processed ${processed}/${overdueTasks.length} overdue tasks`,
          processed,
          total: overdueTasks.length,
          errors: errors.length > 0 ? errors : undefined,
        };
      },
      3,
      'overdue-tasks-notification'
    );
  }

  private async handleBatchProcessing(job: Job) {
    const { tasks, operation } = job.data;
    
    if (!tasks || !Array.isArray(tasks)) {
      throw new Error('Missing required data: tasks array is required');
    }

    const batchSize = 10;
    const batches = this.chunkArray(tasks, batchSize);
    const results = [];
    
    this.logger.debug(`Processing ${tasks.length} tasks in ${batches.length} batches`);

    for (const [batchIndex, batch] of batches.entries()) {
      try {
        const batchResult = await this.processBatch(batch, operation, batchIndex);
        results.push(batchResult);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        this.logger.error(`Batch ${batchIndex} failed: ${errorMessage}`);
        results.push({
          batchIndex,
          success: false,
          error: errorMessage,
          processed: 0,
        });
      }
    }

    const totalProcessed = results.reduce((sum, result) => sum + (result.processed || 0), 0);
    const successfulBatches = results.filter(result => result.success).length;

    return {
      success: successfulBatches > 0,
      totalTasks: tasks.length,
      totalProcessed,
      batchesProcessed: successfulBatches,
      totalBatches: batches.length,
      results,
    };
  }

  private async processBatch(batch: any[], operation: string, batchIndex: number): Promise<any> {
    return await this.degradationService.executeWithPartialDegradation(
      `batch-${operation}`,
      new Map(batch.map((item, index) => [
        `item-${index}`,
        () => this.processItem(item, operation)
      ])),
      (results) => ({
        batchIndex,
        success: results.size >= batch.length * 0.7,
        processed: results.size,
        total: batch.length,
        items: Array.from(results.entries()),
      }),
      {
        minSuccessThreshold: 70,
        timeout: 30000,
      }
    );
  }

  private async processItem(item: any, operation: string): Promise<any> {
    switch (operation) {
      case 'update-priority':
        return await this.tasksService.updatePriority(item.id, item.priority);
      case 'bulk-complete':
        return await this.tasksService.updateStatus(item.id, 'completed');
      default:
        throw new Error(`Unknown operation: ${operation}`);
    }
  }

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }
} 