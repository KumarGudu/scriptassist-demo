import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThan, Repository } from 'typeorm';
import { Task } from '../../modules/tasks/entities/task.entity';
import { TaskStatus } from '../../modules/tasks/enums/task-status.enum';

@Injectable()
export class OverdueTasksService {
  private readonly logger = new Logger(OverdueTasksService.name);

  constructor(
    @InjectQueue('task-processing')
    private taskQueue: Queue,
    @InjectRepository(Task)
    private tasksRepository: Repository<Task>,
  ) {}

  @Cron(CronExpression.EVERY_HOUR)
  async checkOverdueTasks() {
    this.logger.debug('Checking for overdue tasks...');
    
    try {
      const now = new Date();
      
      // Efficient query to get only task IDs for overdue tasks
      const overdueTaskIds = await this.tasksRepository
        .createQueryBuilder('task')
        .select('task.id')
        .where('task.dueDate < :now', { now })
        .andWhere('task.status = :status', { status: TaskStatus.PENDING })
        .getMany();
      
      this.logger.log(`Found ${overdueTaskIds.length} overdue tasks`);
      
      if (overdueTaskIds.length > 0) {
        // Bulk add tasks to queue efficiently
        const queueJobs = overdueTaskIds.map(task => ({
          name: 'overdue-task-notification',
          data: {
            taskId: task.id,
            processedAt: now.toISOString(),
          },
          opts: {
            delay: 0,
            attempts: 3,
            backoff: 'exponential',
          },
        }));\n\n        await this.taskQueue.addBulk(queueJobs);\n        this.logger.log(`Added ${overdueTaskIds.length} tasks to processing queue`);\n      }\n      \n      this.logger.debug('Overdue tasks check completed successfully');\n    } catch (error) {\n      this.logger.error('Error checking overdue tasks:', error);\n      throw error;\n    }\n  }
} 