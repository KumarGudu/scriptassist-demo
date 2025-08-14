import { Injectable, NotFoundException } from '@nestjs/common';
import { Task } from './entities/task.entity';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { TaskStatus } from './enums/task-status.enum';
import { ITaskService } from './interfaces/task.service.interface';
import { ITaskRepository } from './interfaces/task.repository.interface';
import { TransactionService } from '../../common/services/transaction.service';
import { EventBusService } from '../../common/events/event-bus.service';
import { TaskCreatedEvent } from './events/task-created.event';
import { TaskStatusChangedEvent } from './events/task-status-changed.event';

@Injectable()
export class TasksService implements ITaskService {
  constructor(
    private readonly taskRepository: ITaskRepository,
    private readonly transactionService: TransactionService,
    private readonly eventBus: EventBusService,
  ) {}

  async create(createTaskDto: CreateTaskDto): Promise<Task> {
    return this.transactionService.runTransaction(async (queryRunner) => {
      // Create task within transaction
      const task = await this.taskRepository.create(createTaskDto);
      
      // Publish domain event for decoupled processing
      await this.eventBus.publish(
        new TaskCreatedEvent(task.id, task.userId, task.title, task.status)
      );
      
      return task;
    });
  }

  async findAll(options?: {
    status?: TaskStatus;
    priority?: string;
    page?: number;
    limit?: number;
    userId?: string;
  }): Promise<{ data: Task[]; total: number; page?: number; totalPages?: number }> {
    return this.taskRepository.findAll(options);
  }

  async findOne(id: string): Promise<Task> {
    return this.taskRepository.findOne(id);
  }

  async update(id: string, updateTaskDto: UpdateTaskDto): Promise<Task> {
    return this.transactionService.runTransaction(async (queryRunner) => {
      const originalTask = await this.taskRepository.findOne(id);
      const originalStatus = originalTask.status;
      
      const updatedTask = await this.taskRepository.update(id, updateTaskDto);
      
      // Publish domain event if status changed
      if (originalStatus !== updatedTask.status) {
        await this.eventBus.publish(
          new TaskStatusChangedEvent(
            updatedTask.id, 
            updatedTask.userId, 
            originalStatus, 
            updatedTask.status
          )
        );
      }
      
      return updatedTask;
    });
  }

  async remove(id: string): Promise<void> {
    return this.taskRepository.remove(id);
  }

  async findByStatus(status: TaskStatus): Promise<Task[]> {
    return this.taskRepository.findByStatus(status);
  }

  async updateStatus(id: string, status: string): Promise<Task> {
    // This method will be called by the task processor
    const task = await this.findOne(id);
    task.status = status as any;
    return this.tasksRepository.save(task);
  }

  async getStatistics(): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }> {
    return this.taskRepository.getStatistics();
  }

  async processBatchOperation(taskIds: string[], action: 'complete' | 'delete'): Promise<void> {
    return this.transactionService.runTransaction(async (queryRunner) => {
      switch (action) {
        case 'complete':
          await this.taskRepository.bulkUpdate(taskIds, { status: TaskStatus.COMPLETED });
          break;
        case 'delete':
          await this.taskRepository.bulkDelete(taskIds);
          break;
        default:
          throw new Error(`Unknown batch action: ${action}`);
      }
    });
  }
}
