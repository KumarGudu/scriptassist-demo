import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Task } from '../entities/task.entity';
import { CreateTaskDto } from '../dto/create-task.dto';
import { UpdateTaskDto } from '../dto/update-task.dto';
import { TaskStatus } from '../enums/task-status.enum';
import { ITaskRepository } from '../interfaces/task.repository.interface';

@Injectable()
export class TaskRepository implements ITaskRepository {
  constructor(
    @InjectRepository(Task)
    private readonly taskRepository: Repository<Task>,
  ) {}

  async create(createTaskDto: CreateTaskDto): Promise<Task> {
    const task = this.taskRepository.create(createTaskDto);
    return this.taskRepository.save(task);
  }

  async findAll(options?: {
    status?: TaskStatus;
    priority?: string;
    page?: number;
    limit?: number;
    userId?: string;
    search?: string;
    sortBy?: string;
    sortOrder?: 'ASC' | 'DESC';
    dateFrom?: Date;
    dateTo?: Date;
    includeUser?: boolean;
  }): Promise<{ data: Task[]; total: number; page?: number; totalPages?: number }> {
    const queryBuilder = this.taskRepository.createQueryBuilder('task');

    // Conditional eager loading - only join user data when needed
    if (options?.includeUser !== false) {
      queryBuilder.leftJoinAndSelect('task.user', 'user');
    }

    // Optimized filtering with indexed columns
    if (options?.status) {
      queryBuilder.andWhere('task.status = :status', { status: options.status });
    }

    if (options?.priority) {
      queryBuilder.andWhere('task.priority = :priority', { priority: options.priority });
    }

    if (options?.userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId: options.userId });
    }

    // Full-text search optimization
    if (options?.search) {
      queryBuilder.andWhere(
        '(task.title ILIKE :search OR task.description ILIKE :search)',
        { search: `%${options.search}%` }
      );
    }

    // Date range filtering using indexed dueDate column
    if (options?.dateFrom) {
      queryBuilder.andWhere('task.dueDate >= :dateFrom', { dateFrom: options.dateFrom });
    }

    if (options?.dateTo) {
      queryBuilder.andWhere('task.dueDate <= :dateTo', { dateTo: options.dateTo });
    }

    // Optimized sorting with default fallback to indexed columns
    const sortBy = options?.sortBy || 'createdAt';
    const sortOrder = options?.sortOrder || 'DESC';
    
    // Map sort fields to actual database columns for performance
    const sortFieldMap: Record<string, string> = {
      createdAt: 'task.createdAt',
      updatedAt: 'task.updatedAt',
      dueDate: 'task.dueDate',
      title: 'task.title',
      status: 'task.status',
      priority: 'task.priority',
    };

    const sortField = sortFieldMap[sortBy] || 'task.createdAt';
    queryBuilder.orderBy(sortField, sortOrder);

    // Get total count efficiently - avoid counting when not paginating
    let total: number;
    if (options?.page && options?.limit) {
      total = await queryBuilder.getCount();
    } else {
      total = 0; // Will be set after query execution if not paginating
    }

    // Efficient pagination
    if (options?.page && options?.limit) {
      const skip = (options.page - 1) * options.limit;
      queryBuilder.skip(skip).take(options.limit);
    }

    const data = await queryBuilder.getMany();

    // Set total for non-paginated results
    if (!options?.page || !options?.limit) {
      total = data.length;
    }

    return {
      data,
      total,
      ...(options?.page && options?.limit && {
        page: options.page,
        totalPages: Math.ceil(total / options.limit),
      }),
    };
  }

  async findOne(id: string): Promise<Task> {
    const task = await this.taskRepository.findOne({
      where: { id },
      relations: ['user'],
    });

    if (!task) {
      throw new NotFoundException(`Task with ID ${id} not found`);
    }

    return task;
  }

  async findByStatus(status: TaskStatus): Promise<Task[]> {
    return this.taskRepository.find({
      where: { status },
      relations: ['user'],
    });
  }

  async update(id: string, updateTaskDto: UpdateTaskDto): Promise<Task> {
    const task = await this.findOne(id);
    Object.assign(task, updateTaskDto);
    return this.taskRepository.save(task);
  }

  async remove(id: string): Promise<void> {
    const result = await this.taskRepository.delete(id);
    
    if (result.affected === 0) {
      throw new NotFoundException(`Task with ID ${id} not found`);
    }
  }

  async getStatistics(): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }> {
    const stats = await this.taskRepository
      .createQueryBuilder('task')
      .select([
        'COUNT(*) as total',
        'COUNT(CASE WHEN task.status = :completed THEN 1 END) as completed',
        'COUNT(CASE WHEN task.status = :inProgress THEN 1 END) as "inProgress"',
        'COUNT(CASE WHEN task.status = :pending THEN 1 END) as pending',
        'COUNT(CASE WHEN task.priority = :high THEN 1 END) as "highPriority"',
      ])
      .setParameters({
        completed: TaskStatus.COMPLETED,
        inProgress: TaskStatus.IN_PROGRESS,
        pending: TaskStatus.PENDING,
        high: 'HIGH',
      })
      .getRawOne();

    return {
      total: parseInt(stats.total),
      completed: parseInt(stats.completed),
      inProgress: parseInt(stats.inProgress),
      pending: parseInt(stats.pending),
      highPriority: parseInt(stats.highPriority),
    };
  }

  async bulkUpdate(taskIds: string[], updates: Partial<UpdateTaskDto>): Promise<void> {
    if (!taskIds.length) return;

    // Process in chunks to avoid query parameter limits
    const chunkSize = 1000;
    for (let i = 0; i < taskIds.length; i += chunkSize) {
      const chunk = taskIds.slice(i, i + chunkSize);
      await this.taskRepository
        .createQueryBuilder()
        .update(Task)
        .set(updates)
        .where('id IN (:...ids)', { ids: chunk })
        .execute();
    }
  }

  async bulkDelete(taskIds: string[]): Promise<void> {
    if (!taskIds.length) return;

    // Process in chunks to avoid query parameter limits  
    const chunkSize = 1000;
    for (let i = 0; i < taskIds.length; i += chunkSize) {
      const chunk = taskIds.slice(i, i + chunkSize);
      await this.taskRepository
        .createQueryBuilder()
        .delete()
        .from(Task)
        .where('id IN (:...ids)', { ids: chunk })
        .execute();
    }
  }

  async bulkInsert(tasks: CreateTaskDto[]): Promise<Task[]> {
    if (!tasks.length) return [];

    // Use TypeORM's efficient bulk insert
    const chunkSize = 1000;
    const results: Task[] = [];

    for (let i = 0; i < tasks.length; i += chunkSize) {
      const chunk = tasks.slice(i, i + chunkSize);
      const entities = chunk.map(taskDto => this.taskRepository.create(taskDto));
      
      const insertResult = await this.taskRepository
        .createQueryBuilder()
        .insert()
        .into(Task)
        .values(entities)
        .returning('*')
        .execute();

      results.push(...insertResult.generatedMaps as Task[]);
    }

    return results;
  }

  async findWithRelations(
    options: {
      taskIds?: string[];
      userId?: string;
      status?: TaskStatus;
      includeUser?: boolean;
      includeComments?: boolean;
      limit?: number;
    } = {}
  ): Promise<Task[]> {
    const queryBuilder = this.taskRepository.createQueryBuilder('task');

    // Selective eager loading based on requirements
    if (options.includeUser) {
      queryBuilder.leftJoinAndSelect('task.user', 'user');
    }

    if (options.includeComments) {
      queryBuilder.leftJoinAndSelect('task.comments', 'comments');
    }

    // Efficient filtering
    if (options.taskIds?.length) {
      queryBuilder.whereInIds(options.taskIds);
    }

    if (options.userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId: options.userId });
    }

    if (options.status) {
      queryBuilder.andWhere('task.status = :status', { status: options.status });
    }

    if (options.limit) {
      queryBuilder.limit(options.limit);
    }

    return queryBuilder.getMany();
  }

  async getTasksWithUserCount(): Promise<Array<{ userId: string; taskCount: number; completedCount: number }>> {
    return this.taskRepository
      .createQueryBuilder('task')
      .select([
        'task.userId as "userId"',
        'COUNT(*) as "taskCount"',
        'COUNT(CASE WHEN task.status = :completed THEN 1 END) as "completedCount"'
      ])
      .groupBy('task.userId')
      .setParameter('completed', TaskStatus.COMPLETED)
      .getRawMany();
  }

  async findOverdueTasks(limit: number = 100): Promise<Task[]> {
    return this.taskRepository
      .createQueryBuilder('task')
      .leftJoinAndSelect('task.user', 'user')
      .where('task.dueDate < :now', { now: new Date() })
      .andWhere('task.status != :completed', { completed: TaskStatus.COMPLETED })
      .orderBy('task.dueDate', 'ASC')
      .limit(limit)
      .getMany();
  }

  async getTasksByDateRange(startDate: Date, endDate: Date, userId?: string): Promise<Task[]> {
    const queryBuilder = this.taskRepository
      .createQueryBuilder('task')
      .where('task.createdAt >= :startDate', { startDate })
      .andWhere('task.createdAt <= :endDate', { endDate });

    if (userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId });
    }

    return queryBuilder
      .orderBy('task.createdAt', 'DESC')
      .getMany();
  }
}