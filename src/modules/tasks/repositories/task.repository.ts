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
  }): Promise<{ data: Task[]; total: number; page?: number; totalPages?: number }> {
    const queryBuilder = this.taskRepository.createQueryBuilder('task')
      .leftJoinAndSelect('task.user', 'user');

    if (options?.status) {
      queryBuilder.andWhere('task.status = :status', { status: options.status });
    }

    if (options?.priority) {
      queryBuilder.andWhere('task.priority = :priority', { priority: options.priority });
    }

    if (options?.userId) {
      queryBuilder.andWhere('task.userId = :userId', { userId: options.userId });
    }

    const total = await queryBuilder.getCount();

    if (options?.page && options?.limit) {
      const skip = (options.page - 1) * options.limit;
      queryBuilder.skip(skip).take(options.limit);
    }

    const data = await queryBuilder.getMany();

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
    await this.taskRepository
      .createQueryBuilder()
      .update(Task)
      .set(updates)
      .where('id IN (:...ids)', { ids: taskIds })
      .execute();
  }

  async bulkDelete(taskIds: string[]): Promise<void> {
    await this.taskRepository
      .createQueryBuilder()
      .delete()
      .from(Task)
      .where('id IN (:...ids)', { ids: taskIds })
      .execute();
  }
}