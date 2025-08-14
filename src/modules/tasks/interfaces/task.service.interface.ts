import { Task } from '../entities/task.entity';
import { CreateTaskDto } from '../dto/create-task.dto';
import { UpdateTaskDto } from '../dto/update-task.dto';
import { TaskStatus } from '../enums/task-status.enum';

export interface ITaskService {
  create(createTaskDto: CreateTaskDto): Promise<Task>;
  
  findAll(options?: {
    status?: TaskStatus;
    priority?: string;
    page?: number;
    limit?: number;
    userId?: string;
  }): Promise<{ data: Task[]; total: number; page?: number; totalPages?: number }>;
  
  findOne(id: string): Promise<Task>;
  
  update(id: string, updateTaskDto: UpdateTaskDto): Promise<Task>;
  
  remove(id: string): Promise<void>;
  
  getStatistics(): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }>;
  
  processBatchOperation(taskIds: string[], action: 'complete' | 'delete'): Promise<void>;
}