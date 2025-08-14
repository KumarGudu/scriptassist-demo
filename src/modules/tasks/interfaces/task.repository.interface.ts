import { Task } from '../entities/task.entity';
import { CreateTaskDto } from '../dto/create-task.dto';
import { UpdateTaskDto } from '../dto/update-task.dto';
import { TaskStatus } from '../enums/task-status.enum';

export interface ITaskRepository {
  create(createTaskDto: CreateTaskDto): Promise<Task>;
  
  findAll(options?: {
    status?: TaskStatus;
    priority?: string;
    page?: number;
    limit?: number;
    userId?: string;
  }): Promise<{ data: Task[]; total: number; page?: number; totalPages?: number }>;
  
  findOne(id: string): Promise<Task>;
  
  findByStatus(status: TaskStatus): Promise<Task[]>;
  
  update(id: string, updateTaskDto: UpdateTaskDto): Promise<Task>;
  
  remove(id: string): Promise<void>;
  
  getStatistics(): Promise<{
    total: number;
    completed: number;
    inProgress: number;
    pending: number;
    highPriority: number;
  }>;
  
  bulkUpdate(taskIds: string[], updates: Partial<UpdateTaskDto>): Promise<void>;
  
  bulkDelete(taskIds: string[]): Promise<void>;
}