import { Column, CreateDateColumn, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { TaskStatus } from '../enums/task-status.enum';
import { TaskPriority } from '../enums/task-priority.enum';

@Entity('tasks')
@Index('idx_task_status', ['status'])
@Index('idx_task_due_date', ['dueDate'])
@Index('idx_task_user_id', ['userId'])
@Index('idx_task_priority', ['priority'])
@Index('idx_task_created_at', ['createdAt'])
@Index('idx_task_updated_at', ['updatedAt'])
@Index('idx_task_status_due_date', ['status', 'dueDate'])
@Index('idx_task_user_status', ['userId', 'status'])
@Index('idx_task_user_priority', ['userId', 'priority'])
@Index('idx_task_status_priority', ['status', 'priority'])
@Index('idx_task_user_created', ['userId', 'createdAt'])
@Index('idx_task_title_search', ['title']) 
@Index('idx_task_status_created', ['status', 'createdAt'])
@Index('idx_task_overdue', ['status', 'dueDate']) // Composite index for overdue queries
export class Task {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({
    type: 'enum',
    enum: TaskStatus,
    default: TaskStatus.PENDING,
  })
  status: TaskStatus;

  @Column({
    type: 'enum',
    enum: TaskPriority,
    default: TaskPriority.MEDIUM,
  })
  priority: TaskPriority;

  @Column({ name: 'due_date', nullable: true })
  dueDate: Date;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => User, (user) => user.tasks, {
    onDelete: 'CASCADE',
    lazy: false,
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
} 