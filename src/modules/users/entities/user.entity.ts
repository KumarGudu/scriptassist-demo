import { Column, CreateDateColumn, Entity, Index, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import { Task } from '../../tasks/entities/task.entity';
import { Exclude } from 'class-transformer';

@Entity('users')
@Index('idx_user_email', ['email'])
@Index('idx_user_role', ['role'])
@Index('idx_user_created_at', ['createdAt'])
@Index('idx_user_name', ['name'])
@Index('idx_user_email_role', ['email', 'role'])
@Index('idx_user_role_created', ['role', 'createdAt'])
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  name: string;

  @Column()
  @Exclude({ toPlainOnly: true })
  password: string;

  @Column({ default: 'user' })
  role: string;

  @OneToMany(() => Task, (task) => task.user, {
    lazy: true,
    cascade: true,
  })
  tasks: Task[];

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
} 