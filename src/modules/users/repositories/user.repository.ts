import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { IUserRepository } from '../interfaces/user.repository.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserRepository implements IUserRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });
    return this.userRepository.save(user);
  }

  async findAll(options?: {
    page?: number;
    limit?: number;
    search?: string;
    sortBy?: string;
    sortOrder?: 'ASC' | 'DESC';
    includeTasks?: boolean;
    status?: 'active' | 'inactive';
  }): Promise<{ data: User[]; total: number; page?: number; totalPages?: number }> {
    const queryBuilder = this.userRepository.createQueryBuilder('user');

    // Conditional eager loading of tasks
    if (options?.includeTasks) {
      queryBuilder.leftJoinAndSelect('user.tasks', 'tasks');
    }

    // Search functionality
    if (options?.search) {
      queryBuilder.andWhere(
        '(user.email ILIKE :search OR user.firstName ILIKE :search OR user.lastName ILIKE :search)',
        { search: `%${options.search}%` }
      );
    }

    // Status filtering (if user entity has status field)
    if (options?.status) {
      queryBuilder.andWhere('user.status = :status', { status: options.status });
    }

    // Optimized sorting
    const sortBy = options?.sortBy || 'createdAt';
    const sortOrder = options?.sortOrder || 'DESC';
    
    const sortFieldMap: Record<string, string> = {
      createdAt: 'user.createdAt',
      updatedAt: 'user.updatedAt',
      email: 'user.email',
      firstName: 'user.firstName',
      lastName: 'user.lastName',
    };

    const sortField = sortFieldMap[sortBy] || 'user.createdAt';
    queryBuilder.orderBy(sortField, sortOrder);

    // Get count efficiently
    let total: number;
    if (options?.page && options?.limit) {
      total = await queryBuilder.getCount();
    } else {
      total = 0;
    }

    // Pagination
    if (options?.page && options?.limit) {
      const skip = (options.page - 1) * options.limit;
      queryBuilder.skip(skip).take(options.limit);
    }

    const data = await queryBuilder.getMany();

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

  async findOne(id: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.findOne(id);
    
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }
    
    this.userRepository.merge(user, updateUserDto);
    return this.userRepository.save(user);
  }

  async remove(id: string): Promise<void> {
    const result = await this.userRepository.delete(id);
    
    if (result.affected === 0) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  }

  async bulkInsert(users: CreateUserDto[]): Promise<User[]> {
    if (!users.length) return [];

    // Hash passwords in parallel for better performance
    const usersWithHashedPasswords = await Promise.all(
      users.map(async (user) => ({
        ...user,
        password: await bcrypt.hash(user.password, 10),
      }))
    );

    const chunkSize = 1000;
    const results: User[] = [];

    for (let i = 0; i < usersWithHashedPasswords.length; i += chunkSize) {
      const chunk = usersWithHashedPasswords.slice(i, i + chunkSize);
      const entities = chunk.map(userData => this.userRepository.create(userData));
      
      const insertResult = await this.userRepository
        .createQueryBuilder()
        .insert()
        .into(User)
        .values(entities)
        .returning('*')
        .execute();

      results.push(...insertResult.generatedMaps as User[]);
    }

    return results;
  }

  async bulkUpdate(userIds: string[], updates: Partial<UpdateUserDto>): Promise<void> {
    if (!userIds.length) return;

    // Hash password if provided
    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
    }

    const chunkSize = 1000;
    for (let i = 0; i < userIds.length; i += chunkSize) {
      const chunk = userIds.slice(i, i + chunkSize);
      await this.userRepository
        .createQueryBuilder()
        .update(User)
        .set(updates)
        .where('id IN (:...ids)', { ids: chunk })
        .execute();
    }
  }

  async getUsersWithTaskStats(): Promise<Array<{
    id: string;
    email: string;
    taskCount: number;
    completedTaskCount: number;
  }>> {
    return this.userRepository
      .createQueryBuilder('user')
      .leftJoin('user.tasks', 'task')
      .select([
        'user.id as id',
        'user.email as email',
        'COUNT(task.id) as "taskCount"',
        'COUNT(CASE WHEN task.status = :completed THEN 1 END) as "completedTaskCount"'
      ])
      .groupBy('user.id, user.email')
      .setParameter('completed', 'COMPLETED')
      .getRawMany();
  }

  async findByEmails(emails: string[]): Promise<User[]> {
    if (!emails.length) return [];

    return this.userRepository
      .createQueryBuilder('user')
      .where('user.email IN (:...emails)', { emails })
      .getMany();
  }
}