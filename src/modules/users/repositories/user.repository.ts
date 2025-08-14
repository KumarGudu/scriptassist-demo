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
  }): Promise<{ data: User[]; total: number; page?: number; totalPages?: number }> {
    const queryBuilder = this.userRepository.createQueryBuilder('user');

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
}