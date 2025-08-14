import { Injectable } from '@nestjs/common';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { IUserService } from './interfaces/user.service.interface';
import { IUserRepository } from './interfaces/user.repository.interface';

@Injectable()
export class UsersService implements IUserService {
  constructor(
    private readonly userRepository: IUserRepository,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    return this.userRepository.create(createUserDto);
  }

  async findAll(options?: {
    page?: number;
    limit?: number;
  }): Promise<{ data: User[]; total: number; page?: number; totalPages?: number }> {
    return this.userRepository.findAll(options);
  }

  async findOne(id: string): Promise<User> {
    return this.userRepository.findOne(id);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findByEmail(email);
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    return this.userRepository.update(id, updateUserDto);
  }

  async remove(id: string): Promise<void> {
    return this.userRepository.remove(id);
  }
} 