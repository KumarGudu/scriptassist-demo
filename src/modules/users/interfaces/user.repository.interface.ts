import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';

export interface IUserRepository {
  create(createUserDto: CreateUserDto): Promise<User>;
  
  findAll(options?: {
    page?: number;
    limit?: number;
  }): Promise<{ data: User[]; total: number; page?: number; totalPages?: number }>;
  
  findOne(id: string): Promise<User>;
  
  findByEmail(email: string): Promise<User | null>;
  
  update(id: string, updateUserDto: UpdateUserDto): Promise<User>;
  
  remove(id: string): Promise<void>;
}