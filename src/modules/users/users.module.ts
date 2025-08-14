import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User } from './entities/user.entity';
import { UserRepository } from './repositories/user.repository';
import { IUserRepository } from './interfaces/user.repository.interface';
import { IUserService } from './interfaces/user.service.interface';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
  ],
  controllers: [UsersController],
  providers: [
    UsersService,
    UserRepository,
    {
      provide: IUserRepository,
      useClass: UserRepository,
    },
    {
      provide: IUserService,
      useClass: UsersService,
    },
  ],
  exports: [IUserService],
})
export class UsersModule {} 