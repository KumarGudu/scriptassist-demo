import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, ClassSerializerInterceptor, UseInterceptors, Query } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { IUserService } from './interfaces/user.service.interface';

@ApiTags('users')
@Controller('users')
@UseInterceptors(ClassSerializerInterceptor)
export class UsersController {
  constructor(private readonly usersService: IUserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Get()
  findAll(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ) {
    const pageNum = page ? Math.max(1, page) : undefined;
    const limitNum = limit ? Math.max(1, Math.min(100, limit)) : (pageNum ? 10 : undefined);

    const options = {
      ...(pageNum && { page: pageNum }),
      ...(limitNum && { limit: limitNum }),
    };

    return this.usersService.findAll(Object.keys(options).length > 0 ? options : undefined);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
} 