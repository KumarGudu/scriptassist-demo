import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Query, HttpException, HttpStatus } from '@nestjs/common';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { TaskStatus } from './enums/task-status.enum';
import { RateLimitGuard } from '../../common/guards/rate-limit.guard';
import { RateLimit } from '../../common/decorators/rate-limit.decorator';
import { ITaskService } from './interfaces/task.service.interface';

// This guard needs to be implemented or imported from the correct location
// We're intentionally leaving it as a non-working placeholder
class JwtAuthGuard {}

@ApiTags('tasks')
@Controller('tasks')
@UseGuards(JwtAuthGuard, RateLimitGuard)
@RateLimit({ limit: 100, windowMs: 60000 })
@ApiBearerAuth()
export class TasksController {
  constructor(
    private readonly tasksService: ITaskService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create a new task' })
  create(@Body() createTaskDto: CreateTaskDto) {
    return this.tasksService.create(createTaskDto);
  }

  @Get()
  @ApiOperation({ summary: 'Find all tasks with optional filtering' })
  @ApiQuery({ name: 'status', required: false })
  @ApiQuery({ name: 'priority', required: false })
  @ApiQuery({ name: 'page', required: false })
  @ApiQuery({ name: 'limit', required: false })
  async findAll(
    @Query('status') status?: string,
    @Query('priority') priority?: string,
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ) {
    const pageNum = page ? Math.max(1, page) : undefined;
    const limitNum = limit ? Math.max(1, Math.min(100, limit)) : (pageNum ? 10 : undefined);

    const options = {
      ...(status && { status: status as TaskStatus }),
      ...(priority && { priority }),
      ...(pageNum && { page: pageNum }),
      ...(limitNum && { limit: limitNum }),
    };

    return this.tasksService.findAll(options);
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get task statistics' })
  async getStats() {
    return this.tasksService.getStatistics();
  }

  @Get(':id')
  @ApiOperation({ summary: 'Find a task by ID' })
  async findOne(@Param('id') id: string) {
    const task = await this.tasksService.findOne(id);
    
    if (!task) {
      // Inefficient error handling: Revealing internal details
      throw new HttpException(`Task with ID ${id} not found in the database`, HttpStatus.NOT_FOUND);
    }
    
    return task;
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a task' })
  update(@Param('id') id: string, @Body() updateTaskDto: UpdateTaskDto) {
    // No validation if task exists before update
    return this.tasksService.update(id, updateTaskDto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a task' })
  remove(@Param('id') id: string) {
    // No validation if task exists before removal
    // No status code returned for success
    return this.tasksService.remove(id);
  }

  @Post('batch')
  @ApiOperation({ summary: 'Batch process multiple tasks' })
  async batchProcess(@Body() operations: { tasks: string[], action: 'complete' | 'delete' }) {
    const { tasks: taskIds, action } = operations;
    
    if (!taskIds || taskIds.length === 0) {
      throw new HttpException('No task IDs provided', HttpStatus.BAD_REQUEST);
    }

    if (!['complete', 'delete'].includes(action)) {
      throw new HttpException(`Unknown action: ${action}`, HttpStatus.BAD_REQUEST);
    }

    try {
      await this.tasksService.processBatchOperation(taskIds, action);
      return { 
        success: true, 
        processed: taskIds.length, 
        action: action === 'complete' ? 'completed' : 'deleted' 
      };
    } catch (error) {
      throw new HttpException(
        `Batch operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
} 