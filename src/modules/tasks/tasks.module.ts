import { Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';
import { Task } from './entities/task.entity';
import { TaskRepository } from './repositories/task.repository';
import { ITaskRepository } from './interfaces/task.repository.interface';
import { ITaskService } from './interfaces/task.service.interface';
import { TransactionService } from '../../common/services/transaction.service';
import { EventBusService } from '../../common/events/event-bus.service';
import { TaskQueueHandler } from './handlers/task-queue.handler';

@Module({
  imports: [
    TypeOrmModule.forFeature([Task]),
    BullModule.registerQueue({
      name: 'task-processing',
    }),
  ],
  controllers: [TasksController],
  providers: [
    TasksService,
    TaskRepository,
    TransactionService,
    EventBusService,
    TaskQueueHandler,
    {
      provide: ITaskRepository,
      useClass: TaskRepository,
    },
    {
      provide: ITaskService,
      useClass: TasksService,
    },
  ],
  exports: [ITaskService, TypeOrmModule],
})
export class TasksModule implements OnModuleInit {
  constructor(
    private readonly eventBus: EventBusService,
    private readonly taskQueueHandler: TaskQueueHandler,
  ) {}

  onModuleInit() {
    // Register event handlers for decoupled processing
    this.eventBus.subscribe('TaskCreated', this.taskQueueHandler);
    this.eventBus.subscribe('TaskStatusChanged', this.taskQueueHandler);
  }
} 