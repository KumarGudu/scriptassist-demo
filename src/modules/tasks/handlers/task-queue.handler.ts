import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { IEventHandler } from '../../../common/events/event-bus.service';
import { TaskCreatedEvent } from '../events/task-created.event';
import { TaskStatusChangedEvent } from '../events/task-status-changed.event';

@Injectable()
export class TaskQueueHandler implements IEventHandler<TaskCreatedEvent | TaskStatusChangedEvent> {
  constructor(
    @InjectQueue('task-processing')
    private readonly taskQueue: Queue,
  ) {}

  async handle(event: TaskCreatedEvent | TaskStatusChangedEvent): Promise<void> {
    switch (event.eventType) {
      case 'TaskCreated':
        const createdEvent = event as TaskCreatedEvent;
        await this.taskQueue.add('task-status-update', {
          taskId: createdEvent.aggregateId,
          status: createdEvent.status,
          eventType: 'created',
        });
        break;
        
      case 'TaskStatusChanged':
        const statusEvent = event as TaskStatusChangedEvent;
        await this.taskQueue.add('task-status-update', {
          taskId: statusEvent.aggregateId,
          oldStatus: statusEvent.oldStatus,
          newStatus: statusEvent.newStatus,
          eventType: 'status_changed',
        });
        break;
    }
  }
}