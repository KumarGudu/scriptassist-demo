import { DomainEvent } from '../../../common/events/domain-event.interface';

export class TaskCreatedEvent extends DomainEvent {
  constructor(
    taskId: string,
    public readonly userId: string,
    public readonly title: string,
    public readonly status: string,
  ) {
    super(taskId, 'TaskCreated');
  }
}