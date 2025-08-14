import { DomainEvent } from '../../../common/events/domain-event.interface';

export class TaskStatusChangedEvent extends DomainEvent {
  constructor(
    taskId: string,
    public readonly userId: string,
    public readonly oldStatus: string,
    public readonly newStatus: string,
  ) {
    super(taskId, 'TaskStatusChanged');
  }
}