export interface IDomainEvent {
  readonly eventId: string;
  readonly occurredOn: Date;
  readonly aggregateId: string;
  readonly eventType: string;
}

export abstract class DomainEvent implements IDomainEvent {
  public readonly eventId: string;
  public readonly occurredOn: Date;

  constructor(
    public readonly aggregateId: string,
    public readonly eventType: string
  ) {
    this.eventId = crypto.randomUUID();
    this.occurredOn = new Date();
  }
}