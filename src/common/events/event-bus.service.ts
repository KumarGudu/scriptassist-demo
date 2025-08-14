import { Injectable } from '@nestjs/common';
import { IDomainEvent } from './domain-event.interface';

export interface IEventHandler<T extends IDomainEvent = IDomainEvent> {
  handle(event: T): Promise<void> | void;
}

@Injectable()
export class EventBusService {
  private handlers = new Map<string, IEventHandler[]>();

  subscribe<T extends IDomainEvent>(
    eventType: string, 
    handler: IEventHandler<T>
  ): void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }
    this.handlers.get(eventType)!.push(handler);
  }

  async publish<T extends IDomainEvent>(event: T): Promise<void> {
    const handlers = this.handlers.get(event.eventType) || [];
    
    await Promise.all(
      handlers.map(handler => 
        Promise.resolve(handler.handle(event))
      )
    );
  }

  async publishAll(events: IDomainEvent[]): Promise<void> {
    await Promise.all(
      events.map(event => this.publish(event))
    );
  }
}