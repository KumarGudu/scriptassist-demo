import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { UsersModule } from './modules/users/users.module';
import { TasksModule } from './modules/tasks/tasks.module';
import { AuthModule } from './modules/auth/auth.module';
import { TaskProcessorModule } from './queues/task-processor/task-processor.module';
import { ScheduledTasksModule } from './queues/scheduled-tasks/scheduled-tasks.module';
import { CacheService } from './common/services/cache.service';
import { SecurityHeadersMiddleware } from './common/middleware/security-headers.middleware';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { SecureRateLimitGuard } from './common/guards/secure-rate-limit.guard';
import jwtConfig from './config/jwt.config';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [jwtConfig],
      validationOptions: {
        allowUnknown: false,
        abortEarly: true,
      },
    }),
    
    // Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DB_HOST'),
        port: configService.get('DB_PORT'),
        username: configService.get('DB_USERNAME'),
        password: configService.get('DB_PASSWORD'),
        database: configService.get('DB_DATABASE'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') === 'development',
        logging: configService.get('NODE_ENV') === 'development',
        // Security: Prevent SQL injection and ensure secure connections
        extra: {
          ssl: configService.get('NODE_ENV') === 'production',
          connectionTimeoutMillis: 10000,
          query_timeout: 30000,
          statement_timeout: 30000,
        },
      }),
    }),
    
    // Scheduling
    ScheduleModule.forRoot(),
    
    // Queue
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get('REDIS_HOST'),
          port: configService.get('REDIS_PORT'),
          // Security: Redis connection with authentication
          password: configService.get('REDIS_PASSWORD'),
          connectTimeout: 10000,
          lazyConnect: true,
        },
      }),
    }),
    
    // Rate limiting (legacy - using our secure implementation)
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ([
        {
          ttl: 60,
          limit: 10,
        },
      ]),
    }),
    
    // Feature modules
    UsersModule,
    TasksModule,
    AuthModule,
    
    // Queue processing modules
    TaskProcessorModule,
    ScheduledTasksModule,
  ],
  providers: [
    CacheService,
    // Global security filter
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    // Global security guard (optional - can be applied per route)
    // {
    //   provide: APP_GUARD,
    //   useClass: SecureRateLimitGuard,
    // },
  ],
  exports: [CacheService]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply security middleware to all routes
    consumer.apply(SecurityHeadersMiddleware).forRoutes('*');
  }
} 