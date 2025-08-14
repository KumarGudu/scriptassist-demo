import { Injectable } from '@nestjs/common';
import { DataSource, QueryRunner } from 'typeorm';

@Injectable()
export class TransactionService {
  constructor(private readonly dataSource: DataSource) {}

  async runTransaction<T>(
    callback: (queryRunner: QueryRunner) => Promise<T>
  ): Promise<T> {
    const queryRunner = this.dataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const result = await callback(queryRunner);
      await queryRunner.commitTransaction();
      return result;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async runTransactionWithRetry<T>(
    callback: (queryRunner: QueryRunner) => Promise<T>,
    maxRetries: number = 3
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.runTransaction(callback);
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxRetries) {
          break;
        }
        
        // Wait before retrying (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
      }
    }

    throw lastError!;
  }
}