import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPerformanceIndexes1703234567890 implements MigrationInterface {
  name = 'AddPerformanceIndexes1703234567890';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Task table indexes for performance optimization
    await queryRunner.query(`
      -- Composite index for user-specific task filtering
      CREATE INDEX IF NOT EXISTS "idx_task_user_status_priority" ON "tasks" ("user_id", "status", "priority");
    `);

    await queryRunner.query(`
      -- Index for overdue task queries with condition
      CREATE INDEX IF NOT EXISTS "idx_task_overdue_active" ON "tasks" ("due_date", "status") 
      WHERE "status" IN ('PENDING', 'IN_PROGRESS');
    `);

    await queryRunner.query(`
      -- Full-text search index for task title and description
      CREATE INDEX IF NOT EXISTS "idx_task_text_search" ON "tasks" 
      USING gin(to_tsvector('english', coalesce("title", '') || ' ' || coalesce("description", '')));
    `);

    await queryRunner.query(`
      -- Composite index for date-based filtering with status
      CREATE INDEX IF NOT EXISTS "idx_task_created_status" ON "tasks" ("created_at" DESC, "status");
    `);

    await queryRunner.query(`
      -- Index for task statistics queries
      CREATE INDEX IF NOT EXISTS "idx_task_stats" ON "tasks" ("status", "priority", "created_at");
    `);

    // User table indexes
    await queryRunner.query(`
      -- Composite index for user authentication and role-based queries
      CREATE INDEX IF NOT EXISTS "idx_user_email_role_active" ON "users" ("email", "role") 
      WHERE "email" IS NOT NULL;
    `);

    await queryRunner.query(`
      -- Index for user activity queries
      CREATE INDEX IF NOT EXISTS "idx_user_created_role" ON "users" ("created_at" DESC, "role");
    `);

    await queryRunner.query(`
      -- Case-insensitive index for email searches
      CREATE INDEX IF NOT EXISTS "idx_user_email_lower" ON "users" (LOWER("email"));
    `);

    await queryRunner.query(`
      -- Index for user name searches (case-insensitive)
      CREATE INDEX IF NOT EXISTS "idx_user_name_lower" ON "users" (LOWER("name"));
    `);

    // Performance optimization views
    await queryRunner.query(`
      -- Materialized view for task statistics (refresh periodically)
      CREATE MATERIALIZED VIEW IF NOT EXISTS "task_statistics_mv" AS
      SELECT 
        COUNT(*) as total_tasks,
        COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as completed_tasks,
        COUNT(CASE WHEN status = 'IN_PROGRESS' THEN 1 END) as in_progress_tasks,
        COUNT(CASE WHEN status = 'PENDING' THEN 1 END) as pending_tasks,
        COUNT(CASE WHEN priority = 'HIGH' THEN 1 END) as high_priority_tasks,
        COUNT(CASE WHEN due_date < NOW() AND status != 'COMPLETED' THEN 1 END) as overdue_tasks,
        DATE_TRUNC('day', NOW()) as snapshot_date
      FROM tasks;
    `);

    await queryRunner.query(`
      -- Index on materialized view
      CREATE INDEX IF NOT EXISTS "idx_task_statistics_mv_date" ON "task_statistics_mv" ("snapshot_date");
    `);

    await queryRunner.query(`
      -- Materialized view for user task summaries
      CREATE MATERIALIZED VIEW IF NOT EXISTS "user_task_summary_mv" AS
      SELECT 
        u.id as user_id,
        u.email,
        u.name,
        COUNT(t.id) as total_tasks,
        COUNT(CASE WHEN t.status = 'COMPLETED' THEN 1 END) as completed_tasks,
        COUNT(CASE WHEN t.status = 'IN_PROGRESS' THEN 1 END) as in_progress_tasks,
        COUNT(CASE WHEN t.status = 'PENDING' THEN 1 END) as pending_tasks,
        MAX(t.created_at) as last_task_created,
        DATE_TRUNC('day', NOW()) as snapshot_date
      FROM users u
      LEFT JOIN tasks t ON u.id = t.user_id
      GROUP BY u.id, u.email, u.name;
    `);

    await queryRunner.query(`
      -- Index on user task summary materialized view
      CREATE INDEX IF NOT EXISTS "idx_user_task_summary_mv_user" ON "user_task_summary_mv" ("user_id");
      CREATE INDEX IF NOT EXISTS "idx_user_task_summary_mv_date" ON "user_task_summary_mv" ("snapshot_date");
    `);

    // Database configuration optimizations
    await queryRunner.query(`
      -- Enable auto-vacuum for better performance
      ALTER TABLE tasks SET (autovacuum_vacuum_scale_factor = 0.1);
      ALTER TABLE users SET (autovacuum_vacuum_scale_factor = 0.1);
    `);

    await queryRunner.query(`
      -- Increase statistics target for better query planning
      ALTER TABLE tasks ALTER COLUMN status SET STATISTICS 1000;
      ALTER TABLE tasks ALTER COLUMN user_id SET STATISTICS 1000;
      ALTER TABLE tasks ALTER COLUMN due_date SET STATISTICS 1000;
      ALTER TABLE users ALTER COLUMN email SET STATISTICS 1000;
      ALTER TABLE users ALTER COLUMN role SET STATISTICS 1000;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop materialized views
    await queryRunner.query(`DROP MATERIALIZED VIEW IF EXISTS "user_task_summary_mv"`);
    await queryRunner.query(`DROP MATERIALIZED VIEW IF EXISTS "task_statistics_mv"`);

    // Drop performance indexes
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_name_lower"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_email_lower"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_created_role"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_email_role_active"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_stats"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_created_status"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_text_search"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_overdue_active"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_user_status_priority"`);
    
    // Drop materialized view indexes
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_task_summary_mv_date"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_user_task_summary_mv_user"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "idx_task_statistics_mv_date"`);

    // Reset statistics targets
    await queryRunner.query(`ALTER TABLE tasks ALTER COLUMN status SET STATISTICS -1`);
    await queryRunner.query(`ALTER TABLE tasks ALTER COLUMN user_id SET STATISTICS -1`);
    await queryRunner.query(`ALTER TABLE tasks ALTER COLUMN due_date SET STATISTICS -1`);
    await queryRunner.query(`ALTER TABLE users ALTER COLUMN email SET STATISTICS -1`);
    await queryRunner.query(`ALTER TABLE users ALTER COLUMN role SET STATISTICS -1`);

    // Reset autovacuum settings
    await queryRunner.query(`ALTER TABLE tasks RESET (autovacuum_vacuum_scale_factor)`);
    await queryRunner.query(`ALTER TABLE users RESET (autovacuum_vacuum_scale_factor)`);
  }
}