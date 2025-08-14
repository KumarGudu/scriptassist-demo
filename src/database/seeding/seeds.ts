import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import { User } from '../../modules/users/entities/user.entity';
import { Task } from '../../modules/tasks/entities/task.entity';
import { users } from './seed-data/users.seed';
import { tasks } from './seed-data/tasks.seed';

// Load environment variables
config();

// Define the data source
const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_DATABASE || 'taskflow',
  entities: [User, Task],
  synchronize: false,
});

// Initialize and seed database
async function main() {
  try {
    console.log('Starting database seeding process...');
    
    // Initialize connection
    console.log('Initializing database connection...');
    await AppDataSource.initialize();
    console.log('Database connection initialized successfully');

    // Clear existing data
    console.log('Clearing existing data...');
    await AppDataSource.getRepository(Task).delete({});
    console.log('Tasks cleared');
    await AppDataSource.getRepository(User).delete({});
    console.log('Users cleared');

    // Seed users
    console.log('Seeding users...');
    console.log('Users to seed:', users.length);
    const savedUsers = await AppDataSource.getRepository(User).save(users);
    console.log('Users seeded successfully:', savedUsers.length);

    // Seed tasks
    console.log('Seeding tasks...');
    console.log('Tasks to seed:', tasks.length);
    const savedTasks = await AppDataSource.getRepository(Task).save(tasks);
    console.log('Tasks seeded successfully:', savedTasks.length);

    console.log('Database seeding completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error during database seeding:', error);
    console.error('Error stack:', (error as any).stack);
    process.exit(1);
  } finally {
    // Close connection
    try {
      await AppDataSource.destroy();
      console.log('Database connection closed');
    } catch (closeError) {
      console.error('Error closing database connection:', closeError);
    }
  }
}

// Run the seeding
main(); 