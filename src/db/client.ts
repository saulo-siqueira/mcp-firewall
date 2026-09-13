import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';

export const createDatabase = (connectionString = process.env.DATABASE_URL) => {
  if (!connectionString) return null;
  const pool = new pg.Pool({ connectionString, max: 5 });
  return { db: drizzle(pool), pool };
};
