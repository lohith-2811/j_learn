import { createClient } from '@libsql/client';
import dotenv from 'dotenv';

dotenv.config();

const db = createClient({
  url: process.env.DATABASE_URL,
  authToken: process.env.DATABASE_AUTH_TOKEN,
});

export async function initDB() {
  await db.batch([
    {
      sql: `
        CREATE TABLE IF NOT EXISTS user_profiles (
          user_id INTEGER PRIMARY KEY AUTOINCREMENT,
          username VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL UNIQUE,
          password_hash VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `
    },
    {
      sql: `
        CREATE TABLE IF NOT EXISTS user_progress (
          user_id INTEGER,
          language VARCHAR(50),
          level INTEGER,
          module_id INTEGER,
          lesson_id INTEGER,
          is_completed BOOLEAN DEFAULT FALSE,
          current_question_index INTEGER DEFAULT 0,
          last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (user_id, language, level, module_id, lesson_id),
          FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
        )
      `
    },
    {
      sql: `
        CREATE TABLE IF NOT EXISTS user_achievements (
          user_id INTEGER PRIMARY KEY,
          xp_points INTEGER DEFAULT 0,
          FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
        )
      `
    }
  ]);
}

export function getDB() {
  return db;
}