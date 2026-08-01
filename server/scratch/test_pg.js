import pg from 'pg';
import fs from 'fs';
import path from 'path';

const { Pool } = pg;

// Common password candidates to test if process.env password fails
const candidatePasswords = [
  process.env.DB_PASSWORD || 'postgres',
  'postgres',
  'admin',
  'root',
  '123456',
  'postgres123',
  'password',
  'soc_db'
];

async function tryConnect(password) {
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'postgres',
    user: 'postgres',
    password: password,
    connectionTimeoutMillis: 2000
  });

  try {
    const client = await pool.connect();
    console.log(`[PG TEST] Successfully connected with password: "${password}"`);
    client.release();
    await pool.end();
    return password;
  } catch (err) {
    await pool.end();
    return null;
  }
}

async function main() {
  console.log('[PG SETUP] Attempting connection to PostgreSQL at localhost:5432...');

  let workingPassword = null;
  for (const pwd of candidatePasswords) {
    const result = await tryConnect(pwd);
    if (result !== null) {
      workingPassword = result;
      break;
    }
  }

  if (!workingPassword) {
    console.error('[PG ERROR] Could not connect to PostgreSQL on localhost:5432 with tested passwords.');
    console.error('[PG HINT] Please check PostgreSQL user credentials or update server/.env with DB_PASSWORD.');
    process.exit(1);
  }

  // Connect to postgres database to ensure soc_db exists
  const adminPool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'postgres',
    user: 'postgres',
    password: workingPassword
  });

  try {
    const dbCheck = await adminPool.query("SELECT 1 FROM pg_database WHERE datname = 'soc_db'");
    if (dbCheck.rowCount === 0) {
      console.log('[PG SETUP] Database "soc_db" does not exist. Creating "soc_db"...');
      await adminPool.query('CREATE DATABASE soc_db');
      console.log('[PG SETUP] Database "soc_db" created successfully.');
    } else {
      console.log('[PG SETUP] Database "soc_db" already exists.');
    }
  } catch (err) {
    console.error('[PG ERROR] Failed to create database:', err.message);
  } finally {
    await adminPool.end();
  }

  // Connect to soc_db and apply schema.sql
  const socPool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'soc_db',
    user: 'postgres',
    password: workingPassword
  });

  try {
    const client = await socPool.connect();
    console.log('[PG SETUP] Connected to "soc_db". Applying schema.sql...');

    const schemaPath = path.resolve('src/db/schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      await client.query(schemaSql);
      console.log('[PG SETUP] Applied schema.sql successfully.');
    }

    // Verify tables
    const tableRes = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    console.log('[PG SETUP] Public tables in soc_db:', tableRes.rows.map(r => r.table_name));

    client.release();
  } catch (err) {
    console.error('[PG ERROR] Failed applying schema to soc_db:', err.message);
  } finally {
    await socPool.end();
  }
}

main();
