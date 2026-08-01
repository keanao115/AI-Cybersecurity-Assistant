import pg from 'pg';
const { Pool } = pg;

async function main() {
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'postgres',
    user: 'postgres',
  });

  try {
    await pool.query("ALTER USER postgres WITH PASSWORD 'postgres'");
    console.log('[PG OK] Postgres password explicitly set to "postgres".');
  } catch (err) {
    console.error('[PG ERR]', err.message);
  } finally {
    await pool.end();
  }
}

main();
