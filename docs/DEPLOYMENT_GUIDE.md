# Enterprise Deployment Guide

## Production Deployment Checklist

1. **Host Prerequisites**:
   - Node.js v18+ & npm
   - PostgreSQL 16+ running on `localhost:5432` with database `soc_db`
   - Npcap (Windows) or `libpcap-dev` (Linux: `sudo apt install libpcap-dev`)

2. **Environment Setup**:
   Copy `.env.live.example` to `.env`:
   ```bash
   cp .env.live.example .env
   ```

3. **Database Initialization**:
   Execute `server/src/db/schema.sql` against PostgreSQL:
   ```bash
   psql -U postgres -d soc_db -f server/src/db/schema.sql
   ```

4. **Start Backend Operations Center**:
   ```bash
   cd server
   npm install
   npm run dev
   ```

5. **Start Frontend Dashboard**:
   ```bash
   npm install
   npm run dev
   ```
