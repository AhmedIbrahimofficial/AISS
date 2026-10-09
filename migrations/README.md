# AISS — Database Migrations

## Quick Start with Supabase

1. **Create a Supabase project** at [supabase.com](https://supabase.com)

2. **Run the schema** in the Supabase SQL Editor:
   - Go to **SQL Editor → New query**
   - Paste the contents of `001_full_schema.sql`
   - Click **Run**

3. **Get your connection string**:
   - Go to **Project Settings → Database → Connection string**
   - Copy the **URI** under "Transaction" mode (port 6543) for best compatibility
   - It looks like: `postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres`

4. **Set in your `.env`**:
   ```
   DATABASE_URL=postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
   ```

5. **Start the backend** — it will connect to Supabase automatically:
   ```bash
   cd "aiss backend"
   python main.py
   ```

## Notes

- The schema is **idempotent** — safe to run multiple times (`IF NOT EXISTS` everywhere)
- Row Level Security is enabled on all tables with a service-role bypass policy
- The backend auto-creates a default admin on first startup (`admin@aiss-platform.com` / `Admin123!`)
- **Change the default admin password** immediately after first login

## Switching databases

Change `DATABASE_URL` in `.env`:

| Database | URL format |
|----------|-----------|
| Supabase (recommended) | `postgresql://postgres.[ref]:[pass]@[host].pooler.supabase.com:6543/postgres` |
| Local PostgreSQL | `postgresql://postgres:password@localhost:5432/aiss_db` |
| Local SQLite (dev only) | `sqlite+aiosqlite:///./logs/cybersecurity.db` |
| MySQL | `mysql+aiomysql://user:pass@localhost/aiss_db` |
