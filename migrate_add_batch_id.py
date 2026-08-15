"""
Adds a nullable batch_id column to the async_scan_job table, used to
group multiple AsyncScanJob rows submitted together via the batch API.

db.create_all() only creates missing tables, not missing columns on
existing tables, so this raw ALTER TABLE step is needed since the
project doesn't use Alembic/Flask-Migrate.

Safe to run multiple times - checks if the column already exists first.

Run this from the PhishIQ project root:
    python migrate_add_batch_id.py
"""

from app import app, db
from sqlalchemy import inspect, text

with app.app_context():
    insp = inspect(db.engine)
    columns = [col["name"] for col in insp.get_columns("async_scan_job")]

    if "batch_id" in columns:
        print("batch_id column already exists - nothing to do")
    else:
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE async_scan_job ADD COLUMN batch_id VARCHAR(36)"))
            conn.commit()
        print("batch_id column added to async_scan_job")

        # Index it too, since batch status lookups will filter by this column.
        with db.engine.connect() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_async_scan_job_batch_id "
                "ON async_scan_job (batch_id)"
            ))
            conn.commit()
        print("Index added on batch_id")
