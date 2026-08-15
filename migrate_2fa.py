import sqlite3

conn = sqlite3.connect("phishiq.db")
cur = conn.cursor()

existing_cols = [row[1] for row in cur.execute("PRAGMA table_info(user)").fetchall()]

if "totp_secret" not in existing_cols:
    cur.execute("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)")
    print("Added totp_secret column")

if "totp_enabled" not in existing_cols:
    cur.execute("ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN DEFAULT 0")
    print("Added totp_enabled column")

if "backup_codes" not in existing_cols:
    cur.execute("ALTER TABLE user ADD COLUMN backup_codes TEXT")
    print("Added backup_codes column")

conn.commit()
conn.close()
print("Migration complete.")
