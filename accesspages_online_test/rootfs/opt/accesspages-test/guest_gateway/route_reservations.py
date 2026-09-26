"""Short-lived provisioning intents; these never authorize a guest."""
from contextlib import closing
from pathlib import Path
import sqlite3
import time

RESERVATION_SECONDS = 180


def reserve(directory, page, instance, token_hash):
    with closing(sqlite3.connect(Path(directory) / 'nhp-links.db', timeout=10)) as conn, conn:
        conn.execute('CREATE TABLE IF NOT EXISTS pending_routes(token_hash TEXT PRIMARY KEY,page_id TEXT NOT NULL,instance_id TEXT NOT NULL,expires INTEGER NOT NULL)')
        conn.execute('DELETE FROM pending_routes WHERE expires<=?', (int(time.time()),))
        conn.execute('INSERT INTO pending_routes VALUES(?,?,?,?)',
                     (token_hash, page, instance, int(time.time()) + RESERVATION_SECONDS))


def pending(directory):
    path = Path(directory) / 'nhp-links.db'
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='pending_routes'").fetchone():
            return []
        return [{'page_id': p, 'instance_id': i, 'guest_hash': h}
                for p, i, h in conn.execute('SELECT page_id,instance_id,token_hash FROM pending_routes WHERE expires>?', (int(time.time()),))]


def cancel(directory, token_hash=None):
    path = Path(directory) / 'nhp-links.db'
    if not path.exists():
        return
    with closing(sqlite3.connect(path, timeout=10)) as conn, conn:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='pending_routes'").fetchone():
            if token_hash is None:
                conn.execute('DELETE FROM pending_routes')
            else:
                conn.execute('DELETE FROM pending_routes WHERE token_hash=?', (token_hash,))
