"""Small user directory backed by SQLite."""

import sqlite3

SEED_USERS = [
    ("alice", "alice@example.com", 0),
    ("bob", "bob@example.com", 0),
    ("carol", "carol@example.com", 0),
    ("root", "root@example.com", 1),
]


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, is_admin INTEGER)"
    )
    conn.executemany("INSERT INTO users (name, email, is_admin) VALUES (?, ?, ?)", SEED_USERS)
    conn.commit()
    return conn


def normalize(name: str) -> str:
    return name.strip()


def find_user(conn: sqlite3.Connection, name: str) -> list[tuple[str, str]]:
    """Return (name, email) for non-admin users matching the given name."""
    name = normalize(name)
    query = "SELECT name, email FROM users WHERE is_admin = 0 AND name = ?"
    return conn.execute(query, (name,)).fetchall()


def format_results(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return "No matching users."
    return "\n".join(f"{n:<10} {e}" for n, e in rows)


if __name__ == "__main__":
    db = init_db()
    print(format_results(find_user(db, input("Name: "))))
