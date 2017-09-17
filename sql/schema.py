CREATE_REGISTRATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS registrations (
    id SERIAL PRIMARY KEY,
    full_name TEXT,
    email_address TEXT,
    uid UUID DEFAULT uuid_generate_v4 ()
);
""".strip()

CREATE_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    password TEXT,
    salt TEXT,
    first_name TEXT,
    last_name TEXT,
    email_address TEXT,
    phone_number TEXT,
    uid UUID DEFAULT uuid_generate_v4 (),
    api_key TEXT
);
""".strip()
