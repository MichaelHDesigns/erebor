CREATE_REGISTRATIONS_TABLE_SQL = """
CREATE TABLE registrations (
    id SERIAL PRIMARY KEY,
    full_name TEXT,
    email_address TEXT,
    uid UUID DEFAULT uuid_generate_v4 ()
);
""".strip()

CREATE_USERS_TABLE_SQL = """
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    password TEXT,
    salt TEXT,
    full_name TEXT,
    email_address TEXT,
    uid UUID DEFAULT uuid_generate_v4 (),
    api_key TEXT
);
""".strip()
