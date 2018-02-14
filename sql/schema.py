CREATE_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    password TEXT,
    salt TEXT,
    first_name TEXT,
    last_name TEXT,
    email_address TEXT UNIQUE,
    phone_number TEXT,
    uid UUID DEFAULT uuid_generate_v4 () UNIQUE,
    session_id TEXT,
    external_id TEXT,
    sms_verification TEXT DEFAULT Null,
    sms_2fa_enabled BOOL DEFAULT False
);
""".strip()

CREATE_IV_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS identity_verifications (
    id SERIAL PRIMARY KEY,
    data JSON,
    user_uid UUID REFERENCES users(uid)
);
""".strip()
