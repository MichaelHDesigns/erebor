CREATE_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    password TEXT,
    salt TEXT,
    first_name TEXT,
    last_name TEXT,
    email_address TEXT UNIQUE,
    receive_emails_enabled BOOL DEFAULT True,
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
    scan_reference TEXT
);
""".strip()

CREATE_RESET_TOKENS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER REFERENCES users(id) PRIMARY KEY,
    reset_token UUID DEFAULT NULL UNIQUE,
    reset_token_creation_time TIMESTAMP,
    email_address TEXT REFERENCES users(email_address)
);
""".strip()
