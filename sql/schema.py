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
    session_id TEXT,
    external_id TEXT,
    sms_verification TEXT DEFAULT Null,
    sms_2fa_enabled BOOL DEFAULT False
);
""".strip()
