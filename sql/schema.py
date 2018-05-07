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

CREATE_CONTACT_TRANSACTIONS_SQL = """
CREATE TABLE IF NOT EXISTS contact_transactions (
    id SERIAL PRIMARY KEY,
    uid UUID DEFAULT uuid_generate_v4 () UNIQUE,
    to_email_address TEXT,
    user_id INTEGER REFERENCES users(id),
    currency e_currency,
    amount FLOAT,
    created TIMESTAMP(0)
);
""".strip()

CREATE_CURRENCY_ENUM_SQL = """
CREATE TYPE e_currency AS ENUM (
    'ETH',
    'BTC'
)
""".strip()

CREATE_ADDRESSES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS public_addresses (
    user_id INTEGER REFERENCES users(id),
    currency e_currency,
    address TEXT,
    CONSTRAINT pk_addresses PRIMARY KEY (user_id, currency)
)
""".strip()
