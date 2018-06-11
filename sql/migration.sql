ALTER TABLE users ADD COLUMN receive_emails_enabled BOOL DEFAULT True;
ALTER TABLE users ADD COLUMN username TEXT UNIQUE;
ALTER TABLE users ADD COLUMN active BOOL DEFAULT False;
ALTER TABLE users ADD COLUMN activation_key UUID DEFAULT uuid_generate_v4 () UNIQUE;
ALTER TABLE users ADD UNIQUE phone_number;
ALTER TABLE contact_transactions ADD COLUMN created TIMESTAMP(0);
ALTER TABLE contact_transactions ADD COLUMN confirmed BOOL DEFAULT NULL;
ALTER TABLE contact_transactions RENAME COLUMN to_email_address TO recipient;

CREATE TYPE e_currency AS ENUM (
    'ETH',
    'BTC'
)

CREATE TABLE IF NOT EXISTS public_addresses (
    user_id INTEGER REFERENCES users(id),
    currency e_currency,
    address TEXT,
    CONSTRAINT pk_addresses PRIMARY KEY (user_id, currency)
)

CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER REFERENCES users(id) PRIMARY KEY,
    reset_token UUID DEFAULT NULL UNIQUE,
    reset_token_creation_time TIMESTAMP,
    email_address TEXT REFERENCES users(email_address)
);

CREATE TABLE IF NOT EXISTS contact_transactions (
    id SERIAL PRIMARY KEY,
    uid UUID DEFAULT uuid_generate_v4 () UNIQUE,
    recipient TEXT,
    user_id INTEGER REFERENCES users(id),
    currency e_currency,
    amount FLOAT,
    created TIMESTAMP(0),
    confirmed BOOL DEFAULT NULL,
    created TIMESTAMP(0)
);
