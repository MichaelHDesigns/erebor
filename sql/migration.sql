ALTER TABLE users ADD COLUMN receive_emails_enabled BOOL DEFAULT True;

CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER REFERENCES users(id) PRIMARY KEY,
    reset_token UUID DEFAULT NULL UNIQUE,
    reset_token_creation_time TIMESTAMP,
    email_address TEXT REFERENCES users(email_address)
);
