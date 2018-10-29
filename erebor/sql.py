PASSWORD_ACCESS_SQL = """
SELECT
  crypt($1, password) = password AS accessed, id, sms_2fa_enabled,
  phone_number, uid::text
FROM users
WHERE email_address = LOWER($2)
OR username = LOWER($2)
""".strip()

RESET_TOKEN_CREATION_SQL = """
INSERT INTO reset_tokens
    (user_id, reset_token, reset_token_creation_time)
SELECT
     users.id, uuid_generate_v4(), CURRENT_TIMESTAMP
FROM users
WHERE email_address = LOWER($1)
ON CONFLICT (user_id) DO UPDATE
SET reset_token = uuid_generate_v4(),
    reset_token_creation_time = CURRENT_TIMESTAMP
RETURNING reset_token
""".strip()

SELECT_RESET_TOKEN_SQL = """
SELECT user_id
FROM reset_tokens
WHERE reset_token = $1
AND reset_token_creation_time + interval '1 hour' > $2
""".strip()

EXPIRE_RESET_TOKEN_SQL = """
UPDATE reset_tokens
SET reset_token = NULL
WHERE reset_token = $1
"""

SELECT_2FA_SETTINGS_SQL = """
SELECT sms_2fa_enabled FROM users WHERE id = $1
""".strip()

UPDATE_2FA_SETTINGS_SQL = """
UPDATE users
SET sms_2fa_enabled = $1
WHERE id = $2
""".strip()

SELECT_USER_SQL = """
SELECT uid::text, first_name, last_name, phone_number,
       email_address, username, sms_2fa_enabled
FROM users
WHERE id = $1
""".strip()

UPDATE_USER_SQL = """
UPDATE users
SET first_name = $1, last_name = $2, phone_number = $3,
    email_address = LOWER($4), username = LOWER($5)
WHERE id = $6
""".strip()

SELECT_EMAIL_PREFS_SQL = """
SELECT receive_emails_enabled
FROM users
WHERE id = $1
""".strip()

UPDATE_EMAIL_PREFS_SQL = """
UPDATE users
SET receive_emails_enabled = $1
WHERE id = $2
""".strip()

CREATE_USER_SQL = """
WITH x AS (
  SELECT $1::text as password,
    gen_salt('bf')::text AS salt
),
user_ins AS (
INSERT INTO users (password, salt, first_name, last_name, email_address,
                   username, phone_number, register_date)
SELECT crypt(x.password, x.salt), x.salt, $2, $3, LOWER($4), LOWER($5), $6,
       now()
FROM x
RETURNING *
),
device_ins AS (
INSERT INTO devices (user_id, user_uid, session_id, ip, device_type, channel,
                     date)
SELECT user_ins.id, user_ins.uid, $7, $8, $9, $10, CURRENT_TIMESTAMP
FROM user_ins
)
SELECT * FROM user_ins
""".strip()

PRE_REGISTER_USER_SQL = """
INSERT INTO pre_register (email_address, username)
SELECT LOWER($1), LOWER($2)
WHERE NOT EXISTS (
    SELECT * FROM blacklist WHERE username = LOWER($2)
)
RETURNING *
""".strip()

CHANGE_PASSWORD_SQL = """
WITH x AS (
  SELECT $1::text as password,
    gen_salt('bf')::text AS salt
)
UPDATE users
SET password = crypt(x.password, x.salt), salt = x.salt
FROM x
WHERE id = $2
""".strip()

USER_ID_SQL = """
SELECT user_id, user_uid::text, channel
FROM devices
WHERE session_id = $1
""".strip()

LOGOUT_SQL = """
UPDATE devices
SET session_id = NULL
WHERE user_id = $1
AND channel = $2
""".strip()

LOGIN_SQL = """
WITH device_upsert AS (
    UPDATE devices
    SET session_id = $1, date = now()
    WHERE user_id = $2
    AND channel = $3
    RETURNING *
)
INSERT INTO devices (user_id, user_uid, device_type, channel,
                     session_id, ip, date)
SELECT $2, $4, $5, $3, $1, $6, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT * FROM device_upsert)
""".strip()

SET_2FA_CODE_SQL = """
UPDATE users
SET sms_verification = $1
WHERE id = $2
""".strip()

VERIFY_SMS_LOGIN = """
UPDATE users
SET sms_verification = Null
WHERE (email_address = LOWER($1) OR username = LOWER($1))
       AND sms_verification = $2
RETURNING users.id, users.uid::text
""".strip()

CREATE_IV_SQL = """
INSERT INTO identity_verifications (scan_reference, data)
VALUES ($1, $2::json)
""".strip()

IV_RESULTS_SQL = """
SELECT data
FROM identity_verifications
WHERE scan_reference = $1
""".strip()

CREATE_CONTACT_TRANSACTION_SQL = """
INSERT INTO contact_transactions (user_id, recipient,
                                  currency, amount, created, transaction_type)
VALUES ($1, $2, $3, $4, now(), $5)
RETURNING uid::text
""".strip()

SELECT_CONTACT_TRANSACTIONS = """
SELECT users.email_address, users.first_name,
       json_agg(
            json_build_object(
                'recipient', c.recipient,
                'currency', c.currency,
                'amount', c.amount,
                'created', TO_CHAR(date_trunc(
                    'minute', c.created), 'Mon dd, yyyy - hh12:miAM')))
       as transactions
FROM users
LEFT JOIN contact_transactions c ON c.user_id = users.id
WHERE c.user_id = users.id
AND (LOWER(c.recipient) = LOWER($1)
     OR LOWER(c.recipient) = LOWER($2))
GROUP BY users.id
""".strip()

SELECT_ALL_CONTACT_TRANSACTIONS = """
SELECT uid::text, recipient, currency, amount, created, status,
       transaction_type, transaction_hash
FROM contact_transactions
WHERE user_id = $1
"""

SELECT_CONTACT_TRANSACTION_DATA = """
SELECT  uid::text, recipient, currency, amount, created, status,
        transaction_type, transaction_hash, last_notified
FROM contact_transactions
WHERE uid = $1
""".strip()

SELECT_CONTACT_TRANSACTION_RENOTIFY = """
UPDATE contact_transactions
SET last_notified = now()
WHERE uid = $1
AND last_notified + interval '1 day' < now()
RETURNING *
""".strip()

SELECT_RECIPIENT_STATUS_SQL = """
SELECT users.username, users.email_address,
       users.phone_number, addresses.address, addresses.currency
FROM contact_transactions as transactions, users, public_addresses as addresses
WHERE transactions.uid = $1
AND (transactions.recipient = users.username OR
     transactions.recipient = users.email_address OR
     transactions.recipient = users.phone_number)
AND users.active = True
AND addresses.currency::text = transactions.currency::text
AND addresses.user_id = users.id
""".strip()

UPDATE_TRANSACTION_CONFIRMATION_SQL = """
UPDATE contact_transactions
SET status = $1, transaction_hash = $2
WHERE uid = $3
RETURNING *
""".strip()

REGISTER_ADDRESS_SQL = """
INSERT INTO public_addresses (user_id, currency, address)
VALUES ($1, $2, $3)
ON CONFLICT ON CONSTRAINT pk_addresses DO UPDATE
SET address = $3
""".strip()

SELECT_ADDRESS_SQL = """
SELECT public_addresses.address, public_addresses.currency, users.email_address
FROM public_addresses, users
WHERE public_addresses.user_id = users.id
AND public_addresses.currency = $1
AND (users.email_address = LOWER($2)
     OR users.username = LOWER($2)
     OR users.phone_number = $2)
""".strip()

SELECT_EMAIL_AND_FNAME_SQL = """
SELECT email_address, first_name
FROM users
WHERE id = $1
""".strip()

SELECT_EMAIL_FROM_USERNAME_OR_PHONE_SQL = """
SELECT email_address
FROM users
WHERE username = LOWER($1)
OR phone_number = $1
""".strip()

SELECT_USERNAME_FNAME_FROM_EMAIL_SQL = """
SELECT username, first_name
FROM users
WHERE email_address = LOWER($1)
""".strip()

ACTIVATE_USER_SQL = """
UPDATE users
SET active = True
WHERE activation_key = $1
AND active = False
RETURNING email_address, first_name, last_name
""".strip()

ACTIVATE_PRE_REG_SQL = """
UPDATE pre_register
SET active = True
WHERE activation_key = $1
AND active = False
RETURNING email_address, username
""".strip()

INSERT_VOTE_SQL = """
WITH coin AS (
    SELECT symbol, name
    FROM supported_coins
    WHERE symbol = UPPER($1)
)
INSERT INTO votes (name, symbol, ip)
SELECT coin.name, coin.symbol, $2
FROM coin
""".strip()

SELECT_ALL_VOTES_SQL = """
SELECT votes.symbol, votes.name, count(votes.name) as votes, s.round_won
FROM votes, supported_coins as s
WHERE votes.symbol = s.symbol
GROUP BY votes.name, votes.symbol, s.round_won
ORDER BY votes ASC
""".strip()

SELECT_ALL_VOTES_INTERVAL_SQL = """
SELECT symbol, name, count(name) as votes FROM votes
WHERE date > (now() - $1::interval)
GROUP BY name, symbol
ORDER BY votes ASC
"""

SELECT_ALL_SUPPORTED_COINS_SQL = """
SELECT * FROM supported_coins
ORDER BY name
""".strip()

REGISTER_DEVICE_SQL = """
INSERT INTO devices (user_id, user_uid, device_type, channel)
VALUES ($1, $2, $3, $4)
""".strip()

SELECT_DEVICE_BY_EMAIL_SQL = """
SELECT devices.device_type, devices.channel, users.email_address
FROM devices, users
WHERE users.email_address = $1
AND users.id = devices.user_id
AND devices.device_type != 'api'
AND devices.session_id IS NOT NULL
""".strip()

SELECT_DEVICE_BY_USER_ID_SQL = """
SELECT devices.device_type, devices.channel
FROM devices
WHERE user_id = $1
AND device_type != 'api'
AND session_id IS NOT NULL
""".strip()

GET_SESSIONS_SQL = """
SELECT device_type, date, ip
FROM devices
WHERE user_id = $1
""".strip()

DESTROY_SESSIONS_SQL = """
UPDATE devices
SET session_id = NULL
WHERE user_id = $1
""".strip()
