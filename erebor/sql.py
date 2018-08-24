PASSWORD_ACCESS_SQL = """
SELECT
  crypt($1, password) = password AS accessed, id, sms_2fa_enabled,
  phone_number, uid::text
FROM users
WHERE email_address = $2
OR username = $2
""".strip()

RESET_TOKEN_CREATION_SQL = """
INSERT INTO reset_tokens
    (user_id, reset_token, reset_token_creation_time)
SELECT
     users.id, uuid_generate_v4(), CURRENT_TIMESTAMP
FROM users
WHERE email_address = $1
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
SET first_name = $1, last_name = $2, phone_number = $3, email_address = $4,
    username = $5
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
)
INSERT INTO users (password, salt, first_name, last_name, email_address,
                   username, phone_number, session_id, register_date)
SELECT crypt(x.password, x.salt), x.salt, $2, $3, $4, $5, $6, $7, now()
FROM x
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
SELECT id, uid::text
FROM users
WHERE session_id = $1
""".strip()

LOGOUT_SQL = """
UPDATE users
SET session_id = NULL
WHERE id = $1
""".strip()

LOGIN_SQL = """
UPDATE users
SET session_id = $1
WHERE id = $2
""".strip()

SET_2FA_CODE_SQL = """
UPDATE users
SET sms_verification = $1
WHERE id = $2
""".strip()

VERIFY_SMS_LOGIN = """
UPDATE users
SET sms_verification = Null
WHERE (email_address = $1 OR username = $1) AND sms_verification = $2
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
                                  currency, amount, created)
VALUES ($1, $2, $3, $4, now())
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
AND (c.recipient = $1
     OR c.recipient = $2)
GROUP BY users.id
""".strip()

SELECT_ALL_CONTACT_TRANSACTIONS = """
SELECT uid::text, recipient, currency, amount, created, status
FROM contact_transactions
WHERE user_id = $1
"""

SELECT_CONTACT_TRANSACTION_DATA = """
SELECT  uid::text, recipient, currency, amount, created, status
FROM contact_transactions
WHERE uid = $1
""".strip()

UPDATE_TRANSACTION_CONFIRMATION_SQL = """
UPDATE contact_transactions
SET status = $1, transaction_hash = $2
WHERE uid = $3
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
AND (users.email_address = $2
     OR users.username = $2
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
WHERE username = $1
OR phone_number = $1
""".strip()

SELECT_USERNAME_FNAME_FROM_EMAIL_SQL = """
SELECT username, first_name
FROM users
WHERE email_address = $1
""".strip()

ACTIVATE_USER_SQL = """
UPDATE users
SET active = True
WHERE activation_key = $1
AND active = False
RETURNING email_address, first_name, last_name
""".strip()

SELECT_PRICES_SQL = """
SELECT *
FROM prices
WHERE date >= $1 AND date <= $2
""".strip()
