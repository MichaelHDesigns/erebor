from uuid import uuid4
from functools import wraps
from hashlib import sha1
from datetime import datetime as dt
import datetime
import json
import hmac
import logging
import os
import random
import re

from asyncpg.exceptions import UniqueViolationError
from sanic import Sanic, response
from sanic.log import LOGGING_CONFIG_DEFAULTS
from sanic_cors import CORS
from sanic_limiter import Limiter, get_remote_address, RateLimitExceeded
from twilio.rest import Client
import requests
from zenpy import Zenpy
from zenpy.lib.api_objects import Ticket, User
import boto3
from botocore.exceptions import ClientError

from erebor.errors import (error_response, MISSING_FIELDS, UNAUTHORIZED,
                           SMS_VERIFICATION_FAILED, INVALID_CREDENTIALS,
                           INVALID_API_KEY, PASSWORD_TARGET, PASSWORD_CHECK,
                           TICKER_UNAVAILABLE, GENERIC_USER, EXPIRED_TOKEN,
                           INVALID_PLATFORM, RATE_LIMIT_EXCEEDED,
                           INSUFFICIENT_BALANCE, NEGATIVE_AMOUNT,
                           UNSUPPORTED_CURRENCY, INVALID_USERNAME,
                           NO_PUBLIC_KEY, INVALID_EMAIL, USER_NOT_FOUND,
                           USERNAME_EXISTS, EMAIL_ADDRESS_EXISTS,
                           INVALID_TRANSACTION_UID)
from erebor.email import Email
from erebor.render import (unsubscribe_template, result_template,
                           password_template, RESULT_ACTIONS)
from erebor.logs import logging_config
from erebor.db import bp
from erebor.blockchain import get_symbol, get_balance


ETH_NETWORK = (os.environ.get("ETH_NETWORK") if not os.getenv('erebor_test')
               else 'ropsten')
INFURA_API_KEY = os.environ.get("INFURA_API_KEY")


app = Sanic(log_config=logging_config
            if not os.getenv('erebor_test') else LOGGING_CONFIG_DEFAULTS)
CORS(app, automatic_options=True)

limiter = Limiter(app,
                  global_limits=['50 per minute'],
                  key_func=get_remote_address)

email_pattern = re.compile('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
username_pattern = re.compile('[^\w]')

btc_usd_latest = None
eth_usd_latest = None
ticker_last_update = None

android_updates = {}
ios_updates = {}


def refresh_ticker():
    global btc_usd_latest
    global eth_usd_latest
    global ticker_last_update
    if ticker_last_update is None or (dt.utcnow() > ticker_last_update +
                                      datetime.timedelta(seconds=2)):
        r_btc = requests.get('https://api.gdax.com/products/BTC-USD/ticker')
        r_btc_data = r_btc.json()
        if 'price' in r_btc_data.keys():
            btc_usd_latest = r_btc_data['price']
        else:
            logging.error('GDAX BTC-USD ticker error: {}'.format(r_btc_data))
            btc_usd_latest = None
            eth_usd_latest = None
            return
        r_eth = requests.get('https://api.gdax.com/products/ETH-USD/ticker')
        r_eth_data = r_eth.json()
        if 'price' in r_eth_data.keys():
            eth_usd_latest = r_eth_data['price']
        else:
            logging.error('GDAX ETH-USD ticker error: {}'.format(r_eth_data))
            btc_usd_latest = None
            eth_usd_latest = None
            return
        ticker_last_update = dt.utcnow()


def create_zendesk_ticket(description,
                          user_info,
                          subject=None,
                          recipient=None,
                          requester=None):
    zd_credentials = {'email': os.environ.get('ZD_EMAIL'),
                      'token': os.environ.get('ZD_TOKEN'),
                      'subdomain': os.environ.get('ZD_SUBDOMAIN')}
    zenpy_client = Zenpy(**zd_credentials)
    zenpy_client.tickets.create(
        Ticket(subject=subject,
               recipient=recipient,
               requester=requester,
               description=json.dumps({"user_info": user_info,
                                       "data": description})))


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
    (id, reset_token, reset_token_creation_time,
     email_address)
SELECT
     users.id, uuid_generate_v4(), CURRENT_TIMESTAMP,
     users.email_address
FROM users
WHERE email_address = $1
ON CONFLICT (id) DO UPDATE
SET reset_token = uuid_generate_v4(),
    reset_token_creation_time = CURRENT_TIMESTAMP
RETURNING reset_token, email_address
""".strip()

SELECT_RESET_TOKEN_SQL = """
SELECT email_address, id
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
                   username, phone_number, session_id)
SELECT crypt(x.password, x.salt), x.salt, $2, $3, $4, $5, $6, $7
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
AND ($2 is False OR active = $2)
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
INSERT INTO contact_transactions (user_id, to_email_address,
                                  currency, amount, created)
VALUES ($1, $2, $3, $4, now())
""".strip()

SELECT_CONTACT_TRANSACTIONS = """
SELECT users.email_address, users.first_name, c_trans.to_email_address,
       c_trans.currency, c_trans.amount,
       date_trunc('minute', c_trans.created) created
FROM contact_transactions as c_trans, users
WHERE c_trans.user_id = users.id
AND c_trans.to_email_address = $1
""".strip()

SELECT_CONTACT_TRANSACTION_DATA = """
SELECT to_email_address, currency, amount, created
FROM contact_transactions
WHERE uid = $1
""".strip()

UPDATE_TRANSACTION_CONFIRMATION_SQL = """
UPDATE contact_transactions
SET confirmed = $1
WHERE uid = $2
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
     OR users.username = $2)
""".strip()

SELECT_EMAIL_AND_FNAME_SQL = """
SELECT email_address, first_name
FROM users
WHERE id = $1
""".strip()

SELECT_EMAIL_FROM_USERNAME_SQL = """
SELECT email_address
FROM users
WHERE username = $1
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


def authorized(active_required=False):
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            db = app.pg
            cookie = request.cookies.get('session_id')
            if cookie:
                user_ids = await db.fetchrow(USER_ID_SQL, cookie,
                                             active_required)
                if user_ids is not None:
                    request['session'] = {'user_id': user_ids['id'],
                                          'user_uid': user_ids['uid']}
                    request['db'] = app.pg
                    res = await f(request, *args, **kwargs)
                    return res
                else:
                    error_response([INVALID_API_KEY])
            return error_response([UNAUTHORIZED])
        return decorated_function
    return decorator


@app.exception(RateLimitExceeded)
def handle_429(request, exception):
    return error_response([RATE_LIMIT_EXCEEDED])


@app.route('/users', methods=['POST'])
async def users(request):
    if request.json.keys() != {'password', 'first_name', 'last_name',
                               'email_address', 'username', 'phone_number'}:
        return error_response([MISSING_FIELDS])
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = app.pg
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    phone_number = request.json['phone_number']
    email_address = request.json['email_address']
    password = request.json['password']
    username = request.json['username']
    if (username_pattern.search(username) or
       len(username) > 18 or len(username) < 3):
        return error_response([INVALID_USERNAME])
    if not email_pattern.match(email_address):
        return error_response([INVALID_EMAIL])
    try:
        new_user = await db.fetchrow(
            CREATE_USER_SQL, password, first_name,
            last_name, email_address, username, phone_number, session_id)
    except UniqueViolationError as uv_error:
        if uv_error.constraint_name == 'users_email_address_key':
            return error_response([EMAIL_ADDRESS_EXISTS])
        elif uv_error.constraint_name == 'users_username_key':
            return error_response([USERNAME_EXISTS])
        else:
            return error_response([GENERIC_USER])
    except Exception as e:
        logging.info('error creating user {}:{}'.format(email_address, e))
        return error_response([GENERIC_USER])
    # remove sensitive information
    new_user = {
        k: str(v) if k == 'uid' or k == 'activation_key'
        else v for k, v in new_user.items()
        if k not in {'password', 'salt', 'id',
                     'sms_verification', 'external_id'}
    }
    session_id = new_user.pop('session_id')
    activation_key = new_user.pop('activation_key')
    activation_url = ("https://" + str(os.getenv("INSTANCE_HOST")) +
                      '/activate/{}'.format(activation_key))
    full_name = '{} {}'.format(first_name, last_name)
    signup_email = Email(
        email_address,
        'signup',
        full_name=full_name,
        activation_url=activation_url
    )
    signup_email.send()
    await notify_contact_on_signup(email_address, db)
    resp = response.json(new_user, status=201)
    resp.cookies['session_id'] = session_id
    resp.cookies['session_id']['max-age'] = 86400
    resp.cookies['session_id']['domain'] = '.hoardinvest.com'
    resp.cookies['session_id']['httponly'] = True
    return resp


@app.route('/users/<user_uid>', methods=['GET', 'PUT'])
@authorized()
async def user(request, user_uid):
    if request.method == 'GET':
        db = app.pg
        user = await db.fetchrow(SELECT_USER_SQL,
                                 request['session']['user_id'])
        user = {k: v for k, v in user.items()}
        return response.json(user)
    elif request.method == 'PUT':
        if user_uid != request['session']['user_uid']:
            return error_response([UNAUTHORIZED])
        if request.json.keys() != {'first_name', 'last_name', 'phone_number',
                                   'email_address', 'username'}:
            return error_response([MISSING_FIELDS])
        first_name = request.json['first_name']
        last_name = request.json['last_name']
        phone_number = request.json['phone_number']
        email_address = request.json['email_address']
        username = request.json['username']
        await request['db'].execute(
            UPDATE_USER_SQL,
            first_name, last_name, phone_number,
            email_address, username, request['session']['user_id'])
        return response.HTTPResponse(body=None, status=200)


@app.route('/activate/<activation_key>', methods=['GET'])
async def activate_account(request, activation_key):
    if len(activation_key) != 36:
        return error_response([EXPIRED_TOKEN])
    db = app.pg
    try:
        user_info = await db.fetchrow(ACTIVATE_USER_SQL, activation_key)
    except ValueError:
        return error_response([EXPIRED_TOKEN])
    if user_info:
        full_name = '{} {}'.format(
            user_info['first_name'], user_info['last_name'])
        activated_email = Email(
            user_info['email_address'],
            'activated',
            full_name=full_name
        )
        activated_email.send()
        return response.redirect(
            '/result/?action=activate&success=true')
    return error_response([EXPIRED_TOKEN])


@app.route('/2fa/sms_login', methods=['POST'])
async def two_factor_login(request):
    if request.json.keys() != {'sms_verification', 'username_or_email'}:
        return error_response([MISSING_FIELDS])
    db = app.pg
    sms_verification = request.json['sms_verification']
    user = request.json['username_or_email']
    user_ids = await db.fetchrow(VERIFY_SMS_LOGIN,
                                 user, sms_verification)
    if user_ids is None:
        return error_response([SMS_VERIFICATION_FAILED])
    user_id = user_ids['id']
    user_uid = user_ids['uid']
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    await db.execute(LOGIN_SQL,
                     session_id, user_id)
    resp = response.json({'success': ['Login successful'],
                          'user_uid': user_uid}, status=200)
    resp.cookies['session_id'] = session_id
    # expire in one day
    resp.cookies['session_id']['max-age'] = 86400
    resp.cookies['session_id']['domain'] = '.hoardinvest.com'
    resp.cookies['session_id']['httponly'] = True
    return resp


@app.route('/2fa/settings', methods=['GET', 'PUT'])
@authorized()
async def two_factor_settings(request):
    if request.method == 'GET':
        db = app.pg
        settings = await db.fetchrow(SELECT_2FA_SETTINGS_SQL,
                                     request['session']['user_id'])
        return response.json({'sms_2fa_enabled': settings['sms_2fa_enabled']})
    elif request.method == 'PUT':
        if request.json.keys() != {'sms_2fa_enabled'}:
            return error_response([MISSING_FIELDS])
        sms_2fa_enabled = request.json['sms_2fa_enabled']
        db = app.pg
        await db.execute(
            UPDATE_2FA_SETTINGS_SQL,
            sms_2fa_enabled, request['session']['user_id'])
        return response.HTTPResponse(body=None, status=200)


def send_sms(to_number, body):
    account_sid = os.environ['TWILIO_ACCOUNT_SID']
    auth_token = os.environ['TWILIO_AUTH_TOKEN']
    twilio_number = os.environ['TWILIO_NUMBER']
    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,
                               from_=twilio_number,
                               body=body)


@app.route('/login', methods=['POST'])
async def login(request):
    if request.json.keys() != {'username_or_email', 'password'}:
        return error_response([MISSING_FIELDS])
    user = request.json['username_or_email']
    password = request.json['password']
    db = app.pg
    login = await db.fetchrow(PASSWORD_ACCESS_SQL, password, user)
    if login:
        access = login['accessed']
        user_id = login['id']
        sms_2fa = login['sms_2fa_enabled']
        phone_number = login['phone_number']
        user_uid = login['uid']
        if access:
            if sms_2fa:
                code_2fa = str(random.randrange(100000, 999999))
                await db.execute(SET_2FA_CODE_SQL, code_2fa, user_id)
                send_sms(phone_number, code_2fa)
                return response.json({'success': ['2FA has been sent']})
            else:
                session_id = hmac.new(uuid4().bytes,
                                      digestmod=sha1).hexdigest()
                await db.execute(LOGIN_SQL, session_id, user_id)
                resp = response.json({'success': ['Login successful'],
                                      'user_uid': user_uid},
                                     status=200)
                resp.cookies['session_id'] = session_id
                resp.cookies['session_id']['max-age'] = 86400
                resp.cookies['session_id']['domain'] = '.hoardinvest.com'
                resp.cookies['session_id']['httponly'] = True
                return resp
    return error_response([INVALID_CREDENTIALS])


@app.route('/logout', methods=['POST'])
@authorized()
async def logout(request):
    await request['db'].execute(
        LOGOUT_SQL,
        request['session']['user_id'])
    return response.json({'success': ['Your session has been invalidated']})


@app.route('/change_password', methods=['POST'])
@authorized()
async def change_password(request):
    if request.json.keys() != {'new_password', 'password',
                               'username_or_email'}:
        return error_response([MISSING_FIELDS])
    password = request.json['password']
    user = request.json['username_or_email']
    login = await request['db'].fetchrow(
        PASSWORD_ACCESS_SQL,
        password, user)
    if login:
        access = login['accessed']
        user_id = login['id']
        if user_id != request['session']['user_id']:
            logging.warn(
                'Permissions issue: user ID:%s target user ID: %s' %
                (request['session']['user_id'], user_id))
            return error_response([PASSWORD_TARGET])
        elif access:
            new_password = request.json['new_password']
            await request['db'].execute(
                CHANGE_PASSWORD_SQL, new_password, user_id)
            return response.json(
                {'success': ['Your password has been changed']})
    return error_response([PASSWORD_CHECK])


@app.route('/password', methods=['POST'])
async def password(request):
    if request.json.keys() != {'email_address'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    db = app.pg
    reset_token = await db.fetchrow(RESET_TOKEN_CREATION_SQL, email_address)
    if reset_token:
        reset_token = str(reset_token['reset_token'])
        url = ("https://" + str(os.getenv("INSTANCE_HOST")) +
               '/reset_password/{}'.format(reset_token))
        reset_email = Email(email_address,
                            "password_reset", url=url)
        reset_email.send()
    return response.json(
        {'success': ['If our records match you will receive an email']}
    )


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
async def reset_password(request, token):
    if len(token) != 36:
        return error_response([EXPIRED_TOKEN])
    db = app.pg
    data = await db.fetchrow(SELECT_RESET_TOKEN_SQL, token, dt.now())
    if data is not None:
        if request.method == 'GET':
            return response.html(password_template.render(token=token))
        elif request.method == 'POST':
            new_password = request.json['new_password']
            user_id = data['id']
            await db.execute(CHANGE_PASSWORD_SQL, new_password, user_id)
            await db.execute(EXPIRE_RESET_TOKEN_SQL, token)
            return response.json(
                {'success': ['Your password has been changed']})
    else:
        return error_response([EXPIRED_TOKEN])


@app.route('/forgot_username', methods=['POST'])
async def forgot_username(request):
    if request.json.keys() != {'email_address'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    db = app.pg
    user_record = await db.fetchrow(SELECT_USERNAME_FNAME_FROM_EMAIL_SQL,
                                    email_address)
    if user_record:
        forgot_username_email = Email(email_address,
                                      'forgot_username',
                                      username=user_record['username'],
                                      first_name=user_record['first_name'])
        forgot_username_email.send()
    return response.json(
        {'success': ['If our records match you will receive an email']}
    )


@app.route('/email_preferences', methods=['PUT', 'GET'])
@authorized()
async def email_preferences(request):
    if request.method == 'GET':
        db = app.pg
        settings = await db.fetchrow(SELECT_EMAIL_PREFS_SQL,
                                     request['session']['user_id'])
        return response.json({'receive_emails_enabled':
                              settings['receive_emails_enabled']})
    elif request.method == 'PUT':
        if request.json.keys() != {'receive_emails_enabled'}:
            return error_response([MISSING_FIELDS])
        receive_emails_enabled = request.json['receive_emails_enabled']
        db = app.pg
        await db.execute(UPDATE_EMAIL_PREFS_SQL,
                         receive_emails_enabled,
                         request['session']['user_id'])
        return response.json(
            {'success': ['Your email preferences have been updated']}
        )


@app.route('/ticker', methods=['GET'])
@authorized()
async def get_ticker(request):
    refresh_ticker()
    if btc_usd_latest and eth_usd_latest:
        return response.json({'btc_usd': btc_usd_latest,
                              'eth_usd': eth_usd_latest})
    else:
        return error_response([TICKER_UNAVAILABLE])


@app.route('/jumio_callback', methods=['POST'])
async def jumio_callback(request):
    form_data = request.form
    scan_reference = form_data.get('scanReference')
    if scan_reference:
        db = app.pg
        await db.execute(CREATE_IV_SQL, scan_reference, json.dumps(form_data))
        return response.HTTPResponse(body=None, status=201)
    else:
        return response.HTTPResponse(body=None, status=400)


@app.route('/jumio_results/<scan_reference>', methods=['GET'])
@authorized()
async def get_jumio_results(request, scan_reference):
    results = await request['db'].fetch(IV_RESULTS_SQL, scan_reference)
    if results:
        return response.json({'results': [r[0] for r in results]})
    else:
        return response.HTTPResponse(body=None, status=200)


@app.route('/ca_search', methods=['POST', 'GET'])
@authorized()
async def ca_search(request):
    url = "https://api.complyadvantage.com/searches?api_key={}".format(
        os.environ.get('COMPLY_ADVANTAGE_API_KEY'))
    if request.method == 'POST':
        ca_response = requests.post(url, request.json)
        ca_response_json = ca_response.json()
        hits = ca_response_json.get(
            'content', {}).get('data', {}).get('total_hits')
        if hits != 0:
            db = app.pg
            user_info = await db.fetchrow(SELECT_USER_SQL,
                                          request['session']['user_id'])
            user_info = dict(user_info)
            create_zendesk_ticket(ca_response,
                                  user_info, subject="Comply Advantage Hit")
    # DL: Do we actually need to provide GET requests to the mobile app?
    elif request.method == 'GET':
        ca_response = requests.get(url)
    return response.json(ca_response_json)


@app.route('/ca_search/<search_id>', methods=['GET'])
@authorized()
async def ca_search_id(request, search_id):
    url = "https://api.complyadvantage.com/searches/{}?api_key={}".format(
        search_id, os.environ.get('COMPLY_ADVANTAGE_API_KEY'))
    ca_response = requests.get(url)
    return response.json(ca_response)


@app.route('/support', methods=['POST'])
async def zen_support(request):
    if not all(item in list(request.json.keys()) for
               item in ['description', 'email_address']):
        return error_response([MISSING_FIELDS])
    description = request.json['description']
    email_address = request.json['email_address']
    subject = request.json.get('subject')
    user_info = {'email_address': email_address}
    create_zendesk_ticket(description, user_info,
                          subject=subject,
                          requester=User(
                              email=email_address,
                              verified=True
                          ))
    return response.json({'success': 'Ticket submitted'})


@app.route('/users/<user_uid>/register_address', methods=['POST'])
@authorized()
async def register_public_keys(request, user_uid):
    if user_uid != request['session']['user_uid']:
        return error_response([UNAUTHORIZED])
    if request.json.keys() != {'currency', 'address'}:
        return error_response([MISSING_FIELDS])
    currency = request.json['currency']
    if currency not in ['ETH', 'BTC']:
        return error_response([UNSUPPORTED_CURRENCY])
    address = request.json['address']
    user_id = request['session']['user_id']
    await request['db'].execute(REGISTER_ADDRESS_SQL,
                                user_id, currency, address)
    return response.HTTPResponse(body=None, status=200)


async def public_key_for_user(recipient, currency, db):
    # Check if user has any registered public keys
    address = await db.fetchrow(SELECT_ADDRESS_SQL, currency, recipient)
    return address


async def record_contact_transaction(transaction, user_id, db):
    # Record transaction in database
    await db.execute(
        CREATE_CONTACT_TRANSACTION_SQL,
        user_id, transaction['recipient'],
        transaction['currency'], transaction['amount'])
    return


async def notify_contact_on_signup(to_email_address, db):
    """
    Notifies a user if their contact has now signed up to Hoard and displays
    all of the transactions they attempted to do in an email.
    """
    transactions = await db.fetch(SELECT_CONTACT_TRANSACTIONS,
                                  to_email_address)
    if not transactions:
        return
    from_email_address = transactions[0]['email_address']
    first_name = transactions[0]['first_name']
    notify_email = Email(
        from_email_address,
        'pending_contact_transactions',
        first_name=first_name,
        to_email_address=to_email_address,
        transactions=transactions
    )
    notify_email.send()


async def notify_contact_transaction(transaction, user_id, db):
    """
    Notifies a contact that does not have Hoard about a pending transaction
    sent from a Hoard member.
    """
    user_info = await db.fetchrow(SELECT_EMAIL_AND_FNAME_SQL, user_id)
    from_email_address = user_info['email_address']
    from_first_name = user_info['first_name']
    to_email_address = transaction['recipient']
    notify_email = Email(
        to_email_address,
        'contact_transactions',
        to_email_address=to_email_address,
        from_email_address=from_email_address,
        from_first_name=from_first_name,
        amount=transaction['amount'],
        currency=transaction['currency']
    )
    notify_email.send()


@app.route('/contacts/transaction/', methods=['POST'])
@authorized(active_required=True)
async def contact_transaction(request):
    transaction = request.json
    if transaction.keys() != {'sender', 'amount',
                              'recipient', 'currency'}:
        return error_response([MISSING_FIELDS])
    recipient = transaction['recipient']
    currency = transaction['currency']
    sender_address = transaction['sender']
    amount = transaction['amount']
    symbol = None
    if len(currency) == 42:
        symbol = get_symbol(currency)
        if symbol is None:
            return error_response([UNSUPPORTED_CURRENCY])
        transaction['currency'] = symbol
    elif currency not in ['ETH', 'BTC']:
        return error_response([UNSUPPORTED_CURRENCY])
    if amount <= 0:
        return error_response([NEGATIVE_AMOUNT])
    if get_balance(sender_address, currency) < amount:
        return error_response([INSUFFICIENT_BALANCE])
    recipient_public_key = await public_key_for_user(
        recipient,
        currency if not symbol else 'ETH',
        request['db']
    )
    if (recipient_public_key is None and email_pattern.match(recipient)):
        # Record in DB
        await record_contact_transaction(transaction,
                                         request['session']['user_id'],
                                         request['db'])

        # Notify via email
        await notify_contact_transaction(transaction,
                                         request['session']['user_id'],
                                         request['db'])
        return response.json({"success": ["Email sent notifying recipient"]})
    elif recipient_public_key:
        return response.json({'public_key': recipient_public_key[0]})
    else:
        return error_response([NO_PUBLIC_KEY])


@app.route('/contacts/transaction_data/<transaction_uid>', methods=['GET'])
@authorized()
async def contact_transaction_data(request, transaction_uid):
    try:
        transaction = await request['db'].fetchrow(
            SELECT_CONTACT_TRANSACTION_DATA, transaction_uid)
    except ValueError:
        return error_response([INVALID_TRANSACTION_UID])
    return (response.json(dict(transaction)) if transaction else
            error_response([INVALID_TRANSACTION_UID]))


@app.route('/contacts/transaction_confirmation/<transaction_uid>',
           methods=['POST'])
@authorized()
async def contact_transaction_confirmation(request, transaction_uid):
    confirmation = request.json
    if confirmation.keys() != {'confirmed'}:
        return error_response([MISSING_FIELDS])
    confirmation_value = confirmation['confirmed']
    try:
        await request['db'].execute(
            UPDATE_TRANSACTION_CONFIRMATION_SQL,
            confirmation_value, transaction_uid)
    except ValueError:
        return error_response([INVALID_TRANSACTION_UID])
    return (response.json({'success': 'You have confirmed the transaction'}) if
            confirmation_value else
            response.json({'success': 'You have denied the transaction'}))


@app.route('/jsonrpc', methods=['POST'])
@authorized()
async def json_rpc_bridge(request):
    url = "http://hoard:bombadil@shenron.hoardinvest.com:8332"
    headers = {'content-type': 'application/json'}
    payload = request.json
    rpc_response = requests.post(
        url, data=json.dumps(payload), headers=headers)
    return response.json(rpc_response.json())


@app.route('/request_funds/', methods=['POST'])
@authorized(active_required=True)
async def request_funds(request):
    fund_request = request.json
    if fund_request.keys() != {'recipient', 'email_address',
                               'currency', 'amount'}:
        return error_response([MISSING_FIELDS])
    currency = fund_request['currency']
    amount = fund_request['amount']
    from_email_address = fund_request['email_address']
    to_email_address = fund_request['recipient']
    request_time = dt.now().strftime('%B %d, %Y - %I:%M%p')
    if not email_pattern.match(to_email_address):
        user_record = await request['db'].fetchrow(
            SELECT_EMAIL_FROM_USERNAME_SQL, to_email_address)
        if user_record is None:
            return error_response([USER_NOT_FOUND])
        to_email_address = user_record['email_address']

    # TODO: Include push notification here

    request_email = Email(
        to_email_address,
        'request_funds',
        to_email_address=to_email_address,
        from_email_address=from_email_address,
        amount=amount,
        currency=currency,
        request_time=request_time
    )
    request_email.send()
    return response.json({"success": ["Email sent notifying recipient"]})


@app.route('/unsubscribe')
@authorized()
async def unsubscribe(request):
    return response.html(unsubscribe_template.render(
        url="/email_preferences"))


@app.route('/result', methods=['GET'])
async def result(request):
    args = request.args
    # Only allow for 2 url arguments: action and success
    if len(args) > 2:
        return response.HTTPResponse(body=None, status=404)
    try:
        args_action = args['action'][0]
        args_result = args['success'][0]
        action = RESULT_ACTIONS[args_action]
        result = action[args_result]
    except KeyError:
        return response.HTTPResponse(body=None, status=404)
    return response.html(result_template.render(
        action=action, result=result))


@app.route('/updates/<platform>', methods=['GET'])
async def updates(request, platform):
    if platform == 'ios':
        return response.json(ios_updates)
    elif platform == 'android':
        return response.json(android_updates)
    else:
        return error_response([INVALID_PLATFORM])


@app.route('/health', methods=['GET', 'HEAD'])
async def health_check(request):
    return response.HTTPResponse(body=None, status=200)


def load_aws_secret(secret_name):
    secret = None
    endpoint_url = "https://secretsmanager.us-east-2.amazonaws.com"
    region_name = "us-east-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
    return json.loads(secret)


if __name__ == '__main__':
    secret_name = os.environ['EREBOR_DB_AWS_SECRET']

    if secret_name:
        secret = load_aws_secret(secret_name)
        app.db = dict(database=secret['dbname'],
                      user=secret['username'],
                      password=secret['password'],
                      host=secret['host'],
                      port=secret['port'])
        app.blueprint(bp)
    app.run(host='0.0.0.0',
            port=8000,
            access_log=False if os.environ.get('EREBOR_ENV') == 'PROD'
            else True)
