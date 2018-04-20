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

from sanic import Sanic, response
from sanic.log import LOGGING_CONFIG_DEFAULTS
from sanic_cors import CORS
import psycopg2
import psycopg2.extras
from twilio.rest import Client
import requests
from zenpy import Zenpy
from zenpy.lib.api_objects import Ticket
import boto3
from botocore.exceptions import ClientError

from erebor.errors import (error_response, MISSING_FIELDS, UNAUTHORIZED,
                           SMS_VERIFICATION_FAILED, INVALID_CREDENTIALS,
                           INVALID_API_KEY, PASSWORD_TARGET, PASSWORD_CHECK,
                           TICKER_UNAVAILABLE, GENERIC_USER, EXPIRED_TOKEN,
                           INVALID_PLATFORM)
from erebor.email import Email
from erebor.render import (unsubscribe_template, result_template,
                           password_template, RESULT_ACTIONS)
from erebor.logs import logging_config

app = Sanic(log_config=logging_config
            if not os.getenv('erebor_test') else LOGGING_CONFIG_DEFAULTS)
CORS(app, automatic_options=True)

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


def create_zendesk_ticket(ca_response, user_info):
    zd_credentials = {'email': os.environ.get('ZD_EMAIL'),
                      'token': os.environ.get('ZD_TOKEN'),
                      'subdomain': os.environ.get('ZD_SUBDOMAIN')}
    zenpy_client = Zenpy(**zd_credentials)
    zenpy_client.tickets.create(
        Ticket(subject="Comply Advantage Hit",
               description=json.dumps({"user_info": user_info,
                                       "ca_response": ca_response})))


PASSWORD_ACCESS_SQL = """
SELECT
  crypt(%s, password) = password AS accessed, id, sms_2fa_enabled,
  phone_number, uid
FROM users
WHERE email_address = %s
""".strip()

RESET_TOKEN_CREATION_SQL = """
INSERT INTO reset_tokens
    (id, reset_token, reset_token_creation_time,
     email_address)
SELECT
     users.id, uuid_generate_v4(), CURRENT_TIMESTAMP,
     users.email_address
FROM users
WHERE email_address = %s
ON CONFLICT (id) DO UPDATE
SET reset_token = uuid_generate_v4(),
    reset_token_creation_time = CURRENT_TIMESTAMP
RETURNING reset_token, email_address
""".strip()

SELECT_RESET_TOKEN_SQL = """
SELECT email_address, id
FROM reset_tokens
WHERE reset_token = %s
AND reset_token_creation_time + interval '1 hour' > %s
""".strip()

EXPIRE_RESET_TOKEN_SQL = """
UPDATE reset_tokens
SET reset_token = NULL
WHERE reset_token = %s
"""

SELECT_2FA_SETTINGS_SQL = """
SELECT sms_2fa_enabled FROM users WHERE id = %s
""".strip()

UPDATE_2FA_SETTINGS_SQL = """
UPDATE users
SET sms_2fa_enabled = %s
WHERE id = %s
""".strip()

SELECT_USER_SQL = """
SELECT uid, first_name, last_name, phone_number, email_address, sms_2fa_enabled
FROM users
WHERE id = %s
""".strip()

UPDATE_USER_SQL = """
UPDATE users
SET first_name = %s, last_name = %s, phone_number = %s, email_address = %s
WHERE id = %s
""".strip()

SELECT_EMAIL_PREFS_SQL = """
SELECT receive_emails_enabled
FROM users
WHERE uid = %s
""".strip()

UPDATE_EMAIL_PREFS_SQL = """
UPDATE users
SET receive_emails_enabled = %s
WHERE uid = %s
""".strip()

CREATE_USER_SQL = """
WITH x AS (
  SELECT %s::text as password,
    gen_salt('bf')::text AS salt
)
INSERT INTO users (password, salt, first_name, last_name, email_address,
                   phone_number, session_id)
SELECT crypt(x.password, x.salt), x.salt, %s, %s, %s, %s, %s
FROM x
RETURNING *
""".strip()

CHANGE_PASSWORD_SQL = """
WITH x AS (
  SELECT %s::text as password,
    gen_salt('bf')::text AS salt
)
UPDATE users
SET password = crypt(x.password, x.salt), salt = x.salt
FROM x
WHERE id = %s
""".strip()

USER_ID_SQL = """
SELECT id, uid
FROM users
WHERE session_id = %s
""".strip()

LOGOUT_SQL = """
UPDATE users
SET session_id = NULL
WHERE id = %s
""".strip()

LOGIN_SQL = """
UPDATE users
SET session_id = %s
WHERE id = %s
""".strip()

SET_2FA_CODE_SQL = """
UPDATE users
SET sms_verification = %s
WHERE id = %s
""".strip()

VERIFY_SMS_LOGIN = """
UPDATE users
SET sms_verification = Null
WHERE email_address = %s AND sms_verification = %s
RETURNING users.id, users.uid
""".strip()

CREATE_IV_SQL = """
INSERT INTO identity_verifications (scan_reference, data)
VALUES (%s, %s::json)
""".strip()

IV_RESULTS_SQL = """
SELECT data
FROM identity_verifications
WHERE scan_reference = %s
""".strip()


def authorized():
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            cur = app.db.cursor()
            cookie = request.cookies.get('session_id')
            if cookie:
                cur.execute(USER_ID_SQL, (cookie,))
                user_ids = cur.fetchone()
                if user_ids is not None:
                    request['session'] = {'user_id': user_ids[0],
                                          'user_uid': user_ids[1]}
                    request['db'] = cur
                    res = await f(request, *args, **kwargs)
                    return res
                else:
                    error_response([INVALID_API_KEY])
            return error_response([UNAUTHORIZED])
        return decorated_function
    return decorator


@app.route('/users', methods=['POST'])
async def users(request):
    if request.json.keys() != {'password', 'first_name', 'last_name',
                               'email_address', 'phone_number'}:
        return error_response([MISSING_FIELDS])
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    phone_number = request.json['phone_number']
    email_address = request.json['email_address']
    password = request.json['password']
    try:
        db.execute(CREATE_USER_SQL, (password, first_name, last_name,
                                     email_address, phone_number, session_id))
    except Exception as e:
        logging.info('error creating user {}:{}'.format(email_address, e))
        app.db.rollback()
        return error_response([GENERIC_USER])
    new_user = db.fetchone()
    # remove sensitive information
    new_user = {k: v for k, v in new_user.items() if k not in
                {'password', 'salt', 'id', 'sms_verification', 'external_id'}}
    session_id = new_user.pop('session_id')
    app.db.commit()
    full_name = '{} {}'.format(first_name, last_name)
    signup_email = Email(
        email_address,
        'signup',
        full_name=full_name
    )
    signup_email.send()
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
        db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        db.execute(SELECT_USER_SQL, (request['session']['user_id'],))
        user = db.fetchone()
        return response.json(user)
    elif request.method == 'PUT':
        if user_uid != request['session']['user_uid']:
            return error_response([UNAUTHORIZED])
        if request.json.keys() != {'first_name', 'last_name', 'phone_number',
                                   'email_address'}:
            return error_response([MISSING_FIELDS])
        first_name = request.json['first_name']
        last_name = request.json['last_name']
        phone_number = request.json['phone_number']
        email_address = request.json['email_address']
        request['db'].execute(UPDATE_USER_SQL,
                              (first_name, last_name, phone_number,
                               email_address, request['session']['user_id']))
        app.db.commit()
        return response.HTTPResponse(body=None, status=200)


@app.route('/2fa/sms_login', methods=['POST'])
async def two_factor_login(request):
    if request.json.keys() != {'sms_verification', 'email_address'}:
        return error_response([MISSING_FIELDS])
    db = app.db.cursor()
    sms_verification = request.json['sms_verification']
    email_address = request.json['email_address']
    db.execute(VERIFY_SMS_LOGIN,
               (email_address, sms_verification))
    user_id, user_uid = db.fetchone()
    if user_id is None:
        return error_response([SMS_VERIFICATION_FAILED])
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db.execute(LOGIN_SQL,
               (session_id, user_id))
    app.db.commit()
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
        db = app.db.cursor()
        db.execute(SELECT_2FA_SETTINGS_SQL, (request['session']['user_id'],))
        settings = db.fetchone()
        return response.json({'sms_2fa_enabled': settings[0]})
    elif request.method == 'PUT':
        if request.json.keys() != {'sms_2fa_enabled'}:
            return error_response([MISSING_FIELDS])
        sms_2fa_enabled = request.json['sms_2fa_enabled']
        db = app.db.cursor()
        db.execute(UPDATE_2FA_SETTINGS_SQL,
                   (sms_2fa_enabled, request['session']['user_id']))
        app.db.commit()
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
    if request.json.keys() != {'email_address', 'password'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    password = request.json['password']
    db = app.db.cursor()
    db.execute(PASSWORD_ACCESS_SQL, (password, email_address))
    login = db.fetchone()
    if login:
        access, user_id, sms_2fa, phone_number, user_uid = login
        if access:
            if sms_2fa:
                code_2fa = str(random.randrange(100000, 999999))
                db.execute(SET_2FA_CODE_SQL, (code_2fa, user_id))
                app.db.commit()
                send_sms(phone_number, code_2fa)
                return response.json({'success': ['2FA has been sent']})
            else:
                session_id = hmac.new(uuid4().bytes,
                                      digestmod=sha1).hexdigest()
                db.execute(LOGIN_SQL, (session_id, user_id))
                app.db.commit()
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
    request['db'].execute(
        LOGOUT_SQL,
        (request['session']['user_id'],))
    app.db.commit()
    return response.json({'success': ['Your session has been invalidated']})


@app.route('/change_password', methods=['POST'])
@authorized()
async def change_password(request):
    if request.json.keys() != {'new_password', 'password', 'email_address'}:
        return error_response([MISSING_FIELDS])
    password = request.json['password']
    email_address = request.json['email_address']
    request['db'].execute(PASSWORD_ACCESS_SQL, (password, email_address))
    login = request['db'].fetchone()
    if login:
        access, user_id, sms_2fa, phone_number, _ = login
        if user_id != request['session']['user_id']:
            logging.warn(
                'Permissions issue: user ID:%s target user ID: %s' %
                (request['session']['user_id'], user_id))
            return error_response([PASSWORD_TARGET])
        elif access:
            new_password = request.json['new_password']
            request['db'].execute(CHANGE_PASSWORD_SQL, (new_password, user_id))
            app.db.commit()
            return response.json(
                {'success': ['Your password has been changed']})
    return error_response([PASSWORD_CHECK])


@app.route('/password', methods=['POST'])
async def password(request):
    if request.json.keys() != {'email_address'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    db = app.db.cursor()
    db.execute(RESET_TOKEN_CREATION_SQL, (email_address,))
    reset_token = db.fetchone()
    if reset_token[0]:
        app.db.commit()
        reset_token = reset_token[0]
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
    db = app.db.cursor()
    db.execute(SELECT_RESET_TOKEN_SQL, (token, dt.now()))
    data = db.fetchone()
    if data is not None:
        if request.method == 'GET':
            return response.html(password_template.render(token=token))
        elif request.method == 'POST':
            new_password = request.json['new_password']
            user_id = data[1]
            db.execute(CHANGE_PASSWORD_SQL, (new_password, user_id))
            db.execute(EXPIRE_RESET_TOKEN_SQL, (token,))
            app.db.commit()
            return response.json(
                {'success': ['Your password has been changed']})
    else:
        return error_response([EXPIRED_TOKEN])


@app.route('/email_preferences', methods=['PUT', 'GET'])
@authorized()
async def email_preferences(request):
    if request.method == 'GET':
        db = app.db.cursor()
        db.execute(SELECT_EMAIL_PREFS_SQL, (request['session']['user_uid'],))
        settings = db.fetchone()
        return response.json({'receive_emails_enabled': settings[0]})
    elif request.method == 'PUT':
        if request.json.keys() != {'receive_emails_enabled'}:
            return error_response([MISSING_FIELDS])
        receive_emails_enabled = request.json['receive_emails_enabled']
        db = app.db.cursor()
        db.execute(UPDATE_EMAIL_PREFS_SQL,
                   (receive_emails_enabled, request['session']['user_uid']))
        app.db.commit()
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
        cur = app.db.cursor()
        cur.execute(CREATE_IV_SQL, (scan_reference, json.dumps(form_data)))
        app.db.commit()
        return response.HTTPResponse(body=None, status=201)
    else:
        return response.HTTPResponse(body=None, status=400)


@app.route('/jumio_results/<scan_reference>', methods=['GET'])
@authorized()
async def get_jumio_results(request, scan_reference):
    request['db'].execute(IV_RESULTS_SQL, (scan_reference,))
    results = request['db'].fetchall()
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
            db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db.execute(SELECT_USER_SQL, (request['session']['user_id'],))
            user_info = db.fetchone()
            create_zendesk_ticket(ca_response, user_info)
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
        app.db = psycopg2.connect(dbname=secret['dbname'],
                                  user=secret['username'],
                                  password=secret['password'],
                                  host=secret['host'],
                                  port=secret['port'])
    app.run(host='0.0.0.0',
            port=8000,
            access_log=False if os.environ.get('EREBOR_ENV') == 'PROD'
            else True)
