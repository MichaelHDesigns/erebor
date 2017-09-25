from uuid import uuid4
from functools import wraps
from hashlib import sha1
import hmac
import logging
import os
import random

from sanic import Sanic, response
import psycopg2
import psycopg2.extras
from twilio.rest import Client


app = Sanic()

PASSWORD_ACCESS_SQL = """
SELECT
  crypt(%s, password) = password AS accessed, id, sms_2fa_enabled, phone_number
FROM users
WHERE email_address = %s
""".strip()

SELECT_2FA_SETTINGS_SQL = """
SELECT sms_2fa_enabled FROM users WHERE uid = %s
""".strip()

UPDATE_2FA_SETTINGS_SQL = """
UPDATE users
SET sms_2fa_enabled = %s
WHERE uid = %s
""".strip()

SELECT_USER_SQL = """
SELECT uid, first_name, last_name, phone_number, email_address, sms_2fa_enabled
FROM users
WHERE uid = %s
""".strip()

UPDATE_USER_SQL = """
UPDATE users
SET first_name = %s, last_name = %s, phone_number = %s, email_address = %s
WHERE uid = %s
""".strip()

CREATE_USER_SQL = """
WITH x AS (
  SELECT %s::text as password,
    gen_salt('bf')::text AS salt
)
INSERT INTO users (password, salt, first_name, last_name, email_address,
                   phone_number, api_key)
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
WHERE api_key = %s
""".strip()

LOGOUT_SQL = """
UPDATE users
SET api_key = NULL
WHERE uid = %s
""".strip()

LOGIN_SQL = """
UPDATE users
SET api_key = %s
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
RETURNING users.id
""".strip()


def authorized():
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            cur = app.db.cursor()
            api_key_header = request.headers.get('authorization')
            if api_key_header:
                # Remove prefix from API key
                api_key = api_key_header[7:]
                cur.execute(
                    USER_ID_SQL,
                    (api_key,))
                user_ids = cur.fetchone()
                if user_ids is not None:
                    request['session'] = {'user_id': user_ids[0],
                                          'user_uid': user_ids[1]}
                    request['db'] = cur
                    res = await f(request, *args, **kwargs)
                    return res
                else:
                    response.json({'errors': ['Invalid Api key']})
            return response.json({'errors': ['Not authorized']}, 403)
        return decorated_function
    return decorator


@app.route('/users', methods=['POST'])
async def users(request):
    if request.json.keys() != {'password', 'first_name', 'last_name',
                               'email_address', 'phone_number'}:
        return response.json({'errors': ['Missing fields']}, status=400)
    api_key = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    phone_number = request.json['phone_number']
    email_address = request.json['email_address']
    password = request.json['password']
    db.execute(CREATE_USER_SQL, (password, first_name, last_name,
                                 email_address, phone_number, api_key))
    new_user = db.fetchone()
    # remove sensitive information
    new_user = {k: v for k, v in new_user.items() if k not in
                {'password', 'salt', 'id', 'sms_verification'}}
    app.db.commit()
    return response.json(new_user, status=201)


@app.route('/users/<user_uid>', methods=['GET', 'PUT'])
@authorized()
async def user(request, user_uid):
    if request.method == 'GET':
        db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        db.execute(SELECT_USER_SQL, (user_uid,))
        user = db.fetchone()
        return response.json(user)
    elif request.method == 'PUT':
        if user_uid != request['session']['user_uid']:
            return response.json({'errors': ['Unauthorized']}, 403)
        if request.json.keys() != {'first_name', 'last_name', 'phone_number',
                                   'email_address'}:
            return response.json({'errors': ['Missing fields']}, status=400)
        first_name = request.json['first_name']
        last_name = request.json['last_name']
        phone_number = request.json['phone_number']
        email_address = request.json['email_address']
        request['db'].execute(UPDATE_USER_SQL,
                              (first_name, last_name, phone_number,
                               email_address, user_uid))
        app.db.commit()
        return response.HTTPResponse(body=None, status=200)


@app.route('/2fa/sms_login', methods=['POST'])
async def two_factor_login(request):
    if request.json.keys() != {'sms_verification', 'email_address'}:
        return response.json({'errors': ['Missing fields']})
    db = app.db.cursor()
    sms_verification = request.json['sms_verification']
    email_address = request.json['email_address']
    db.execute(VERIFY_SMS_LOGIN,
               (email_address, sms_verification))
    user_id = db.fetchone()
    if user_id is None:
        return response.json({'errors': ['Verification failed']})
    api_key = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db.execute(LOGIN_SQL,
               (api_key, user_id))
    app.db.commit()
    return response.json({'api_key': api_key}, status=200)


@app.route('/2fa/settings', methods=['GET', 'PUT'])
@authorized()
async def two_factor_settings(request):
    if request.method == 'GET':
        db = app.db.cursor()
        db.execute(SELECT_2FA_SETTINGS_SQL, (request['session']['user_uid'],))
        settings = db.fetchone()
        return response.json({'sms_2fa_enabled': settings[0]})
    elif request.method == 'PUT':
        if request.json.keys() != {'sms_2fa_enabled'}:
            return response.json({'errors': ['Missing fields']}, status=400)
        sms_2fa_enabled = request.json['sms_2fa_enabled']
        db = app.db.cursor()
        db.execute(UPDATE_2FA_SETTINGS_SQL,
                   (sms_2fa_enabled, request['session']['user_uid']))
        return response.HTTPResponse(body=None, status=200)


def send_sms(to_number, body):
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    twilio_number = os.environ.get('TWILIO_NUMBER')
    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,
                               from_=twilio_number,
                               body=body)


@app.route('/login', methods=['POST'])
async def login(request):
    email_address = request.json.get('email_address')
    password = request.json.get('password')
    db = app.db.cursor()
    db.execute(PASSWORD_ACCESS_SQL, (password, email_address))
    login = db.fetchone()
    if login:
        access, user_id, sms_2fa, phone_number = login
        if access:
            if sms_2fa:
                code_2fa = str(random.randrange(100000, 999999))
                db.execute(SET_2FA_CODE_SQL, (code_2fa, user_id))
                send_sms(phone_number, code_2fa)
                return response.json({'success': ['2FA has been sent']})
            else:
                api_key = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
                db.execute(LOGIN_SQL,
                           (api_key, user_id))
                app.db.commit()
                return response.json({'api_key': api_key}, status=200)
    return response.json({'errors': ['Invalid credentials']}, status=403)


@app.route('/logout', methods=['POST'])
@authorized()
async def logout(request):
    request['db'].execute(
        LOGOUT_SQL,
        (request['session']['user_uid'],))
    return response.json({'success': 'Your API key has been invalidated'})


@app.route('/change_password', methods=['POST'])
@authorized()
async def change_password(request):
    if request.json.keys() != {'new_password', 'password', 'email_address'}:
        return response.json({'errors': ['Missing fields']}, status=400)
    password = request.json.get('password')
    email_address = request.json.get('email_address')
    request['db'].execute(PASSWORD_ACCESS_SQL, (password, email_address))
    login = request['db'].fetchone()
    if login:
        access, user_id, sms_2fa, phone_number = login
        if user_id != request['session']['user_id']:
            logging.warn(
                'Permissions issue: user ID:%s target user ID: %s' %
                (request['session']['user_id'], user_id))
            return response.json({'errors': ['Password error']}, status=403)
        elif access:
            new_password = request.json.get('new_password')
            request['db'].execute(CHANGE_PASSWORD_SQL, (new_password, user_id))
            return response.json(
                {'success': ['Your password has been changed']})
    return response.json({'errors': ['Password error']}, status=403)


@app.route('/users/<user_uid>/wallet', methods=['GET'])
@authorized()
async def get_wallet(request, user_uid):
    if user_uid != request['session']['user_uid']:
        return response.json({'errors': ['Unauthorized']}, 403)
    else:
        return response.json([{'symbol': 'OAR',
                               'amount': '123.456789'},
                              {'symbol': 'BITB',
                               'amount': '1.0'}])


@app.route('/health', methods=['GET'])
async def health_check(request):
    return response.HTTPResponse(body=None, status=200)


if __name__ == '__main__':
    app.db = psycopg2.connect(dbname=os.environ.get('SMAUG_DB_NAME'),
                              user=os.environ.get('SMAUG_DB_USER'),
                              password=os.environ.get('SMAUG_DB_PASSWORD'),
                              host=os.environ.get('SMAUG_DB_HOST'),
                              port=5432)
    app.run(host='0.0.0.0', port=80)
