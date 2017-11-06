from uuid import uuid4
from functools import wraps
from hashlib import sha1
import hmac
import logging
import os
import random
from urllib.request import urlopen
import json

from sanic import Sanic, response
from sanic_cors import CORS, cross_origin
import psycopg2
import psycopg2.extras
from twilio.rest import Client
from jose import jwt


app = Sanic()
CORS(app, automatic_options=True)

INVITE_ACCESS_SQL = """
SELECT place FROM invites WHERE email_address = %s;
""".strip()

SELECT_NOW_SERVING_SQL = """
SELECT place FROM now_serving;
""".strip()

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
                   phone_number, session_id)
SELECT crypt(x.password, x.salt), x.salt, %s, %s, %s, %s, %s
FROM x
RETURNING *
""".strip()

CREATE_USER_AUTH0_SQL = """
INSERT INTO users (password, salt, first_name, last_name, email_address,
                   phone_number, session_id, external_id)
VALUES (Null, Null, %s, '', %s, Null, %s, %s)
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

USER_ID_AUTH0_SQL = """
SELECT id, uid, session_id
FROM users
WHERE external_id = %s
""".strip()

LOGOUT_SQL = """
UPDATE users
SET session_id = NULL
WHERE uid = %s
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
RETURNING users.id
""".strip()


# Format error response and append status code.
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def auth_zero_validate(token, access_token):
    auth0_domain = os.environ.get('AUTH0_DOMAIN', 'oar-dev01.auth0.com')
    jsonurl = urlopen("https://"+auth0_domain+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read().decode('utf8'))
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        print(e)
    rsa_key = {}
    print('jwks: %s' % jwks)
    print('unverified_header: %s' % unverified_header)
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=os.environ.get('API_AUDIENCE'),
            issuer="https://"+auth0_domain+"/",
            access_token=access_token
        )
    return payload


def auth_zero_get_or_create_user(cur, payload):
    first_name = payload['nickname']
    email_address = payload['name']
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    external_id = payload['sub']
    cur.execute(USER_ID_AUTH0_SQL, (external_id,))
    res = cur.fetchone()
    if res:
        user_ids = [res['id'], res['uid']]
        session_id = res['session_id']
        return user_ids, session_id
    else:
        cur.execute(CREATE_USER_AUTH0_SQL, (first_name,
                                            email_address,
                                            session_id,
                                            external_id))
        new_user = cur.fetchone()
        new_user = {k: v for k, v in new_user.items() if k not in
                    {'password', 'salt', 'sms_verification'}}
        session_id = new_user.pop('session_id')
        app.db.commit()
        return (new_user['id'], new_user['uid']), session_id


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
                    response.json({'errors': ['Invalid Api key']})
            return response.json({'errors': ['Not authorized']}, 403)
        return decorated_function
    return decorator


def check_invite(db, email_address):
    db.execute(SELECT_NOW_SERVING_SQL)
    now_serving = db.fetchone()['place']
    db.execute(INVITE_ACCESS_SQL, (email_address,))
    place = db.fetchone()['place']
    if place is not None and now_serving is not None and place <= now_serving:
        return True
    else:
        return False


@app.route('/auth_zero', methods=['POST', 'OPTIONS'])
@cross_origin(app)
async def auth_zero(request):
    cur = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    id_token = request.json.get('id_token')
    access_token = request.json.get('access_token')
    payload = auth_zero_validate(id_token, access_token)
    if check_invite(cur, payload['name']) is False:
        return response.json(
            {'errors': ['Please wait until your invite is ready']})
    user_ids, session_id = auth_zero_get_or_create_user(cur, payload)
    resp = response.redirect('/users/{}/wallet'.format(user_ids[1]))
    resp.cookies['session_id'] = session_id
    resp.cookies['session_id']['max-age'] = 86400
    resp.cookies['session_id']['domain'] = '.hoardinvest.com'
    resp.cookies['session_id']['httponly'] = True
    return resp


@app.route('/users', methods=['POST'])
async def users(request):
    if request.json.keys() != {'password', 'first_name', 'last_name',
                               'email_address', 'phone_number'}:
        return response.json({'errors': ['Missing fields']}, status=400)
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    phone_number = request.json['phone_number']
    email_address = request.json['email_address']
    if check_invite(db, email_address) is False:
        return response.json(
            {'errors': ['Please wait until your invite is ready']})
    password = request.json['password']
    db.execute(CREATE_USER_SQL, (password, first_name, last_name,
                                 email_address, phone_number, session_id))
    new_user = db.fetchone()
    # remove sensitive information
    new_user = {k: v for k, v in new_user.items() if k not in
                {'password', 'salt', 'id', 'sms_verification', 'external_id'}}
    session_id = new_user.pop('session_id')
    app.db.commit()
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
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db.execute(LOGIN_SQL,
               (session_id, user_id))
    app.db.commit()
    resp = response.json({'success': ['Login successful']}, status=200)
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
                session_id = hmac.new(uuid4().bytes,
                                      digestmod=sha1).hexdigest()
                db.execute(LOGIN_SQL, (session_id, user_id))
                app.db.commit()
                resp = response.json({'success': ['Login successful']},
                                     status=200)
                resp.cookies['session_id'] = session_id
                resp.cookies['session_id']['max-age'] = 86400
                resp.cookies['session_id']['domain'] = '.hoardinvest.com'
                resp.cookies['session_id']['httponly'] = True
                return resp
    return response.json({'errors': ['Invalid credentials']}, status=403)


@app.route('/logout', methods=['POST'])
@authorized()
async def logout(request):
    request['db'].execute(
        LOGOUT_SQL,
        (request['session']['user_uid'],))
    return response.json({'success': ['Your session has been invalidated']})


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
    app.run(host='0.0.0.0', port=8000)
