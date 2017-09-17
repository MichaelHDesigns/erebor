from uuid import uuid4
from functools import wraps
from hashlib import sha1
import hmac
import logging
import os

from sanic import Sanic, response
from sanic.config import LOGGING
import psycopg2
import psycopg2.extras


app = Sanic()

try:
    LOGGING['loggers']['network']['handlers'] = [
        'accessTimedRotatingFile', 'errorTimedRotatingFile']
except Exception as e:
    print('Logging disabled: %s' % e)

CREATE_REGISTRATION_SQL = """
INSERT INTO registrations (full_name, email_address)
VALUES (%s, %s)
RETURNING *;
""".strip()

PASSWORD_ACCESS_SQL = """
SELECT crypt(%s, password) = password AS accessed, id
FROM users
WHERE email_address = %s
""".strip()

SELECT_USER_SQL = """
SELECT uid, full_name, email_address
FROM users
WHERE uid = %s
""".strip()

UPDATE_USER_SQL = """
UPDATE users
SET full_name = %s, email_address = %s
WHERE uid = %s
""".strip()

CREATE_USER_SQL = """
WITH x AS (
  SELECT %s::text as password,
    gen_salt('bf')::text AS salt
)
INSERT INTO users (password, salt, full_name, email_address, api_key)
SELECT crypt(x.password, x.salt), x.salt, r.full_name, r.email_address, %s
FROM x, registrations r
WHERE r.uid = (%s)
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


@app.route('/registration', methods=['POST'])
async def registration(request):
    if request.json.keys() != {'full_name', 'email_address'}:
        return response.json({'errors': ['Missing fields']},
                             status=400)
    db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    full_name = request.json['full_name']
    email_address = request.json['email_address']
    db.execute(CREATE_REGISTRATION_SQL, (full_name, email_address,))
    res = db.fetchone()
    app.db.commit()
    return response.json({'registration_id': res['uid']}, 201)


@app.route('/users', methods=['POST'])
async def users(request):
    if request.json.keys() != {'registration_id', 'password'}:
        return response.json({'errors': ['Missing fields']}, status=400)
    api_key = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    registration_id = request.json['registration_id']
    password = request.json['password']
    db.execute(CREATE_USER_SQL, (password, api_key, registration_id))
    new_user = db.fetchone()
    # remove sensitive information
    new_user = {k: v for k, v in new_user.items() if k not in
                {'password', 'salt', 'id'}}
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
        if request.json.keys() != {'full_name', 'email_address'}:
            return response.json({'errors': ['Missing fields']}, status=400)
        full_name = request.json['full_name']
        email_address = request.json['email_address']
        request['db'].execute(UPDATE_USER_SQL,
                              (full_name, email_address, user_uid))
        app.db.commit()
        return response.HTTPResponse(body=None, status=200)


@app.route('/login', methods=['POST'])
async def login(request):
    email_address = request.json.get('email_address')
    password = request.json.get('password')
    db = app.db.cursor()
    db.execute(PASSWORD_ACCESS_SQL, (password, email_address))
    login = db.fetchone()
    if login:
        access, user_id = login
        if access:
            api_key = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
            db.execute(LOGIN_SQL,
                       (api_key, user_id))
            app.db.commit()
            return response.json({'api_key': api_key}, status=200)
    return response.json({'errors': 'Invalid credentials'}, status=403)


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
        access, user_id = login
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
                               'amount': 123.456789},
                              {'symbol': 'BITB',
                               'amount': 1.0}])


@app.route('/health', methods=['GET'])
async def health_check(request):
    return response.HTTPResponse(body=None, status=200)


if __name__ == '__main__':
    app.db = psycopg2.connect(dbname=os.environ.get('SMAUG_DB_NAME'),
                              user=os.environ.get('SMAUG_DB_USER'),
                              password=os.environ.get('SMAUG_DB_PASSWORD'),
                              host=os.enivorn.get('SMAUG_DB_HOST'),
                              port=5432)
    app.run(host='0.0.0.0', port=80, log_config=LOGGING)
