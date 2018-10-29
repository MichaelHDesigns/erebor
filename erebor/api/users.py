from uuid import uuid4
from hashlib import sha1
from datetime import datetime as dt
import json
import hmac
import logging
import os
import random

from asyncpg.exceptions import UniqueViolationError
from sanic import Blueprint, response

from . import (username_pattern, email_pattern, e164_pattern,
               error_response, Email, limiter, authorized, send_sms,
               password_template, verify, uuid_pattern, hoard_pattern,
               admin_pattern, check_channel)

# errors
from . import (INVALID_USERNAME, INVALID_EMAIL,
               INVALID_PHONE_NUMBER, MISSING_FIELDS, EMAIL_ADDRESS_EXISTS,
               USERNAME_EXISTS, GENERIC_USER, UNAUTHORIZED, EXPIRED_TOKEN,
               INVALID_CREDENTIALS, SMS_VERIFICATION_FAILED, PASSWORD_TARGET,
               PASSWORD_CHECK, CAPTCHA_FAILED, UNSUPPORTED_DEVICE,
               DEVICE_EXISTS, DEVICE_NOT_FOUND)
# sql
from . import (CREATE_USER_SQL, SELECT_USER_SQL, UPDATE_USER_SQL,
               ACTIVATE_USER_SQL, PASSWORD_ACCESS_SQL, SET_2FA_CODE_SQL,
               LOGIN_SQL, VERIFY_SMS_LOGIN, LOGOUT_SQL,
               SELECT_2FA_SETTINGS_SQL, UPDATE_2FA_SETTINGS_SQL,
               SELECT_CONTACT_TRANSACTIONS, CHANGE_PASSWORD_SQL,
               RESET_TOKEN_CREATION_SQL, SELECT_RESET_TOKEN_SQL,
               EXPIRE_RESET_TOKEN_SQL, SELECT_USERNAME_FNAME_FROM_EMAIL_SQL,
               SELECT_EMAIL_PREFS_SQL, UPDATE_EMAIL_PREFS_SQL,
               PRE_REGISTER_USER_SQL, ACTIVATE_PRE_REG_SQL,
               REGISTER_DEVICE_SQL, GET_SESSIONS_SQL, DESTROY_SESSIONS_SQL)


users_bp = Blueprint('users')


async def notify_contact_on_signup(to_email_address, phone_number, db):
    """
    Notifies a user if their contact has now signed up to Hoard and displays
    all of the transactions they attempted to do in an email.
    """
    transactions = await db.fetch(SELECT_CONTACT_TRANSACTIONS,
                                  to_email_address, phone_number)
    if not transactions:
        return
    for record in transactions:
        from_email_address = record['email_address']
        first_name = record['first_name']
        notify_email = Email(
            from_email_address,
            'pending_contact_transactions',
            first_name=first_name,
            to_email_address=to_email_address,
            transactions=json.loads(record['transactions'])
        )
        notify_email.send()


@users_bp.route('/users', methods=['POST'])
async def users(request):
    if not (all([
            field in request.json.keys() for field in [
            'password', 'first_name', 'last_name', 'email_address',
            'username', 'phone_number']])):
        return error_response([MISSING_FIELDS])
    device_info = request.json.get('device_info')
    if device_info is None:
        channel = '0'
        device_type = 'api'
    elif not (type(device_info) is dict and
              device_info.keys() == {'device_type', 'channel'}):
        return error_response([MISSING_FIELDS])
    else:
        channel = device_info['channel']
        device_type = device_info['device_type']
        channel_exists = await check_channel(channel)
        if not channel_exists['ok']:
            return error_response([DEVICE_NOT_FOUND])
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    db = request.app.pg
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    phone_number = (request.json['phone_number'] if
                    request.json['phone_number'] != '' else None)
    email_address = request.json['email_address']
    password = request.json['password']
    username = request.json['username']
    if (username_pattern.search(username) or
       len(username) > 18 or len(username) < 3):
        return error_response([INVALID_USERNAME])
    if not email_pattern.match(email_address):
        return error_response([INVALID_EMAIL])
    if phone_number and not e164_pattern.match(phone_number):
        return error_response([INVALID_PHONE_NUMBER])
    try:
        new_user = await db.fetchrow(
            CREATE_USER_SQL, password, first_name,
            last_name, email_address, username, phone_number, session_id,
            request.remote_addr, device_type, channel)
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
    await notify_contact_on_signup(email_address, phone_number, db)
    resp = response.json(new_user, status=201)
    resp.cookies['session_id'] = session_id
    resp.cookies['session_id']['max-age'] = 86400
    resp.cookies['session_id']['domain'] = '.hoardinvest.com'
    resp.cookies['session_id']['httponly'] = True
    return resp


@users_bp.route('/pre_register', methods=['POST'])
async def pre_register(request):
    if request.json.keys() != {'email_address', 'username', 'captcha'}:
        return error_response([MISSING_FIELDS])
    captcha = request.json['captcha']
    verify_response = await verify(captcha, request.remote_addr,
                                   'PRE_REG_RECAPTCHA_SECRET')
    verify_success = verify_response.get('success')
    verify_score = verify_response.get('score')
    if not verify_success:
        return error_response([CAPTCHA_FAILED])
    if verify_score and verify_score < 0.5:
        return error_response([CAPTCHA_FAILED])
    db = request.app.pg
    email_address = request.json['email_address']
    username = request.json['username']
    if (username_pattern.search(username) or
       len(username) > 18 or len(username) < 3 or
       hoard_pattern.match(username) or admin_pattern.match(username)):
        return error_response([INVALID_USERNAME])
    if not email_pattern.match(email_address):
        return error_response([INVALID_EMAIL])
    try:
        new_user = await db.fetchrow(
            PRE_REGISTER_USER_SQL, email_address, username)
    except UniqueViolationError as uv_error:
        if uv_error.constraint_name == 'pre_register_email_address_key':
            return error_response([EMAIL_ADDRESS_EXISTS])
        elif uv_error.constraint_name == 'pre_register_username_key':
            return error_response([USERNAME_EXISTS])
        else:
            return error_response([GENERIC_USER])
    except Exception as e:
        logging.info('error creating user {}:{}'.format(email_address, e))
        return error_response([GENERIC_USER])
    if new_user is None:
        return error_response([INVALID_USERNAME])
    # remove sensitive information
    new_user = {
        k: str(v) if k == 'uid' or k == 'activation_key'
        else v for k, v in new_user.items()
        if k not in {'id', 'uid', 'active'}
    }
    activation_key = new_user.pop('activation_key')
    activation_url = ("https://" + str(os.getenv("INSTANCE_HOST")) +
                      '/pre_register/{}'.format(activation_key))
    # TODO: Add a specific pre-registration email w/ copy about how users will
    # be able to complete their info at a later date
    pre_register_email = Email(
        email_address,
        'pre_register',
        activation_url=activation_url
    )
    pre_register_email.send()
    resp = response.json(new_user, status=201)
    return resp


@users_bp.route('/pre_register/<activation_key>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='activate/activation_key')
async def activate_pre_reg(request, activation_key):
    if not uuid_pattern.match(activation_key):
        return error_response([EXPIRED_TOKEN])
    db = request.app.pg
    try:
        user_info = await db.fetchrow(ACTIVATE_PRE_REG_SQL, activation_key)
    except ValueError:
        return error_response([EXPIRED_TOKEN])
    if user_info:
        activated_email = Email(
            user_info['email_address'],
            'activated_pre_reg',
            username=user_info['username']
        )
        activated_email.send()
        return response.redirect(
            '/result/?action=pre_reg_activate&success=true')
    return error_response([EXPIRED_TOKEN])


@users_bp.route('/users/<user_uid>', methods=['GET', 'PUT'])
@limiter.shared_limit('50 per minute', scope='users/user_uid')
@authorized()
async def user(request, user_uid):
    if request.method == 'GET':
        db = request.app.pg
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


@users_bp.route('/users/<user_uid>/register_device', methods=['POST'])
@authorized()
async def register_channel(request, user_uid):
    if user_uid != request['session']['user_uid']:
        return error_response([UNAUTHORIZED])
    registration = request.json
    if registration.keys() != {'device_type', 'channel'}:
        return error_response([MISSING_FIELDS])
    device_type = registration['device_type']
    if device_type not in ['ios', 'android']:
        return error_response([UNSUPPORTED_DEVICE])
    channel = registration['channel']
    if request['session']['channel'] == channel:
        return error_response([DEVICE_EXISTS])
    channel_exists = check_channel(channel)['ok']
    if not channel_exists:
        return error_response([DEVICE_NOT_FOUND])
    user_id = request['session']['user_id']
    await request['db'].execute(REGISTER_DEVICE_SQL, user_id, user_uid,
                                device_type, channel)
    return response.json({'success': ['Device registered']})


@users_bp.route('/activate/<activation_key>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='activate/activation_key')
async def activate_account(request, activation_key):
    if len(activation_key) != 36:
        return error_response([EXPIRED_TOKEN])
    db = request.app.pg
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


@users_bp.route('/login', methods=['POST'])
async def login(request):
    if not all([field in request.json.keys()
               for field in ['username_or_email', 'password']]):
        return error_response([MISSING_FIELDS])
    user = request.json['username_or_email']
    password = request.json['password']
    device_info = request.json.get('device_info')
    if device_info is None:
        channel = '0'
        device_type = 'api'
    elif not (type(device_info) is dict and
              device_info.keys() == {'device_type', 'channel'}):
        return error_response([MISSING_FIELDS])
    else:
        channel = device_info['channel']
        device_type = device_info['device_type']
        channel_exists = await check_channel(channel)
        if not channel_exists['ok']:
            return error_response([DEVICE_NOT_FOUND])
    db = request.app.pg
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
                await db.execute(
                    LOGIN_SQL, session_id, user_id, channel, user_uid,
                    device_type, request.remote_addr)
                resp = response.json({'success': ['Login successful'],
                                      'user_uid': user_uid},
                                     status=200)
                resp.cookies['session_id'] = session_id
                resp.cookies['session_id']['max-age'] = 86400
                resp.cookies['session_id']['domain'] = '.hoardinvest.com'
                resp.cookies['session_id']['httponly'] = True
                return resp
    return error_response([INVALID_CREDENTIALS])


@users_bp.route('/2fa/sms_login', methods=['POST'])
async def two_factor_login(request):
    if not all([field in request.json.keys()
               for field in ['username_or_email', 'sms_verification']]):
        return error_response([MISSING_FIELDS])
    device_info = request.json.get('device_info')
    if device_info is None:
        channel = '0'
        device_type = 'api'
    elif not (type(device_info) is dict and
              device_info.keys() == {'device_type', 'channel'}):
        return error_response([MISSING_FIELDS])
    else:
        channel = device_info['channel']
        device_type = device_info['device_type']
        channel_exists = check_channel(channel)['ok']
        if not channel_exists:
            return error_response([DEVICE_NOT_FOUND])
    db = request.app.pg
    sms_verification = request.json['sms_verification']
    user = request.json['username_or_email']
    user_ids = await db.fetchrow(VERIFY_SMS_LOGIN,
                                 user, sms_verification)
    if user_ids is None:
        return error_response([SMS_VERIFICATION_FAILED])
    user_id = user_ids['id']
    user_uid = user_ids['uid']
    session_id = hmac.new(uuid4().bytes, digestmod=sha1).hexdigest()
    await db.execute(
        LOGIN_SQL, session_id, user_id, channel, user_uid,
        device_type, request.remote_addr)
    resp = response.json({'success': ['Login successful'],
                          'user_uid': user_uid}, status=200)
    resp.cookies['session_id'] = session_id
    # expire in one day
    resp.cookies['session_id']['max-age'] = 86400
    resp.cookies['session_id']['domain'] = '.hoardinvest.com'
    resp.cookies['session_id']['httponly'] = True
    return resp


@users_bp.route('/logout', methods=['POST'])
@authorized()
async def logout(request):
    await request['db'].execute(
        LOGOUT_SQL,
        request['session']['user_id'], request['session']['channel'])
    return response.json({'success': ['Your session has been invalidated']})


@users_bp.route('/2fa/settings', methods=['GET', 'PUT'])
@authorized()
async def two_factor_settings(request):
    if request.method == 'GET':
        db = request.app.pg
        settings = await db.fetchrow(SELECT_2FA_SETTINGS_SQL,
                                     request['session']['user_id'])
        return response.json({'sms_2fa_enabled': settings['sms_2fa_enabled']})
    elif request.method == 'PUT':
        if request.json.keys() != {'sms_2fa_enabled'}:
            return error_response([MISSING_FIELDS])
        sms_2fa_enabled = request.json['sms_2fa_enabled']
        db = request.app.pg
        await db.execute(
            UPDATE_2FA_SETTINGS_SQL,
            sms_2fa_enabled, request['session']['user_id'])
        return response.HTTPResponse(body=None, status=200)


@users_bp.route('/change_password', methods=['POST'])
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


@users_bp.route('/password', methods=['POST'])
async def password(request):
    if request.json.keys() != {'email_address'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    db = request.app.pg
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


@users_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.shared_limit('50 per minute', scope='reset_password/token')
async def reset_password(request, token):
    if len(token) != 36:
        return error_response([EXPIRED_TOKEN])
    db = request.app.pg
    data = await db.fetchrow(SELECT_RESET_TOKEN_SQL, token, dt.now())
    if data is not None:
        if request.method == 'GET':
            return response.html(password_template.render(token=token))
        elif request.method == 'POST':
            new_password = request.json['new_password']
            user_id = data['user_id']
            await db.execute(CHANGE_PASSWORD_SQL, new_password, user_id)
            await db.execute(EXPIRE_RESET_TOKEN_SQL, token)
            return response.json(
                {'success': ['Your password has been changed']})
    else:
        return error_response([EXPIRED_TOKEN])


@users_bp.route('/forgot_username', methods=['POST'])
async def forgot_username(request):
    if request.json.keys() != {'email_address'}:
        return error_response([MISSING_FIELDS])
    email_address = request.json['email_address']
    db = request.app.pg
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


@users_bp.route('/email_preferences', methods=['PUT', 'GET'])
@authorized()
async def email_preferences(request):
    if request.method == 'GET':
        db = request.app.pg
        settings = await db.fetchrow(SELECT_EMAIL_PREFS_SQL,
                                     request['session']['user_id'])
        return response.json({'receive_emails_enabled':
                              settings['receive_emails_enabled']})
    elif request.method == 'PUT':
        if request.json.keys() != {'receive_emails_enabled'}:
            return error_response([MISSING_FIELDS])
        receive_emails_enabled = request.json['receive_emails_enabled']
        db = request.app.pg
        await db.execute(UPDATE_EMAIL_PREFS_SQL,
                         receive_emails_enabled,
                         request['session']['user_id'])
        return response.json(
            {'success': ['Your email preferences have been updated']}
        )


@users_bp.route('/users/<user_uid>/destroy_sessions', methods=['POST'])
@authorized()
async def destroy_sessions(request, user_uid):
    if user_uid != request['session']['user_uid']:
        return error_response([UNAUTHORIZED])
    await request['db'].execute(DESTROY_SESSIONS_SQL, request[
        'session']['user_id'])
    return response.json({'success': [
        'Your sessions across all devices have been invalidated']})


@users_bp.route('/users/<user_uid>/get_sessions', methods=['GET'])
@authorized()
async def get_sessions(request, user_uid):
    if user_uid != request['session']['user_uid']:
        return error_response([UNAUTHORIZED])
    sessions = await request['db'].fetch(GET_SESSIONS_SQL, request[
        'session']['user_id'])
    return response.json({'sessions': [dict(session) for session in sessions]})
