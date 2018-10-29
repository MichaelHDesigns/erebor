from datetime import timedelta
import json

from sanic import Blueprint, response
from asyncpg.exceptions import UniqueViolationError
from aiocache import cached

from . import (error_response, limiter, authorized,
               unsubscribe_template, result_template, verify)

from . import (INSERT_VOTE_SQL, SELECT_ALL_VOTES_SQL,
               SELECT_ALL_SUPPORTED_COINS_SQL, SELECT_ALL_VOTES_INTERVAL_SQL)

from . import (RESULT_ACTIONS, INVALID_PLATFORM, MISSING_FIELDS, ALREADY_VOTED,
               UNSUPPORTED_CURRENCY, INVALID_ARGS, CAPTCHA_FAILED)


misc_bp = Blueprint('misc')

android_updates = {}
ios_updates = {}


@misc_bp.route('/unsubscribe')
@authorized()
async def unsubscribe(request):
    return response.html(unsubscribe_template.render(
        url="/email_preferences"))


@misc_bp.route('/result', methods=['GET'])
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


@misc_bp.route('/updates/<platform>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='updates/platform')
async def updates(request, platform):
    if platform == 'ios':
        return response.json(ios_updates)
    elif platform == 'android':
        return response.json(android_updates)
    else:
        return error_response([INVALID_PLATFORM])


@misc_bp.route('/vote', methods=['GET', 'POST'])
async def vote(request):
    db = request.app.pg
    if request.method == 'GET':
        args = request.raw_args
        if not args:
            votes = await db.fetch(SELECT_ALL_VOTES_SQL)
            return response.json({'data': [dict(record) for record in votes]})
        if args.keys() != {'interval'}:
            return error_response([INVALID_ARGS])
        try:
            interval_arg = json.loads(args['interval'])
            hours = interval_arg.get('hours')
            days = interval_arg.get('days')
            interval = timedelta(hours=hours or 0, days=days or 0)
        except ValueError:
            return error_response([INVALID_ARGS])
        if interval.total_seconds() == 0.0:
            return error_response([INVALID_ARGS])
        votes = await db.fetch(SELECT_ALL_VOTES_INTERVAL_SQL, interval)
        return response.json({'data': [dict(record) for record in votes]})
    if request.method == 'POST':
        if request.json.keys() != {'symbol', 'captcha'}:
            return error_response([MISSING_FIELDS])
        captcha = request.json['captcha']
        verify_response = await verify(captcha, request.remote_addr,
                                       'VOTE_RECAPTCHA_SECRET')
        verify_success = verify_response.get('success')
        verify_score = verify_response.get('score')
        if not verify_success:
            return error_response([CAPTCHA_FAILED])
        if verify_score and verify_score < 0.5:
            return error_response([CAPTCHA_FAILED])
        symbol = request.json['symbol']
        try:
            insert = await db.execute(INSERT_VOTE_SQL,
                                      symbol, request.remote_addr)
        except UniqueViolationError:
            return error_response([ALREADY_VOTED])
        return (response.json({'success': ['Vote registered']})
                if insert.split()[2] == '1'
                else error_response([UNSUPPORTED_CURRENCY]))


@misc_bp.route('/supported_coins', methods=['GET'])
@cached(ttl=3600)
async def supported_coins(request):
    db = request.app.pg
    coins = await db.fetch(SELECT_ALL_SUPPORTED_COINS_SQL)
    return response.json({'data': [dict(record) for record in coins]})


@misc_bp.route('/health', methods=['GET', 'HEAD'])
async def health_check(request):
    return response.HTTPResponse(body=None, status=200)
