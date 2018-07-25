from sanic import Blueprint, response

from . import (error_response, limiter, authorized,
               unsubscribe_template, result_template)

from . import (RESULT_ACTIONS, INVALID_PLATFORM)


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


@misc_bp.route('/health', methods=['GET', 'HEAD'])
async def health_check(request):
    return response.HTTPResponse(body=None, status=200)
