from sanic import response


def error_response(errors, status=None):
    response_data = []
    if not status:
        status = errors[0]['status']
    for error in errors:
        response_data.append({k: error[k] for k in ('code', 'message')})
    return response.json({'errors': [response_data]}, status=status)


MISSING_FIELDS = {'code': 100, 'message': 'Missing fields', 'status': 400}
UNAUTHORIZED = {'code': 101, 'message': 'Unauthorized', 'status': 403}
SMS_VERIFICATION_FAILED = {'code': 102, 'message': 'Verification failed',
                           'status': 403}
INVALID_CREDENTIALS = {'code': 103, 'message': 'Invalid credentials',
                       'status': 403}
INVALID_API_KEY = {'code': 104, 'message': 'Invalid API key', 'status': 403}
PASSWORD_TARGET = {'code': 901, 'message': 'Password target error',
                   'status': 403}
PASSWORD_CHECK = {'code': 105, 'message': 'Password error', 'status': 403}
