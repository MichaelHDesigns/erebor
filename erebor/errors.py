from sanic import response


def error_response(errors, status=None):
    error_data = []
    if not status:
        status = errors[0]['status']
    for error in errors:
        error_data.append({k: error[k] for k in ('code', 'message')})
    return response.json({'errors': error_data}, status=status)


# Web server errors
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
TICKER_UNAVAILABLE = {'code': 106, 'message': 'Ticker currently unavailable',
                      'status': 500}
GENERIC_USER = {'code': 107, 'message': 'Error creating user', 'status': 400}
INVALID_PLATFORM = {'code': 400, 'message': 'Invalid platform', 'status': 404}
EXPIRED_TOKEN = {'code': 108,
                 'message': 'Token is either invalid or expired',
                 'status': 403}
INVALID_USERNAME = {'code': 109, 'message': 'Invalid username',
                    'status': 400}
INVALID_EMAIL = {'code': 110, 'message': 'Invalid email address',
                 'status': 400}
USER_NOT_FOUND = {'code': 111, 'message': 'User not found for given username',
                  'status': 400}
USERNAME_EXISTS = {'code': 112, 'message': 'Username already exists',
                   'status': 403}
EMAIL_ADDRESS_EXISTS = {'code': 113, 'message': 'Email address already exists',
                        'status': 403}
INVALID_TRANSACTION_UID = {'code': 114, 'message': 'Invalid transaction UID',
                           'status': 400}
PHONE_NUMBER_EXISTS = {'code': 115, 'message': 'Phone number already exists',
                       'status': 403}
INVALID_PHONE_NUMBER = {'code': 116, 'message': 'Invalid phone number',
                        'status': 400}
RATE_LIMIT_EXCEEDED = {'code': 429, 'message': 'Too many requests.',
                       'status': 429}
ROUTE_NOT_FOUND = {'code': 404, 'message': 'Route not found', 'status': 404}
USER_NOT_REGISTERED = {'code': 117, 'message': 'User has not registered yet',
                       'status': 400}
ALREADY_NOTIFIED = {'code': 118,
                    'message': 'User recently notified, please wait 24 hours '
                    'before notifying again.',
                    'status': 403}

# Blockchain errors
INSUFFICIENT_BALANCE = {'code': 200, 'message': 'Insufficient balance',
                        'status': 403}
NEGATIVE_AMOUNT = {'code': 201, 'message': 'Invalid amount', 'status': 403}
UNSUPPORTED_CURRENCY = {'code': 202, 'message': 'Unsupported Currency',
                        'status': 403}
NO_PUBLIC_KEY = {'code': 203, 'message': 'No public key found for user',
                 'status': 403}
INVALID_SWAP_SERVICE = {'code': 204, 'message': 'Unsupported swap service',
                        'status': 403}

# Misc Errors
ALREADY_VOTED = {'code': 300,
                 'message': 'You have already voted for this coin',
                 'status': 403}
INVALID_ARGS = {'code': 301,
                'message': 'Invalid parameter arguments',
                'status': 404}
CURRENCY_ALREADY_SUPPORTED = {'code': 302,
                              'message': 'Currency already supported',
                              'status': 403}
VOTING_SUSPENDED = {'code': 303,
                    'message': '{} temporarily suspended',
                    'status': 403}
CAPTCHA_FAILED = {'code': 304, 'message': 'Captcha failed',
                  'status': 403}
