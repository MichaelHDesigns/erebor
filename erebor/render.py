from jinja2 import Environment, PackageLoader, select_autoescape


jinja_env = Environment(
    loader=PackageLoader('erebor', 'templates'),
    autoescape=select_autoescape(['html'])
)

unsubscribe_template = jinja_env.get_template('unsubscribe.html')
signup_email_template = jinja_env.get_template('signup_email.html')
response_template = jinja_env.get_template('response.html')

RESPONSE_ACTIONS = {
    'unsubscribe': {
        'true': 'You will no longer receive emails from Hoard.',
        'false': 'You are still set to receive emails from Hoard.'
    }
}
