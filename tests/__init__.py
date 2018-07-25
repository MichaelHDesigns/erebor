import testing.postgresql
import psycopg2
import flexmock
import json
from os import environ
environ['erebor_test'] = 'true'

from erebor import api  # noqa
from erebor.api.users import users_bp  # noqa
from erebor.api.transactions import transactions_bp  # noqa
from erebor.api.support import support_bp  # noqa
from erebor.api.misc import misc_bp  # noqa
from erebor.api.prices import prices_bp  # noqa
from erebor.api.verification import verification_bp  # noqa
from erebor.db import db_bp  # noqa
from erebor.email import boto3, AWS_REGION  # noqa
from erebor.erebor import app  # noqa

from sql.schema import (CREATE_USERS_TABLE_SQL, CREATE_IV_TABLE_SQL,
                        CREATE_RESET_TOKENS_TABLE_SQL,
                        CREATE_CONTACT_TRANSACTIONS_SQL,
                        CREATE_CURRENCY_ENUM_SQL,
                        CREATE_ADDRESSES_TABLE_SQL)  # noqa
app.blueprint(db_bp)
app.blueprint(users_bp)
app.blueprint(transactions_bp)
app.blueprint(support_bp)
app.blueprint(misc_bp)
app.blueprint(prices_bp)
app.blueprint(verification_bp)


test_user_data = {'first_name': 'Testy',
                  'last_name': 'McTestface',
                  'email_address': 'test@example.com',
                  'username': 'xXtestyXx',
                  'password': 't3st_password',
                  'phone_number': '19105552323'}


def new_user(app):
    request, response = app.test_client.post(
        '/users', data=json.dumps(test_user_data))
    u_data = response.json
    cookies = response.cookies
    session_id = cookies['session_id'].value
    return u_data, session_id


class TestErebor(object):

    def setup_method(method):
        method.postgresql = testing.postgresql.Postgresql()
        app.db = (method.postgresql.dsn())
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
                cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
                cur.execute(CREATE_USERS_TABLE_SQL)
                cur.execute(CREATE_IV_TABLE_SQL)
                cur.execute(CREATE_IV_TABLE_SQL)
                cur.execute(CREATE_CURRENCY_ENUM_SQL)
                cur.execute(CREATE_RESET_TOKENS_TABLE_SQL)
                cur.execute(CREATE_CONTACT_TRANSACTIONS_SQL)
                cur.execute(CREATE_ADDRESSES_TABLE_SQL)

        # mock SES
        boto_response = {'ResponseMetadata': {'RequestId': '12345'}}
        mock_boto3_client = flexmock(boto3.client(
            'ses', region_name=AWS_REGION))
        flexmock(mock_boto3_client).should_receive('send_email').and_return(
            boto_response)
        flexmock(boto3).should_receive("client").and_return(mock_boto3_client)
        flexmock(api.users).should_receive('send_sms').and_return()
        flexmock(api.transactions).should_receive('send_sms').and_return()

    def teardown_method(method):
        method.postgresql.stop()
