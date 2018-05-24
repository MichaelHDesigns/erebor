import testing.postgresql
import psycopg2
import flexmock
from os import environ
environ['erebor_test'] = 'true'

from erebor.db import bp  # noqa
from erebor.email import boto3, AWS_REGION  # noqa
from erebor.erebor import app  # noqa
from erebor.email import boto3, AWS_REGION  # noqa

from sql.schema import (CREATE_USERS_TABLE_SQL, CREATE_IV_TABLE_SQL,
                        CREATE_RESET_TOKENS_TABLE_SQL,
                        CREATE_CONTACT_TRANSACTIONS_SQL,
                        CREATE_CURRENCY_ENUM_SQL,
                        CREATE_ADDRESSES_TABLE_SQL)  # noqa
app.blueprint(bp)


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

    def teardown_method(method):
        method.postgresql.stop()
