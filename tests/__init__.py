import testing.postgresql
import psycopg2
import flexmock
from os import environ
environ['erebor_test'] = 'true'

from erebor.erebor import app  # noqa
from erebor.email import boto3, AWS_REGION  # noqa
from sql.schema import CREATE_USERS_TABLE_SQL, CREATE_IV_TABLE_SQL  # noqa


class TestErebor(object):

    def setup_method(method):
        method.postgresql = testing.postgresql.Postgresql()
        app.db = psycopg2.connect(**method.postgresql.dsn())
        cur = app.db.cursor()
        cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        cur.execute(CREATE_USERS_TABLE_SQL)
        cur.execute(CREATE_IV_TABLE_SQL)
        app.db.commit()

        # mock SES
        boto_response = {'ResponseMetadata': {'RequestId': '12345'}}
        mock_boto3_client = flexmock(boto3.client(
            'ses', region_name=AWS_REGION))
        flexmock(mock_boto3_client).should_receive('send_email').and_return(
            boto_response)
        flexmock(boto3).should_receive("client").and_return(mock_boto3_client)

    def teardown_method(method):
        method.postgresql.stop()
