import testing.postgresql
import flexmock
import pytest
from asyncpg import connect
from os import environ
environ['erebor_test'] = 'true'

from erebor.db import bp  # noqa
from erebor.email import boto3, AWS_REGION  # noqa
from erebor.erebor import app as erebor_app  # noqa

from sql.schema import (CREATE_USERS_TABLE_SQL, CREATE_IV_TABLE_SQL,
                        CREATE_RESET_TOKENS_TABLE_SQL,
                        CREATE_CONTACT_TRANSACTIONS_SQL,
                        CREATE_CURRENCY_ENUM_SQL,
                        CREATE_ADDRESSES_TABLE_SQL)  # noqa


class TestErebor(object):
    @pytest.yield_fixture
    async def app(self):
        postgresql = testing.postgresql.Postgresql()
        erebor_app.db = (postgresql.dsn())
        if not erebor_app.blueprints:
            erebor_app.blueprint(bp)
        conn = await connect(**erebor_app.db)
        await conn.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        await conn.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        await conn.execute(CREATE_USERS_TABLE_SQL)
        await conn.execute(CREATE_IV_TABLE_SQL)
        await conn.execute(CREATE_IV_TABLE_SQL)
        await conn.execute(CREATE_CURRENCY_ENUM_SQL)
        await conn.execute(CREATE_RESET_TOKENS_TABLE_SQL)
        await conn.execute(CREATE_CONTACT_TRANSACTIONS_SQL)
        await conn.execute(CREATE_ADDRESSES_TABLE_SQL)

        # mock SES
        boto_response = {'ResponseMetadata': {'RequestId': '12345'}}
        mock_boto3_client = flexmock(boto3.client(
            'ses', region_name=AWS_REGION))
        flexmock(mock_boto3_client).should_receive('send_email').and_return(
            boto_response)
        flexmock(boto3).should_receive("client").and_return(mock_boto3_client)
        yield erebor_app
        postgresql.stop()

    @pytest.fixture
    def test_cli(self, loop, app, test_client):
        return loop.run_until_complete(test_client(app))
