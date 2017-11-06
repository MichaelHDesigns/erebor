import testing.postgresql
import psycopg2

from smaug.smaug import app
from sql.schema import (
    CREATE_USERS_TABLE_SQL, CREATE_INVITES_TABLE_SQL,
    CREATE_NOW_SERVING_TABLE_SQL)


class TestSmaug(object):

    def setup_method(method):
        method.postgresql = testing.postgresql.Postgresql()
        app.db = psycopg2.connect(**method.postgresql.dsn())
        cur = app.db.cursor()
        cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        cur.execute(CREATE_USERS_TABLE_SQL)
        cur.execute(CREATE_INVITES_TABLE_SQL)
        cur.execute(CREATE_NOW_SERVING_TABLE_SQL)
        cur.execute('INSERT INTO now_serving (place) VALUES (100);')
        app.db.commit()

    def teardown_method(method):
        method.postgresql.stop()
