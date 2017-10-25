import testing.postgresql
import psycopg2

from smaug.smaug import app
from sql.schema import CREATE_USERS_TABLE_SQL


class TestSmaug(object):

    def setup_method(method):
        method.postgresql = testing.postgresql.Postgresql()
        app.db = psycopg2.connect(**method.postgresql.dsn())
        cur = app.db.cursor()
        cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        cur.execute(CREATE_USERS_TABLE_SQL)
        app.db.commit()

    def teardown_method(method):
        method.postgresql.stop()
