import json

import testing.postgresql
import psycopg2

from smaug import app
from sql.schema import CREATE_REGISTRATIONS_TABLE_SQL, CREATE_USERS_TABLE_SQL


class TestHoard(object):

    def setup_method(method):
        method.postgresql = testing.postgresql.Postgresql()
        app.db = psycopg2.connect(**method.postgresql.dsn())
        cur = app.db.cursor()
        cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
        cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
        cur.execute(CREATE_REGISTRATIONS_TABLE_SQL)
        cur.execute(CREATE_USERS_TABLE_SQL)
        app.db.commit()

    def teardown_method(method):
        method.postgresql.stop()

    def test_health(self):
        request, response = app.test_client.get('/health')
        assert response.status == 200

    def test_registration(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}))
        data = response.json
        assert data.keys() == {'registration_id'}
        assert response.status == 201

    def test_registration_no_info(self):
        request, response = app.test_client.post(
            '/registration', data=json.dumps({'full_name': 'test'}))
        data = response.json
        assert response.status == 400
        assert data.keys() == {'errors'}

    def test_create_account(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}))
        r_data = response.json
        r_id = r_data['registration_id']
        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        data = response.json
        assert data.keys() == {'uid', 'api_key', 'full_name',
                               'email_address'}
        assert (data['full_name'],
                data['email_address']) == ('test', 'test@example.com')

    def test_get_user(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        data = response.json
        assert data.keys() == {'uid', 'email_address', 'full_name'}
        assert (data['full_name'],
                data['email_address']) == ('test', 'test@example.com')

    def test_update_user(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}))
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.put(
            '/users/{}/'.format(u_data['uid']),
            data=json.dumps({'full_name': 'changed',
                             'email_address': 'changed@example.com'}),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        c_data = response.json
        assert (c_data['full_name'],
                c_data['email_address']) == ('changed', 'changed@example.com')

    def test_login(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/login', data=json.dumps({'email_address': 'test@example.com',
                                       'password': 'test'}))
        l_data = response.json
        assert l_data.keys() == {'api_key'}

        new_api_key = l_data['api_key']
        assert new_api_key != u_data['api_key']

        # test new api key
        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 403

        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + new_api_key})
        assert response.status == 200

    def test_logout(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/logout',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 403

    def test_change_password(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/change_password',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']},
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'email_address': 'test@example.com'}))
        assert response.status == 200

        request, response = app.test_client.post(
            '/logout',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'email_address': 'test@example.com',
                             'password': 'test'}))
        assert response.status == 403

        request, response = app.test_client.post(
            '/login',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']},
            data=json.dumps({'email_address': 'test@example.com',
                             'password': 'test2'}))
        assert response.status == 200
        assert response.json.keys() == {'api_key'}

    def test_change_password_permissions(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'Bob Smith',
                             'email_address': 'bob@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        bob_data = response.json

        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'Larry Ramsay',
                             'email_address': 'larry@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        larry_data = response.json

        request, response = app.test_client.post(
            '/change_password',
            headers={'Authorization': 'ApiKey ' + larry_data['api_key']},
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'email_address': 'bob@example.com'}))
        assert response.status == 403

    def test_get_wallet(self):
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'test',
                             'email_address': 'test@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}/wallet'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

    def test_wallet_permissions(self):
        # B: Users can only get their own wallet
        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'Bob Smith',
                             'email_address': 'bob@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        bob_data = response.json

        request, response = app.test_client.post(
            '/registration',
            data=json.dumps({'full_name': 'Larry Ramsay',
                             'email_address': 'larry@example.com'}),
            )
        r_data = response.json
        r_id = r_data['registration_id']

        request, response = app.test_client.post(
            '/users', data=json.dumps({'registration_id': r_id,
                                       'password': 'test'}))
        larry_data = response.json

        request, response = app.test_client.get(
            '/users/{}/wallet'.format(bob_data['uid']),
            headers={'Authorization': 'ApiKey ' + larry_data['api_key']},
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'email_address': 'bob@example.com'}))
        assert response.status == 403
