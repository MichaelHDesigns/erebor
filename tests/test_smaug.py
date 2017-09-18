import json

import flexmock
import testing.postgresql
import psycopg2

from smaug import app
from sql.schema import CREATE_USERS_TABLE_SQL


test_user_data = {'first_name': 'Testy',
                  'last_name': 'McTestface',
                  'email_address': 'test@example.com',
                  'password': 't3st_password',
                  'phone_number': '19105552323'}


class TestHoard(object):

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

    def test_health(self):
        request, response = app.test_client.get('/health')
        assert response.status == 200

    def test_create_account(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        assert u_data.keys() == {'uid', 'api_key', 'first_name', 'last_name',
                                 'email_address', 'phone_number',
                                 'sms_2fa_enabled'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

    def test_get_user(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        data = response.json
        assert data.keys() == {'uid', 'email_address', 'first_name',
                               'last_name', 'phone_number', 'sms_2fa_enabled'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

    def test_update_user(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        change_data = {'first_name': 'Changey',
                       'last_name': 'McChangeface',
                       'phone_number': '12345678989',
                       'email_address': 'changed@example.com'}

        request, response = app.test_client.put(
            '/users/{}/'.format(u_data['uid']),
            data=json.dumps(change_data),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        c_data = response.json
        for each_key in test_user_data.keys() - {'password'}:
            assert c_data[each_key] == change_data[each_key]

    def test_login(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'email_address': test_user_data['email_address'],
                             'password': test_user_data['password']}))
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
            '/users', data=json.dumps(test_user_data))
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
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        request, response = app.test_client.post(
            '/change_password',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']},
            data=json.dumps(
                {'new_password': 'test2',
                 'password': test_user_data['password'],
                 'email_address': test_user_data['email_address']}))
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
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.post(
            '/users',
            data=json.dumps({'first_name': 'Bob',
                             'last_name': 'Smith',
                             'phone_number': '19876543232',
                             'email_address': 'bob@example.com',
                             'password': 'test'}))

        request, response = app.test_client.post(
            '/change_password',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']},
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'email_address': 'bob@example.com'}))
        assert response.status == 403

    def test_get_wallet(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.get(
            '/users/{}/wallet'.format(u_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.status == 200

        wallet_data = response.json
        for coin in wallet_data:
            assert coin.keys() == {'symbol', 'amount'}

    def test_wallet_permissions(self):
        # B: Users can only get their own wallet
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.post(
            '/users',
            data=json.dumps({'first_name': 'Bob',
                             'last_name': 'Smith',
                             'phone_number': '19876543232',
                             'email_address': 'bob@example.com',
                             'password': 'test'}),
            )
        bob_data = response.json

        request, response = app.test_client.get(
            '/users/{}/wallet'.format(bob_data['uid']),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']},
        )
        assert response.status == 403

    def test_enable_sms_2fa(self):
        # B: Users can see if sms-based 2fa is enabled
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.get(
            '/2fa/settings',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.json.keys() == {'sms_2fa_enabled'}

        # B: 2fa is disabled by default
        assert response.json['sms_2fa_enabled'] is False

        # B: Users can enable sms-based 2fa
        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})

        assert response.status == 200

        request, response = app.test_client.get(
            '/2fa/settings',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})
        assert response.json['sms_2fa_enabled'] is True

        # B: Users can disable sms-based 2fa
        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': False}),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})

        assert response.status == 200

        request, response = app.test_client.get(
            '/2fa/settings',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})

        assert response.json['sms_2fa_enabled'] is False

    def test_2fa_login(self):
        # B: Users can see if sms-based 2fa is enabled
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        u_data = response.json

        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}),
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})

        request, response = app.test_client.post(
            '/logout',
            headers={'Authorization': 'ApiKey ' + u_data['api_key']})

        import smaug
        flexmock(smaug).should_receive('send_sms').and_return()

        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'email_address': test_user_data['email_address'],
                             'password': test_user_data['password']}))
        l_data = response.json
        assert l_data == {'success': ['2FA has been sent']}

        # Grab generated code
        db = app.db.cursor()
        db.execute(
            'SELECT sms_verification FROM users WHERE email_address = %s',
            (test_user_data['email_address'],))
        result = db.fetchone()
        sms_verification = result[0]

        request, response = app.test_client.post(
            '/2fa/sms_login',
            data=json.dumps(
                {'sms_verification': sms_verification,
                 'email_address': test_user_data['email_address']}))
        assert response.json.keys() == {'api_key'}
