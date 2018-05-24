import json
from uuid import uuid4
from datetime import datetime

import flexmock
import requests
import psycopg2
from psycopg2.extras import RealDictCursor

from erebor import erebor
from erebor.erebor import app

from . import TestErebor

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


class TestResources(TestErebor):

    def test_health(self):
        request, response = app.test_client.head('/health')
        assert response.status == 200

    def test_limiter(self):
        for i in range(0, 49):
            request, response = app.test_client.head('/health')
            assert response.status == 200

        # Now throttled after 50 requests in a minute
        request, response = app.test_client.head('/health')
        assert response.status == 429

    def test_errors(self):
        request, response = app.test_client.post(
            '/users', data=json.dumps({'blah': 'blah'}))
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Missing fields',
                                     'code': 100}]}

    def test_create_account(self):
        u_data, session_id = new_user(app)

        assert u_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'username',
                                 'receive_emails_enabled', 'phone_number',
                                 'sms_2fa_enabled', 'active'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

        # B: Users can have one account per email
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        e_data = response.json
        assert e_data.keys() == {'errors'}

        # Doing this doesn't break the db connection
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test2@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        o_data = response.json
        assert o_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'username',
                                 'receive_emails_enabled', 'phone_number',
                                 'sms_2fa_enabled', 'active'}

        # B: Users can have one account per username
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test3@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors':
                          [{'code': 112,
                            'message': 'Username already exists'}]}

        # B: Username cannot have special characters
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test4@example.com'
        other_test_user_data['username'] = 'new_user_@@!'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 109,
                                      'message': 'Invalid username'}]}

        # B: Username cannot be greater than 32 characters
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test4@example.com'
        other_test_user_data['username'] = 'new_user_of_length_greater_than_32'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 109,
                                      'message': 'Invalid username'}]}

        # B: Email must be a valid email
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'not_an_email@@test.org'
        other_test_user_data['username'] = 'new_user_name'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 110,
                                      'message': 'Invalid email address'}]}

    def test_account_creation_error(self):
        u_data, session_id = new_user(app)

        # B: Email address already exists error response
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        e_data = response.json
        assert response.status == 403
        assert e_data == {'errors': [
                {'code': 113, 'message': 'Email address already exists'}]}

        other_user_data = test_user_data.copy()
        other_user_data['email_address'] = 'other_email@test.com'

        # B: Username already exists error response
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_user_data))
        e_data = response.json
        assert response.status == 403
        assert e_data == {'errors': [
                {'code': 112, 'message': 'Username already exists'}]}

    def test_activate_account(self):
        u_data, session_id = new_user(app)

        # Connect to the DB to retrieve the user's activation key
        SELECT_ACTIVATION_KEY = """
        SELECT activation_key, active
        FROM users
        WHERE id = 1
        """.strip()

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(SELECT_ACTIVATION_KEY)
                result = cur.fetchone()
        activation_key = result[0]
        active = result[1]

        assert active is False

        # B: User activates their account via the activation link
        request, response = app.test_client.get(
            '/activate/{}'.format(activation_key),
            data=json.dumps(test_user_data))

        assert response.status == 200

        # Connect to the DB to verify active is now True
        SELECT_ACTIVE_STATUS = """
        SELECT active
        FROM users
        WHERE id = 1
        """.strip()

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(SELECT_ACTIVE_STATUS)
                result = cur.fetchone()
        active = result[0]

        assert active is True

        # B: User clicks the link and sees an expired activation key
        request, response = app.test_client.get(
            '/activate/{}'.format(activation_key),
            data=json.dumps(test_user_data))
        e_data = response.json
        assert e_data == {'errors': [
            {'code': 108, 'message': 'Token is either invalid or expired'}]}

    def test_get_user(self):
        u_data, session_id = new_user(app)

        # B: User retrieves their account's information
        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})
        data = response.json
        assert data.keys() == {'uid', 'email_address', 'username',
                               'first_name', 'last_name', 'phone_number',
                               'sms_2fa_enabled'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

    def test_update_user(self):
        u_data, session_id = new_user(app)

        change_data = {'first_name': 'Changey',
                       'last_name': 'McChangeface',
                       'phone_number': '12345678989',
                       'email_address': 'changed@example.com',
                       'username': 'changed_user_nam3'}

        # B: User updates their account with new data
        request, response = app.test_client.put(
            '/users/{}/'.format(u_data['uid']),
            data=json.dumps(change_data),
            cookies={'session_id': session_id})

        assert response.status == 200

        # B: User retrieves their account's information to see the changes
        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            cookies={'session_id': session_id})
        c_data = response.json
        for each_key in test_user_data.keys() - {'password'}:
            assert c_data[each_key] == change_data[each_key]

    def test_login(self):
        u_data, session_id = new_user(app)
        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})
        assert response.status == 200

        # B: User logs in with their email address
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({
                'username_or_email': test_user_data['email_address'],
                'password': test_user_data['password']}))
        new_cookies = response.cookies
        assert new_cookies.keys() == {'session_id'}

        data = response.json
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

        new_session_id = new_cookies['session_id'].value
        assert new_session_id != session_id

        # Verify old api key is invalid
        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})

        assert response.status == 403

        # Key from email address login is currently valid
        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            cookies={'session_id': new_session_id})

        assert response.status == 200

        # B: User logs in with their username instead
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({
                'username_or_email': test_user_data['username'],
                'password': test_user_data['password']}))
        session_from_username = response.cookies['session_id'].value
        assert session_from_username != new_session_id

        # Verify old api key is invalid
        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': new_session_id})

        assert response.status == 403

        # Key from username login is currently valid
        request, response = app.test_client.get(
            '/users/{}/'.format(u_data['uid']),
            cookies={'session_id': session_from_username})

        assert response.status == 200

    def test_logout(self):
        u_data, session_id = new_user(app)

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})

        assert response.status == 200

        request, response = app.test_client.post(
            '/logout',
            cookies={'session_id': session_id})

        assert response.status == 200

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})

        assert response.status == 403

    def test_change_password(self):
        u_data, session_id = new_user(app)

        request, response = app.test_client.get(
            '/users/{}'.format(u_data['uid']),
            cookies={'session_id': session_id})

        assert response.status == 200

        # B: User changes their password using their email address
        request, response = app.test_client.post(
            '/change_password',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'new_password': 'test2',
                 'password': test_user_data['password'],
                 'username_or_email': test_user_data['email_address']}))
        assert response.status == 200

        request, response = app.test_client.post(
            '/logout',
            cookies={'session_id': session_id})
        assert response.status == 200

        # Verify old password returns FORBIDDEN
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'username_or_email': 'test@example.com',
                             'password': 'test'}))
        assert response.status == 403

        # B: User logs in with their new password
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'username_or_email': 'test@example.com',
                             'password': 'test2'}))
        assert response.status == 200
        assert response.cookies.keys() == {'session_id'}
        new_session = response.cookies['session_id'].value

        # B: User changes their password with their username instead
        request, response = app.test_client.post(
            '/change_password',
            cookies={'session_id': new_session},
            data=json.dumps(
                {'new_password': 'test3',
                 'password': 'test2',
                 'username_or_email': test_user_data['username']}))
        assert response.status == 200

        # Verify old password returns FORBIDDEN
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'username_or_email': 'test@example.com',
                             'password': 'test2'}))
        assert response.status == 403

        # B: User logs in with their new password
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({'username_or_email': 'test@example.com',
                             'password': 'test3'}))
        assert response.status == 200
        assert response.cookies.keys() == {'session_id'}

    def test_change_password_permissions(self):
        u_data, session_id = new_user(app)

        request, response = app.test_client.post(
            '/users',
            data=json.dumps({'first_name': 'Bob',
                             'last_name': 'Smith',
                             'phone_number': '19876543232',
                             'email_address': 'bob@example.com',
                             'username': 'bobTHEbuilder',
                             'password': 'test'}))

        # B: User attempts to change their password while having another user's
        # active API key
        request, response = app.test_client.post(
            '/change_password',
            cookies={'session_id': session_id},
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'username_or_email': 'bob@example.com'}))
        assert response.status == 403

    def test_reset_password(self):
        u_data, session_id = new_user(app)

        # B: User types their email address for a password reset. Email sent
        request, response = app.test_client.post(
            '/password',
            data=json.dumps({'email_address': 'test@example.com'})
        )
        assert response.status == 200
        assert response.json == {
            'success': ['If our records match you will receive an email']
        }

        # Grab the reset token generated for the user which would normally be
        # included as a link in their email
        SELECT_RESET_TOKEN_SQL = """
        SELECT reset_token, id
        FROM reset_tokens
        WHERE email_address = %s
        """.strip()
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    SELECT_RESET_TOKEN_SQL,
                    (test_user_data['email_address'],))
                test_token, user_id = cur.fetchone()

        # B: User alters the reset password URL with an invalid length token
        # and returns invalid token error
        request, response = app.test_client.get(
            '/reset_password/{}'.format(test_token + 'a'))
        assert response.status == 403
        e_data = response.json
        assert e_data == {
            'errors': [{
                'message': 'Token is either invalid or expired',
                'code': 108
            }]
        }

        # B: User sees the password reset form with their valid reset token
        # link
        request, response = app.test_client.get(
            '/reset_password/{}'.format(test_token))
        assert response.status == 200

        # B: User changes password with unique URL form
        request, response = app.test_client.post(
            '/reset_password/{}'.format(test_token),
            data=json.dumps({'new_password': 'test_pw_reset'}))
        assert response.status == 200

        # B: User attempts to click on the link again and sees that the
        # reset token has now been expired
        request, response = app.test_client.get(
            '/reset_password/{}'.format(test_token))
        assert response.status == 403
        e_data = response.json
        assert e_data == {
            'errors': [{
                'message': 'Token is either invalid or expired',
                'code': 108
            }]
        }

        # B: User logs in with new password
        request, response = app.test_client.post(
            '/login',
            data=json.dumps({
                'username_or_email': test_user_data['email_address'],
                'password': 'test_pw_reset'}))
        new_cookies = response.cookies
        assert new_cookies.keys() == {'session_id'}

        data = response.json
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

    def test_email_preferences(self):
        u_data, session_id = new_user(app)

        # Users can check their email preferences
        request, response = app.test_client.get(
            '/email_preferences',
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json.keys() == {'receive_emails_enabled'}

        # Receiving emails are enabled by default
        assert response.json['receive_emails_enabled'] is True

        # Users can disable receiving emails
        request, response = app.test_client.put(
            '/email_preferences',
            data=json.dumps({'receive_emails_enabled': False}),
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json.keys() == {'success'}

        request, response = app.test_client.get(
            '/email_preferences',
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json['receive_emails_enabled'] is False

        # Users can re-enable receiving emails
        request, response = app.test_client.put(
            '/email_preferences',
            data=json.dumps({'receive_emails_enabled': True}),
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json.keys() == {'success'}

        request, response = app.test_client.get(
            '/email_preferences',
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json['receive_emails_enabled'] is True

    def test_enable_sms_2fa(self):
        # B: Users can see if sms-based 2fa is enabled
        u_data, session_id = new_user(app)

        request, response = app.test_client.get(
            '/2fa/settings',
            cookies={'session_id': session_id})
        assert response.json.keys() == {'sms_2fa_enabled'}

        # B: 2fa is disabled by default
        assert response.json['sms_2fa_enabled'] is False

        # B: Users can enable sms-based 2fa
        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}),
            cookies={'session_id': session_id})

        assert response.status == 200

        request, response = app.test_client.get(
            '/2fa/settings',
            cookies={'session_id': session_id})
        assert response.json['sms_2fa_enabled'] is True

        # B: Users can disable sms-based 2fa
        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': False}),
            cookies={'session_id': session_id})

        assert response.status == 200

        request, response = app.test_client.get(
            '/2fa/settings',
            cookies={'session_id': session_id})

        assert response.json['sms_2fa_enabled'] is False

    def test_2fa_login(self):
        # B: Users can see if sms-based 2fa is enabled
        u_data, session_id = new_user(app)

        request, response = app.test_client.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}),
            cookies={'session_id': session_id})

        request, response = app.test_client.post(
            '/logout',
            cookies={'session_id': session_id})

        import erebor
        flexmock(erebor.erebor).should_receive('send_sms').and_return()

        request, response = app.test_client.post(
            '/login',
            data=json.dumps({
                'username_or_email': test_user_data['email_address'],
                'password': test_user_data['password']}))
        l_data = response.json
        assert l_data == {'success': ['2FA has been sent']}

        # Grab generated code
        TEST_SQL = """
        SELECT sms_verification
        FROM users WHERE email_address = %s
        """.strip()
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    TEST_SQL,
                    (test_user_data['email_address'],))
                result = cur.fetchone()
        sms_verification = result[0]

        request, response = app.test_client.post(
            '/2fa/sms_login',
            data=json.dumps(
                {'sms_verification': sms_verification,
                 'username_or_email': test_user_data['email_address']}))
        assert response.cookies.keys() == {'session_id'}
        data = response.json
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

    def test_ticker(self):
        # B: Logged in users can access BTC/USD and ETH/USD pricing
        u_data, session_id = new_user(app)

        request, response = app.test_client.get(
            '/ticker',
            cookies={'session_id': session_id})
        assert response.status == 200
        data = response.json
        assert data.keys() == {'btc_usd', 'eth_usd'}
        # B: do it again to make sure caching works
        request, response = app.test_client.get(
            '/ticker',
            cookies={'session_id': session_id})
        assert response.status == 200

        request, response = app.test_client.get(
            '/ticker')
        assert response.status == 403

    def test_jumio(self):
        # B: Callbacks from Jumio can be parsed
        u_data, session_id = new_user(app)

        CALLBACK_UPLOADED = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22AUT%22%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22UPLOADED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa
        CALLBACK_SUCCESS = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22USA%22%2C%22extractedData%22%3A%7B%22firstName%22%3A%22FIRSTNAME%22%2C%22lastName%22%3A%22LASTNAME%22%2C%22signatureAvailable%22%3Atrue%2C%22ssn%22%3A%22xxxxxxxxx%22%7D%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22EXTRACTED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa
        CALLBACK_FAILURE = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22USA%22%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22DISCARDED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa

        scan_reference = uuid4()

        request, response = app.test_client.post(
            '/jumio_callback',
            data=CALLBACK_UPLOADED.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        request, response = app.test_client.get(
            '/jumio_results/{}'.format(scan_reference),
            cookies={'session_id': session_id})
        assert response.status == 200
        data = response.json

        assert len(data['results']) == 1
        print(data['results'])
        assert json.loads(data['results'][0]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        request, response = app.test_client.post(
            '/jumio_callback',
            data=CALLBACK_SUCCESS.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        request, response = app.test_client.get(
            '/jumio_results/{}'.format(scan_reference),
            cookies={'session_id': session_id})
        assert response.status == 200
        data = response.json
        assert len(data['results']) == 2
        assert json.loads(data['results'][1]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        # B: User can fail to scan their documents correctly
        scan_reference = uuid4()

        request, response = app.test_client.post(
            '/jumio_callback',
            data=CALLBACK_UPLOADED.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        request, response = app.test_client.get(
            '/jumio_results/{}'.format(scan_reference),
            cookies={'session_id': session_id})
        assert response.status == 200
        data = response.json

        assert len(data['results']) == 1
        assert json.loads(data['results'][0]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        request, response = app.test_client.post(
            '/jumio_callback',
            data=CALLBACK_FAILURE.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        request, response = app.test_client.get(
            '/jumio_results/{}'.format(scan_reference),
            cookies={'session_id': session_id})
        assert response.status == 200
        data = response.json
        assert len(data['results']) == 2
        assert json.loads(data['results'][1]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

    def test_ca_bridge(self):
        # B: Comply Advantage API bridge works
        u_data, session_id = new_user(app)
        ca_data = {
            "search_term": "A Bad Company Ltd",
            "fuzziness": 0.6,
            "filters": {
                "types": ["sanction", "warning"]
            },
            "tags": {
                "name": "value"
            },
            "share_url": 1
        }

        with open('./tests/ca_mock.json') as ca_mock_file:
            ca_mock_resp_data = json.load(ca_mock_file)
            ca_mock_resp = flexmock(json=lambda: ca_mock_resp_data)
            flexmock(requests).should_receive('post').and_return(
                ca_mock_resp)

        request, response = app.test_client.post(
            '/ca_search',
            cookies={'session_id': session_id},
            data=json.dumps(ca_data))

        assert response.status == 200

    def test_ca_bridge_zd_ticket(self):
        # B: Search hits result in sending zendesk ticket
        u_data, session_id = new_user(app)
        ca_data = {
            "search_term": "A Bad Company Ltd",
            "fuzziness": 0.6,
            "filters": {
                "types": ["sanction", "warning"]
            },
            "tags": {
                "name": "value"
            },
            "share_url": 1
        }

        with open('./tests/ca_mock_hits.json') as ca_mock_file:
            ca_mock_resp_data = json.load(ca_mock_file)
            ca_mock_resp = flexmock(json=lambda: ca_mock_resp_data)
            flexmock(requests).should_receive('post').and_return(
                ca_mock_resp)
            flexmock(erebor).should_receive(
                'create_zendesk_ticket').and_return()

        request, response = app.test_client.post(
            '/ca_search',
            cookies={'session_id': session_id},
            data=json.dumps(ca_data))

        assert response.status == 200

    def test_results_html(self):
        u_data, session_id = new_user(app)

        request, response = app.test_client.get(
            '/result',
            cookies={'session_id': session_id})

        assert response.status == 404

        request, response = app.test_client.get(
            '/result/?action=unsubscribe&success=true',
            cookies={'session_id': session_id})

        assert response.status == 200
        assert b'You will no longer receive ' in response.body

        request, response = app.test_client.get(
            '/result/?action=unsubscribe&success=false',
            cookies={'session_id': session_id})

        assert response.status == 200
        assert b'You are still set to receive ' in response.body

        request, response = app.test_client.get(
            '/result/?action=unsubscribe',
            cookies={'session_id': session_id})

        assert response.status == 404

    def test_updates(self):
        request, response = app.test_client.get('/updates/ios/')

        assert response.status == 200

        request, response = app.test_client.get('/updates/android/')

        assert response.status == 200

        request, response = app.test_client.get('/updates/blackberry/')

        assert response.status == 404
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Invalid platform',
                                      'code': 400}]}

    def test_json_rpc(self):
        u_data, session_id = new_user(app)

        json_rpc_mock_resp_data = {'error': None, 'id': 0,
                                   'result': ['echome!']}
        json_rpc_mock_resp = flexmock(json=lambda: json_rpc_mock_resp_data)
        flexmock(requests).should_receive('post').and_return(
                 json_rpc_mock_resp)

        payload = {
            "method": "echo",
            "params": ["echome!"],
            "jsonrpc": "2.0",
            "id": 0,
        }

        request, response = app.test_client.post(
            '/jsonrpc',
            data=json.dumps(payload),
            cookies={'session_id': session_id})

        assert response.status == 200
        assert response.json == json_rpc_mock_resp_data

    def test_register_address(self):
        u_data, session_id = new_user(app)

        SELECT_ADDRESS_SQL = """
        SELECT public_addresses.address, public_addresses.currency
        FROM public_addresses, users
        WHERE public_addresses.user_id = users.id
        AND public_addresses.currency = %s
        AND users.email_address = %s
        """.strip()

        # B: User adds a new ETH wallet and registers the public address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xDEADBEEF'}),
            cookies={'session_id': session_id})
        assert response.status == 200

        # B: User adds a new BTC wallet and registers the public address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'BTC', 'address': '0xTESTBEEF'}),
            cookies={'session_id': session_id})
        assert response.status == 200

        # Retrieve user's BTC address to verify it has been set
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_ADDRESS_SQL,
                            ('BTC', 'test@example.com'))
                result = cur.fetchone()

        assert result['address'] == '0xTESTBEEF'
        assert result['currency'] == 'BTC'

        # Retrieve user's ETH address to verify it has been set
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_ADDRESS_SQL,
                            ('ETH', 'test@example.com'))
                result = cur.fetchone()
        assert result['address'] == '0xDEADBEEF'
        assert result['currency'] == 'ETH'

        # B: User decides to create a new ETH wallet to serve as their default
        # public ETH address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xNEWETHADDRESS'}),
            cookies={'session_id': session_id})
        assert response.status == 200

        # Retrieve user's ETH address to verify it has been changed
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_ADDRESS_SQL,
                            ('ETH', 'test@example.com'))
                result = cur.fetchone()
        assert result['address'] == '0xNEWETHADDRESS'
        assert result['currency'] == 'ETH'

        # B: User decides to create a new BTC wallet to serve as their default
        # public BTC address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'BTC', 'address': '0xNEWBTCADDRESS'}),
            cookies={'session_id': session_id})
        assert response.status == 200

        # Retrieve user's BTC address to verify it has been changed
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_ADDRESS_SQL,
                            ('BTC', 'test@example.com'))
                result = cur.fetchone()
        assert result['address'] == '0xNEWBTCADDRESS'
        assert result['currency'] == 'BTC'

        # Retrieve all current registered public addresses and verify they are
        # the ones set by the user above
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM public_addresses')
                result = cur.fetchall()
        assert result == [
            {'user_id': 1,
             'currency': 'ETH', 'address': '0xNEWETHADDRESS'},
            {'user_id': 1,
             'currency': 'BTC', 'address': '0xNEWBTCADDRESS'}
        ]

    def test_pending_contact_transactions(self):
        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))
        u_data, session_id = new_user(app)

        SELECT_CONTACT_TRANSACTIONS = """
        SELECT users.email_address, users.first_name, c_trans.to_email_address,
               c_trans.currency, c_trans.amount,
               date_trunc('minute', c_trans.created) created
        FROM contact_transactions as c_trans, users
        WHERE c_trans.user_id = users.id
        AND c_trans.to_email_address = %s
        """.strip()

        # B: User makes three contact transactions to contacts that are not
        # currently signed up with Hoard
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json == {"success": ["Email sent notifying recipient"]}

        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 4.2, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json == {"success": ["Email sent notifying recipient"]}

        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'random_email@example.com',
                             'amount': 3.14, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json == {"success": ["Email sent notifying recipient"]}
        # ---------------------------------------------------------------------

        # Retrive pending transactions for user first_test@example.com
        # and verify there is a total of two
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_CONTACT_TRANSACTIONS,
                            ('first_test@example.com',))
                pending_transactions = cur.fetchall()
        assert pending_transactions == [
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'to_email_address': 'first_test@example.com',
             'currency': 'BTC', 'amount': 4.2,
             'created': datetime.now().replace(microsecond=0, second=0)},
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'to_email_address': 'first_test@example.com',
             'currency': 'ETH', 'amount': 1.0,
             'created': datetime.now().replace(microsecond=0, second=0)}]

        # Retrive pending transactions for user random_email@example.com
        # and verify there is a total of one
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_CONTACT_TRANSACTIONS,
                            ('random_email@example.com',))
                pending_transactions = cur.fetchall()
        assert pending_transactions == [
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'to_email_address': 'random_email@example.com',
             'currency': 'BTC', 'amount': 3.14,
             'created': datetime.now().replace(microsecond=0, second=0)}]

        # B: User with two pending contact transactions signs up to Hoard and
        # the sender receives an email indicating their contact is now a user
        new_user_data = {'first_name': 'First',
                         'last_name': 'McFirstyson',
                         'email_address': 'first_test@example.com',
                         'password': 't3st_password',
                         'phone_number': '19105552323'}
        request, response = app.test_client.post(
            '/users', data=json.dumps(new_user_data))

    def test_contact_transaction(self):
        u_data, session_id = new_user(app)

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # B: User sees missing fields error response
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'blah': 'blah'}),
            cookies={'session_id': session_id})
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Missing fields',
                                     'code': 100}]}

        # B: User sees their currency is currently unsupported
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test_send@example.com',
                             'amount': 10, 'currency': 'ADA'}),
            cookies={'session_id': session_id})
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Unsupported Currency',
                                     'code': 202}]}

        # B: User attempts to make a transaction with a negative amount
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test_send@example.com',
                             'amount': -1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Invalid amount',
                                     'code': 201}]}

        # B: User attempts to make a transaction from an address that has
        # not enough funds in ETH
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test_send@example.com',
                             'amount': 5, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Insufficient balance',
                                     'code': 200}]}
        assert response.status == 403

        # B: User attempts to make a transaction from an address that has
        # not enough funds in BTC
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test_send@example.com',
                             'amount': 10, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        e_data = response.json
        assert e_data == {'errors': [{'message': 'Insufficient balance',
                                     'code': 200}]}
        assert response.status == 403

        # B: User transacts with their contact who has no Hoard account
        # via email address
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test_send@example.com',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json == {"success": ["Email sent notifying recipient"]}

        # B: User transacts with their contact who has a Hoard account
        # via username but the recipient has no public key registered
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'xXtestyXx',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json == {'errors': [{
            'code': 203,
            'message': 'No public key found for user'}]}

        # B: Recipient user creates and registers their ETH address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xDEADBEEF'}),
            cookies={'session_id': session_id})
        assert response.status == 200

        # B: User transacts with another Hoard user via email address and
        # the public key of the recipient is shown
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'test@example.com',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json == {'public_key': '0xDEADBEEF'}

        # B: User transacts with another Hoard user via username and
        # the public key of the recipient is shown
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'xXtestyXx',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json == {'public_key': '0xDEADBEEF'}

    def test_request_funds(self):
        u_data, session_id = new_user(app)

        # B: User requests funds from someone who is not a Hoard user using
        # their email address
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'recipient@test.com',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': '9001'}))
        assert response.json == {"success": ["Email sent notifying recipient"]}

        # B: User attempts to request funds from someone who is not a Hoard
        # user using a username that does not exist
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'test_recipient_user_name',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': '9001'}))
        e_data = response.json
        assert e_data == {'errors': [{
            'message': 'User not found for given username', 'code': 111}]}

        other_new_user = test_user_data.copy()
        other_new_user['email_address'] = 'recipient@test.com'
        other_new_user['username'] = 'other_test_user'

        request, response = app.test_client.post(
            '/users/', data=json.dumps(other_new_user))

        # B: User posts the same transaction to 'test_recipient_user_name' only
        # after they have signed up
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'other_test_user',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': '9001'}))
        assert response.json == {"success": ["Email sent notifying recipient"]}
