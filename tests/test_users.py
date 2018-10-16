import json

import psycopg2
import flexmock

from . import test_user_data, new_user, app, TestErebor, api


class TestUsers(TestErebor):
    def test_create_account(self):
        u_data, session_id = new_user(app)

        assert u_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'username',
                                 'receive_emails_enabled', 'phone_number',
                                 'sms_2fa_enabled', 'active', 'register_date'}
        for each_key in test_user_data.keys() - {'password'}:
            assert (u_data[each_key] == test_user_data[each_key].lower()
                    if each_key == 'username' or each_key == 'email_address'
                    else test_user_data[each_key])

        # B: Users can have one account per email
        request, response = app.test_client.post(
            '/users', data=json.dumps(test_user_data))
        e_data = response.json
        assert e_data.keys() == {'errors'}

        # Doing this doesn't break the db connection
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test2@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        other_test_user_data['phone_number'] = '+11234567890'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        o_data = response.json
        assert o_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'username',
                                 'receive_emails_enabled', 'phone_number',
                                 'sms_2fa_enabled', 'active', 'register_date'}

        # B: Users can have one account per username
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test3@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        other_test_user_data['phone_number'] = '+19998887777'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors':
                          [{'code': 112,
                            'message': 'Username already exists'}]}

        # B: Users can have one account per phone number
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test3@example.com'
        other_test_user_data['username'] = 'phone_number_user'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors':
                          [{'code': 107,
                            'message': 'Error creating user'}]}

        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test4@example.com'
        other_test_user_data['username'] = 'new_user_@@!'
        other_test_user_data['phone_number'] = '+12223334444'

        # B: Username cannot have special characters
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 109,
                                      'message': 'Invalid username'}]}

        # B: Username cannot be greater than 18 characters
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test4@example.com'
        other_test_user_data['username'] = 'new_user_of_length_greater_than_18'
        other_test_user_data['phone_number'] = '+13334445555'

        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 109,
                                      'message': 'Invalid username'}]}

        # B: Email must be a valid email
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'not_an_email@@test.org'
        other_test_user_data['username'] = 'new_user_name'
        other_test_user_data['phone_number'] = '+14445556666'

        # Email must be a valid email
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        e_data = response.json
        assert e_data == {'errors': [{'code': 110,
                                      'message': 'Invalid email address'}]}

        # B: Multiple NULL phone numbers allowed
        other_test_user_data['email_address'] = 'an_email@test.com'
        other_test_user_data['phone_number'] = ''
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        assert response.status == 201

        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'another_one@example.com'
        other_test_user_data['username'] = 'userNAME'
        other_test_user_data['phone_number'] = ''
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        assert response.status == 201

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
            assert (u_data[each_key] == test_user_data[each_key].lower()
                    if each_key == 'username' or each_key == 'email_address'
                    else test_user_data[each_key])

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
        SELECT reset_token, user_id
        FROM reset_tokens
        WHERE user_id = 1
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

    def test_forgot_username(self):
        u_data, session_id = new_user(app)

        # B: User requests their forgotten username using their email address
        request, response = app.test_client.post(
            '/forgot_username',
            data=json.dumps({
                'email_address': test_user_data['email_address']}))
        assert response.json == {
            'success': ['If our records match you will receive an email']}

        # B: User attempts to get the username of an invalid email
        request, response = app.test_client.post(
            '/forgot_username',
            data=json.dumps({
                'email_address': 'not_someones_email@email.com'}))
        # Response is the same to prevent phishing and enumeration
        assert response.json == {
            'success': ['If our records match you will receive an email']}

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

    def test_pre_register(self):
        async def mock_verify_fun():
            return {'success': True, 'score': 0.6}
        flexmock(api.users).should_receive(
            'verify').and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun())

        with open('./tests/blacklist.json') as blacklist_file:
            blacklist_data = json.load(blacklist_file)
            INSERT_BLACKLIST_SQL = """
            INSERT INTO blacklist (username)
            VALUES
            """.strip()
            args = ", ".join('(\'{}\')'.format(
                username) for username in blacklist_data)
            INSERT_BLACKLIST_SQL += args

            with psycopg2.connect(**app.db) as conn:
                with conn.cursor() as cur:
                    cur.execute(INSERT_BLACKLIST_SQL)

        user = {
            'username': 'co00l_username',
            'email_address': 'an_email@example.com',
            'captcha': 'abcdefghijklmnop'
        }

        request, response = app.test_client.post(
            '/pre_register',
            data=json.dumps(user)
        )
        assert response.status == 201
        assert response.json.keys() == {'email_address', 'username',
                                        'register_date'}

        # Connect to the DB to retrieve the user's activation key
        SELECT_ACTIVATION_KEY = """
        SELECT activation_key, active
        FROM pre_register
        WHERE username = 'co00l_username'
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
            '/pre_register/{}'.format(activation_key))
        assert response.status == 200

        # Connect to the DB to verify active is now True
        SELECT_ACTIVE_STATUS = """
        SELECT active
        FROM pre_register
        WHERE username = 'co00l_username'
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

        request, response = app.test_client.post(
            '/pre_register',
            data=json.dumps(user)
        )
        assert response.status == 403

        # B: User attempts to register a username on the blacklist
        user = {
            'username': '404',
            'email_address': 'another_email@example.com',
            'captcha': 'abcdefghijklmnop'
        }

        request, response = app.test_client.post(
            '/pre_register',
            data=json.dumps(user)
        )
        assert response.status == 400
        assert response.json == {
            'errors': [{'code': 109, 'message': 'Invalid username'}]}

        # B: User attempts to register a name with 'admin' or 'hoard' in it
        user = {
            'username': 'hoard_cool_guy',
            'email_address': 'another_email@example.com',
            'captcha': 'abcdefghijklmnop'
        }

        request, response = app.test_client.post(
            '/pre_register',
            data=json.dumps(user)
        )
        assert response.status == 400
        assert response.json == {
            'errors': [{'code': 109, 'message': 'Invalid username'}]}

        user = {
            'username': 'official_administrator',
            'email_address': 'another_email@example.com',
            'captcha': 'abcdefghijklmnop'
        }

        request, response = app.test_client.post(
            '/pre_register',
            data=json.dumps(user)
        )
        assert response.status == 400
        assert response.json == {
            'errors': [{'code': 109, 'message': 'Invalid username'}]}
