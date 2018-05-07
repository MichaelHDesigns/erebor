import json
from uuid import uuid4
from datetime import datetime

import flexmock
import requests

from erebor import erebor

from . import TestErebor

test_user_data = {'first_name': 'Testy',
                  'last_name': 'McTestface',
                  'email_address': 'test@example.com',
                  'password': 't3st_password',
                  'phone_number': '19105552323'}


async def new_user(app):
    response = await app.post(
        '/users', data=json.dumps(test_user_data))
    u_data = await response.json()
    cookies = response.cookies
    session_id = cookies['session_id'].value
    return u_data, session_id


class TestResources(TestErebor):
    async def test_health(self, test_cli):
        response = await test_cli.head('/health')
        assert response.status == 200

    async def test_limiter(self, test_cli):
        for i in range(0, 49):
            response = await test_cli.head('/health')
            assert response.status == 200

        # Now throttled after 50 requests in a minute
        response = await test_cli.head('/health')
        assert response.status == 429

    async def test_errors(self, test_cli):
        response = await test_cli.post(
            '/users', data=json.dumps({'blah': 'blah'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Missing fields',
                                     'code': 100}]}

    async def test_create_account(self, test_cli):
        u_data, session_id = await new_user(test_cli)

        assert u_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'receive_emails_enabled',
                                 'phone_number', 'sms_2fa_enabled'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

        # B: Users can have one account per email
        response = await test_cli.post(
            '/users', data=json.dumps(test_user_data))
        e_data = await response.json()
        assert e_data.keys() == {'errors'}

        # Doing this doesn't break the db connection
        other_test_user_data = test_user_data.copy()
        other_test_user_data['email_address'] = 'test2@example.com'
        response = await test_cli.post(
            '/users', data=json.dumps(other_test_user_data))
        o_data = await response.json()
        assert o_data.keys() == {'uid', 'first_name', 'last_name',
                                 'email_address', 'receive_emails_enabled',
                                 'phone_number', 'sms_2fa_enabled'}

    async def test_get_user(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))
        data = await response.json()
        assert data.keys() == {'uid', 'email_address', 'first_name',
                               'last_name', 'phone_number', 'sms_2fa_enabled'}
        for each_key in test_user_data.keys() - {'password'}:
            assert u_data[each_key] == test_user_data[each_key]

    async def test_update_user(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        change_data = {'first_name': 'Changey',
                       'last_name': 'McChangeface',
                       'phone_number': '12345678989',
                       'email_address': 'changed@example.com'}

        response = await test_cli.put(
            '/users/{}/'.format(u_data['uid']),
            data=json.dumps(change_data))

        assert response.status == 200

        response = await test_cli.get(
            '/users/{}/'.format(u_data['uid']))
        c_data = await response.json()
        for each_key in test_user_data.keys() - {'password'}:
            assert c_data[each_key] == change_data[each_key]

    async def test_login(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))
        assert response.status == 200

        response = await test_cli.post(
            '/login',
            data=json.dumps({'email_address': test_user_data['email_address'],
                             'password': test_user_data['password']}))
        new_cookies = response.cookies
        assert new_cookies.keys() == {'session_id'}

        data = await response.json()
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

        new_session_id = new_cookies['session_id'].value
        assert new_session_id != session_id

        # test new api key
        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))

        assert response.status == 403

        test_cli.session.cookie_jar.update_cookies({'session_id':
                                                    new_session_id})
        response = await test_cli.get(
            '/users/{}/'.format(u_data['uid']))

        assert response.status == 200

    async def test_logout(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))

        assert response.status == 200

        response = await test_cli.post('/logout')

        assert response.status == 200

        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))

        assert response.status == 403

    async def test_change_password(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get(
            '/users/{}'.format(u_data['uid']))

        assert response.status == 200

        response = await test_cli.post(
            '/change_password',
            data=json.dumps(
                {'new_password': 'test2',
                 'password': test_user_data['password'],
                 'email_address': test_user_data['email_address']}))
        assert response.status == 200

        response = await test_cli.post('/logout')
        assert response.status == 200

        response = await test_cli.post(
            '/login',
            data=json.dumps({'email_address': 'test@example.com',
                             'password': 'test'}))
        assert response.status == 403

        response = await test_cli.post(
            '/login',
            data=json.dumps({'email_address': 'test@example.com',
                             'password': 'test2'}))
        assert response.status == 200
        assert response.cookies.keys() == {'session_id'}

    async def test_change_password_permissions(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.post(
            '/users',
            data=json.dumps({'first_name': 'Bob',
                             'last_name': 'Smith',
                             'phone_number': '19876543232',
                             'email_address': 'bob@example.com',
                             'password': 'test'}))

        response = await test_cli.post(
            '/change_password',
            data=json.dumps({'new_password': 'test2',
                             'password': 'test',
                             'email_address': 'bob@example.com'}))
        assert response.status == 403

    async def test_reset_password(self, test_cli):
        u_data, session_id = await new_user(test_cli)

        # Request for reset, email sent
        response = await test_cli.post(
            '/password',
            data=json.dumps({'email_address': 'test@example.com'})
        )
        assert response.status == 200
        assert await response.json() == {
            'success': ['If our records match you will receive an email']
        }

        # Grab the reset token generated for the user
        SELECT_RESET_TOKEN_SQL = """
        SELECT reset_token::text
        FROM reset_tokens
        WHERE email_address = $1
        """.strip()
        test_token_record = await test_cli.app.pg.fetchrow(
            SELECT_RESET_TOKEN_SQL, 'test@example.com')
        test_token = test_token_record['reset_token']

        # URL with an invalid length returns invalid token error
        response = await test_cli.get(
            '/reset_password/{}'.format(test_token + 'a'))
        assert response.status == 403
        e_data = await response.json()
        assert e_data == {
            'errors': [{
                'message': 'Reset token is either invalid or expired',
                'code': 108
            }]
        }

        # Valid reset token returns change password form
        response = await test_cli.get(
            '/reset_password/{}'.format(test_token))
        assert response.status == 200

        # User changes password with unique URL form
        response = await test_cli.post(
            '/reset_password/{}'.format(test_token),
            data=json.dumps({'new_password': 'test_pw_reset'}))
        assert response.status == 200

        # Reset token has now been expired
        response = await test_cli.get(
            '/reset_password/{}'.format(test_token))
        assert response.status == 403
        e_data = await response.json()
        assert e_data == {
            'errors': [{
                'message': 'Reset token is either invalid or expired',
                'code': 108
            }]
        }

        # User logins with new password
        response = await test_cli.post(
            '/login',
            data=json.dumps({'email_address': test_user_data['email_address'],
                             'password': 'test_pw_reset'}))
        new_cookies = response.cookies
        assert new_cookies.keys() == {'session_id'}

        data = await response.json()
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

    async def test_email_preferences(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        # Users can check their email preferences
        response = await test_cli.get('/email_preferences')

        assert response.status == 200
        j_data = await response.json()
        assert j_data.keys() == {'receive_emails_enabled'}

        # Receiving emails are enabled by default
        assert j_data['receive_emails_enabled'] is True

        # Users can disable receiving emails
        response = await test_cli.put(
            '/email_preferences',
            data=json.dumps({'receive_emails_enabled': False}))

        assert response.status == 200
        j_data = await response.json()
        assert j_data.keys() == {'success'}

        response = await test_cli.get('/email_preferences')

        assert response.status == 200
        j_data = await response.json()
        assert j_data['receive_emails_enabled'] is False

        # Users can re-enable receiving emails
        response = await test_cli.put(
            '/email_preferences',
            data=json.dumps({'receive_emails_enabled': True}))

        assert response.status == 200
        j_data = await response.json()
        assert j_data.keys() == {'success'}

        response = await test_cli.get('/email_preferences')

        assert response.status == 200
        j_data = await response.json()
        assert j_data['receive_emails_enabled'] is True

    async def test_enable_sms_2fa(self, test_cli):
        # B: Users can see if sms-based 2fa is enabled
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get('/2fa/settings')
        j_data = await response.json()
        assert j_data.keys() == {'sms_2fa_enabled'}

        # B: 2fa is disabled by default
        j_data = await response.json()
        assert j_data['sms_2fa_enabled'] is False

        # B: Users can enable sms-based 2fa
        response = await test_cli.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}))

        assert response.status == 200

        response = await test_cli.get('/2fa/settings')
        j_data = await response.json()
        assert j_data['sms_2fa_enabled'] is True

        # B: Users can disable sms-based 2fa
        response = await test_cli.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': False}))

        assert response.status == 200

        response = await test_cli.get('/2fa/settings')

        j_data = await response.json()
        assert j_data['sms_2fa_enabled'] is False

    async def test_2fa_login(self, test_cli):
        # B: Users can see if sms-based 2fa is enabled
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.put(
            '/2fa/settings',
            data=json.dumps({'sms_2fa_enabled': True}))

        response = await test_cli.post('/logout')

        import erebor
        flexmock(erebor.erebor).should_receive('send_sms').and_return()

        response = await test_cli.post(
            '/login',
            data=json.dumps({'email_address': test_user_data['email_address'],
                             'password': test_user_data['password']}))
        l_data = await response.json()
        assert l_data == {'success': ['2FA has been sent']}

        # Grab generated code
        TEST_SQL = """
        SELECT sms_verification
        FROM users WHERE email_address = $1
        """.strip()
        sms_verification_record = await test_cli.app.pg.fetchrow(
            TEST_SQL, test_user_data['email_address'])
        sms_verification = sms_verification_record['sms_verification']

        response = await test_cli.post(
            '/2fa/sms_login',
            data=json.dumps(
                {'sms_verification': sms_verification,
                 'email_address': test_user_data['email_address']}))
        assert response.cookies.keys() == {'session_id'}
        data = await response.json()
        assert data.keys() == {'success', 'user_uid'}
        assert len(data['user_uid']) == 36

    async def test_ticker(self, test_cli):
        # B: Logged in users can access BTC/USD and ETH/USD pricing
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get('/ticker')
        assert response.status == 200
        data = await response.json()
        assert data.keys() == {'btc_usd', 'eth_usd'}
        # B: do it again to make sure caching works
        response = await test_cli.get('/ticker')
        assert response.status == 200

        # Drop the session_id from cookies
        test_cli.session.cookie_jar.update_cookies({'session_id': 0})
        response = await test_cli.get('/ticker')
        assert response.status == 403

    async def test_jumio(self, test_cli):
        # B: Callbacks from Jumio can be parsed
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        CALLBACK_UPLOADED = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22AUT%22%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22UPLOADED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa
        CALLBACK_SUCCESS = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22USA%22%2C%22extractedData%22%3A%7B%22firstName%22%3A%22FIRSTNAME%22%2C%22lastName%22%3A%22LASTNAME%22%2C%22signatureAvailable%22%3Atrue%2C%22ssn%22%3A%22xxxxxxxxx%22%7D%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22EXTRACTED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa
        CALLBACK_FAILURE = "timestamp=2017-06-06T12%3A06%3A49.016Z&scanReference={}&document=%7B%22type%22%3A%22SSC%22%2C%22country%22%3A%22USA%22%2C%22images%22%3A%5B%22https%3A%2F%2Fretrieval.netverify.com%2Fapi%2Fnetverify%2Fv2%2Fdocuments%2Fxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx%2Fpages%2F1%22%5D%2C%22status%22%3A%22DISCARDED%22%7D&transaction=%7B%22customerId%22%3A%22CUSTOMERID%22%2C%22date%22%3A%222014-10-17T06%3A37%3A51.969Z%22%2C%22merchantScanReference%22%3A%22YOURSCANREFERENCE%22%2C%22source%22%3A%22DOC_SDK%22%2C%22status%22%3A%22DONE%22%7D"  # noqa

        scan_reference = uuid4()

        response = await test_cli.post(
            '/jumio_callback',
            data=CALLBACK_UPLOADED.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        response = await test_cli.get(
            '/jumio_results/{}'.format(scan_reference))
        assert response.status == 200
        data = await response.json()

        assert len(data['results']) == 1
        assert json.loads(data['results'][0]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        response = await test_cli.post(
            '/jumio_callback',
            data=CALLBACK_SUCCESS.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        response = await test_cli.get(
            '/jumio_results/{}'.format(scan_reference))
        assert response.status == 200
        data = await response.json()
        assert len(data['results']) == 2
        assert json.loads(data['results'][1]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        # B: User can fail to scan their documents correctly
        scan_reference = uuid4()

        response = await test_cli.post(
            '/jumio_callback',
            data=CALLBACK_UPLOADED.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        response = await test_cli.get(
            '/jumio_results/{}'.format(scan_reference))
        assert response.status == 200
        data = await response.json()

        assert len(data['results']) == 1
        assert json.loads(data['results'][0]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

        response = await test_cli.post(
            '/jumio_callback',
            data=CALLBACK_FAILURE.format(scan_reference),
            headers={'content-type': 'application/x-www-form-urlencoded'})
        assert response.status == 201

        response = await test_cli.get(
            '/jumio_results/{}'.format(scan_reference))
        assert response.status == 200
        data = await response.json()
        assert len(data['results']) == 2
        assert json.loads(data['results'][1]).keys() == {
            'timestamp', 'scanReference', 'document', 'transaction'}

    async def test_ca_bridge(self, test_cli):
        # B: Comply Advantage API bridge works
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})
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

        response = await test_cli.post(
            '/ca_search',
            data=json.dumps(ca_data))

        assert response.status == 200

    async def test_ca_bridge_zd_ticket(self, test_cli):
        # B: Search hits result in sending zendesk ticket
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})
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

        response = await test_cli.post(
            '/ca_search',
            data=json.dumps(ca_data))

        assert response.status == 200

    async def test_results_html(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.get('/result')

        assert response.status == 404

        response = await test_cli.get(
            '/result/?action=unsubscribe&success=true')

        assert response.status == 200
        html_text = await response.text()
        assert 'You will no longer receive ' in html_text

        response = await test_cli.get(
            '/result/?action=unsubscribe&success=false')

        assert response.status == 200
        html_text = await response.text()
        assert 'You are still set to receive ' in html_text

        response = await test_cli.get(
            '/result/?action=unsubscribe')

        assert response.status == 404

    async def test_updates(self, test_cli):
        response = await test_cli.get('/updates/ios/')

        assert response.status == 200

        response = await test_cli.get('/updates/android/')

        assert response.status == 200

        response = await test_cli.get('/updates/blackberry/')

        assert response.status == 404
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Invalid platform',
                                      'code': 400}]}

    async def test_json_rpc(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

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

        response = await test_cli.post(
            '/jsonrpc',
            data=json.dumps(payload))

        assert response.status == 200
        j_data = await response.json()
        assert j_data == json_rpc_mock_resp_data

    async def test_register_address(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        response = await test_cli.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xDEADBEEF'}))
        assert response.status == 200

        response = await test_cli.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'BTC', 'address': '0xTESTBEEF'}))
        assert response.status == 200

        result = await test_cli.app.pg.fetchrow(
            erebor.SELECT_ADDRESS_SQL, 'BTC', 'test@example.com')

        assert result['address'] == '0xTESTBEEF'
        assert result['currency'] == 'BTC'

        result = await test_cli.app.pg.fetchrow(
            erebor.SELECT_ADDRESS_SQL, 'ETH', 'test@example.com')

        assert result['address'] == '0xDEADBEEF'
        assert result['currency'] == 'ETH'

        # Register a new address for ETH
        response = await test_cli.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xNEWETHADDRESS'}))
        assert response.status == 200

        result = await test_cli.app.pg.fetchrow(
            erebor.SELECT_ADDRESS_SQL, 'ETH', 'test@example.com')

        assert result['address'] == '0xNEWETHADDRESS'
        assert result['currency'] == 'ETH'

        # Register new address for BTC
        response = await test_cli.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'BTC', 'address': '0xNEWBTCADDRESS'}))
        assert response.status == 200

        result = await test_cli.app.pg.fetchrow(
            erebor.SELECT_ADDRESS_SQL, 'BTC', 'test@example.com')
        assert result['address'] == '0xNEWBTCADDRESS'
        assert result['currency'] == 'BTC'

        result = await test_cli.app.pg.fetch(
            'SELECT * FROM public_addresses')
        assert dict(result[0]) == {
            'user_id': 1, 'currency': 'ETH', 'address': '0xNEWETHADDRESS'}
        assert dict(result[1]) == {
            'user_id': 1, 'currency': 'BTC', 'address': '0xNEWBTCADDRESS'}

    async def test_pending_contact_transactions(self, test_cli):
        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        # User makes three contact transactions to contacts that are not
        # currently signed up with Hoard
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}))
        j_data = await response.json()
        assert j_data == {"success": ["Email sent notifying recipient"]}

        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'first_test@example.com',
                             'amount': 4.2, 'currency': 'BTC'}))
        j_data = await response.json()
        assert j_data == {"success": ["Email sent notifying recipient"]}

        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'random_email@example.com',
                             'amount': 3.14, 'currency': 'BTC'}))
        j_data = await response.json()
        assert j_data == {"success": ["Email sent notifying recipient"]}
        # ---------------------------------------------------------------------

        # Pending transactions for user first_test@example.com is a total of
        # two from above
        pending_transactions = await test_cli.app.pg.fetch(
            erebor.SELECT_CONTACT_TRANSACTIONS, 'first_test@example.com'
        )
        assert dict(pending_transactions[0]) == {
            'email_address': 'test@example.com',
            'first_name': 'Testy',
            'to_email_address': 'first_test@example.com',
            'currency': 'BTC', 'amount': 4.2,
            'created': datetime.now().replace(microsecond=0, second=0)}
        assert dict(pending_transactions[1]) == {
            'email_address': 'test@example.com',
            'first_name': 'Testy',
            'to_email_address': 'first_test@example.com',
            'currency': 'ETH', 'amount': 1.0,
            'created': datetime.now().replace(microsecond=0, second=0)}

        # Another pending transaction to a different email is a total of one
        pending_transactions = await test_cli.app.pg.fetch(
            erebor.SELECT_CONTACT_TRANSACTIONS, 'random_email@example.com'
        )
        assert dict(pending_transactions[0]) == {
            'email_address': 'test@example.com',
            'first_name': 'Testy',
            'to_email_address': 'random_email@example.com',
            'currency': 'BTC', 'amount': 3.14,
            'created': datetime.now().replace(microsecond=0, second=0)}

        new_user_data = {'first_name': 'First',
                         'last_name': 'McFirstyson',
                         'email_address': 'first_test@example.com',
                         'password': 't3st_password',
                         'phone_number': '19105552323'}
        response = await test_cli.post(
            '/users', data=json.dumps(new_user_data))

    async def test_contact_transaction(self, test_cli):
        u_data, session_id = await new_user(test_cli)
        test_cli.session.cookie_jar.update_cookies({'session_id': session_id})

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # Missing fields error response
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'blah': 'blah'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Missing fields',
                                     'code': 100}]}

        # Unsupported currency error response
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test_send@example.com',
                             'amount': 10, 'currency': 'ADA'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Unsupported Currency',
                                     'code': 202}]}

        # Negative balance error response
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test_send@example.com',
                             'amount': -1, 'currency': 'ETH'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Invalid amount',
                                     'code': 201}]}

        # Insufficient balance error response for ETH
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test_send@example.com',
                             'amount': 5, 'currency': 'ETH'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Insufficient balance',
                                     'code': 200}]}
        assert response.status == 403

        # Insufficient balance error response for BTC
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test_send@example.com',
                             'amount': 10, 'currency': 'BTC'}))
        e_data = await response.json()
        assert e_data == {'errors': [{'message': 'Insufficient balance',
                                     'code': 200}]}
        assert response.status == 403

        # Recipient email address has no Hoard account
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test_send@example.com',
                             'amount': 2, 'currency': 'ETH'}))
        j_data = await response.json()
        assert j_data == {"success": ["Email sent notifying recipient"]}

        # Register an address for the user
        response = await test_cli.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xDEADBEEF'}))
        assert response.status == 200

        # Transaction returns the public key of the recipient
        response = await test_cli.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'to_email_address': 'test@example.com',
                             'amount': 2, 'currency': 'ETH'}))
        j_data = await response.json()
        assert j_data == {'public_key': '0xDEADBEEF'}
