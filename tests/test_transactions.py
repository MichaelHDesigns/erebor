import json
import requests
from datetime import datetime

import psycopg2
import flexmock
from psycopg2.extras import RealDictCursor

from . import new_user, app, TestErebor, api, test_user_data, blockchain


class TestTransactions(TestErebor):
    flexmock(api.transactions).should_receive(
        'send_push_notification').and_return()

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
        assert response.json == {'success': ['Address registered']}

        # B: User adds a new BOAR wallet and registers the public address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'BOAR', 'address': '0xBOARBEEF'}),
            cookies={'session_id': session_id})
        assert response.status == 200
        assert response.json == {'success': ['Address registered']}

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

        # Retrieve user's BOAR address to verify it has been set
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_ADDRESS_SQL,
                            ('BOAR', 'test@example.com'))
                result = cur.fetchone()
        assert result['address'] == '0xBOARBEEF'
        assert result['currency'] == 'BOAR'

        # B: User decides to create a new ETH wallet to serve as their default
        # public ETH address
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(u_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xNEWETHADDRESS'}),
            cookies={'session_id': session_id})
        assert response.status == 200
        assert response.json == {'success': ['Address registered']}

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
        assert response.json == {'success': ['Address registered']}

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
             'currency': 'BOAR', 'address': '0xBOARBEEF'},
            {'user_id': 1,
             'currency': 'ETH', 'address': '0xNEWETHADDRESS'},
            {'user_id': 1,
             'currency': 'BTC', 'address': '0xNEWBTCADDRESS'}
        ]

    def test_pending_contact_transactions(self):
        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x1b1ae4d6e2ef500000",'
                '"final_balance": 556484529}')))
        flexmock(blockchain).should_receive('get_token_balance').and_return(
            500)
        flexmock(api.transactions).should_receive('send_sms').and_return()
        u_data, session_id = new_user(app)

        other_test_user_data = test_user_data.copy()
        other_test_user_data['first_name'] = 'Other'
        other_test_user_data['email_address'] = 'test2@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        other_test_user_data['phone_number'] = '+11234567890'
        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        other_session_id = response.cookies['session_id'].value

        SELECT_CONTACT_TRANSACTIONS = """
        SELECT users.email_address, users.first_name, c_trans.recipient,
               c_trans.currency, c_trans.amount,
               date_trunc('minute', c_trans.created) created
        FROM contact_transactions as c_trans, users
        WHERE c_trans.user_id = users.id
        AND (c_trans.recipient = %s
             OR c_trans.recipient = %s)
        """.strip()

        # B: User makes five contact transactions to contacts that are not
        # currently signed up with Hoard
        # ---------------------------------------------------------------------
        # Transaction 1
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Transaction 2
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 4.2, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Transcation 3
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'random_email@example.com',
                             'amount': 3.14, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Transaction 4
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'BOAR'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User makes a contact transaction to a phone number
        # Transaction 5
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': '+1234567890',
                             'amount': 0.012345, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}
        # ---------------------------------------------------------------------

        # B: Another user makes a contact transaction to the same phone number
        # above
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': '+1234567890',
                             'amount': 0.012345, 'currency': 'BTC'}),
            cookies={'session_id': other_session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Retrive pending transactions for user first_test@example.com
        # and verify there is a total of two
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_CONTACT_TRANSACTIONS,
                            ('first_test@example.com', ''))
                pending_transactions = cur.fetchall()
        assert pending_transactions == [
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'recipient': 'first_test@example.com',
             'currency': 'BOAR', 'amount': 1.0,
             'created': datetime.now().replace(microsecond=0, second=0)},
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'recipient': 'first_test@example.com',
             'currency': 'BTC', 'amount': 4.2,
             'created': datetime.now().replace(microsecond=0, second=0)},
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'recipient': 'first_test@example.com',
             'currency': 'ETH', 'amount': 1.0,
             'created': datetime.now().replace(microsecond=0, second=0)}]

        # Retrive pending transactions for user random_email@example.com
        # and verify there is a total of one
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_CONTACT_TRANSACTIONS,
                            ('random_email@example.com', ''))
                pending_transactions = cur.fetchall()
        assert pending_transactions == [
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'recipient': 'random_email@example.com',
             'currency': 'BTC', 'amount': 3.14,
             'created': datetime.now().replace(microsecond=0, second=0)}]

        # Pending transaction to the phone number from above is a total of two
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(SELECT_CONTACT_TRANSACTIONS,
                            ('', '+1234567890'))
                pending_transactions = cur.fetchall()
        assert pending_transactions == [
            {'email_address': 'test@example.com',
             'first_name': 'Testy',
             'recipient': '+1234567890',
             'currency': 'BTC', 'amount': 0.012345,
             'created': datetime.now().replace(microsecond=0, second=0)},
            {'email_address': 'test2@example.com',
             'first_name': 'Other',
             'recipient': '+1234567890',
             'currency': 'BTC', 'amount': 0.012345,
             'created': datetime.now().replace(microsecond=0, second=0)}]

        # B: User with pending contact transactions signs up to Hoard and
        # the senders receive an email indicating their contact is now a user
        new_user_data = {'first_name': 'First',
                         'last_name': 'McFirstyson',
                         'email_address': 'first_test@example.com',
                         'username': 'testing_user',
                         'password': 't3st_password',
                         'phone_number': '+1234567890'}
        request, response = app.test_client.post(
            '/users', data=json.dumps(new_user_data))

    def test_contact_transaction(self):
        u_data, session_id = new_user(app)

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))
        flexmock(api.transactions).should_receive('send_sms').and_return()

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
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User transacts with their contact who has no Hoard account
        # via phone number
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': '+1234567890',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

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
        assert response.json['public_key'] == '0xDEADBEEF'
        assert response.json.keys() == {'public_key', 'transaction_uid'}

        # B: User transacts with another Hoard user via username and
        # the public key of the recipient is shown
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'xXtestyXx',
                             'amount': 2, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json['public_key'] == '0xDEADBEEF'
        assert response.json.keys() == {'public_key', 'transaction_uid'}

        # Set up mock to return appropriate values through subsequent infura
        # requests: get_symbol, get_balance, get_decimal
        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000034f4d470000000000000000000000000000000000000000000000000000000000",'  # noqa
                '"final_balance": 556484529}'))).and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}'))).and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x0000000000000000000000000000000000000000000000000000000000000012",'  # noqa
                '"final_balance": 556484529}')))

        # B: User transacts the 'OMG' token with another Hoard user
        # via email address
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps(
                {'sender': '0x1111111111111111111111111111111111111111',
                 'recipient': 'test@example.com',
                 'amount': 2,
                 'currency': '0x0d729b3e930521e95de0efbdcd573f4cdc697b82'}),
            cookies={'session_id': session_id})
        assert response.json['public_key'] == '0xDEADBEEF'
        assert response.json.keys() == {'public_key', 'transaction_uid'}

    def test_contact_transaction_data(self):
        u_data, session_id = new_user(app)

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # B: User transacts with their contact who has no Hoard account
        # via email address
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Retrieve the contact transaction from the DB to get its UID that
        # would normally be in the transactions screen
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 1')
                result = cur.fetchone()
        trans_uid = result['uid']

        # B: After receiving the notification, user taps on it to retrieve data
        request, response = app.test_client.get(
            '/contacts/transaction_data/{}'.format(trans_uid),
            cookies={'session_id': session_id}
        )
        assert response.status == 200

        # B: User attempts to use an invalid transaction UID
        # which returns an error response
        request, response = app.test_client.get(
            '/contacts/transaction_data/{}'.format(
                'aa40c00e-79e7-438d-8c40-0bd31951cf54'),
            cookies={'session_id': session_id}
        )
        assert response.json.keys() == {'errors'}
        assert response.status == 400

    def test_all_transactions_data(self):
        u_data, session_id = new_user(app)
        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))
        flexmock(api.transactions).should_receive('send_sms').and_return()

        # B: User makes four contact transactions to contacts that are not
        # currently signed up with Hoard
        # ---------------------------------------------------------------------
        # Transaction 1
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Transaction 2
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 4.2, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Transcation 3
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'random_email@example.com',
                             'amount': 3.14, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User makes a contact transaction to a phone number
        # Transaction 4
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': '+1234567890',
                             'amount': 0.012345, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User makes request to view all transactions
        request, response = app.test_client.get(
            '/users/{}/contact_transactions'.format(u_data['uid']),
            cookies={'session_id': session_id}
        )
        assert len(response.json) == 4
        assert response.json[0].keys() == {'uid', 'recipient', 'currency',
                                           'amount', 'created',
                                           'transaction_type', 'status',
                                           'transaction_hash'}

    def test_contact_transaction_confirmation(self):
        u_data, session_id = new_user(app)

        async def mock_check_channel():
            return {'ok': True}
        flexmock(api.users).should_receive('check_channel').and_return(
            mock_check_channel())
        flexmock(api.transactions).should_receive(
            'send_push_notification').and_return({'ok': True})

        # B: User logs into Hoard from their Android device in order to
        # receive a push notification
        request, response = app.test_client.post(
            '/login', data=json.dumps({
                'username_or_email': test_user_data['username'],
                'password': test_user_data['password'],
                'device_info': {
                    'channel': 'c00l_ch4nn3l',
                    'device_type': 'android'
                }
            })
        )
        assert response.status == 200

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # B: User transacts with their contact who has no Hoard account
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Retrieve the contact transaction UID
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 1')
                result = cur.fetchone()
        trans_uid = result['uid']
        status = result['status']
        # Transaction has not been confirmed or denied yet
        assert status == 'pending'

        # B: User confirms the transaction
        request, response = app.test_client.post(
            '/contacts/transaction_confirmation/{}'.format(trans_uid),
            cookies={'session_id': session_id},
            data=json.dumps({'confirmed': True, 'transaction_hash': '0x0'})
        )

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 1')
                result = cur.fetchone()
        status = result['status']
        assert status == 'confirmed'

        # B: User transacts with their contact who has no Hoard account
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xBTCADDRESS',
                             'recipient': 'first_test@example.com',
                             'amount': 2, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 2')
                result = cur.fetchone()
        trans_uid = result['uid']
        status = result['status']
        # Transaction has not been confirmed or denied yet
        assert status == 'pending'

        # B: User denies the transaction
        request, response = app.test_client.post(
            '/contacts/transaction_confirmation/{}'.format(trans_uid),
            cookies={'session_id': session_id},
            data=json.dumps({'confirmed': False, 'transaction_hash': None})
        )

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 2')
                result = cur.fetchone()
        status = result['status']
        assert status == 'denied'

        other_new_user = test_user_data.copy()
        other_new_user['email_address'] = 'new_one@example.com'
        other_new_user['username'] = 'new_one'
        other_new_user['phone_number'] = '+11096667777'

        request, response = app.test_client.post(
            '/users', data=json.dumps(other_new_user)
        )
        assert response.status == 201
        cookies = response.cookies
        other_session_id = cookies['session_id'].value

        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'new_one',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': 9001}))
        assert response.json.keys() == {'success', 'transaction_uid'}

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM contact_transactions"
                            " WHERE transaction_type = 'request'")
                result = cur.fetchone()
        trans_uid = result['uid']
        status = result['status']

        request, response = app.test_client.post(
            '/contacts/transaction_confirmation/{}'.format(trans_uid),
            cookies={'session_id': other_session_id},
            data=json.dumps({'confirmed': False, 'transaction_hash': None})
        )
        assert response.status == 200

    def test_request_funds(self):
        u_data, session_id = new_user(app)
        flexmock(api.transactions).should_receive(
            'send_push_notification').and_return()

        async def mock_check_channel():
            return {'ok': True}
        flexmock(api.users).should_receive('check_channel').and_return(
            mock_check_channel())

        # B: User requests funds from someone who is not a Hoard user using
        # their email address
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'recipient@test.com',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': 9001}))
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User attempts to request funds from someone who is not a Hoard
        # user using a username that does not exist
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': 'test_recipient_user_name',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': 9001}))
        e_data = response.json
        assert e_data == {'errors': [{
            'message': 'User not found for given username', 'code': 111}]}

        other_new_user = test_user_data.copy()
        other_new_user['email_address'] = 'recipient@test.com'
        other_new_user['username'] = 'other_test_user'
        other_new_user['phone_number'] = '+12223334444'
        other_new_user['device_info'] = {
            'device_type': 'android',
            'channel': 'andr01d_ch4nn3l'
        }

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
                 'currency': 'BTC', 'amount': 9001}))
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User posts request using recipient's phone number
        request, response = app.test_client.post(
            '/request_funds/',
            cookies={'session_id': session_id},
            data=json.dumps(
                {'recipient': '+12223334444',
                 'email_address': test_user_data['email_address'],
                 'currency': 'BTC', 'amount': 9001}))
        assert response.json.keys() == {'success', 'transaction_uid'}

    def test_recipient_status(self):
        u_data, session_id = new_user(app)
        other_test_user_data = test_user_data.copy()
        other_test_user_data['first_name'] = 'Other'
        other_test_user_data['email_address'] = 'test2@example.com'
        other_test_user_data['username'] = 'c00l_n3w_us3r'
        other_test_user_data['phone_number'] = '+11234567890'

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # B: User transacts with their contact who has no
        # Hoard account with ETH
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({
                'sender': '0xDEADBEEF',
                'recipient': other_test_user_data['email_address'],
                'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        eth_transaction_uid = response.json['transaction_uid']
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User transacts with their contact who has no
        # Hoard account with BTC
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({
                'sender': '3abtcaddress',
                'recipient': other_test_user_data['email_address'],
                'amount': 1, 'currency': 'BTC'}),
            cookies={'session_id': session_id})
        btc_transaction_uid = response.json['transaction_uid']
        assert response.json.keys() == {'success', 'transaction_uid'}

        # B: User checks status of recipient's account which has not signed
        # up yet
        request, response = app.test_client.get(
            '/contacts/transaction/'
            '{}/recipient_status'.format(eth_transaction_uid),
            cookies={'session_id': session_id})
        status_data = response.json
        assert status_data.keys() == {'errors'}

        request, response = app.test_client.post(
            '/users', data=json.dumps(other_test_user_data))
        other_data = response.json
        other_session = response.cookies['session_id'].value

        # Connect to the DB to retrieve the user's activation key
        SELECT_ACTIVATION_KEY = """
        SELECT activation_key, active
        FROM users
        WHERE id = 2
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
            '/activate/{}'.format(activation_key))

        # B: User registers ETH
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(other_data['uid']),
            data=json.dumps({'currency': 'ETH', 'address': '0xNEWBEEF'}),
            cookies={'session_id': other_session})
        assert response.status == 200

        # B: User registers BTC
        request, response = app.test_client.post(
            '/users/{}/register_address'.format(other_data['uid']),
            data=json.dumps({'currency': 'BTC', 'address': '3btCaddress'}),
            cookies={'session_id': other_session})
        assert response.status == 200

        # B: User checks status of recipient's account for the ETH transaction
        request, response = app.test_client.get(
            '/contacts/transaction/'
            '{}/recipient_status'.format(eth_transaction_uid),
            cookies={'session_id': session_id})
        status_data = response.json
        for key in status_data.keys() - {'address', 'currency'}:
            assert status_data[key] == other_test_user_data[key]
        assert status_data['address'] == '0xNEWBEEF'
        assert status_data['currency'] == 'ETH'

        # B: User checks status of recipient's account for the BTC transaction
        request, response = app.test_client.get(
            '/contacts/transaction/'
            '{}/recipient_status'.format(btc_transaction_uid),
            cookies={'session_id': session_id})
        status_data = response.json
        for key in status_data.keys() - {'address', 'currency'}:
            assert status_data[key] == other_test_user_data[key]
        assert status_data['address'] == '3btCaddress'
        assert status_data['currency'] == 'BTC'

    def test_notify_transaction(self):
        u_data, session_id = new_user(app)

        flexmock(requests).should_receive('get').and_return(
            flexmock(json=lambda: json.loads(
                '{"jsonrpc": "2.0", "id": 1,'
                '"result": "0x37942530c308b7e7",'
                '"final_balance": 556484529}')))

        # B: User transacts with their contact who has no Hoard account
        # via email address
        request, response = app.test_client.post(
            '/contacts/transaction/',
            data=json.dumps({'sender': '0xDEADBEEF',
                             'recipient': 'first_test@example.com',
                             'amount': 1, 'currency': 'ETH'}),
            cookies={'session_id': session_id})
        assert response.json.keys() == {'success', 'transaction_uid'}

        # Retrieve the contact transaction from the DB to get its UID that
        # would normally be in the transactions screen
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute('SELECT * FROM contact_transactions WHERE id = 1')
                result = cur.fetchone()
        trans_uid = result['uid']

        # B: User taps to renotify recipient only to find that they've done
        # a renotify recently
        request, response = app.test_client.post(
            '/contacts/transaction/{}/notify'.format(trans_uid),
            cookies={'session_id': session_id}
        )
        assert response.status == 403
        assert response.json.keys() == {'errors'}

        # Update the last notified date to be a few days in the past
        UPDATE_LAST_NOTIFIED = """
        UPDATE contact_transactions
        SET last_notified = last_notified - interval '2 days'
        """.strip()
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(UPDATE_LAST_NOTIFIED)

        # B: User renotifies a recipient of a pending transaction that was last
        # notified two days ago
        request, response = app.test_client.post(
            '/contacts/transaction/{}/notify'.format(trans_uid),
            cookies={'session_id': session_id}
        )
        assert response.status == 200
        assert response.json.keys() == {'success'}

        # B: User taps to renotify recipient only to find that they've done
        # a renotify recently
        request, response = app.test_client.post(
            '/contacts/transaction/{}/notify'.format(trans_uid),
            cookies={'session_id': session_id}
        )
        assert response.status == 403
        assert response.json.keys() == {'errors'}
