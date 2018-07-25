import json

import flexmock

from . import new_user, TestErebor, app, test_user_data, api


class TestSupport(TestErebor):
    def test_zd_support(self):
        u_data, session_id = new_user(app)

        flexmock(api.support).should_receive(
            'create_zendesk_ticket').and_return()

        # B: A Hoard user creates a support ticket
        request, response = app.test_client.post(
            '/support', data=json.dumps({
                'description': 'Im experiencing an error!',
                'subject': 'There is an error here',
                'name': test_user_data['first_name'],
                'email_address': test_user_data['email_address']
            }),
            cookies={'session_id': session_id}
        )
        assert response.json == {'success': 'Ticket submitted'}

        # B: A non-Hoard user creates a support ticket
        request, response = app.test_client.post(
            '/support', data=json.dumps({
                'description': 'Im experiencing an error with the wallet!',
                'subject': 'There is an error here in the wallet',
                'name': 'Bob',
                'email_address': 'wallet_user@example.com',
            }),
        )
        assert response.json == {'success': 'Ticket submitted'}
