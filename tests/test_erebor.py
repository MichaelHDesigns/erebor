import json

import flexmock
import requests
import pytest

from . import app, TestErebor, new_user


class TestResources(TestErebor):
    def test_health(self):
        request, response = app.test_client.head('/health')
        assert response.status == 200

    @pytest.mark.skip(reason="Skip for load testing")
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
