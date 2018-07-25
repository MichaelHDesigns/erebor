import requests
import json
from uuid import uuid4

import flexmock
import pytest

from . import new_user, TestErebor, app, api


class TestVerification(TestErebor):
    @pytest.mark.skip(reason="Unsupported for now")
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

    @pytest.mark.skip(reason="Unsupported for now")
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

    @pytest.mark.skip(reason="Unsupported for now")
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
            flexmock(api.support).should_receive(
                'create_zendesk_ticket').and_return()

        request, response = app.test_client.post(
            '/ca_search',
            cookies={'session_id': session_id},
            data=json.dumps(ca_data))

        assert response.status == 200
