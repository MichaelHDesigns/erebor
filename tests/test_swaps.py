import json
import flexmock
import pytest

from . import app, TestErebor, new_user


class TestSwaps(TestErebor):
    @pytest.mark.skip(reason="Unsupported for now")
    def test_swaps(self):
        u_data, session_id = new_user(app)
        from erebor.api.swaps.services import Shapeshift
        mock_market_info = {'pair': 'LTC_BTC',
                            'rate': 0.0118902,
                            'minerFee': 0.0003,
                            'limit': 65.70987371,
                            'minimum': 0.05,
                            'maxLimit': 65.70987371}

        async def mock_get_marketinfo():
            return mock_market_info

        flexmock(Shapeshift).should_receive(
            'get_marketinfo').and_return(mock_get_marketinfo())

        request, response = app.test_client.post(
            '/swap_rate',
            data=json.dumps({'from': 'LTC', 'to': 'BTC', 'amount': 1}),
            cookies={'session_id': session_id})
        assert response.status == 200
        assert response.json == {
            'service': 'shapeshift',
            'pair': 'LTC_BTC',
            'rate': 0.0118902,
            'final_amount': 0.0118902}
