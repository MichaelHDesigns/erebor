import flexmock
import psycopg2
import json

from . import new_user, app, TestErebor, api


class TestPrices(TestErebor):
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

    def test_price_data(self):
        u_data, session_id = new_user(app)
        mock_multi_price_data = {
            "BTC": {"USD": 6711.79, "AUD": 9004.21},
            "ETH": {"USD": 516.4, "AUD": 694.4}
        }
        mock_histoday_price_data = {
            "Response": "Success",
            "Type": 100,
            "Aggregated": False,
            "Data": [
                {
                    "time": 1529280000,
                    "close": 6714.82,
                    "high": 6802.03,
                    "low": 6401.41,
                    "open": 6457.78,
                    "volumefrom": 65285.57,
                    "volumeto": 430241689.1299999952
                 },
                {
                    "time": 1529366400,
                    "close": 6719.72,
                    "high": 6839.6,
                    "low": 6672.2,
                    "open": 6714.56,
                    "volumefrom": 43175.8,
                    "volumeto": 291436647.1299999952}
                    ],
            "TimeTo": 1529366400,
            "TimeFrom": 1529280000,
            "FirstValueInArray": True,
            "ConversionType": {"type": "direct", "conversionSymbol": ""}
                }

        async def mock_price_func():
            return mock_multi_price_data

        async def mock_histoday_func():
            return mock_histoday_price_data

        flexmock(api.prices).should_receive(
            'current_prices').and_return(mock_price_func())
        flexmock(api.prices).should_receive(
            'historical_prices').and_return(mock_histoday_func())

        request, response = app.test_client.get(
            '/pricing_data/pricemulti?fsyms=BTC,ETH&tsyms=USD,AUD'
        )
        assert response.json == mock_multi_price_data

        request, response = app.test_client.get(
            '/pricing_data/histoday?fsym=BTC&tsym=USD&limit=1'
        )
        assert response.json == mock_histoday_price_data

    def test_local_prices(self):
        u_data, session_id = new_user(app)
        mock_price_data = [
            {'currency': 'ETH', 'time': 1451433600, 'close': 0.8925},
            {'currency': 'ETH', 'time': 1453334400, 'close': 1.54},
            {'currency': 'ETH', 'time': 1453420800, 'close': 1.52},
            {'currency': 'ETH', 'time': 1455321600, 'close': 5.22},
            {'currency': 'ETH', 'time': 1479859200, 'close': 9.78},
            {'currency': 'ETH', 'time': 1506643200, 'close': 292.58}
        ]
        INSERT_PRICES = """
        INSERT INTO prices (currency, date, price) VALUES """
        args = ", ".join('(\'{}\', {}, {})'.format(
            str(entry['currency']), entry['time'], entry['close'])
            for entry in mock_price_data)
        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(INSERT_PRICES + args)

        request, response = app.test_client.post(
            '/local_prices',
            data=json.dumps({'from_date': 1451433600, 'to_date': 1479859200}),
            cookies={'session_id': session_id})
        p_data = response.json
        assert len(p_data['result']) == 5
