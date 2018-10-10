import json

import psycopg2
import flexmock

from . import app, TestErebor, api


class TestMisc(TestErebor):
    def test_voting(self):
        async def mock_verify_fun():
            return {'success': True, 'score': 0.6}
        flexmock(api.misc).should_receive(
            'verify').and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun()).and_return(
                mock_verify_fun())
        with open('./tests/coin_list.json') as coin_list_file:
            coin_list_data = json.load(coin_list_file)
            INSERT_COINS_SQL = """
            INSERT INTO supported_coins (symbol, name)
            VALUES
            """.strip()
            args = ", ".join('(\'{}\', \'{}\')'.format(
                coin_list_data[key], key) for key in coin_list_data)
            INSERT_COINS_SQL += args

            with psycopg2.connect(**app.db) as conn:
                with conn.cursor() as cur:
                    cur.execute(INSERT_COINS_SQL)

        request, response = app.test_client.get('/supported_coins')
        assert response.status == 200
        assert len(response.json['data']) == 6

        request, response = app.test_client.post(
            '/vote', data=json.dumps({'symbol': 'ZCN', 'captcha': 'c4ptch4'}))
        assert response.status == 200

        request, response = app.test_client.post(
            '/vote', data=json.dumps({'symbol': 'ZRX', 'captcha': 'c4ptch4'}))
        assert response.status == 200

        request, response = app.test_client.post(
            '/vote', data=json.dumps({'symbol': 'BEN', 'captcha': 'c4ptch4'}))
        assert response.status == 200

        request, response = app.test_client.post(
            '/vote', data=json.dumps({
                'symbol': 'EsdsadaTH', 'captcha': 'c4ptch4'}))
        assert response.status == 403
        assert response.json == {'errors': [
            {'code': 202, 'message': 'Unsupported Currency'}]}

        request, response = app.test_client.post(
            '/vote', data=json.dumps({'symbol': 'BTC', 'captcha': 'c4ptch4'}))
        assert response.status == 403

        request, response = app.test_client.post(
            '/vote', data=json.dumps({'symbol': 'ZRX', 'captcha': 'c4ptch4'}))
        assert response.status == 403
        assert response.json == {'errors': [
            {'code': 300, 'message': 'You have already voted for this coin'}]}

        request, response = app.test_client.get('/vote')
        assert response.status == 200
        assert len(response.json['data']) == 3
        for item in response.json['data']:
            assert item['votes'] == 1

        request, response = app.test_client.get('/vote?test=1')
        assert response.status == 404

        request, response = app.test_client.get(
            "/vote?interval={\"hours\": 1, \"days\": 2}")
        assert response.status == 200

        request, response = app.test_client.get(
            "/vote?interval={\"not_hours\": 1, \"not_days\": 2}")
        assert response.status == 404

        # Declare winners of the current round
        DECLARE_WINNER_SQL = """
        UPDATE supported_coins
        SET round_won = 1
        WHERE symbol = 'ZCN'
        OR symbol = 'BEN'
        """.strip()

        with psycopg2.connect(**app.db) as conn:
            with conn.cursor() as cur:
                cur.execute(DECLARE_WINNER_SQL)

        request, response = app.test_client.get('/vote')
        assert response.status == 200
        for item in response.json['data']:
            assert item['votes'] == 1
            if item['symbol'] == 'ZCN' or item['symbol'] == 'BEN':
                assert item['round_won'] == 1
            else:
                assert item['round_won'] is None
