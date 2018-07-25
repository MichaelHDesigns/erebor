from datetime import datetime as dt
import logging
import requests
import datetime

from aiocache import cached
from sanic import Blueprint, response

from . import authorized, fetch, limiter

# errors
from . import (error_response, TICKER_UNAVAILABLE)


prices_bp = Blueprint('prices')
ticker_last_update = None


def refresh_ticker():
    global btc_usd_latest
    global eth_usd_latest
    global ticker_last_update
    if ticker_last_update is None or (dt.utcnow() > ticker_last_update +
                                      datetime.timedelta(seconds=2)):
        r_btc = requests.get('https://api.gdax.com/products/BTC-USD/ticker')
        r_btc_data = r_btc.json()
        if 'price' in r_btc_data.keys():
            btc_usd_latest = r_btc_data['price']
        else:
            logging.error('GDAX BTC-USD ticker error: {}'.format(r_btc_data))
            btc_usd_latest = None
            eth_usd_latest = None
            return
        r_eth = requests.get('https://api.gdax.com/products/ETH-USD/ticker')
        r_eth_data = r_eth.json()
        if 'price' in r_eth_data.keys():
            eth_usd_latest = r_eth_data['price']
        else:
            logging.error('GDAX ETH-USD ticker error: {}'.format(r_eth_data))
            btc_usd_latest = None
            eth_usd_latest = None
            return
        ticker_last_update = dt.utcnow()


@prices_bp.route('/ticker', methods=['GET'])
@authorized()
async def get_ticker(request):
    refresh_ticker()
    if btc_usd_latest and eth_usd_latest:
        return response.json({'btc_usd': btc_usd_latest,
                              'eth_usd': eth_usd_latest})
    else:
        return error_response([TICKER_UNAVAILABLE])


@cached(ttl=10)
async def current_prices(method, params):
    url = ("https://min-api.cryptocompare.com/data/"
           "{}?{}".format(method, "".join(
            item + "=" + params[item][0] + "&" for item in params)))
    return await fetch(url)


@cached(ttl=610)
async def historical_prices(method, params):
    url = ("https://min-api.cryptocompare.com/data/"
           "{}?{}".format(method, "".join(
            item + "=" + params[item][0] + "&" for item in params)))
    return await fetch(url)


@prices_bp.route('/pricing_data/<method>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='pricing_data/method')
async def pricing_data(request, method):
    if 'hist' in method:
        return response.json(await historical_prices(method, request.args))
    return response.json(await current_prices(method, request.args))
