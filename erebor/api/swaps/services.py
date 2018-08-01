from .. import fetch, post


class Shapeshift(object):
    def __init__(self):
        return

    async def get_coins(self):
        coin_req = await fetch(
            "https://shapeshift.io/getcoins"
        )
        full_list = coin_req
        symbols = list(full_list.keys())
        return full_list, symbols

    async def get_limit(self, _from, to):
        pair = _from + "_" + to
        limit_req = await fetch(
            "https://shapeshift.io/limit/{}".format(pair)
        )
        limit = limit_req
        return ({'min': limit['min'], 'max': limit['limit']} if
                limit.get('pair') else limit)

    async def get_rate(self, _from, to):
        pair = _from + "_" + to
        rate_req = await fetch(
            "https://shapeshift.io/rate/{}".format(pair)
        )
        rate = rate_req
        return rate['rate'] if rate.get('pair') else rate

    async def get_exchange_amount(self, _from, to, amount):
        pair = _from + "_" + to
        marketinfo_req = await fetch(
            "https://shapeshift.io/marketinfo/{}".format(pair)
        )
        marketinfo = marketinfo_req
        rate = marketinfo['rate']
        miner_fee = marketinfo['minerFee']
        exchange_amount = (rate * amount) - miner_fee
        return exchange_amount

    async def get_marketinfo(self, _from, to):
        pair = _from + "_" + to
        marketinfo_req = await fetch(
            "https://shapeshift.io/marketinfo/{}".format(pair)
        )
        marketinfo = marketinfo_req
        return marketinfo

    async def get_recent_transactions(self, limit=5):
        recent_transactions_req = fetch(
            "https://shapeshift.io/recenttx/{}".format(limit)
        )
        recent_transactions = recent_transactions_req
        return recent_transactions

    async def validate_address(self, address, currency):
        validate_req = await fetch(
            "https://shapeshift.io/validateAddress/{}/{}".format(
                address, currency)
        )
        validation = validate_req
        return validation

    async def get_transaction_status(self, address):
        status_req = await fetch(
            "https://shapeshift.io/txstat/{}".format(address)
        )
        status = status_req
        return status

    async def get_transaction_time_remaining(self, address):
        time_req = await fetch(
            "https://shapeshift.io/timeremaining/{}".format(address)
        )
        time = time_req
        return time

    async def create_dynamic_transaction(self,
                                         _from,
                                         to,
                                         address,
                                         return_address=None):
        pair = _from + "_" + to
        transaction_req = await post(
            "https://shapeshift.io/shift",
            json={
                'withdrawal': address,
                'pair': pair,
                'returnAddress': return_address
            }
        )
        transaction = transaction_req
        return transaction

    async def create_transaction(self,
                                 _from,
                                 to,
                                 address,
                                 amount,
                                 return_address=None):
        pair = _from + "_" + to
        transaction_req = await post(
            "https://shapeshift.io/sendamount",
            json={
                'withdrawal': address,
                'pair': pair,
                'depositAmount': amount,
                'return_address': return_address
            }
        )
        transaction = transaction_req
        return transaction
