import requests
import re
import json
import os
from codecs import decode
from decimal import Decimal


INFURA_API_KEY = os.environ.get("INFURA_API_KEY")
ETH_NETWORK = os.environ.get("ETH_NETWORK")
BTC_NETWORK = os.environ.get("BTC_NETWORK")
symbol_pattern = re.compile("[0-9a-zA-Z!@#$%^&*()-]{2,10}")
address_pattern = re.compile("^0x[a-fA-F0-9]{40}$")

# sha3 of getBalance(address) function
get_Balance_sha3 = "0x70a08231" + "0" * 24

# sha3 of decimals() getter function
decimals_sha3 = "0x313ce567"

# sha3 of symbols() getter function
symbols_sha3 = "0x95d89b41"


class memoize(dict):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args):
        return self[args]

    def __missing__(self, key):
        result = self[key] = self.func(*key)
        return result


def get_balance(address, currency):
    if currency == 'ETH':
        params = {
            "token": INFURA_API_KEY,
            "params": json.dumps([address, "latest"])
        }
        balance_req = requests.get(
            "https://api.infura.io/v1/jsonrpc/{}/"
            "eth_getBalance".format(ETH_NETWORK), params=params)
        balance = balance_req.json().get('result')
        if balance is None:
            return 0
        return Decimal(float.fromhex(balance)/(10e+17))
    elif currency == 'BTC':
        balance_req = requests.get(
            "https://{}blockchain.info/rawaddr/{}"
            "?limit=0".format(BTC_NETWORK, address))
        try:
            balance = balance_req.json().get('final_balance')
        except json.decoder.JSONDecodeError:
            return 0
        return balance / 100000000.0
    else:
        # Currency is a contract address
        return get_token_balance(address, currency)


def get_token_balance(address, contract):
    if not address_pattern.match(address):
        return 0
    address = get_Balance_sha3 + address[2:]
    params = {
        "token": INFURA_API_KEY,
        "params": json.dumps([
            {
                "to": contract,
                "data": address
            },
            "latest"
        ])
    }
    balance_req = requests.get(
        "https://api.infura.io/v1/jsonrpc/{}/"
        "eth_call".format(ETH_NETWORK), params=params)
    balance = balance_req.json().get('result')
    if balance is not None:
        return Decimal(
            float.fromhex(balance)/(10 ** get_decimal(contract)))
    else:
        return 0


@memoize
def get_decimal(contract):
    params = {
        "token": INFURA_API_KEY,
        "params": json.dumps([
            {
                "to": contract,
                "data": decimals_sha3
            },
            "latest"
        ])
    }
    decimal_req = requests.get(
        "https://api.infura.io/v1/jsonrpc/{}/"
        "eth_call".format(ETH_NETWORK), params=params)
    decimal = decimal_req.json().get('result')
    return float.fromhex(decimal)


@memoize
def get_symbol(contract):
    params = {
        "token": INFURA_API_KEY,
        "params": json.dumps([
            {
                "to": contract,
                "data": symbols_sha3
            },
            "latest"
        ])
    }
    symbol_req = requests.get(
        "https://api.infura.io/v1/jsonrpc/{}/"
        "eth_call".format(ETH_NETWORK), params=params)
    symbol_result = symbol_req.json().get('result')
    if symbol_result:
        symbol_string = decode(symbol_result[2:], "hex").decode('utf-8')
        symbol_match = symbol_pattern.search(symbol_string)
        if symbol_match:
            symbol_match = symbol_match.group()
        else:
            return None
        return symbol_match.replace(" ", "")
    return None
