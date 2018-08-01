from sanic import Blueprint, response

from .services import Shapeshift
from .. import authorized
from .. import (error_response, MISSING_FIELDS, NEGATIVE_AMOUNT,
                INVALID_SWAP_SERVICE)

swap_bp = Blueprint('swap')
shapeshift = Shapeshift()
SWAP_SERVICES = {'shapeshift': shapeshift}


@swap_bp.route('/swap_rate', methods=['POST'])
@authorized()
async def swap_rates(request):
    if request.json.keys() != {'from', 'to', 'amount'}:
        return error_response([MISSING_FIELDS])
    _from = request.json['from']
    to = request.json['to']
    amount = request.json['amount']
    if (not (isinstance(amount, float) or
             isinstance(amount, int)) or
            amount <= 0):
        return error_response([NEGATIVE_AMOUNT])
    service_info = []
    for name, service in SWAP_SERVICES.items():
        market_info = await service.get_marketinfo(_from, to)
        if not market_info.get('error'):
            errors = []
            if amount < float(market_info['minimum']):
                errors.append('Amount is below service\'s minimum')
            elif amount > float(market_info['limit']):
                errors.append('Amount exceeded service\'s maximum')
            service_info.append({
                name: {'rate': market_info['rate'],
                       'limits': {'min': market_info['minimum'],
                                  'max': market_info['limit']},
                       'errors': errors if errors else None}})
        else:
            service_info.append({name: {'errors': ['Invalid pair']}})
    service, result = max(
        service_info,
        key=lambda r: (list(r.values())[0]['rate'] if r.get('rate') and
                       not r['errors'] else 0)).popitem()
    if not result['errors']:
        return response.json({'service': service,
                              'pair': _from + '_' + to,
                              'rate': result['rate'],
                              'final_amount': result['rate'] * amount})
    else:
        return response.json({'service': service,
                              'rate': result.get('rate'),
                              'limits': result.get('limits'),
                              'errors': result['errors']})


@swap_bp.route('/swap', methods=['POST'])
@authorized()
async def swap(request):
    if request.json.keys() != {'from', 'to', 'amount',
                               'service', 'address'}:
        return error_response([MISSING_FIELDS])
    service = request.json['service']
    if service not in SWAP_SERVICES.keys():
        return error_response([INVALID_SWAP_SERVICE])
    _from = request.json['from']
    to = request.json['to']
    amount = request.json['amount']
    address = request.json['address']
    return_address = request.json.get('return_address')
    transaction = await SWAP_SERVICES[service].create_transaction(
        _from, to, address, amount, return_address=return_address)
    return response.json(transaction)


@swap_bp.route('/swap_status', methods=['POST'])
@authorized()
async def swap_status(request):
    if request.json.keys() != {'address', 'service'}:
        return error_response([MISSING_FIELDS])
    address = request.json['address']
    service = request.json['service']
    time_remaining = await SWAP_SERVICES[
        service].get_transaction_time_remaining(address)
    transaction_status = await SWAP_SERVICES[
        service].get_transaction_status(address)
    if time_remaining.get('error') or transaction_status.get('error'):
        return response.json({'errors': [
            time_remaining.get('error'),
            transaction_status.get('error')]})
    return response.json(
        {'status': [time_remaining['status'], transaction_status['status']],
         'seconds_remaining': time_remaining['seconds_remaining'],
         'address': transaction_status['address']})
