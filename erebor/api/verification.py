import json
import os
import requests

from sanic import Blueprint, response

from . import limiter, authorized, create_zendesk_ticket

# sql
from . import CREATE_IV_SQL, IV_RESULTS_SQL, SELECT_USER_SQL


verification_bp = Blueprint('verification')


@verification_bp.route('/jumio_callback', methods=['POST'])
async def jumio_callback(request):
    form_data = request.form
    scan_reference = form_data.get('scanReference')
    if scan_reference:
        db = request.app.pg
        await db.execute(CREATE_IV_SQL, scan_reference, json.dumps(form_data))
        return response.HTTPResponse(body=None, status=201)
    else:
        return response.HTTPResponse(body=None, status=400)


@verification_bp.route('/jumio_results/<scan_reference>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='jumio_results/scan_reference')
@authorized()
async def get_jumio_results(request, scan_reference):
    results = await request['db'].fetch(IV_RESULTS_SQL, scan_reference)
    if results:
        return response.json({'results': [r[0] for r in results]})
    else:
        return response.HTTPResponse(body=None, status=200)


@verification_bp.route('/ca_search', methods=['POST', 'GET'])
@authorized()
async def ca_search(request):
    url = "https://api.complyadvantage.com/searches?api_key={}".format(
        os.environ.get('COMPLY_ADVANTAGE_API_KEY'))
    if request.method == 'POST':
        ca_response = requests.post(url, request.json)
        ca_response_json = ca_response.json()
        hits = ca_response_json.get(
            'content', {}).get('data', {}).get('total_hits')
        if hits != 0:
            db = request.app.pg
            user_info = await db.fetchrow(SELECT_USER_SQL,
                                          request['session']['user_id'])
            user_info = dict(user_info)
            create_zendesk_ticket(ca_response,
                                  user_info, subject="Comply Advantage Hit")
    # DL: Do we actually need to provide GET requests to the mobile app?
    elif request.method == 'GET':
        ca_response = requests.get(url)
    return response.json(ca_response_json)


@verification_bp.route('/ca_search/<search_id>', methods=['GET'])
@limiter.shared_limit('50 per minute', scope='ca_search/search_id')
@authorized()
async def ca_search_id(request, search_id):
    url = "https://api.complyadvantage.com/searches/{}?api_key={}".format(
        search_id, os.environ.get('COMPLY_ADVANTAGE_API_KEY'))
    ca_response = requests.get(url)
    return response.json(ca_response)
