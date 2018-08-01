import os

import aiohttp
from zenpy import Zenpy
from zenpy.lib.api_objects import Ticket
from twilio.rest import Client


async def fetch(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()


async def post(url, json):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=json) as response:
            return await response.json()


def send_sms(to_number, body):
    account_sid = os.environ['TWILIO_ACCOUNT_SID']
    auth_token = os.environ['TWILIO_AUTH_TOKEN']
    twilio_number = os.environ['TWILIO_NUMBER']
    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,
                               from_=twilio_number,
                               body=body)


def create_zendesk_ticket(description,
                          user_info,
                          subject=None,
                          recipient=None,
                          requester=None):
    zd_credentials = {'email': os.environ.get('ZD_EMAIL'),
                      'token': os.environ.get('ZD_TOKEN'),
                      'subdomain': os.environ.get('ZD_SUBDOMAIN')}
    zenpy_client = Zenpy(**zd_credentials)
    zenpy_client.tickets.create(
        Ticket(subject=subject,
               recipient=recipient,
               requester=requester,
               description=description))
