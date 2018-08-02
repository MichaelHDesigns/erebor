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


def send_sms(to_number, body, twilio_credentials):
    account_sid = twilio_credentials['account_sid']
    auth_token = twilio_credentials['auth_token']
    twilio_number = twilio_credentials['twilio_number']
    client = Client(account_sid, auth_token)
    client.api.messages.create(to_number,
                               from_=twilio_number,
                               body=body)


def create_zendesk_ticket(description,
                          user_info,
                          zd_credentials,
                          subject=None,
                          recipient=None,
                          requester=None):
    zenpy_client = Zenpy(**zd_credentials)
    zenpy_client.tickets.create(
        Ticket(subject=subject,
               recipient=recipient,
               requester=requester,
               description=description))
