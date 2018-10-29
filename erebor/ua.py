import requests
from os import environ


UA_API_KEY = environ.get("UA_API_KEY")


def send_push_notification(message, audience, deep_link=None):
    device_type = audience['device_type']
    channel = audience['channel']
    headers = {
        "Authorization": ("Basic " + str(UA_API_KEY)),
        "Accept": "application/vnd.urbanairship+json; version=3;",
        "Content-Type": "application/json"
    }
    data = {
        "audience": {"channel": channel},
        "notification": {
            "alert": message,
            "actions": {
                "app_defined": {
                    "^d": deep_link
                 }
             }
        },
        "device_types": [device_type]
    }

    push_req = requests.post(
        "https://go.urbanairship.com/"
        "api/push/", headers=headers, json=data)
    return push_req.json()


def check_channel(channel):
    headers = {
        "Authorization": ("Basic " + str(UA_API_KEY)),
        "Accept": "application/vnd.urbanairship+json; version=3;",
        "Content-Type": "application/json"
    }
    channel_req = requests.get(
        "https://go.urbanairship.com/"
        "api/channels/{}".format(channel), headers=headers)
    return channel_req
