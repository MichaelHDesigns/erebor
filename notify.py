import json
import requests
import argparse


def audience_loader(path):
    """
    Loads a JSON file of device IDs to push to. Either ios_channel or
    android_channel
    """
    data = json.load(open(path))
    return data


def validate_and_push(message,
                      key,
                      audience=None,
                      validate=False):
    """
    Sends a push notification to specified audience. If no file of device IDs
    is provided the audience defaults to 'all' (all devices using our app)
    """
    audience = audience_loader(audience) if audience else "all"
    headers = {
        "Authorization": ("Basic " + key),
        "Accept": "application/vnd.urbanairship+json; version=3;",
        "Content-Type": "application/json"
    }
    data = {
        "audience": audience,
        "notification": {"alert": message},
        "device_types": ["android", "ios"]
    }
    if validate:
        validate_req = requests.post(
            "https://go.urbanairship.com/"
            "api/push/validate", headers=headers, data=json.dumps(data))

        validation = validate_req.json()
        if not validation['ok']:
            return validation['error']
        else:
            return json.dumps({
                "success": "Request resulted in success",
                "audience": audience,
                "message": message,
            })

    push_req = requests.post(
        "https://go.urbanairship.com/"
        "api/push/", headers=headers, data=json.dumps(data))
    return push_req.json()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--audience', type=str)
    parser.add_argument('-m', '--message', type=str, required=True)
    parser.add_argument('-k', '--key', type=str, required=True)
    parser.add_argument('-v', '--validate', action='store_true')
    args = vars(parser.parse_args())
    print(validate_and_push(args['message'],
                            args['key'],
                            audience=args['audience'],
                            validate=args['validate']))
