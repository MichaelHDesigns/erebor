import boto3
from botocore.exceptions import ClientError


AWS_REGION = "us-east-1"

SIGNUP_SUBJECT = "Welcome to Hoard, {}!"

SENDER = "do-not-reply@hoardinvest.com"

SIGNUP_BODY_TEXT = ("Welcome to Hoard!\r\n"
                    "Hello {} - welcome to Hoard! Your account is now active!")

CHARSET = "UTF-8"


class Email(object):
    def __init__(self,
                 recipient_address,
                 subject,
                 body_text,
                 body_html):
        self.recipient_address = recipient_address
        self.subject = subject
        self.body_text = body_text
        self.body_html = body_html
        self.client = boto3.client('ses', region_name=AWS_REGION)

    def send(self):
        try:
            response = self.client.send_email(
                Destination={
                    'ToAddresses': [
                        self.recipient_address,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': CHARSET,
                            'Data': self.body_html,
                        },
                        'Text': {
                            'Charset': CHARSET,
                            'Data': self.body_text,
                        },
                    },
                    'Subject': {
                        'Charset': CHARSET,
                        'Data': self.subject,
                    },
                },
                Source=SENDER,
            )
        # Display an error if something goes wrong.
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['ResponseMetadata']['RequestId'])
            return response['ResponseMetadata']
