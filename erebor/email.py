import boto3
from botocore.exceptions import ClientError

from erebor.render import (
    signup_email_template, reset_password_email_template,
    contact_transaction_email_template, pending_transactions_email,
    request_funds_email_template, activated_email_template,
    forgot_username_template
    )


AWS_REGION = "us-east-1"

SENDER = "do-not-reply@hoardinvest.com"

CHARSET = "UTF-8"

EMAIL_TYPES = {
    'signup': {
        'subject': "Welcome to Hoard, {full_name}!",
        'body_text': ("Hello {full_name} - welcome to Hoard! Your account"
                      " has been created!\r\nPlease use the following url to"
                      " activate and confirm your account: {activation_url}"),
        'body_html': signup_email_template
    },
    'password_reset': {
        'subject': "Hoard - Reset Password",
        'body_text': ("Hello - please visit this link to reset your password:"
                      "\r\n{url}"),
        'body_html': reset_password_email_template
    },
    'contact_transactions': {
        'subject': "Hoard - You have {amount} pending {currency}!",
        'body_text': ("Hello {to_email_address} - {from_email_address}"
                      "at Hoard wishes to send you {amount}{currency}!"),
        'body_html': contact_transaction_email_template
    },
    'pending_contact_transactions': {
        'subject': "Your contact has signed up to Hoard",
        'body_text': ("Hello {first_name}\r\n"
                      'Your contact {to_email_address} has just '
                      'signed up to Hoard!\r\n'
                      'This email is to serve as a reminder about the '
                      'transactions you previously wished to send them.'),
        'body_html': pending_transactions_email
    },
    'request_funds': {
        'subject': "You've got a crypto request",
        'body_text': ("Hello {to_email_address},\r\n"
                      "{from_email_address} sent you a crypto request.\r\n"
                      "Crypto request details:\r\n"
                      "Amount requested {amount} {currency}\r\n"
                      "{request_time}"),
        'body_html': request_funds_email_template
    },
    'activated': {
        'subject': "Your account is now active, {full_name}!",
        'body_text': ("Welcome to Hoard!\r\n"
                      "Hello {full_name} - welcome to Hoard! "
                      "Your account is now active!"),
        'body_html': activated_email_template
    },
    'forgot_username': {
        'subject': "Hoard - Forgot Username",
        'body_text': ('Hello {first_name} - your username is:\r\n'
                      '{username}'),
        'body_html': forgot_username_template
    }
}


class Email(object):
    def __init__(self, recipient_address, email_type, **kwargs):
        self.recipient_address = "success@simulator.amazonses.com"
        self.subject = EMAIL_TYPES[email_type]['subject']
        self.body_text = EMAIL_TYPES[email_type]['body_text']
        self.body_html = EMAIL_TYPES[email_type]['body_html']
        self.client = boto3.client('ses', region_name=AWS_REGION)
        if kwargs:
            self.subject = self.subject.format(**kwargs)
            self.body_text = self.body_text.format(**kwargs)
            self.body_html = self.body_html.render(**kwargs)
        else:
            self.body_html = self.body_html.render()

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
