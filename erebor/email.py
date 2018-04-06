import boto3
from botocore.exceptions import ClientError

from erebor.render import signup_email_template

AWS_REGION = "us-east-1"

SUBJECT = "Welcome to Hoard, {}!"

SENDER = "do-not-reply@hoardinvest.com"

BODY_TEXT = ("Welcome to Hoard!\r\n"
             "Hello {} - welcome to Hoard! Your account is now active!")

# The character encoding for the email.
CHARSET = "UTF-8"


def send_signup_email(recipient_address, recipient_name):
    # Create a new SES resource and specify a region.
    client = boto3.client('ses', region_name=AWS_REGION)
    BODY_HTML = signup_email_template.render(
        recipient_name=recipient_name)
    try:
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    recipient_address,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT.format(recipient_name),
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT.format(recipient_name),
                },
            },
            Source=SENDER,
            # If you are not using a configuration set, comment or delete the
            # following line
            # ConfigurationSetName=CONFIGURATION_SET,
        )
    # Display an error if something goes wrong.
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['ResponseMetadata']['RequestId'])
        return response['ResponseMetadata']
