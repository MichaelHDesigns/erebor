# Erebor
This is the backend API server for Hoard. The primary functions of Erebor are to
facilitate the user creation process, allow users to transact with their contacts,
and swap various currencies.

## Modules
Endpoints are organized into their own modules corresponding to functionality.

### Users
 - /users
 - /users/<user_uid>
 - /activate/<activation_key>
 - /login
 - /2fa/sms_login
 - /2fa/settings
 - /logout
 - /change_password
 - /password
 - /reset_password/\<token>
 - /forgot_username
 - /email_preferences

### Transactions
 - /users/<user_uid>/register_address
 - /users/<user_uid>/contact_transactions
 - /contacts/transaction
 - /contacts/transaction_data/<transaction_uid>
 - /contacts/transaction_confirmation/<transaction_uid>
 - /contacts/transaction/<transaction_uid>/recipient_status
 - /request_funds

### Prices - uses cryptocompare API
 - /pricing_data/\<method>
 - /ticker

### Support
 - /support

### Misc
 - /unsubscribe
 - /result
 - /updates/\<platform>
 - /health

## Installation

Ensure you have PostgreSQL server installed, then install the requirements

First create a virtualenv outside the cloned directory

`python3 -m venv ereborvenv`

Then activate the virtualenv

`source ereborvenv/bin/activate`

Once the virtualenv is activated, install the requirements

`pip3 install -r requirements.txt`

#### Running Tests

`pytest tests`

#### Running the Server

`python3 erebor.py`

Note that you will need to set several environment variables to allow erebor to access the database, interact with external services, etc. Also note that Erebor uses AWS secret manager for the database connection as well AWS credentials for the email service (boto3). The environment variables are:

#### Full Erebor Package
 - Database:
`EREBOR_DB_AWS_SECRET`
 - Twilio:
`TWILIO_ACCOUNT_SID`
`TWILIO_AUTH_TOKEN`
`TWILIO_NUMBER`
- Blockchain:
`ETH_NETWORK`
`BTC_NETWORK`
`INFURA_API_KEY`
 - Zendesk:
`ZD_EMAIL`
`ZD_TOKEN`
`ZD_SUBDOMAIN`

#### Erebor-lite
- Database:
`EREBOR_DB_AWS_SECRET`
- Blockchain:
`ETH_NETWORK`
`BTC_NETWORK`
`INFURA_API_KEY`

#### Example usage
```python
health_check = requests.head('localhost:8000/health')
health_check.raise_for_status()

user_data = {
    'first_name': 'example',
    'last_name': 'example',
    'email_address': 'test@example.com',
    'username': 'example',
    'password': 'example',
    'phone_number': '+1234567890'
}
user_creation = requests.post(
    'localhost:8000/users',
    json=user_data)
user_creation.raise_for_status()
print(user_creation.json())

login_data = {
    'username_or_email': 'example',
    'password': 'example'
}
login = requests.post(
    'localhost:8000/login',
    json=login_data
)
login.raise_for_status()
print(login.json())
```
