# smaug
Backend API server for Hoard

#### Installation

Ensure you have PostgreSQL server installed, then install the requirements

First create a virtualenv outside the cloned directory

`python3 -m venv smaugvenv`

Then activate the virtualenv

`source smaugvenv/bin/activate`

Once the virtualenv is activated, install the requirements

`pip3 install -r requirements.txt`

#### Running Tests

`pytest tests`

#### Running the Server

`python3 smaug.py`

Note that you will need to set several environment variables to allow smaug to access the database, interact with external services, etc.  The environment variables are:

`SMAUG_DB_NAME`
`SMAUG_DB_USER`
`SMAUG_DB_PASSWORD`
`SMAUG_DB_HOST`
`TWILIO_ACCOUNT_SID`
`TWILIO_AUTH_TOKEN`
`TWILIO_NUMBER`
