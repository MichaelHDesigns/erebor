# Erebor
Backend API server for Hoard

#### Installation

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

Note that you will need to set several environment variables to allow erebor to access the database, interact with external services, etc.  The environment variables are:

`EREBOR_DB_NAME`
`EREBOR_DB_USER`
`EREBOR_DB_PASSWORD`
`EREBOR_DB_HOST`
`TWILIO_ACCOUNT_SID`
`TWILIO_AUTH_TOKEN`
`TWILIO_NUMBER`
