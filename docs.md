### Authentication

Most endpoints require authentication. To authenticate a request, you can
obtain a session_id HttpOnly cookie by creating a new user via the /users/
endpoint, or using the /login/ endpoint.

### Users

#### /users/

POST:
  - first_name
  - last_name
  - phone_number
  - email_address
  - password

  Response: {'uid': UUID,
             'email_address': STRING,
             'first_name': STRING,
             'last_name': STRING,
             'phone_number': STRING}
  Response Cookie: session_id

#### /users/{uid}/

UPDATE:
  - first_name
  - last_name
  - phone_number
  - email_address

 GET:
  {'uid': UUID,
   'first_name': STRING,
   'last_name': STRING,
   'phone_number': STRING,
   'email_address': STRING}

#### /users/{uid}/wallet/

GET:
  {'symbol': STRING,
   'amount': STRING}

#### /change_password/

POST:
  - password
  - email_address
  - new_password

  Response: 200 OK, empty body

#### /logout/

POST (empty body)

  Response: {'success': ['Your session has been invalidated']}

#### /login/

POST:
  - email_address
  - password

  Response: {'success': ['Login successful']}
  Response Cookie: session_id

    OR if 2fa is enabled

  Response: {'success': ['2FA has been sent']}

#### /2fa/sms_login/

POST:
  - email_address
  - sms_verification

  Response: {'success': ['Login successful']}
  Response Cookie: session_id

#### /2fa/settings/

PUT:
  - sms_2fa_enabled

  Response: 200 OK, empty body

GET:

  Response: {'sms_2fa_enabled': BOOL}

### KYC/AML/Identity Verification

#### /ca_search/

Bridge to POST/GET /searches on Comply Advantage API

POST:
  - see Comply Advantage documentation

  Response: 200 OK, body according to Comply Advantage documentation

GET:

  Response: 200 OK, body according to Comply Advantage documentation

#### /ca_search/{search_id}/

Bridge to GET /searches/{search_id}/ on Comply Advantage API

GET:

  Response: 200 OK, body according to Comply Advantage documentation

#### /jumio_results/

GET:

  Response: {'results': [LIST OF JUMIO RESULTS]}

### Ticker

#### /ticker/

GET:

  Response {'btc_usd': USD Currency,
            'eth_usd': USD Currency}
