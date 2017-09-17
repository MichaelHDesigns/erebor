### Authentication

Most endpoints require authentication. To authenticate a request, add a header containing the API key:

"Authorization": "ApiKey KEY"

### Users

#### /users/

POST:
  - first_name
  - last_name
  - phone_number
  - email_address
  - password

  Response: {'uid': UUID,
             'api_key': STRING,
             'email_address': STRING,
             'first_name': STRING,
             'last_name': STRING,
             'phone_number': STRING}

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

#### /users/{uid}/wallet

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

  Response: 200 OK, empty body

#### /login/

POST:
  - email_address
  - password

  Response: {'api_key': UUID}
