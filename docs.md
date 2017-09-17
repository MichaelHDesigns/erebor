### Authentication

Most endpoints require authentication. To authenticate a request, add a header containing the API key:

"Authorization": "ApiKey KEY"

### Users

#### /registration/

POST:
  - full_name
  - email_address
  
  Response: {'registration_id': UUID}

#### /users/

POST:
  - registration_id
  - password
  
  Response: {'uid': UUID,
             'api_key': STRING,
             'email_address': STRING,
             'full_name': STRING}

#### /users/{uid}/

UPDATE:
  - full_name
  - email_address

GET:
  {'uid': UUID,
   'full_name': STRING,
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
