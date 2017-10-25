import psycopg2

from smaug.smaug import app, auth_zero_get_or_create_user

from . import TestSmaug


class TestAuthZero(TestSmaug):

    def test_create_account(self):
        db = app.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        payload = {'sub': 'auth0|12345',
                   'nickname': 'Test',
                   'name': 'test@example.com'}
        user_ids, session_id = auth_zero_get_or_create_user(db, payload)
        assert len(user_ids) == 2
        assert user_ids[0] == 1
        assert session_id is not None

    '''
    def test_jwt(self):
        id_token = "h3h7PPmRSUQVXsPGYEdoI7HalEVKdm4M"
        id_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjiM0NTY"\
                   "3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95O"\
                   "rM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        payload = auth_zero_validate(id_token)
        print(payload)
        assert type(payload) == dict
    '''
