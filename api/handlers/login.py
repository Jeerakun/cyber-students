import base64
from datetime import datetime, timedelta
from time import mktime
from tornado.gen import coroutine
from tornado.escape import json_decode
from uuid import uuid4
from .base import BaseHandler
from api.encrypt import hash_email, encrypt_password

class LoginHandler(BaseHandler):
    async def generate_token(self, email_hash):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        await self.db.users.update_one({'email_hash': email_hash}, {'$set': token})
        return token

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']

            email_hash = hash_email(email)
            user = await self.db.users.find_one({'email_hash': email_hash}, {'password': 1, 'salt': 1})

            if not user:
                self.send_error(403, message='User not found')
                return

            salt = base64.urlsafe_b64decode(user['salt'].encode())
            stored_password_hash, _ = encrypt_password(password, salt)

            if stored_password_hash != user['password']:
                self.send_error(403, message='Incorrect username or password')
                return

            token = await self.generate_token(email_hash)
            response = {
                'message': 'Login successful',
                'token': token['token'],
                'expiresIn': token['expiresIn']
            }
            self.write_json(response)

        except Exception as e:
            self.send_error(400, message=str(e))
