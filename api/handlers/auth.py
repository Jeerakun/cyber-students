from datetime import datetime, timezone
from tornado.gen import coroutine
from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            # Allow pre-flight checks for CORS
            return

        token = self.request.headers.get('X-Token')
        if not token:
            self.handle_auth_error(401, "No token provided")
            return

        user = yield self.db.users.find_one({'token': token}, {
            'email': 1,
            'displayName': 1,
            'dob': 1,
            'disability': 1,
            'phoneNumber': 1,
            'studentNumber': 1,
            'address': 1,  # Request the address field
            'expiresIn': 1
        })

        if not user:
            self.handle_auth_error(403, "Invalid token")
            return

        # Convert expiresIn to a datetime object assuming expiresIn is stored as a timestamp
        token_expires = datetime.fromtimestamp(user['expiresIn'], timezone.utc)
        if datetime.now(timezone.utc) > token_expires:
            self.handle_auth_error(403, "Token has expired")
            return

        # Setting the current_user if all checks pass
        self.current_user = user

    def handle_auth_error(self, status_code, message):
        self.set_status(status_code)
        self.finish({"error": message})
        # This method centralizes the error handling for authentication issues.
