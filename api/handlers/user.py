import json
import logging
from tornado.web import authenticated
from api.encrypt import decrypt_data
from .auth import AuthHandler

class UserHandler(AuthHandler):
    @authenticated
    async def get(self):
        try:
            # Decrypt necessary fields. Check if fields exist and are not None before decrypting.
            decrypted_email = decrypt_data(self.current_user.get('email')) if self.current_user.get('email') else ''
            decrypted_displayName = decrypt_data(self.current_user.get('displayName')) if self.current_user.get('displayName') else ''
            decrypted_dob = decrypt_data(self.current_user.get('dob')) if self.current_user.get('dob') else ''
            decrypted_disability = decrypt_data(self.current_user.get('disability')) if self.current_user.get('disability') else ''
            decrypted_phoneNumber = decrypt_data(self.current_user.get('phoneNumber')) if self.current_user.get('phoneNumber') else ''
            decrypted_studentNumber = decrypt_data(self.current_user.get('studentNumber')) if self.current_user.get('studentNumber') else ''
            decrypted_address = decrypt_data(self.current_user.get('address')) if self.current_user.get('address') else ''

            user_info = {
                'email': decrypted_email,
                'displayName': decrypted_displayName,
                'dob': decrypted_dob,
                'disability': decrypted_disability,
                'phoneNumber': decrypted_phoneNumber,
                'studentNumber': decrypted_studentNumber,
                'address': decrypted_address  # Include decrypted address in the response
            }
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(user_info))
            self.finish()
        except Exception as e:
            logging.error(f"Unexpected error processing user data: {str(e)}")
            if "decryption" in str(e).lower():
                self.send_error(500, message="Failed to decrypt user data")
            else:
                self.send_error(500, message="Internal Server Error")
