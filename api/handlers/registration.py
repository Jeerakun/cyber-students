from .base import BaseHandler
from hashlib import sha256
from tornado.gen import coroutine
from tornado.escape import json_decode
from api.encrypt import encrypt_data, encrypt_password, hash_email  # Import hash_email from encrypt.py

class RegistrationHandler(BaseHandler):
    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise ValueError("Email must be a string")
            password = body['password']
            if not isinstance(password, str):
                raise ValueError("Password must be a string")
            display_name = body.get('displayName')
            dob = body.get('dob')
            disability_level = body.get('disability_level')
            phone_number = body.get('phone_number')
            student_number = body.get('student_number')
            address = body.get('address')

            mandatory_fields = [email, password, display_name]
            if not all(mandatory_fields):
                self.send_error(400, message='Missing mandatory field!')
                return

            encrypted_email = encrypt_data(email)
            email_hash = hash_email(email)
            hashed_password, salt = encrypt_password(password)
            encrypted_display_name = encrypt_data(display_name) if display_name else None
            encrypted_dob = encrypt_data(dob) if dob else None
            encrypted_disability_level = encrypt_data(disability_level) if disability_level else None
            encrypted_phone_number = encrypt_data(phone_number) if phone_number else None
            encrypted_student_number = encrypt_data(student_number) if student_number else None
            encrypted_address = encrypt_data(address) if address else None

            user = await self.db.users.find_one({'email_hash': email_hash}, {})
            if user is not None:
                self.send_error(409, message='A user with the given email address already exists!')
                return

            await self.db.users.insert_one({
                'email': encrypted_email,
                'email_hash': email_hash,
                'password': hashed_password,
                'salt': salt,
                'displayName': encrypted_display_name,
                'dob': encrypted_dob,
                'disability': encrypted_disability_level,
                'phoneNumber': encrypted_phone_number,
                'studentNumber': encrypted_student_number,
                'address': encrypted_address
            })

            self.set_status(200)
            self.write_json({"message": "Registration successful"})
        except Exception as e:
            self.send_error(400, message=str(e))
            return
