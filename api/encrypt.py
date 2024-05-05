from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Placeholder for ENC_KEY from external configuration
ENC_KEY = b'mysecretkey12345678901234567890123'  # Example key, typically should be base64 URL-safe encoded

def create_fernet_key():
    """Create a Fernet key from the provided ENC_KEY or generate a new one if the provided one is not valid."""
    try:
        # This will raise an exception if ENC_KEY is not correctly padded or incorrect base64
        key = urlsafe_b64decode(ENC_KEY)
        assert len(key) == 32, "Key must be 32 bytes after decoding."
    except (AssertionError, ValueError):
        # If not valid, generate a new valid Fernet key
        key = Fernet.generate_key()
    return Fernet(key)

fernet = create_fernet_key()

def encrypt_data(data):
    """Encrypts data"""
    try:
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def decrypt_data(encrypted_data):
    """Decrypts data"""
    try:
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None

def generate_salt(length=16):
    """Generate a random salt"""
    return os.urandom(length)

def encrypt_password(password, salt=None):
    """Hashes a password using SHA-256 with a salt"""
    if salt is None:
        salt = generate_salt()
    # Combine the password and the salt, then hash them
    salted_password = password.encode() + salt
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    # Return the hashed password and the salt used, ensuring salt is encoded in base64 for consistent storage and retrieval
    return hashed_password, urlsafe_b64encode(salt).decode()

def hash_email(email):
    """Hashes the email for consistent lookup."""
    try:
        return hashlib.sha256(email.lower().strip().encode()).hexdigest()
    except Exception as e:
        print(f"Hashing email error: {str(e)}")
        return None

def generate_fernet_key(password, salt):
    """Generate a Fernet key from a password and salt using PBKDF2"""
    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # length required for Fernet key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return urlsafe_b64encode(key)
