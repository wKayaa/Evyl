"""
Encryption and Cryptography Utilities for Evyl Framework

Provides secure encryption, decryption, and security utilities.
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional

from utils.logger import Logger

class CryptoManager:
    """Handles encryption and security operations"""
    
    def __init__(self):
        self.logger = Logger()
        self._key = None
        
    def generate_key(self) -> bytes:
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def set_key(self, key: bytes):
        """Set the encryption key"""
        self._key = key
    
    def encrypt_data(self, data: str, key: Optional[bytes] = None) -> str:
        """Encrypt string data"""
        if key is None:
            key = self._key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data: str, key: Optional[bytes] = None) -> str:
        """Decrypt string data"""
        if key is None:
            key = self._key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        f = Fernet(key)
        decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(decoded_data)
        return decrypted_data.decode()
    
    def encrypt_file(self, file_path: str, output_path: str, key: Optional[bytes] = None):
        """Encrypt a file"""
        if key is None:
            key = self._key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        f = Fernet(key)
        
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)
        
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
        
        self.logger.info(f"File encrypted: {output_path}")
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str, key: Optional[bytes] = None):
        """Decrypt a file"""
        if key is None:
            key = self._key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        f = Fernet(key)
        
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = f.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        
        self.logger.info(f"File decrypted: {output_path}")
    
    def hash_data(self, data: str, algorithm: str = 'sha256') -> str:
        """Hash data with specified algorithm"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj = algorithms[algorithm]()
        hash_obj.update(data.encode())
        return hash_obj.hexdigest()
    
    def secure_delete(self, file_path: str, passes: int = 3):
        """Securely delete a file by overwriting"""
        try:
            if not os.path.exists(file_path):
                return
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            os.remove(file_path)
            self.logger.debug(f"Securely deleted: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to securely delete {file_path}: {e}")
    
    def generate_random_string(self, length: int = 32) -> str:
        """Generate a random string"""
        return base64.urlsafe_b64encode(os.urandom(length)).decode()[:length]
    
    def constant_time_compare(self, a: str, b: str) -> bool:
        """Compare two strings in constant time to prevent timing attacks"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def obfuscate_credential(self, credential: str, show_chars: int = 4) -> str:
        """Obfuscate credential for logging"""
        if len(credential) <= show_chars * 2:
            return '*' * len(credential)
        
        return credential[:show_chars] + '*' * (len(credential) - show_chars * 2) + credential[-show_chars:]
    
    def memory_wipe(self, data: bytes):
        """Attempt to wipe sensitive data from memory"""
        # Note: This is best effort in Python due to string immutability
        # For production use, consider using ctypes or specialized libraries
        try:
            if hasattr(data, '__del__'):
                data.__del__()
        except:
            pass