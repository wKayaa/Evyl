"""
SMTP Validator for Evyl Framework

Validates SMTP server credentials.
"""

import asyncio
import smtplib
from typing import Dict, Any
import socket

from utils.logger import Logger

class SMTPValidator:
    """Validator for SMTP server credentials"""
    
    def __init__(self):
        self.logger = Logger()
    
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SMTP credentials"""
        # For SMTP validation, we need server, username, and password
        # This is a placeholder implementation
        
        return {
            'status': 'incomplete',
            'details': {'reason': 'SMTP validation requires server, username, and password'}
        }
    
    async def validate_smtp_credentials(self, server: str, port: int, username: str, password: str, 
                                      use_tls: bool = True) -> Dict[str, Any]:
        """Validate SMTP server credentials"""
        try:
            # Test connection
            if use_tls:
                smtp_server = smtplib.SMTP(server, port)
                smtp_server.starttls()
            else:
                smtp_server = smtplib.SMTP(server, port)
            
            # Test authentication
            smtp_server.login(username, password)
            
            # Get server info
            server_info = smtp_server.noop()
            
            smtp_server.quit()
            
            return {
                'status': 'valid',
                'details': {
                    'server': server,
                    'port': port,
                    'username': username,
                    'tls_enabled': use_tls,
                    'server_response': server_info[1].decode() if server_info[1] else None
                }
            }
            
        except smtplib.SMTPAuthenticationError:
            return {
                'status': 'invalid',
                'details': {'error': 'Authentication failed'}
            }
        except smtplib.SMTPConnectError as e:
            return {
                'status': 'error',
                'details': {'error': f'Connection failed: {e}'}
            }
        except socket.gaierror as e:
            return {
                'status': 'error',
                'details': {'error': f'DNS resolution failed: {e}'}
            }
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }