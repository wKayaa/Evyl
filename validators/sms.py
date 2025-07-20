"""
SMS Service Validator for Evyl Framework

Validates API keys for SMS services like Twilio.
"""

import asyncio
import aiohttp
import base64
from typing import Dict, Any

from utils.logger import Logger

class SMSValidator:
    """Validator for SMS service API keys"""
    
    def __init__(self):
        self.logger = Logger()
    
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SMS service credentials"""
        cred_type = credential.get('type', '').lower()
        api_key = credential.get('value', '')
        
        if 'twilio' in cred_type:
            return await self._validate_twilio(api_key, cred_type)
        else:
            return {
                'status': 'unsupported',
                'details': {'reason': f'Unsupported SMS service: {cred_type}'}
            }
    
    async def _validate_twilio(self, api_key: str, cred_type: str) -> Dict[str, Any]:
        """Validate Twilio credentials"""
        try:
            if 'account_sid' in cred_type:
                # This is an Account SID, we need the Auth Token to validate
                return {
                    'status': 'incomplete',
                    'details': {'reason': 'Auth Token required for Account SID validation'}
                }
            elif 'auth_token' in cred_type:
                # This is an Auth Token, we need the Account SID to validate
                return {
                    'status': 'incomplete', 
                    'details': {'reason': 'Account SID required for Auth Token validation'}
                }
            elif 'api_key' in cred_type:
                # This is an API Key, we need the API Secret to validate
                return {
                    'status': 'incomplete',
                    'details': {'reason': 'API Secret required for API Key validation'}
                }
            
            # If we somehow get both parts, we could validate
            return await self._validate_twilio_full(None, api_key)
            
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    async def _validate_twilio_full(self, account_sid: str, auth_token: str) -> Dict[str, Any]:
        """Validate full Twilio credentials (Account SID + Auth Token)"""
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json"
            
            # Create basic auth header
            auth_string = f"{account_sid}:{auth_token}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        account_data = await response.json()
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'Twilio',
                                'account_sid': account_data.get('sid'),
                                'friendly_name': account_data.get('friendly_name'),
                                'status': account_data.get('status'),
                                'type': account_data.get('type')
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid credentials'}
                        }
                    else:
                        error_text = await response.text()
                        return {
                            'status': 'error',
                            'details': {'error': f'HTTP {response.status}: {error_text}'}
                        }
                        
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }