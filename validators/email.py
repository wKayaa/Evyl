"""
Email Service Validator for Evyl Framework

Validates API keys for various email services including SendGrid, Mailgun, Postmark, etc.
"""

import asyncio
import aiohttp
import json
import base64
from typing import Dict, Any

from utils.logger import Logger

class EmailValidator:
    """Validator for email service API keys"""
    
    def __init__(self):
        self.logger = Logger()
    
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate email service credentials"""
        cred_type = credential.get('type', '').lower()
        api_key = credential.get('value', '')
        
        if 'sendgrid' in cred_type:
            return await self._validate_sendgrid(api_key)
        elif 'mailgun' in cred_type:
            return await self._validate_mailgun(api_key)
        elif 'postmark' in cred_type:
            return await self._validate_postmark(api_key)
        elif 'sparkpost' in cred_type:
            return await self._validate_sparkpost(api_key)
        elif 'brevo' in cred_type:
            return await self._validate_brevo(api_key)
        else:
            return {
                'status': 'unsupported',
                'details': {'reason': f'Unsupported email service: {cred_type}'}
            }
    
    async def _validate_sendgrid(self, api_key: str) -> Dict[str, Any]:
        """Validate SendGrid API key"""
        try:
            url = "https://api.sendgrid.com/v3/user/account"
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        account_data = await response.json()
                        
                        # Get additional information
                        quotas = await self._get_sendgrid_quotas(api_key)
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'SendGrid',
                                'account_type': account_data.get('type'),
                                'reputation': account_data.get('reputation'),
                                'quotas': quotas
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid API key'}
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
    
    async def _get_sendgrid_quotas(self, api_key: str) -> Dict[str, Any]:
        """Get SendGrid quotas and limits"""
        try:
            url = "https://api.sendgrid.com/v3/user/credits"
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        return await response.json()
                    
        except Exception:
            pass
        
        return {}
    
    async def _validate_mailgun(self, api_key: str) -> Dict[str, Any]:
        """Validate Mailgun API key"""
        try:
            url = "https://api.mailgun.net/v3/domains"
            auth = base64.b64encode(f'api:{api_key}'.encode()).decode()
            headers = {
                'Authorization': f'Basic {auth}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        domains_data = await response.json()
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'Mailgun',
                                'domains_count': len(domains_data.get('items', [])),
                                'domains': [d.get('name') for d in domains_data.get('items', [])]
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid API key'}
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
    
    async def _validate_postmark(self, api_key: str) -> Dict[str, Any]:
        """Validate Postmark API key"""
        try:
            url = "https://api.postmarkapp.com/account"
            headers = {
                'X-Postmark-Account-Token': api_key,
                'Accept': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        account_data = await response.json()
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'Postmark',
                                'account_id': account_data.get('AccountId'),
                                'name': account_data.get('Name'),
                                'plan': account_data.get('PlanType')
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid API key'}
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
    
    async def _validate_sparkpost(self, api_key: str) -> Dict[str, Any]:
        """Validate SparkPost API key"""
        try:
            url = "https://api.sparkpost.com/api/v1/account"
            headers = {
                'Authorization': api_key,
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        account_data = await response.json()
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'SparkPost',
                                'company_name': account_data.get('company_name'),
                                'plan': account_data.get('plan'),
                                'service_level': account_data.get('service_level')
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid API key'}
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
    
    async def _validate_brevo(self, api_key: str) -> Dict[str, Any]:
        """Validate Brevo (formerly Sendinblue) API key"""
        try:
            url = "https://api.brevo.com/v3/account"
            headers = {
                'api-key': api_key,
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    
                    if response.status == 200:
                        account_data = await response.json()
                        
                        return {
                            'status': 'valid',
                            'details': {
                                'service': 'Brevo',
                                'company_name': account_data.get('companyName'),
                                'first_name': account_data.get('firstName'),
                                'last_name': account_data.get('lastName'),
                                'email': account_data.get('email')
                            }
                        }
                    elif response.status == 401:
                        return {
                            'status': 'invalid',
                            'details': {'error': 'Invalid API key'}
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