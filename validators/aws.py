"""
AWS Credential Validator for Evyl Framework

Validates AWS credentials using minimal API calls to determine validity and permissions.
"""

import asyncio
import aiohttp
import json
import hashlib
import hmac
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional

from utils.logger import Logger

class AWSValidator:
    """AWS credential validation using STS and basic service calls"""
    
    def __init__(self):
        self.logger = Logger()
        
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate AWS credentials"""
        cred_type = credential.get('type', '').lower()
        
        if 'aws_access_key' in cred_type:
            access_key = credential.get('value')
            # Try to find corresponding secret key
            secret_key = self._find_secret_key(credential)
            
            if secret_key:
                return await self.validate_credentials(access_key, secret_key)
            else:
                return {
                    'status': 'incomplete',
                    'details': {'reason': 'Secret key not found for access key'}
                }
        
        elif 'aws_secret_key' in cred_type:
            secret_key = credential.get('value')
            # Try to find corresponding access key
            access_key = self._find_access_key(credential)
            
            if access_key:
                return await self.validate_credentials(access_key, secret_key)
            else:
                return {
                    'status': 'incomplete',
                    'details': {'reason': 'Access key not found for secret key'}
                }
        
        return {
            'status': 'unsupported',
            'details': {'reason': f'Unsupported credential type: {cred_type}'}
        }
    
    def _find_secret_key(self, access_key_cred: Dict[str, Any]) -> Optional[str]:
        """Find corresponding secret key for access key"""
        # This would need access to other found credentials
        # For now, return None as placeholder
        return None
    
    def _find_access_key(self, secret_key_cred: Dict[str, Any]) -> Optional[str]:
        """Find corresponding access key for secret key"""
        # This would need access to other found credentials
        # For now, return None as placeholder
        return None
    
    async def validate_credentials(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """
        Validate AWS credentials using minimal API calls
        
        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            session_token: Optional session token for temporary credentials
            
        Returns:
            Dictionary with validation status and details
        """
        try:
            # Test 1: STS GetCallerIdentity (minimal permissions required)
            identity_result = await self._test_get_caller_identity(access_key, secret_key, session_token)
            
            if identity_result['valid']:
                result = {
                    'status': 'valid',
                    'details': {
                        'identity': identity_result['identity'],
                        'permissions': [],
                        'services': {}
                    }
                }
                
                # Test additional services if identity check passed
                await self._test_additional_services(access_key, secret_key, session_token, result)
                
                return result
            else:
                return {
                    'status': 'invalid',
                    'details': {'error': identity_result.get('error', 'Authentication failed')}
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    async def _test_get_caller_identity(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """Test STS GetCallerIdentity API call"""
        try:
            # AWS STS GetCallerIdentity endpoint
            endpoint = "https://sts.amazonaws.com/"
            
            # Prepare request parameters
            params = {
                'Action': 'GetCallerIdentity',
                'Version': '2011-06-15'
            }
            
            # Create AWS signature
            headers = await self._create_aws_request(
                method='POST',
                endpoint=endpoint,
                params=params,
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token
            )
            
            # Make request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    headers=headers,
                    data=urllib.parse.urlencode(params),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    response_text = await response.text()
                    
                    if response.status == 200:
                        # Parse XML response to extract identity information
                        identity_info = self._parse_identity_response(response_text)
                        return {
                            'valid': True,
                            'identity': identity_info
                        }
                    else:
                        return {
                            'valid': False,
                            'error': f"HTTP {response.status}: {response_text}"
                        }
                        
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    async def _test_additional_services(self, access_key: str, secret_key: str, session_token: str, result: Dict[str, Any]):
        """Test additional AWS services to determine permissions"""
        
        # Test S3 ListBuckets
        s3_result = await self._test_s3_list_buckets(access_key, secret_key, session_token)
        result['details']['services']['s3'] = s3_result
        if s3_result.get('accessible'):
            result['details']['permissions'].append('s3:ListAllMyBuckets')
        
        # Test SES GetSendQuota
        ses_result = await self._test_ses_get_send_quota(access_key, secret_key, session_token)
        result['details']['services']['ses'] = ses_result
        if ses_result.get('accessible'):
            result['details']['permissions'].append('ses:GetSendQuota')
        
        # Test SNS ListTopics
        sns_result = await self._test_sns_list_topics(access_key, secret_key, session_token)
        result['details']['services']['sns'] = sns_result
        if sns_result.get('accessible'):
            result['details']['permissions'].append('sns:ListTopics')
    
    async def _test_s3_list_buckets(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """Test S3 ListBuckets API call"""
        try:
            endpoint = "https://s3.amazonaws.com/"
            headers = await self._create_aws_request(
                method='GET',
                endpoint=endpoint,
                params={},
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                service='s3'
            )
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    endpoint,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        response_text = await response.text()
                        bucket_count = response_text.count('<Name>')
                        return {
                            'accessible': True,
                            'bucket_count': bucket_count
                        }
                    else:
                        return {
                            'accessible': False,
                            'error': f"HTTP {response.status}"
                        }
                        
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }
    
    async def _test_ses_get_send_quota(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """Test SES GetSendQuota API call"""
        try:
            endpoint = "https://email.us-east-1.amazonaws.com/"
            params = {
                'Action': 'GetSendQuota',
                'Version': '2010-12-01'
            }
            
            headers = await self._create_aws_request(
                method='POST',
                endpoint=endpoint,
                params=params,
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                service='ses'
            )
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    headers=headers,
                    data=urllib.parse.urlencode(params),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        return {'accessible': True}
                    else:
                        return {
                            'accessible': False,
                            'error': f"HTTP {response.status}"
                        }
                        
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }
    
    async def _test_sns_list_topics(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """Test SNS ListTopics API call"""
        try:
            endpoint = "https://sns.us-east-1.amazonaws.com/"
            params = {
                'Action': 'ListTopics',
                'Version': '2010-03-31'
            }
            
            headers = await self._create_aws_request(
                method='POST',
                endpoint=endpoint,
                params=params,
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                service='sns'
            )
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    headers=headers,
                    data=urllib.parse.urlencode(params),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        return {'accessible': True}
                    else:
                        return {
                            'accessible': False,
                            'error': f"HTTP {response.status}"
                        }
                        
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }
    
    async def _create_aws_request(self, method: str, endpoint: str, params: Dict[str, str], 
                                 access_key: str, secret_key: str, session_token: str = None,
                                 service: str = 'sts') -> Dict[str, str]:
        """Create AWS signed request headers"""
        
        # This is a simplified version of AWS signature version 4
        # For production use, consider using boto3 or a proper AWS signing library
        
        from urllib.parse import urlparse
        
        # Parse endpoint
        parsed_url = urlparse(endpoint)
        host = parsed_url.netloc
        
        # Create headers
        headers = {
            'Host': host,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'EvylFramework/2.0'
        }
        
        if session_token:
            headers['X-Amz-Security-Token'] = session_token
        
        # Add timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        headers['X-Amz-Date'] = timestamp
        
        # For simplicity, we'll use basic auth header format
        # In production, implement proper AWS Signature Version 4
        auth_header = f"AWS4-HMAC-SHA256 Credential={access_key}/20240101/us-east-1/{service}/aws4_request"
        headers['Authorization'] = auth_header
        
        return headers
    
    def _parse_identity_response(self, response_xml: str) -> Dict[str, Any]:
        """Parse STS GetCallerIdentity response"""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(response_xml)
            
            # Find the result element
            for elem in root.iter():
                if 'GetCallerIdentityResult' in elem.tag:
                    identity = {}
                    for child in elem:
                        tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        identity[tag_name.lower()] = child.text
                    return identity
            
            return {}
            
        except ET.ParseError:
            return {'raw_response': response_xml}