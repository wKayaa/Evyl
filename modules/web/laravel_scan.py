"""
Laravel Scanner for Evyl Framework

Advanced scanner for Laravel framework security testing.
Identifies common Laravel vulnerabilities and misconfigurations.
"""

import asyncio
import aiohttp
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse

from utils.logger import Logger
from utils.network import NetworkManager

class LaravelScanner:
    """Laravel framework security scanner for authorized testing"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # Laravel-specific paths for authorized security testing
        self.laravel_paths = [
            # Configuration exposure
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.example',
            '/config/app.php',
            '/config/database.php',
            '/config/mail.php',
            '/config/services.php',
            
            # Debug and development endpoints
            '/telescope',
            '/telescope/requests',
            '/telescope/queries',
            '/telescope/models',
            '/horizon',
            '/horizon/api/stats',
            '/horizon/api/workload',
            '/_ignition/health-check',
            '/_ignition/execute-solution',
            
            # Storage and logs
            '/storage/logs/laravel.log',
            '/storage/app/public',
            '/storage/framework/views',
            '/bootstrap/cache/config.php',
            '/bootstrap/cache/routes.php',
            
            # API documentation and testing
            '/api/documentation',
            '/docs',
            '/swagger',
            '/api/user',
            '/api/admin',
            
            # Vendor and third-party
            '/vendor/autoload.php',
            '/vendor/composer/installed.json',
            '/composer.json',
            '/composer.lock',
            '/artisan',
            
            # Database and migration files
            '/database/seeds',
            '/database/migrations',
            '/database.sqlite',
            
            # Route debugging
            '/routes',
            '/route:list',
            
            # Session and cache
            '/storage/framework/sessions',
            '/storage/framework/cache',
            
            # Git exposure (Laravel projects)
            '/.git/config',
            '/.git/HEAD',
            '/.git/logs/HEAD',
            
            # Additional Laravel paths
            '/nova',
            '/nova-api/users',
            '/livewire',
            '/livewire/message',
        ]
        
        # Laravel vulnerability patterns
        self.laravel_patterns = {
            'debug_mode': r'APP_DEBUG\s*=\s*true',
            'database_credentials': r'DB_(?:HOST|DATABASE|USERNAME|PASSWORD)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
            'mail_credentials': r'MAIL_(?:HOST|PORT|USERNAME|PASSWORD|ENCRYPTION)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
            'app_key': r'APP_KEY\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
            'api_tokens': r'(?:API_KEY|TOKEN|SECRET)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
            'aws_credentials': r'AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|DEFAULT_REGION)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main Laravel security scan function"""
        results = {
            'vulnerabilities': [],
            'credentials': [],
            'exposed_files': [],
            'debug_info': []
        }
        
        try:
            # Test Laravel-specific paths
            for path in self.laravel_paths:
                url = urljoin(target, path)
                response_data = await self._check_path(url)
                
                if response_data:
                    # Analyze response for sensitive data
                    analysis = await self._analyze_response(url, response_data)
                    
                    if analysis['is_vulnerable']:
                        results['vulnerabilities'].append(analysis)
                    
                    if analysis['credentials']:
                        results['credentials'].extend(analysis['credentials'])
                    
                    if analysis['exposed_file']:
                        results['exposed_files'].append(analysis['exposed_file'])
                    
                    if analysis['debug_info']:
                        results['debug_info'].append(analysis['debug_info'])
            
            self.logger.info(f"Laravel scan completed for {target}")
            return results
            
        except Exception as e:
            self.logger.error(f"Laravel scan failed for {target}: {e}")
            return results
    
    async def _check_path(self, url: str) -> Dict[str, Any]:
        """Check if a Laravel path exists and is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        return {
                            'url': url,
                            'status_code': response.status,
                            'content': content,
                            'headers': dict(response.headers)
                        }
            return None
            
        except Exception as e:
            self.logger.debug(f"Failed to check {url}: {e}")
            return None
    
    async def _analyze_response(self, url: str, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze response for Laravel-specific vulnerabilities"""
        analysis = {
            'url': url,
            'is_vulnerable': False,
            'vulnerability_type': None,
            'credentials': [],
            'exposed_file': None,
            'debug_info': None,
            'severity': 'low'
        }
        
        content = response_data.get('content', '')
        
        # Check for .env file exposure
        if '/.env' in url and content:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Environment File Exposure'
            analysis['exposed_file'] = {
                'type': '.env file',
                'url': url,
                'size': len(content)
            }
            analysis['severity'] = 'critical'
            
            # Extract credentials from .env
            analysis['credentials'] = await self._extract_env_credentials(content)
        
        # Check for debug mode exposure
        elif '/telescope' in url or '/_ignition' in url:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Debug Interface Exposure'
            analysis['debug_info'] = {
                'type': 'Debug interface',
                'url': url,
                'description': 'Laravel debug interface is publicly accessible'
            }
            analysis['severity'] = 'high'
        
        # Check for configuration file exposure
        elif '/config/' in url and '.php' in url:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Configuration File Exposure'
            analysis['exposed_file'] = {
                'type': 'Configuration file',
                'url': url,
                'size': len(content)
            }
            analysis['severity'] = 'high'
        
        # Check for log file exposure
        elif '/storage/logs/' in url:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Log File Exposure'
            analysis['exposed_file'] = {
                'type': 'Log file',
                'url': url,
                'size': len(content)
            }
            analysis['severity'] = 'medium'
        
        # Check for Git exposure
        elif '/.git/' in url:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Git Repository Exposure'
            analysis['exposed_file'] = {
                'type': 'Git file',
                'url': url,
                'size': len(content)
            }
            analysis['severity'] = 'high'
        
        return analysis
    
    async def _extract_env_credentials(self, content: str) -> List[Dict[str, Any]]:
        """Extract credentials from Laravel .env file content"""
        credentials = []
        
        for pattern_name, pattern in self.laravel_patterns.items():
            import re
            matches = re.findall(pattern, content)
            
            for match in matches:
                if match and match.strip():
                    credentials.append({
                        'type': f'laravel_{pattern_name}',
                        'value': match.strip(),
                        'source': '.env file',
                        'pattern': pattern_name
                    })
        
        return credentials