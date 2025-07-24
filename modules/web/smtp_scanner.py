"""
SMTP Security Scanner for Evyl Framework

Legitimate SMTP service security testing for authorized penetration testing.
Tests for common SMTP misconfigurations and security issues.
"""

import asyncio
import aiohttp
import socket
import smtplib
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin, urlparse
import re

from utils.logger import Logger
from utils.network import NetworkManager

class SMTPSecurityScanner:
    """SMTP service security scanner for authorized testing"""
    
    def __init__(self):
        self.logger = Logger()
        self.network_manager = NetworkManager()
        
        # Common SMTP ports
        self.smtp_ports = [25, 465, 587, 2525]
        
        # SMTP configuration paths commonly exposed in web applications
        self.smtp_config_paths = [
            '/config/mail.php',
            '/config/email.php',
            '/mail-config.php',
            '/.env',
            '/wp-config.php',
            '/configuration.php',
            '/config.php',
            '/settings.php',
            '/admin/config.php',
            '/include/config.php',
            '/includes/config.php',
            '/config/database.yml',
            '/config/application.yml',
            '/application.properties',
            '/mail.properties',
        ]
        
        # SMTP credential patterns
        self.smtp_patterns = {
            'smtp_host': r'(?:SMTP_HOST|MAIL_HOST|MAILER_HOST)\s*[:=]\s*[\'"]?([a-zA-Z0-9.-]+)[\'"]?',
            'smtp_port': r'(?:SMTP_PORT|MAIL_PORT|MAILER_PORT)\s*[:=]\s*[\'"]?(\d+)[\'"]?',
            'smtp_username': r'(?:SMTP_USERNAME|SMTP_USER|MAIL_USERNAME|MAIL_USER|MAILER_USERNAME)\s*[:=]\s*[\'"]?([^\'"\s]+)[\'"]?',
            'smtp_password': r'(?:SMTP_PASSWORD|SMTP_PASS|MAIL_PASSWORD|MAIL_PASS|MAILER_PASSWORD)\s*[:=]\s*[\'"]?([^\'"\s]+)[\'"]?',
            'smtp_encryption': r'(?:SMTP_ENCRYPTION|MAIL_ENCRYPTION|MAILER_ENCRYPTION)\s*[:=]\s*[\'"]?(tls|ssl|starttls)[\'"]?',
            'smtp_auth': r'(?:SMTP_AUTH|MAIL_AUTH|MAILER_AUTH)\s*[:=]\s*[\'"]?(true|false|yes|no)[\'"]?',
        }
        
        # AWS SES configuration patterns
        self.ses_patterns = {
            'aws_ses_key': r'(?:AWS_ACCESS_KEY_ID|SES_KEY)\s*[:=]\s*[\'"]?(AKIA[A-Z0-9]{16})[\'"]?',
            'aws_ses_secret': r'(?:AWS_SECRET_ACCESS_KEY|SES_SECRET)\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            'aws_ses_region': r'(?:AWS_DEFAULT_REGION|SES_REGION)\s*[:=]\s*[\'"]?([a-z0-9-]+)[\'"]?',
            'ses_sender': r'(?:SES_SENDER|SES_FROM_EMAIL)\s*[:=]\s*[\'"]?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\'"]?',
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """Main SMTP security scan function"""
        results = {
            'smtp_services': [],
            'exposed_configs': [],
            'credentials': [],
            'vulnerabilities': [],
            'ses_configs': []
        }
        
        try:
            # Discover SMTP services
            smtp_services = await self._discover_smtp_services(target)
            results['smtp_services'] = smtp_services
            
            # Check for exposed SMTP configurations
            exposed_configs = await self._check_exposed_configs(target)
            results['exposed_configs'] = exposed_configs
            
            # Extract credentials from exposed configurations
            for config in exposed_configs:
                credentials = await self._extract_smtp_credentials(config)
                results['credentials'].extend(credentials)
                
                # Check for AWS SES configurations
                ses_configs = await self._extract_ses_configs(config)
                results['ses_configs'].extend(ses_configs)
            
            # Analyze SMTP service security
            for service in smtp_services:
                vulnerabilities = await self._analyze_smtp_security(service)
                results['vulnerabilities'].extend(vulnerabilities)
            
            self.logger.info(f"SMTP security scan completed for {target}")
            return results
            
        except Exception as e:
            self.logger.error(f"SMTP security scan failed for {target}: {e}")
            return results
    
    async def _discover_smtp_services(self, target: str) -> List[Dict[str, Any]]:
        """Discover SMTP services on common ports"""
        services = []
        hostname = urlparse(target).hostname if '//' in target else target
        
        if not hostname:
            return services
        
        for port in self.smtp_ports:
            service_info = await self._test_smtp_port(hostname, port)
            if service_info:
                services.append(service_info)
        
        return services
    
    async def _test_smtp_port(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test if SMTP service is running on a specific port"""
        try:
            # Test basic connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                # Try to get SMTP banner
                banner = await self._get_smtp_banner(hostname, port)
                
                return {
                    'host': hostname,
                    'port': port,
                    'status': 'open',
                    'banner': banner,
                    'service': 'smtp'
                }
                
        except Exception as e:
            self.logger.debug(f"SMTP port test failed for {hostname}:{port}: {e}")
        
        return None
    
    async def _get_smtp_banner(self, hostname: str, port: int) -> str:
        """Get SMTP service banner"""
        try:
            smtp = smtplib.SMTP()
            smtp.connect(hostname, port)
            banner = smtp.getwelcome()
            smtp.quit()
            return banner
        except Exception as e:
            self.logger.debug(f"Failed to get SMTP banner from {hostname}:{port}: {e}")
            return "Unknown"
    
    async def _check_exposed_configs(self, target: str) -> List[Dict[str, Any]]:
        """Check for exposed SMTP configuration files"""
        exposed_configs = []
        
        for path in self.smtp_config_paths:
            url = urljoin(target, path)
            config_data = await self._check_config_path(url)
            
            if config_data:
                exposed_configs.append(config_data)
        
        return exposed_configs
    
    async def _check_config_path(self, url: str) -> Dict[str, Any]:
        """Check if a configuration path contains SMTP settings"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if content contains SMTP-related keywords
                        smtp_keywords = ['smtp', 'mail', 'mailer', 'email', 'ses']
                        content_lower = content.lower()
                        
                        if any(keyword in content_lower for keyword in smtp_keywords):
                            return {
                                'url': url,
                                'status_code': response.status,
                                'content': content,
                                'size': len(content),
                                'headers': dict(response.headers)
                            }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Failed to check config path {url}: {e}")
            return None
    
    async def _extract_smtp_credentials(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract SMTP credentials from configuration content"""
        credentials = []
        content = config.get('content', '')
        
        for pattern_name, pattern in self.smtp_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                if match and match.strip():
                    credentials.append({
                        'type': f'smtp_{pattern_name}',
                        'value': match.strip(),
                        'source': config['url'],
                        'pattern': pattern_name,
                        'service': 'smtp'
                    })
        
        return credentials
    
    async def _extract_ses_configs(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract AWS SES configurations from content"""
        ses_configs = []
        content = config.get('content', '')
        
        for pattern_name, pattern in self.ses_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                if match and match.strip():
                    ses_configs.append({
                        'type': f'aws_ses_{pattern_name}',
                        'value': match.strip(),
                        'source': config['url'],
                        'pattern': pattern_name,
                        'service': 'aws_ses'
                    })
        
        return ses_configs
    
    async def _analyze_smtp_security(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze SMTP service for security issues"""
        vulnerabilities = []
        
        # Check for open relay
        relay_test = await self._test_open_relay(service['host'], service['port'])
        if relay_test['is_vulnerable']:
            vulnerabilities.append({
                'type': 'Open SMTP Relay',
                'severity': 'high',
                'description': 'SMTP server allows relaying emails without authentication',
                'host': service['host'],
                'port': service['port'],
                'details': relay_test
            })
        
        # Check for STARTTLS support
        starttls_test = await self._test_starttls_support(service['host'], service['port'])
        if not starttls_test['supported']:
            vulnerabilities.append({
                'type': 'Missing STARTTLS Support',
                'severity': 'medium',
                'description': 'SMTP server does not support STARTTLS encryption',
                'host': service['host'],
                'port': service['port'],
                'details': starttls_test
            })
        
        return vulnerabilities
    
    async def _test_open_relay(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test if SMTP server is an open relay"""
        try:
            smtp = smtplib.SMTP()
            smtp.connect(hostname, port)
            
            # Try to send an email from external domain to external domain
            try:
                smtp.mail('test@external.com')
                smtp.rcpt('recipient@external.com')
                smtp.quit()
                
                return {
                    'is_vulnerable': True,
                    'description': 'Server accepts external relay'
                }
                
            except smtplib.SMTPRecipientsRefused:
                smtp.quit()
                return {
                    'is_vulnerable': False,
                    'description': 'Server properly rejects external relay'
                }
                
        except Exception as e:
            return {
                'is_vulnerable': False,
                'description': f'Test failed: {e}'
            }
    
    async def _test_starttls_support(self, hostname: str, port: int) -> Dict[str, Any]:
        """Test if SMTP server supports STARTTLS"""
        try:
            smtp = smtplib.SMTP()
            smtp.connect(hostname, port)
            
            # Check STARTTLS support
            if smtp.has_extn('STARTTLS'):
                smtp.starttls()
                smtp.quit()
                return {
                    'supported': True,
                    'description': 'STARTTLS is supported'
                }
            else:
                smtp.quit()
                return {
                    'supported': False,
                    'description': 'STARTTLS is not supported'
                }
                
        except Exception as e:
            return {
                'supported': False,
                'description': f'Test failed: {e}'
            }