"""
SMTP Validator for Evyl Framework

Validates SMTP server credentials and tests configuration security.
"""

import asyncio
import smtplib
import ssl
from typing import Dict, Any, List
import socket
import re

from utils.logger import Logger

class SMTPValidator:
    """Validator for SMTP server credentials and security testing"""
    
    def __init__(self):
        self.logger = Logger()
    
    async def validate(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SMTP credentials"""
        cred_type = credential.get('type', '').lower()
        value = credential.get('value', '')
        
        # Handle different types of SMTP credentials
        if 'smtp_host' in cred_type:
            return await self._validate_smtp_host(value)
        elif 'smtp_username' in cred_type or 'smtp_password' in cred_type:
            return await self._validate_smtp_auth_component(credential)
        elif 'smtp_config' in cred_type:
            return await self._validate_smtp_config(value)
        else:
            return {
                'status': 'unsupported',
                'details': {'reason': f'Unsupported SMTP credential type: {cred_type}'}
            }
    
    async def _validate_smtp_host(self, host: str) -> Dict[str, Any]:
        """Validate SMTP host connectivity"""
        try:
            # Test common SMTP ports
            common_ports = [25, 465, 587, 2525]
            accessible_ports = []
            
            for port in common_ports:
                if await self._test_smtp_port(host, port):
                    accessible_ports.append(port)
            
            if accessible_ports:
                return {
                    'status': 'accessible',
                    'details': {
                        'host': host,
                        'accessible_ports': accessible_ports,
                        'security_note': 'SMTP host is accessible - ensure proper authentication'
                    }
                }
            else:
                return {
                    'status': 'inaccessible',
                    'details': {
                        'host': host,
                        'reason': 'No common SMTP ports are accessible'
                    }
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    async def _test_smtp_port(self, host: str, port: int, timeout: int = 5) -> bool:
        """Test if SMTP port is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def _validate_smtp_auth_component(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SMTP authentication component"""
        return {
            'status': 'component',
            'details': {
                'type': credential.get('type'),
                'value_length': len(credential.get('value', '')),
                'note': 'SMTP authentication component detected - requires full credentials for testing'
            }
        }
    
    async def _validate_smtp_config(self, config: str) -> Dict[str, Any]:
        """Validate complete SMTP configuration"""
        try:
            # Extract SMTP parameters from configuration
            smtp_params = self._extract_smtp_params(config)
            
            if not smtp_params.get('host'):
                return {
                    'status': 'incomplete',
                    'details': {'reason': 'SMTP host not found in configuration'}
                }
            
            # Test the SMTP configuration
            return await self.validate_smtp_credentials(
                smtp_params.get('host'),
                smtp_params.get('port', 587),
                smtp_params.get('username', ''),
                smtp_params.get('password', ''),
                smtp_params.get('use_tls', True)
            )
            
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    def _extract_smtp_params(self, config: str) -> Dict[str, Any]:
        """Extract SMTP parameters from configuration string"""
        params = {}
        
        # Host extraction
        host_match = re.search(r'(?:host|server)[:=]\s*[\'"]?([a-zA-Z0-9.-]+)[\'"]?', config, re.IGNORECASE)
        if host_match:
            params['host'] = host_match.group(1)
        
        # Port extraction
        port_match = re.search(r'port[:=]\s*[\'"]?(\d+)[\'"]?', config, re.IGNORECASE)
        if port_match:
            params['port'] = int(port_match.group(1))
        
        # Username extraction
        username_match = re.search(r'(?:username|user)[:=]\s*[\'"]?([^\'"\s]+)[\'"]?', config, re.IGNORECASE)
        if username_match:
            params['username'] = username_match.group(1)
        
        # Password extraction
        password_match = re.search(r'(?:password|pass)[:=]\s*[\'"]?([^\'"\s]+)[\'"]?', config, re.IGNORECASE)
        if password_match:
            params['password'] = password_match.group(1)
        
        # TLS/SSL detection
        tls_match = re.search(r'(?:tls|ssl|encryption)[:=]\s*[\'"]?(true|yes|ssl|tls)[\'"]?', config, re.IGNORECASE)
        params['use_tls'] = bool(tls_match)
        
        return params
    
    async def validate_smtp_credentials(self, server: str, port: int, username: str, password: str, 
                                      use_tls: bool = True) -> Dict[str, Any]:
        """Validate SMTP server credentials with security testing"""
        try:
            # Test connection and authentication
            if use_tls and port == 465:
                # Use SMTP_SSL for port 465
                context = ssl.create_default_context()
                smtp_server = smtplib.SMTP_SSL(server, port, context=context)
            else:
                # Use regular SMTP with optional STARTTLS
                smtp_server = smtplib.SMTP(server, port)
                if use_tls:
                    smtp_server.starttls()
            
            # Test authentication if credentials provided
            auth_result = None
            if username and password:
                try:
                    smtp_server.login(username, password)
                    auth_result = 'success'
                except smtplib.SMTPAuthenticationError:
                    auth_result = 'failed'
            
            # Get server capabilities
            capabilities = smtp_server.esmtp_features if hasattr(smtp_server, 'esmtp_features') else {}
            
            # Test for open relay (security check)
            relay_test = await self._test_open_relay_safe(smtp_server)
            
            # Get server info
            server_info = smtp_server.noop()
            
            smtp_server.quit()
            
            return {
                'status': 'valid' if auth_result == 'success' else 'accessible',
                'details': {
                    'server': server,
                    'port': port,
                    'username': username if username else 'not_provided',
                    'authentication': auth_result,
                    'tls_enabled': use_tls,
                    'server_response': server_info[1].decode() if server_info[1] else None,
                    'capabilities': list(capabilities.keys()) if capabilities else [],
                    'security_notes': relay_test
                }
            }
            
        except smtplib.SMTPAuthenticationError:
            return {
                'status': 'invalid_auth',
                'details': {'error': 'Authentication failed - credentials are invalid'}
            }
        except smtplib.SMTPConnectError as e:
            return {
                'status': 'connection_error',
                'details': {'error': f'Connection failed: {e}'}
            }
        except socket.gaierror as e:
            return {
                'status': 'dns_error',
                'details': {'error': f'DNS resolution failed: {e}'}
            }
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }
    
    async def _test_open_relay_safe(self, smtp_server) -> Dict[str, Any]:
        """Safely test for open relay vulnerability"""
        try:
            # Only test with safe, non-functional email addresses
            test_from = 'security-test@example.com'
            test_to = 'security-test@example.com'
            
            try:
                smtp_server.mail(test_from)
                response = smtp_server.rcpt(test_to)
                smtp_server.rset()  # Reset the transaction
                
                # Analyze the response
                if response[0] == 250:
                    return {
                        'open_relay_test': 'potential_vulnerability',
                        'note': 'Server may accept external relay - requires manual verification'
                    }
                else:
                    return {
                        'open_relay_test': 'properly_configured',
                        'note': 'Server properly rejects unauthorized relay'
                    }
                    
            except smtplib.SMTPRecipientsRefused:
                return {
                    'open_relay_test': 'properly_configured',
                    'note': 'Server properly rejects unauthorized relay'
                }
                
        except Exception as e:
            return {
                'open_relay_test': 'test_failed',
                'note': f'Could not test relay: {e}'
            }
    
    async def validate_aws_ses_credentials(self, access_key: str, secret_key: str, region: str = 'us-east-1') -> Dict[str, Any]:
        """Validate AWS SES credentials"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Create SES client
            ses_client = boto3.client(
                'ses',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            
            # Test credentials by getting sending quota
            quota_response = ses_client.get_send_quota()
            
            # Get verified email addresses
            verified_response = ses_client.list_verified_email_addresses()
            
            return {
                'status': 'valid',
                'details': {
                    'service': 'aws_ses',
                    'region': region,
                    'sending_quota': {
                        'max_24_hour': quota_response.get('Max24HourSend', 0),
                        'max_send_rate': quota_response.get('MaxSendRate', 0),
                        'sent_last_24_hours': quota_response.get('SentLast24Hours', 0)
                    },
                    'verified_emails': len(verified_response.get('VerifiedEmailAddresses', [])),
                    'security_note': 'Valid AWS SES credentials with sending capabilities'
                }
            }
            
        except NoCredentialsError:
            return {
                'status': 'invalid',
                'details': {'error': 'Invalid AWS credentials'}
            }
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            return {
                'status': 'error',
                'details': {'error': f'AWS SES error: {error_code}'}
            }
        except ImportError:
            return {
                'status': 'error',
                'details': {'error': 'boto3 library required for AWS SES validation'}
            }
        except Exception as e:
            return {
                'status': 'error',
                'details': {'error': str(e)}
            }