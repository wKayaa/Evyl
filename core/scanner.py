"""
Multi-threaded Scanner Engine for Evyl Framework

This module implements the core scanning functionality with:
- ThreadPoolExecutor for concurrent requests
- Intelligent path discovery
- Request queuing with priority
- Automatic retry with exponential backoff
- Response caching
- Content-type based routing
"""

import asyncio
import aiohttp
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import ssl
from pathlib import Path

from utils.logger import Logger
from utils.network import NetworkManager
from patterns.endpoints import ENDPOINTS
from patterns.regex_db import PATTERNS

@dataclass
class ScanResult:
    """Represents a scan result"""
    url: str
    status_code: int
    content: str
    headers: Dict[str, str]
    response_time: float
    error: Optional[str] = None
    credentials: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ScanStats:
    """Scan statistics"""
    total_processed: int = 0
    unique_urls: int = 0
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    valid_credentials: int = 0
    success_rate: float = 0.0
    validation_results: List[Dict[str, Any]] = field(default_factory=list)

class Scanner:
    """Multi-threaded scanner with advanced capabilities - optimized for VPS deployment"""
    
    def __init__(self, threads: int = 200, timeout: int = 8, network_manager=None, config: Dict[str, Any] = None):
        self.threads = threads
        self.timeout = timeout
        self.config = config or {}
        self.logger = Logger()
        self.network_manager = network_manager or NetworkManager()
        
        # Scanning state
        self.processed_urls: Set[str] = set()
        self.results: List[ScanResult] = []
        self.stats = ScanStats()
        
        # Performance optimizations from config
        self.batch_size = self.config.get('batch_size', 1000)
        self.memory_efficient = self.config.get('memory_efficient', True)
        self.request_delay = self.config.get('request_delay', 0.05)
        
        # Path lists
        self.load_paths()
        
        # SSL context for bypassing certificate verification
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        self.logger.info(f"Scanner initialized: {threads} threads, {timeout}s timeout, batch size: {self.batch_size}")
    
    def load_paths(self):
        """Load scanning paths from files"""
        self.paths = {
            'kubernetes': self._load_path_file('paths/kubernetes.txt'),
            'cloud': self._load_path_file('paths/cloud.txt'),
            'web': self._load_path_file('paths/web_common.txt')
        }
        
        # Add built-in endpoints if files don't exist
        for category, endpoints in ENDPOINTS.items():
            if category not in self.paths or not self.paths[category]:
                self.paths[category] = endpoints
        
        total_paths = sum(len(paths) for paths in self.paths.values())
        self.logger.info(f"Loaded {total_paths} scanning paths across {len(self.paths)} categories")
    
    def _load_path_file(self, filename: str) -> List[str]:
        """Load paths from a file"""
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.warning(f"Path file not found: {filename}")
            return []
    
    async def scan_targets(self, targets: List[str], progress_display=None) -> ScanStats:
        """Scan multiple targets concurrently - optimized for large lists"""
        self.logger.info(f"Starting scan of {len(targets)} targets with {self.threads} threads")
        
        # Generate all URLs to scan
        urls_to_scan = self._generate_urls(targets)
        self.stats.unique_urls = len(urls_to_scan)
        
        self.logger.info(f"Generated {len(urls_to_scan)} URLs to scan")
        
        # Update progress display with filename if available
        if progress_display and hasattr(progress_display, 'update_filename'):
            target_file = getattr(progress_display, 'current_file', 'targets')
            progress_display.update_filename(target_file)
        
        # Process URLs in batches for memory efficiency
        if self.memory_efficient and len(urls_to_scan) > self.batch_size:
            await self._scan_in_batches(urls_to_scan, progress_display)
        else:
            await self._scan_all_urls(urls_to_scan, progress_display)
        
        # Calculate final statistics
        self._calculate_final_stats()
        
        self.logger.info(f"Scan completed: {self.stats.total_processed} URLs processed, "
                        f"{len(self.stats.credentials)} credentials found")
        
        return self.stats
    
    async def _scan_in_batches(self, urls: List[str], progress_display=None):
        """Scan URLs in batches to manage memory usage"""
        total_batches = (len(urls) + self.batch_size - 1) // self.batch_size
        
        for batch_num in range(total_batches):
            start_idx = batch_num * self.batch_size
            end_idx = min(start_idx + self.batch_size, len(urls))
            batch_urls = urls[start_idx:end_idx]
            
            self.logger.info(f"Processing batch {batch_num + 1}/{total_batches} ({len(batch_urls)} URLs)")
            
            await self._scan_all_urls(batch_urls, progress_display)
            
            # Small delay between batches to prevent overwhelming
            if batch_num < total_batches - 1:
                await asyncio.sleep(0.5)
    
    async def _scan_all_urls(self, urls_to_scan: List[str], progress_display=None):
        """Scan all URLs in the list"""
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create async session with optimized settings
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=self.threads * 3,  # Increased connection pool
            limit_per_host=20,       # Higher per-host limit
            ttl_dns_cache=300,       # DNS caching
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=5,  # Separate connect timeout
            sock_read=self.timeout
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        ) as session:
            # Create tasks for all URLs
            tasks = [
                self._scan_url_async(session, semaphore, url, progress_display)
                for url in urls_to_scan
            ]
            
            # Process tasks as they complete
            completed_count = 0
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    if result:
                        self.results.append(result)
                        self._extract_credentials(result)
                        
                        # Log credentials immediately for real-time monitoring
                        if result.credentials:
                            for cred in result.credentials:
                                self.logger.credential_found(cred['type'], result.url)
                    
                    completed_count += 1
                    self.stats.total_processed = completed_count
                    
                    # Update progress more frequently for better feedback
                    if progress_display and completed_count % 10 == 0:
                        progress_display.update_stats(self.stats)
                        
                except Exception as e:
                    self.logger.debug(f"Task failed: {e}")
                    completed_count += 1
    
    async def _scan_url_async(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, 
                             url: str, progress_display=None) -> Optional[ScanResult]:
        """Scan a single URL asynchronously - optimized for performance"""
        async with semaphore:
            try:
                # Small delay for rate limiting
                if self.request_delay > 0:
                    await asyncio.sleep(self.request_delay)
                
                start_time = time.time()
                
                # Get headers and proxy
                headers = self.network_manager.get_headers()
                proxy = self.network_manager.get_proxy()
                
                # Make request with improved error handling
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        proxy=proxy,
                        allow_redirects=True,
                        max_redirects=2  # Reduced for performance
                    ) as response:
                        # Only read content for successful responses or specific error codes
                        if response.status in [200, 401, 403, 500]:
                            content = await response.text(errors='ignore')
                        else:
                            content = ""
                        
                        response_time = time.time() - start_time
                        
                        result = ScanResult(
                            url=url,
                            status_code=response.status,
                            content=content,
                            headers=dict(response.headers),
                            response_time=response_time
                        )
                        
                        # Only log successful requests and errors in verbose mode
                        if response.status == 200:
                            self.logger.debug(f"✅ {url} - {response.status}")
                        elif response.status >= 400:
                            self.logger.debug(f"⚠️  {url} - {response.status}")
                        
                        return result
                        
                except aiohttp.ClientError as e:
                    self.logger.debug(f"Client error for {url}: {e}")
                    return None
                    
            except asyncio.TimeoutError:
                self.logger.debug(f"⏰ Timeout: {url}")
                return None
            except Exception as e:
                self.logger.debug(f"❌ Error scanning {url}: {e}")
                return None
    
    def _generate_urls(self, targets: List[str]) -> List[str]:
        """Generate all URLs to scan from targets"""
        urls = set()
        
        for target in targets:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            
            # Add base URL
            urls.add(target)
            
            # Add paths for each category
            for category, paths in self.paths.items():
                for path in paths:
                    if path.startswith('http'):
                        # Absolute URL (e.g., metadata endpoints)
                        urls.add(path)
                    else:
                        # Relative path
                        urls.add(urljoin(target, path))
        
        return list(urls)
    
    def _extract_credentials(self, result: ScanResult):
        """Extract credentials from scan result"""
        if result.status_code != 200:
            return
        
        content = result.content
        
        # Check each pattern
        for pattern_name, pattern in PATTERNS.items():
            import re
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                credential = {
                    'type': pattern_name,
                    'value': match.group(0),
                    'url': result.url,
                    'line': content[:match.start()].count('\n') + 1,
                    'context': self._get_context(content, match.start(), match.end())
                }
                
                # Extract additional information based on pattern type
                if pattern_name.startswith('aws'):
                    credential = self._enrich_aws_credential(credential, match)
                elif pattern_name in ['sendgrid', 'mailgun', 'twilio']:
                    credential = self._enrich_email_credential(credential, match)
                
                result.credentials.append(credential)
                self.stats.credentials.append(credential)
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Get context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]
    
    def _enrich_aws_credential(self, credential: Dict[str, Any], match) -> Dict[str, Any]:
        """Enrich AWS credential with additional information"""
        value = credential['value']
        
        if value.startswith('AKIA'):
            credential['aws_type'] = 'access_key'
        elif value.startswith('ASIA'):
            credential['aws_type'] = 'temporary_access_key'
        elif len(value) == 40:
            credential['aws_type'] = 'secret_key'
        
        return credential
    
    def _enrich_email_credential(self, credential: Dict[str, Any], match) -> Dict[str, Any]:
        """Enrich email service credential with additional information"""
        value = credential['value']
        
        if credential['type'] == 'sendgrid':
            credential['service'] = 'SendGrid'
        elif credential['type'] == 'mailgun':
            credential['service'] = 'Mailgun'
        elif credential['type'] == 'twilio':
            credential['service'] = 'Twilio'
        
        return credential
    
    def _calculate_final_stats(self):
        """Calculate final scan statistics"""
        if self.stats.unique_urls > 0:
            self.stats.success_rate = (self.stats.total_processed / self.stats.unique_urls) * 100
        
        # Count unique credentials
        unique_creds = set()
        for cred in self.stats.credentials:
            unique_creds.add((cred['type'], cred['value']))
        
        self.stats.credentials = list(self.stats.credentials)
        
        self.logger.info(f"Scan completed: {self.stats.total_processed} URLs processed, "
                        f"{len(self.stats.credentials)} credentials found")
    
    def get_results(self) -> List[ScanResult]:
        """Get scan results"""
        return self.results
    
    def get_stats(self) -> ScanStats:
        """Get scan statistics"""
        return self.stats