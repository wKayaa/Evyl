"""
Network Manager for Evyl Framework

Provides advanced HTTP client capabilities with:
- Connection pooling
- Proxy rotation
- User-agent rotation (500+ agents)
- Request timing randomization
- CloudFlare bypass
- Rate limiting
"""

import random
import time
import requests
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin
from pathlib import Path
import json

from utils.logger import Logger

class NetworkManager:
    """Advanced network manager with evasion capabilities"""
    
    def __init__(self):
        self.logger = Logger()
        self.session = requests.Session()
        
        # Load configurations
        self.user_agents = self._load_user_agents()
        self.proxies = self._load_proxies()
        
        # State tracking
        self.current_proxy_index = 0
        self.current_ua_index = 0
        self.request_count = 0
        self.last_request_time = 0
        
        # Configure session
        self._configure_session()
    
    def _load_user_agents(self) -> List[str]:
        """Load user agents from file or use built-in list"""
        try:
            with open('config/user_agents.txt', 'r') as f:
                agents = [line.strip() for line in f if line.strip()]
                if agents:
                    return agents
        except FileNotFoundError:
            pass
        
        # Built-in user agents (subset of 500+)
        return [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            
            # Chrome macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            
            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            
            # Firefox macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            
            # Mobile Chrome
            "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            
            # Linux browsers
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Curl-like agents for API testing
            "curl/7.68.0",
            "wget/1.20.3",
            "HTTPie/3.2.0",
            
            # Bot-like agents
            "python-requests/2.31.0",
            "Go-http-client/1.1",
            "Java/17.0.2",
            
            # Security tools
            "Nikto/2.5.0",
            "sqlmap/1.7.2",
            "Nmap Scripting Engine",
            
            # More diverse agents
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
        ]
    
    def _load_proxies(self) -> List[str]:
        """Load proxies from file"""
        try:
            with open('config/proxies.txt', 'r') as f:
                proxies = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Support different proxy formats
                        if '://' not in line:
                            line = f"http://{line}"
                        proxies.append(line)
                return proxies
        except FileNotFoundError:
            self.logger.debug("No proxy file found, using direct connection")
            return []
    
    def _configure_session(self):
        """Configure the requests session"""
        # Set connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=3
        )
        
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
        
        # Set default timeout
        self.session.timeout = 10
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers with rotated user agent"""
        user_agent = self.get_user_agent()
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Randomly add additional headers for evasion
        if random.random() < 0.3:
            headers['DNT'] = '1'
        
        if random.random() < 0.2:
            headers['Cache-Control'] = 'no-cache'
        
        if random.random() < 0.1:
            headers['X-Forwarded-For'] = self._generate_fake_ip()
        
        return headers
    
    def get_user_agent(self) -> str:
        """Get a user agent with rotation"""
        if not self.user_agents:
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # Rotate user agent
        user_agent = self.user_agents[self.current_ua_index]
        self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
        
        return user_agent
    
    def get_proxy(self) -> Optional[str]:
        """Get a proxy with rotation"""
        if not self.proxies:
            return None
        
        # Rotate proxy
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        
        return proxy
    
    def _generate_fake_ip(self) -> str:
        """Generate a fake IP address for X-Forwarded-For header"""
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make an HTTP request with evasion techniques"""
        # Rate limiting
        self._apply_rate_limiting()
        
        # Get headers and proxy
        headers = kwargs.pop('headers', {})
        headers.update(self.get_headers())
        
        proxy = self.get_proxy()
        proxies = {'http': proxy, 'https': proxy} if proxy else None
        
        # Disable SSL verification
        kwargs['verify'] = False
        
        # Make request
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                proxies=proxies,
                **kwargs
            )
            
            self.request_count += 1
            self.logger.debug(f"Request to {url}: {response.status_code}")
            
            return response
            
        except requests.exceptions.ProxyError:
            # Try without proxy on proxy error
            self.logger.warning(f"Proxy error, retrying without proxy for {url}")
            return self.session.request(
                method=method,
                url=url,
                headers=headers,
                **kwargs
            )
    
    def _apply_rate_limiting(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # Add random delay between 0.1-0.5 seconds
        min_delay = 0.1
        max_delay = 0.5
        
        if time_since_last < min_delay:
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)
        
        self.last_request_time = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        return {
            'total_requests': self.request_count,
            'proxy_count': len(self.proxies),
            'user_agent_count': len(self.user_agents),
            'current_proxy': self.proxies[self.current_proxy_index] if self.proxies else None,
            'current_ua': self.user_agents[self.current_ua_index] if self.user_agents else None
        }
    
    def test_proxies(self) -> List[str]:
        """Test all proxies and return working ones"""
        working_proxies = []
        test_url = "http://httpbin.org/ip"
        
        for proxy in self.proxies:
            try:
                response = requests.get(
                    test_url,
                    proxies={'http': proxy, 'https': proxy},
                    timeout=5
                )
                if response.status_code == 200:
                    working_proxies.append(proxy)
                    self.logger.info(f"Proxy working: {proxy}")
                else:
                    self.logger.warning(f"Proxy failed: {proxy}")
            except Exception as e:
                self.logger.warning(f"Proxy error {proxy}: {e}")
        
        self.proxies = working_proxies
        return working_proxies
    
    def add_custom_headers(self, headers: Dict[str, str]):
        """Add custom headers to all requests"""
        self.session.headers.update(headers)
    
    def set_timeout(self, timeout: int):
        """Set request timeout"""
        self.session.timeout = timeout
    
    def close(self):
        """Close the session"""
        self.session.close()