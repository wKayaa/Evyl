"""
Colored Logger with Progress Support for Evyl Framework

Provides comprehensive logging capabilities with:
- Colored output based on log levels
- Progress integration
- File and console output
- Performance tracking
"""

import logging
import sys
from datetime import datetime
from typing import Optional
from pathlib import Path

from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Create colored message
        message = f"{Fore.BLUE}[{timestamp}]{Style.RESET_ALL} "
        message += f"{log_color}[{record.levelname}]{Style.RESET_ALL} "
        message += f"{record.getMessage()}"
        
        return message

class Logger:
    """Advanced logger with color support and file output"""
    
    def __init__(self, name: str = "evyl", verbose: bool = False, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.verbose = verbose
        
        # Set log level
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            self._setup_file_handler(log_file)
        
        # Prevent propagation to root logger
        self.logger.propagate = False
    
    def _setup_file_handler(self, log_file: str):
        """Setup file handler for logging"""
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            self.warning(f"Failed to setup file logging: {e}")
    
    def debug(self, message: str):
        """Log debug message"""
        if self.verbose:
            self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)
    
    def success(self, message: str):
        """Log success message (custom level)"""
        # Use info level with green color
        success_msg = f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}"
        self.logger.info(success_msg)
    
    def failure(self, message: str):
        """Log failure message (custom level)"""
        # Use error level with red color
        failure_msg = f"{Fore.RED}❌ {message}{Style.RESET_ALL}"
        self.logger.error(failure_msg)
    
    def credential_found(self, cred_type: str, url: str):
        """Log credential discovery"""
        msg = f"{Fore.YELLOW}🔑 {cred_type.upper()} credential found at {url}{Style.RESET_ALL}"
        self.logger.info(msg)
    
    def validation_result(self, cred_type: str, status: str):
        """Log credential validation result"""
        if status.lower() == 'valid':
            icon = "✅"
            color = Fore.GREEN
        else:
            icon = "❌"
            color = Fore.RED
        
        msg = f"{color}{icon} {cred_type.upper()} validation: {status}{Style.RESET_ALL}"
        self.logger.info(msg)
    
    def scan_progress(self, processed: int, total: int, hits: int):
        """Log scan progress"""
        percentage = (processed / total * 100) if total > 0 else 0
        msg = f"{Fore.CYAN}📊 Progress: {processed}/{total} ({percentage:.1f}%) - Hits: {hits}{Style.RESET_ALL}"
        self.logger.info(msg)
    
    def performance_stats(self, urls_per_second: float, memory_mb: float, cpu_percent: float):
        """Log performance statistics"""
        msg = (f"{Fore.MAGENTA}⚡ Performance: {urls_per_second:.1f} URLs/s, "
               f"RAM: {memory_mb:.1f} MB, CPU: {cpu_percent:.1f}%{Style.RESET_ALL}")
        self.logger.info(msg)
    
    def banner(self, text: str):
        """Log a banner message"""
        border = "=" * len(text)
        banner_msg = f"\n{Fore.CYAN}{border}\n{text}\n{border}{Style.RESET_ALL}\n"
        self.logger.info(banner_msg)
    
    def section(self, title: str):
        """Log a section header"""
        section_msg = f"\n{Fore.YELLOW}📋 {title}{Style.RESET_ALL}"
        self.logger.info(section_msg)
    
    def target_info(self, target: str, paths_count: int):
        """Log target information"""
        msg = f"{Fore.BLUE}🎯 Target: {target} ({paths_count} paths){Style.RESET_ALL}"
        self.logger.info(msg)
    
    def module_status(self, module: str, status: str):
        """Log module status"""
        if status.lower() == 'enabled':
            icon = "🟢"
            color = Fore.GREEN
        else:
            icon = "🔴"
            color = Fore.RED
        
        msg = f"{color}{icon} Module {module}: {status}{Style.RESET_ALL}"
        self.logger.info(msg)
    
    def network_info(self, proxy: Optional[str], user_agent: str):
        """Log network configuration"""
        proxy_info = proxy if proxy else "Direct connection"
        msg = f"{Fore.CYAN}🌐 Network: {proxy_info}, UA: {user_agent[:50]}...{Style.RESET_ALL}"
        self.logger.debug(msg)
    
    def exploitation_attempt(self, exploit_type: str, target: str):
        """Log exploitation attempt"""
        msg = f"{Fore.MAGENTA}🎯 Attempting {exploit_type} on {target}{Style.RESET_ALL}"
        self.logger.debug(msg)
    
    def vulnerability_found(self, vuln_type: str, target: str, severity: str = "medium"):
        """Log vulnerability discovery"""
        severity_colors = {
            'low': Fore.YELLOW,
            'medium': Fore.YELLOW,
            'high': Fore.RED,
            'critical': Fore.RED + Back.WHITE + Style.BRIGHT
        }
        
        color = severity_colors.get(severity.lower(), Fore.YELLOW)
        msg = f"{color}🚨 {vuln_type.upper()} vulnerability found on {target} [{severity.upper()}]{Style.RESET_ALL}"
        self.logger.warning(msg)
    
    def set_verbose(self, verbose: bool):
        """Change verbose mode"""
        self.verbose = verbose
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
    
    def add_file_handler(self, log_file: str):
        """Add file handler for logging"""
        self._setup_file_handler(log_file)