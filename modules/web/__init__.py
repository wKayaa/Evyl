# Web module initialization
"""
Web Application Exploitation Module

Provides web application security testing capabilities:
- Git repository exposure scanning
- JavaScript analysis and secret extraction
- Configuration file discovery
- Laravel framework exploitation
- SMTP security testing
"""

from .git_dumper import GitDumper
from .js_crawler import JSCrawler
from .config_scanner import ConfigScanner
from .laravel_scan import LaravelScanner
from .smtp_scanner import SMTPSecurityScanner

__all__ = ["GitDumper", "JSCrawler", "ConfigScanner", "LaravelScanner", "SMTPSecurityScanner"]