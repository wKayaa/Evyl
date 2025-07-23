#!/usr/bin/env python3
"""
Evyl Framework v2.0 - Advanced Cloud Exploitation Framework
Author: Evyl Team
License: MIT

A modular exploitation framework for authorized security testing that:
- Scans and exploits cloud infrastructure (AWS, GCP, Azure, Kubernetes)
- Extracts credentials from 1500+ vulnerable endpoints
- Validates all discovered secrets automatically
- Provides real-time progress monitoring
- Operates with advanced evasion techniques
"""

import argparse
import asyncio
import sys
import os
import time
from typing import List, Optional
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.table import Table

from core.scanner import Scanner
from core.exploiter import Exploiter
from core.validator import Validator
from core.reporter import Reporter
from utils.logger import Logger
from utils.progress import ProgressDisplay
from utils.network import NetworkManager

console = Console()

class EvylFramework:
    """Main Evyl Framework orchestrator"""
    
    def __init__(self, args):
        self.args = args
        self.logger = Logger(verbose=args.verbose)
        self.network_manager = NetworkManager()
        
        # Handle unlimited values
        threads = self._parse_unlimited_value(args.threads, default_unlimited=1000)
        timeout = self._parse_unlimited_value(args.timeout, default_unlimited=None)
        
        self.scanner = Scanner(
            threads=threads,
            timeout=timeout,
            network_manager=self.network_manager
        )
        self.exploiter = Exploiter(self.scanner)
        self.validator = Validator() if args.validate else None
        self.reporter = Reporter(args.output_dir)
        self.progress = ProgressDisplay()
        
    def _parse_unlimited_value(self, value, default_unlimited=None):
        """Parse unlimited values from arguments"""
        if isinstance(value, str) and value.lower() in ['unlimited', 'inf', 'infinite']:
            return default_unlimited
        elif isinstance(value, str) and value.isdigit():
            return int(value)
        elif isinstance(value, int):
            return value
        else:
            return default_unlimited
        
    def banner(self):
        """Display the framework banner"""
        banner_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                       🔥 EVYL FRAMEWORK v2.0 🔥                             ║
║                   Advanced Cloud Exploitation Framework                      ║
║                                                                              ║
║  🎯 Target Discovery    🔍 Credential Extraction    ✅ Automatic Validation ║
║  ☁️  Cloud Platforms    🐳 Kubernetes Clusters     🌐 Web Applications      ║
║  🛡️  Evasion Techniques 📊 Real-time Progress      📈 Performance Analytics ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner_text, style="bold green"))
    
    async def run_scan(self):
        """Execute the main scanning process"""
        try:
            # Load targets
            targets = self.load_targets()
            if not targets:
                self.logger.error("No targets provided")
                return
            
            self.logger.info(f"Loaded {len(targets)} targets")
            
            # Initialize progress display
            with Live(self.progress.create_layout(), refresh_per_second=4, console=console):
                # Start scanning
                scan_results = await self.scanner.scan_targets(targets, self.progress)
                
                # Validate credentials if requested
                if self.validator and scan_results.credentials:
                    self.logger.info("Starting credential validation...")
                    validation_results = await self.validator.validate_all(
                        scan_results.credentials, self.progress
                    )
                    scan_results.validation_results = validation_results
                
                # Generate reports
                self.logger.info("Generating reports...")
                await self.reporter.generate_reports(scan_results)
                
                # Final summary
                self.display_summary(scan_results)
                
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
    
    def load_targets(self) -> List[str]:
        """Load targets from file or command line"""
        targets = []
        
        if self.args.target_file:
            try:
                with open(self.args.target_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                self.logger.error(f"Target file not found: {self.args.target_file}")
        
        if self.args.targets:
            targets.extend(self.args.targets)
        
        return list(set(targets))  # Remove duplicates
    
    def display_summary(self, results):
        """Display final scan summary"""
        table = Table(title="🎯 Scan Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total URLs Processed", str(results.total_processed))
        table.add_row("Unique URLs", str(results.unique_urls))
        table.add_row("Credentials Found", str(len(results.credentials)))
        table.add_row("Valid Credentials", str(results.valid_credentials))
        table.add_row("Success Rate", f"{results.success_rate:.2f}%")
        
        console.print(table)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Evyl Framework v2.0 - Advanced Cloud Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f targets.txt -o results/
  %(prog)s -t https://example.com -t https://test.com
  %(prog)s -f domains.txt --threads unlimited --timeout unlimited
  %(prog)s -f targets.txt --all-modules --validate --crack-aws --crack-api --crack-smtp
  %(prog)s -t example.com --path-scanner --js-scanner --git-scanner
        """
    )
    
    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-f', '--file', dest='target_file', 
                             help='File containing target URLs/domains')
    target_group.add_argument('-t', '--target', dest='targets', action='append',
                             help='Single target URL/domain (can be used multiple times)')
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('--threads', default='unlimited',
                           help='Number of threads (default: unlimited, use integer for specific limit)')
    scan_group.add_argument('--timeout', default='unlimited',
                           help='Request timeout in seconds (default: unlimited, use integer for specific limit)')
    scan_group.add_argument('--retries', type=int, default=3,
                           help='Number of retries per request (default: 3)')
    scan_group.add_argument('--delay', type=float, default=0,
                           help='Delay between requests in seconds (default: 0)')
    
    # Module options
    module_group = parser.add_argument_group('Module Options')
    module_group.add_argument('--kubernetes', action='store_true', default=True,
                             help='Enable Kubernetes scanning (default: enabled)')
    module_group.add_argument('--aws', action='store_true', default=True,
                             help='Enable AWS scanning (default: enabled)')
    module_group.add_argument('--gcp', action='store_true', default=True,
                             help='Enable GCP scanning (default: enabled)')
    module_group.add_argument('--azure', action='store_true', default=True,
                             help='Enable Azure scanning (default: enabled)')
    module_group.add_argument('--web', action='store_true', default=True,
                             help='Enable web application scanning (default: enabled)')
    module_group.add_argument('--all-modules', action='store_true', default=True,
                             help='Enable all scanning modules (default: enabled)')
    module_group.add_argument('--path-scanner', action='store_true', default=True,
                             help='Enable path scanning (default: enabled)')
    module_group.add_argument('--js-scanner', action='store_true', default=True,
                             help='Enable JavaScript analysis (default: enabled)')
    module_group.add_argument('--git-scanner', action='store_true', default=True,
                             help='Enable Git repository scanning (default: enabled)')
    
    # Validation options
    validation_group = parser.add_argument_group('Validation Options')
    validation_group.add_argument('--validate', action='store_true', default=True,
                                 help='Validate found credentials (default: enabled)')
    validation_group.add_argument('--validation-timeout', type=int, default=30,
                                 help='Validation timeout in seconds (default: 30)')
    validation_group.add_argument('--crack-aws', action='store_true', default=True,
                                 help='Enable AWS credential cracking (default: enabled)')
    validation_group.add_argument('--crack-api', action='store_true', default=True,
                                 help='Enable API credential cracking (default: enabled)')
    validation_group.add_argument('--crack-smtp', action='store_true', default=True,
                                 help='Enable SMTP credential cracking (default: enabled)')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output-dir', default='results',
                             help='Output directory (default: results)')
    output_group.add_argument('--format', choices=['json', 'html', 'txt', 'all'],
                             default='json', help='Output format (default: json)')
    output_group.add_argument('--encrypt', action='store_true',
                             help='Encrypt output files')
    
    # Network options
    network_group = parser.add_argument_group('Network Options')
    network_group.add_argument('--proxy', help='HTTP proxy (http://host:port)')
    network_group.add_argument('--proxy-file', help='File containing proxy list')
    network_group.add_argument('--user-agent', help='Custom User-Agent string')
    network_group.add_argument('--headers', help='Custom headers (JSON format)')
    
    # Miscellaneous
    misc_group = parser.add_argument_group('Miscellaneous')
    misc_group.add_argument('-v', '--verbose', action='store_true',
                           help='Enable verbose output')
    misc_group.add_argument('--resume', help='Resume from previous scan state')
    misc_group.add_argument('--config', help='Configuration file')
    misc_group.add_argument('--version', action='version', version='Evyl Framework v2.0')
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Validate arguments
    if not args.target_file and not args.targets:
        console.print("[red]Error: No targets specified. Use -f or -t option.[/red]")
        sys.exit(1)
    
    # Create output directory
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize framework
    framework = EvylFramework(args)
    
    # Display banner
    framework.banner()
    
    # Run the scan
    try:
        asyncio.run(framework.run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()