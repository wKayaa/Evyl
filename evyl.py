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
import yaml
from typing import List, Optional, Dict, Any
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

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        console.print(f"[red]Error: Configuration file not found: {config_path}[/red]")
        sys.exit(1)
    except yaml.YAMLError as e:
        console.print(f"[red]Error: Invalid YAML in configuration file: {e}[/red]")
        sys.exit(1)

class EvylFramework:
    """Main Evyl Framework orchestrator - now config-driven"""
    
    def __init__(self, args, config: Dict[str, Any]):
        self.args = args
        self.config = config
        
        # Setup logging with config
        log_config = config.get('logging', {})
        log_file = log_config.get('log_file') if log_config.get('file_logging') else None
        self.logger = Logger(verbose=args.verbose, log_file=log_file)
        
        # Initialize components with config
        scanner_config = config.get('scanner', {})
        self.network_manager = NetworkManager()
        self.scanner = Scanner(
            threads=scanner_config.get('threads', 200),
            timeout=scanner_config.get('timeout', 8),
            network_manager=self.network_manager,
            config=scanner_config
        )
        
        self.exploiter = Exploiter(self.scanner)
        
        # Only create validator if enabled in config
        validation_config = config.get('validation', {})
        self.validator = Validator() if validation_config.get('enabled', False) else None
        
        output_config = config.get('output', {})
        self.reporter = Reporter(args.output, config=output_config)
        self.progress = ProgressDisplay()
        
        # Log configuration
        self.logger.info(f"Loaded configuration from {args.config}")
        self.logger.info(f"Scanner threads: {scanner_config.get('threads', 200)}")
        self.logger.info(f"Request timeout: {scanner_config.get('timeout', 8)}s")
        self.logger.info(f"Validation: {'enabled' if self.validator else 'disabled'}")
    
    def banner(self):
        """Display the framework banner"""
        banner_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                       🔥 EVYL FRAMEWORK v2.0 🔥                             ║
║                   Advanced Cloud Exploitation Framework                      ║
║                        Optimized for VPS Deployment                         ║
║                                                                              ║
║  🎯 Target Discovery    🔍 Credential Extraction    ✅ Automatic Validation ║
║  ☁️  Cloud Platforms    🐳 Kubernetes Clusters     🌐 Web Applications      ║
║  🛡️  Evasion Techniques 📊 Real-time Progress      📈 Performance Analytics ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner_text, style="bold green"))
    
    async def run_scan(self):
        """Execute the main scanning process - optimized for large lists"""
        try:
            # Load targets
            targets = self.load_targets()
            if not targets:
                self.logger.error("No targets provided")
                return
            
            self.logger.info(f"Loaded {len(targets)} targets")
            
            # Update progress display filename if available
            if hasattr(self.progress, 'update_filename') and self.args.target_file:
                filename = os.path.basename(self.args.target_file)
                self.progress.update_filename(filename)
            
            # Start scanning without hanging progress display
            self.logger.section("Starting Scan")
            scan_results = await self.scanner.scan_targets(targets, self.progress)
            
            # Validate credentials if requested
            if self.validator and scan_results.credentials:
                self.logger.section("Validating Credentials")
                validation_results = await self.validator.validate_all(
                    scan_results.credentials, self.progress
                )
                scan_results.validation_results = validation_results
            
            # Generate reports
            self.logger.section("Generating Reports")
            await self.reporter.generate_reports(scan_results)
            
            # Final summary
            self.display_summary(scan_results)
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
    
    def load_targets(self) -> List[str]:
        """Load targets from file or command line - optimized for large files"""
        targets = set()  # Use set to automatically handle duplicates
        
        # Process input file
        if self.args.target_file:
            targets.update(self._load_targets_from_file(self.args.target_file))
        
        # Add command line targets
        if self.args.targets:
            targets.update(self.args.targets)
        
        # Convert back to list and filter empty/invalid entries
        target_list = [target.strip() for target in targets if target.strip()]
        
        self.logger.info(f"Loaded {len(target_list)} unique targets")
        return target_list
    
    def _load_targets_from_file(self, filename: str) -> List[str]:
        """Load targets from file with optimizations for large files"""
        targets = []
        input_config = self.config.get('input', {})
        chunk_size = input_config.get('chunk_size', 10000)
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Basic validation - ensure line looks like a target
                    if self._is_valid_target(line):
                        targets.append(line)
                        line_count += 1
                        
                        # Log progress for large files
                        if line_count % chunk_size == 0:
                            self.logger.debug(f"Processed {line_count} lines from {filename}")
                    
                self.logger.info(f"Processed {line_count} valid targets from {filename}")
                
        except FileNotFoundError:
            self.logger.error(f"Target file not found: {filename}")
        except Exception as e:
            self.logger.error(f"Error reading target file {filename}: {e}")
        
        return targets
    
    def _is_valid_target(self, target: str) -> bool:
        """Basic validation for target format"""
        # Check if target looks like a URL, domain, or IP
        if any(target.startswith(prefix) for prefix in ['http://', 'https://']):
            return True
        
        # Check for domain-like strings (contains dot and valid chars)
        if '.' in target and all(c.isalnum() or c in '.-_:/' for c in target):
            return True
        
        # Check for IP addresses
        parts = target.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                pass
        
        return False
    
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
    """Parse simplified command line arguments - most options now in config file"""
    parser = argparse.ArgumentParser(
        description="Evyl Framework v2.0 - Advanced Cloud Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Simplified Usage Examples:
  %(prog)s -f targets.txt
  %(prog)s -f huge_list.txt -c custom_config.yaml
  %(prog)s -t https://example.com
  %(prog)s --config vps_config.yaml -f targets.txt
        """
    )
    
    # Essential options only
    parser.add_argument('-f', '--file', dest='target_file', 
                       help='File containing target URLs/domains/IPs (one per line)')
    parser.add_argument('-t', '--target', dest='targets', action='append',
                       help='Single target URL/domain/IP (can be used multiple times)')
    parser.add_argument('-c', '--config', default='config/settings.yaml',
                       help='Configuration file (default: config/settings.yaml)')
    parser.add_argument('-o', '--output', default='results',
                       help='Output directory (default: results)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--version', action='version', version='Evyl Framework v2.0')
    
    return parser.parse_args()

def main():
    """Main entry point - simplified and config-driven"""
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Validate arguments
    if not args.target_file and not args.targets:
        console.print("[red]Error: No targets specified. Use -f or -t option.[/red]")
        sys.exit(1)
    
    # Create output directory
    Path(args.output).mkdir(parents=True, exist_ok=True)
    
    # Initialize framework with config
    framework = EvylFramework(args, config)
    
    # Display banner
    framework.banner()
    
    # Log configuration summary
    framework.logger.section("Configuration Summary")
    scanner_config = config.get('scanner', {})
    framework.logger.info(f"Threads: {scanner_config.get('threads', 200)}")
    framework.logger.info(f"Timeout: {scanner_config.get('timeout', 8)}s")
    framework.logger.info(f"Batch size: {scanner_config.get('batch_size', 1000)}")
    framework.logger.info(f"Memory efficient: {scanner_config.get('memory_efficient', True)}")
    
    # Run the scan
    try:
        asyncio.run(framework.run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        framework.logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()