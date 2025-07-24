"""
Optimized Real-time Progress Display for Evyl Framework v3.0

Creates a high-performance live display with:
- Reduced refresh overhead
- Configurable language support
- Optimized memory usage
- Smoother progress tracking
- Enhanced system monitoring
"""

import time
import psutil
from datetime import datetime
from typing import Dict, Any
from dataclasses import dataclass

from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.console import Console

@dataclass
class ScanMetrics:
    """Holds scan metrics for display"""
    filename: str = ""
    start_time: float = 0
    urls_processed: int = 0
    urls_unique: int = 0
    urls_validated: int = 0
    total_hits: int = 0
    hits_by_service: Dict[str, int] = None
    
    def __post_init__(self):
        if self.hits_by_service is None:
            self.hits_by_service = {
                'aws': 0,
                'sendgrid': 0,
                'brevo': 0,
                'smtp': 0,
                'postmark': 0,
                'sparkpost': 0,
                'mailgun': 0,
                'twilio': 0
            }

class ProgressDisplay:
    """Optimized real-time progress display with improved performance"""
    
    def __init__(self, language='en'):
        self.console = Console()
        self.language = language  # 'en' for English, 'fr' for French
        self.metrics = ScanMetrics()
        self.start_time = time.time()
        self.metrics.start_time = self.start_time
        
        # Performance optimization: reduce update frequency
        self.last_update = 0
        self.update_interval = 0.5  # Update every 500ms instead of 250ms
        
        # Language configuration
        self.text_config = self._get_text_config()
        
        # Progress tracking with optimization
        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),  # Auto-width for performance
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            expand=True
        )
        
        # System monitoring with caching
        self.process = psutil.Process()
        self.network_stats = {'requests': 0, 'bytes_sent': 0, 'bytes_received': 0}
        self.cached_stats = None
        self.stats_cache_time = 0
    
    def _get_text_config(self):
        """Get language-specific text configuration"""
        if self.language == 'fr':
            return {
                'header': '🔍 EVYL CHECKER V3.0 - SCAN EN COURS 🔍',
                'file': 'Fichier',
                'elapsed': 'Temps écoulé',
                'progress': 'Progression',
                'stats_total': 'STATS TOTAL',
                'urls_processed': 'URLs traitées',
                'urls_unique': 'URLs uniques',
                'urls_validated': 'URLs validées',
                'success_rate': 'Taux de réussite',
                'hits_found': 'HITS TROUVÉS',
                'total': 'TOTAL',
                'proxies_used': 'Proxies utilisés'
            }
        else:
            return {
                'header': '🔍 EVYL SCANNER V3.0 - SCAN IN PROGRESS 🔍',
                'file': 'File',
                'elapsed': 'Elapsed time',
                'progress': 'Progress',
                'stats_total': 'TOTAL STATS',
                'urls_processed': 'URLs processed',
                'urls_unique': 'Unique URLs',
                'urls_validated': 'URLs validated',
                'success_rate': 'Success rate',
                'hits_found': 'HITS FOUND',
                'total': 'TOTAL',
                'proxies_used': 'Proxies used'
            }
    
    def create_layout(self) -> Layout:
        """Create optimized layout for live display"""
        # Check if we should update (performance optimization)
        current_time = time.time()
        if current_time - self.last_update < self.update_interval and self.cached_stats:
            return self.cached_layout if hasattr(self, 'cached_layout') else self._build_layout()
        
        self.last_update = current_time
        layout = self._build_layout()
        self.cached_layout = layout
        return layout
    
    def _build_layout(self) -> Layout:
        """Build the actual layout"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=6)  # Reduced from 8 for better performance
        )
        
        layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="stats", ratio=1)
        )
        
        # Update each section
        layout["header"].update(self._create_header())
        layout["progress"].update(self._create_progress_panel())
        layout["stats"].update(self._create_stats_panel())
        layout["footer"].update(self._create_hits_panel())
        
        return layout
    
    def _create_header(self) -> Panel:
        """Create the optimized header panel"""
        header_text = Text()
        header_text.append(self.text_config['header'], style="bold green")
        
        return Panel(
            header_text,
            style="bold green",
            padding=(0, 1)
        )
    
    def _create_progress_panel(self) -> Panel:
        """Create the optimized progress panel"""
        elapsed_time = self._format_elapsed_time()
        progress_percentage = self._calculate_progress()
        progress_bar = self._create_progress_bar(progress_percentage)
        
        content = f"""{self.text_config['file']}: {self.metrics.filename}
⏱️ {self.text_config['elapsed']}: {elapsed_time}
📊 {self.text_config['progress']}: [{progress_bar}] {progress_percentage:.1f}%"""
        
        return Panel(
            content,
            title="Progress",
            border_style="blue"
        )
    
    def _create_stats_panel(self) -> Panel:
        """Create the optimized statistics panel"""
        success_rate = self._calculate_success_rate()
        
        content = f"""📈 {self.text_config['stats_total']}:
🌐 {self.text_config['urls_processed']}: {self.metrics.urls_processed:,}
🎯 {self.text_config['urls_unique']}: {self.metrics.urls_unique:,}
✅ {self.text_config['urls_validated']}: {self.metrics.urls_validated:,}
📉 {self.text_config['success_rate']}: {success_rate:.1f}%"""
        
        return Panel(
            content,
            title="Statistics",
            border_style="yellow"
        )
    
    def _create_hits_panel(self) -> Panel:
        """Create the optimized hits panel"""
        system_stats = self._get_system_stats()
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Organize hits in a more compact way
        hits_line1 = f"✅ AWS: {self.metrics.hits_by_service['aws']}  ✅ SendGrid: {self.metrics.hits_by_service['sendgrid']}  ✅ Brevo: {self.metrics.hits_by_service['brevo']}  ✅ SMTP: {self.metrics.hits_by_service['smtp']}"
        hits_line2 = f"✅ Postmark: {self.metrics.hits_by_service['postmark']}  ✅ SparkPost: {self.metrics.hits_by_service['sparkpost']}  ✅ Mailgun: {self.metrics.hits_by_service['mailgun']}  ✅ Twilio: {self.metrics.hits_by_service['twilio']}"
        
        content = f"""🏆 {self.text_config['hits_found']} ({self.text_config['total']}: {self.metrics.total_hits}):
{hits_line1}
{hits_line2}

💻 CPU: {system_stats['cpu']}% | 🧠 RAM: {system_stats['ram']} MB | 📡 HTTP: {system_stats['network']} | ⏰ {current_time}"""
        
        return Panel(
            content,
            title="Results & System Info",
            border_style="green"
        )
    
    def _format_elapsed_time(self) -> str:
        """Format elapsed time as 73s 33m 21s"""
        elapsed = int(time.time() - self.start_time)
        
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def _calculate_progress(self) -> float:
        """Calculate progress percentage"""
        if self.metrics.urls_unique == 0:
            return 0.0
        return (self.metrics.urls_processed / self.metrics.urls_unique) * 100
    
    def _create_progress_bar(self, percentage: float, width: int = 25) -> str:
        """Create an optimized text-based progress bar (reduced width for performance)"""
        filled = int((percentage / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        return bar
    
    def _calculate_success_rate(self) -> float:
        """Calculate success rate"""
        if self.metrics.urls_processed == 0:
            return 0.0
        return (self.metrics.urls_validated / self.metrics.urls_processed) * 100
    
    def _get_system_stats(self) -> Dict[str, Any]:
        """Get cached system statistics for better performance"""
        current_time = time.time()
        
        # Use cached stats if recent enough (1 second cache)
        if self.cached_stats and (current_time - self.stats_cache_time) < 1.0:
            return self.cached_stats
        
        try:
            cpu_percent = psutil.cpu_percent(interval=None)  # Use None for non-blocking
            memory_info = self.process.memory_info()
            ram_mb = memory_info.rss / 1024 / 1024
            
            # Network stats (simplified for performance)
            network_info = f"{self.network_stats['requests']}/s"
            
            stats = {
                'cpu': f"{cpu_percent:.1f}",
                'ram': f"{ram_mb:.1f}",
                'network': network_info,
                'proxy_count': 0  # Will be updated by network manager
            }
            
            # Cache the stats
            self.cached_stats = stats
            self.stats_cache_time = current_time
            return stats
            
        except Exception:
            return {
                'cpu': "N/A",
                'ram': "N/A", 
                'network': "N/A",
                'proxy_count': 0
            }
    
    def update_stats(self, scan_stats):
        """Update metrics from scan statistics with throttling"""
        current_time = time.time()
        
        # Throttle updates for very high-frequency scans
        if hasattr(self, 'last_stats_update') and (current_time - self.last_stats_update) < 0.1:
            return  # Skip update if too frequent
        
        self.last_stats_update = current_time
        
        self.metrics.urls_processed = scan_stats.total_processed
        self.metrics.urls_unique = scan_stats.unique_urls
        self.metrics.urls_validated = scan_stats.valid_credentials
        
        # Update hits by service
        self.metrics.total_hits = len(scan_stats.credentials)
        
        # Reset service counts
        for service in self.metrics.hits_by_service:
            self.metrics.hits_by_service[service] = 0
        
        # Count hits by service (optimized)
        for cred in scan_stats.credentials:
            cred_type = cred.get('type', '').lower()
            service = cred.get('service', '').lower()
            
            # Faster string matching
            if 'aws' in cred_type:
                self.metrics.hits_by_service['aws'] += 1
            elif 'sendgrid' in cred_type or 'sendgrid' in service:
                self.metrics.hits_by_service['sendgrid'] += 1
            elif 'brevo' in cred_type or 'brevo' in service:
                self.metrics.hits_by_service['brevo'] += 1
            elif 'smtp' in cred_type or 'smtp' in service:
                self.metrics.hits_by_service['smtp'] += 1
            elif 'postmark' in cred_type or 'postmark' in service:
                self.metrics.hits_by_service['postmark'] += 1
            elif 'sparkpost' in cred_type or 'sparkpost' in service:
                self.metrics.hits_by_service['sparkpost'] += 1
            elif 'mailgun' in cred_type or 'mailgun' in service:
                self.metrics.hits_by_service['mailgun'] += 1
            elif 'twilio' in cred_type or 'twilio' in service:
                self.metrics.hits_by_service['twilio'] += 1
    
    def update_filename(self, filename: str):
        """Update the current filename being processed"""
        self.metrics.filename = filename
    
    def update_network_stats(self, requests: int, bytes_sent: int = 0, bytes_received: int = 0):
        """Update network statistics"""
        self.network_stats['requests'] = requests
        self.network_stats['bytes_sent'] = bytes_sent
        self.network_stats['bytes_received'] = bytes_received