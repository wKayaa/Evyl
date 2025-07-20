"""
Real-time Progress Display for Evyl Framework

Creates a live display matching the specified format with:
- Elapsed time tracking
- Progress bars with percentages
- Live statistics
- Hit counters per service
- CPU/RAM/Network monitoring
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
    """Real-time progress display with live updates"""
    
    def __init__(self):
        self.console = Console()
        self.metrics = ScanMetrics()
        self.start_time = time.time()
        self.metrics.start_time = self.start_time
        
        # Progress tracking
        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        
        # System monitoring
        self.process = psutil.Process()
        self.network_stats = {'requests': 0, 'bytes_sent': 0, 'bytes_received': 0}
    
    def create_layout(self) -> Layout:
        """Create the main layout for live display"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=8)
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
        """Create the header panel"""
        header_text = Text()
        header_text.append("🔍 EVYL CHECKER V2.0 - SCAN EN COURS 🔍", style="bold green")
        
        return Panel(
            header_text,
            style="bold green",
            padding=(0, 1)
        )
    
    def _create_progress_panel(self) -> Panel:
        """Create the progress panel"""
        elapsed_time = self._format_elapsed_time()
        progress_percentage = self._calculate_progress()
        progress_bar = self._create_progress_bar(progress_percentage)
        
        content = f"""📁 Fichier: {self.metrics.filename}
⏱️ Temps écoulé: {elapsed_time}
📊 Progression: [{progress_bar}] {progress_percentage:.1f}%"""
        
        return Panel(
            content,
            title="Progress",
            border_style="blue"
        )
    
    def _create_stats_panel(self) -> Panel:
        """Create the statistics panel"""
        success_rate = self._calculate_success_rate()
        
        content = f"""📈 STATS TOTAL:
🌐 URLs traitées: {self.metrics.urls_processed:,}
🎯 URLs uniques: {self.metrics.urls_unique:,}
✅ URLs validées: {self.metrics.urls_validated:,}
📉 Taux de réussite: {success_rate:.1f}%"""
        
        return Panel(
            content,
            title="Statistics",
            border_style="yellow"
        )
    
    def _create_hits_panel(self) -> Panel:
        """Create the hits panel"""
        system_stats = self._get_system_stats()
        current_time = datetime.now().strftime("%H:%M:%S")
        
        content = f"""🏆 HITS TROUVÉS (TOTAL: {self.metrics.total_hits}):
✅ AWS: {self.metrics.hits_by_service['aws']}
✅ SendGrid: {self.metrics.hits_by_service['sendgrid']}
✅ Brevo: {self.metrics.hits_by_service['brevo']}
✅ SMTP: {self.metrics.hits_by_service['smtp']}
✅ Postmark: {self.metrics.hits_by_service['postmark']}
✅ SparkPost: {self.metrics.hits_by_service['sparkpost']}
✅ Mailgun: {self.metrics.hits_by_service['mailgun']}
✅ Twilio: {self.metrics.hits_by_service['twilio']}

💻 CPU: {system_stats['cpu']}% | 🧠 RAM: {system_stats['ram']} MB | 📡 HTTP: {system_stats['network']}
🔄 Proxies utilisés: {system_stats['proxy_count']}
⏰ {current_time}"""
        
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
    
    def _create_progress_bar(self, percentage: float, width: int = 30) -> str:
        """Create a text-based progress bar"""
        filled = int((percentage / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        return bar
    
    def _calculate_success_rate(self) -> float:
        """Calculate success rate"""
        if self.metrics.urls_processed == 0:
            return 0.0
        return (self.metrics.urls_validated / self.metrics.urls_processed) * 100
    
    def _get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_info = self.process.memory_info()
            ram_mb = memory_info.rss / 1024 / 1024
            
            # Network stats (simplified)
            network_info = f"{self.network_stats['requests']} req"
            
            return {
                'cpu': f"{cpu_percent:.1f}",
                'ram': f"{ram_mb:.1f}",
                'network': network_info,
                'proxy_count': 0  # Will be updated by network manager
            }
        except Exception:
            return {
                'cpu': "N/A",
                'ram': "N/A", 
                'network': "N/A",
                'proxy_count': 0
            }
    
    def update_stats(self, scan_stats):
        """Update metrics from scan statistics"""
        self.metrics.urls_processed = scan_stats.total_processed
        self.metrics.urls_unique = scan_stats.unique_urls
        self.metrics.urls_validated = scan_stats.valid_credentials
        
        # Update hits by service
        self.metrics.total_hits = len(scan_stats.credentials)
        
        # Reset service counts
        for service in self.metrics.hits_by_service:
            self.metrics.hits_by_service[service] = 0
        
        # Count hits by service
        for cred in scan_stats.credentials:
            cred_type = cred.get('type', '').lower()
            service = cred.get('service', '').lower()
            
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