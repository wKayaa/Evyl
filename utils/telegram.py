"""
Telegram Notification System for Evyl Framework

Provides real-time notifications via Telegram Bot API:
- Scan start/completion notifications
- Hit alerts with details
- Progress updates
- Error notifications
"""

import asyncio
import aiohttp
import json
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from utils.logger import Logger


class TelegramNotifier:
    """Telegram notification manager"""
    
    def __init__(self, bot_token: str = None, chat_id: str = None):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.logger = Logger()
        self.enabled = bool(bot_token and chat_id)
        
        if not self.enabled:
            self.logger.warning("Telegram notifications disabled - missing bot token or chat ID")
        else:
            self.logger.info("Telegram notifications enabled")
    
    async def send_message(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send a message to Telegram"""
        if not self.enabled:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            
            data = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        self.logger.debug("Telegram message sent successfully")
                        return True
                    else:
                        result = await response.text()
                        self.logger.error(f"Failed to send Telegram message: {response.status} - {result}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending Telegram message: {e}")
            return False
    
    async def notify_scan_start(self, target_file: str, target_count: int, threads: int) -> bool:
        """Notify about scan start"""
        message = f"""🔥 <b>EVYL SCAN STARTED</b> 🔥

📁 <b>Target File:</b> {target_file}
🎯 <b>Targets:</b> {target_count:,}
🧵 <b>Threads:</b> {threads}
⏰ <b>Started:</b> {datetime.now().strftime('%H:%M:%S')}

🔍 Scanning in progress..."""

        return await self.send_message(message)
    
    async def notify_scan_complete(self, stats: Dict[str, Any]) -> bool:
        """Notify about scan completion"""
        duration = stats.get('duration', 0)
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        
        if hours > 0:
            duration_str = f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            duration_str = f"{minutes}m {seconds}s"
        else:
            duration_str = f"{seconds}s"
        
        message = f"""✅ <b>EVYL SCAN COMPLETED</b> ✅

📊 <b>Results:</b>
• URLs Processed: {stats.get('total_processed', 0):,}
• Unique URLs: {stats.get('unique_urls', 0):,}
• Credentials Found: {stats.get('credentials_found', 0)}
• Success Rate: {stats.get('success_rate', 0):.1f}%

⏱️ <b>Duration:</b> {duration_str}
⏰ <b>Completed:</b> {datetime.now().strftime('%H:%M:%S')}"""

        return await self.send_message(message)
    
    async def notify_hit_found(self, credential: Dict[str, Any]) -> bool:
        """Notify about a new hit/credential found"""
        cred_type = credential.get('type', 'Unknown')
        service = credential.get('service', cred_type.upper())
        url = credential.get('url', 'Unknown')
        value = credential.get('value', '')
        
        # Mask sensitive parts of the credential
        masked_value = self._mask_credential(value)
        
        message = f"""🎯 <b>HIT FOUND!</b> 🎯

🔑 <b>Type:</b> {service}
🌐 <b>URL:</b> <code>{url}</code>
💎 <b>Value:</b> <code>{masked_value}</code>

⏰ <b>Found at:</b> {datetime.now().strftime('%H:%M:%S')}"""

        return await self.send_message(message)
    
    async def notify_progress(self, processed: int, total: int, hits: int) -> bool:
        """Notify about scan progress"""
        if total == 0:
            return False
            
        percentage = (processed / total) * 100
        
        message = f"""📊 <b>SCAN PROGRESS</b>

🌐 <b>Progress:</b> {processed:,} / {total:,} ({percentage:.1f}%)
🎯 <b>Hits Found:</b> {hits}
⏰ <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}

{'█' * int(percentage / 5)}{'░' * (20 - int(percentage / 5))} {percentage:.1f}%"""

        return await self.send_message(message)
    
    async def notify_error(self, error_message: str) -> bool:
        """Notify about an error"""
        message = f"""❌ <b>EVYL ERROR</b> ❌

⚠️ <b>Error:</b> {error_message}
⏰ <b>Time:</b> {datetime.now().strftime('%H:%M:%S')}"""

        return await self.send_message(message)
    
    def _mask_credential(self, value: str) -> str:
        """Mask sensitive parts of credentials"""
        if not value:
            return ""
            
        # For long values, show first and last few characters
        if len(value) > 20:
            return f"{value[:8]}...{value[-4:]}"
        elif len(value) > 10:
            return f"{value[:4]}...{value[-2:]}"
        else:
            return f"{value[:2]}***"


class TelegramProgressNotifier:
    """Manages automatic progress notifications"""
    
    def __init__(self, notifier: TelegramNotifier, progress_interval: int = 30):
        self.notifier = notifier
        self.progress_interval = progress_interval  # seconds between progress updates
        self.last_progress_time = 0
        self.last_hit_count = 0
        
    async def maybe_notify_progress(self, processed: int, total: int, hits: int) -> bool:
        """Send progress notification if interval has passed"""
        current_time = time.time()
        
        # Send progress update every interval or when new hits are found
        if (current_time - self.last_progress_time >= self.progress_interval or 
            hits > self.last_hit_count):
            
            success = await self.notifier.notify_progress(processed, total, hits)
            if success:
                self.last_progress_time = current_time
                self.last_hit_count = hits
            return success
        
        return False