"""
Report Generator for Evyl Framework

Generates comprehensive reports in multiple formats (JSON, HTML, TXT).
"""

import json
import os
import time
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import uuid

from utils.logger import Logger
from utils.crypto import CryptoManager

class Reporter:
    """Comprehensive report generator - config-driven"""
    
    def __init__(self, output_dir: str = "results", config: Dict[str, Any] = None):
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.logger = Logger()
        
        # Setup logging to file if configured
        log_file = self.config.get('log_file')
        if log_file:
            self.logger.add_file_handler(log_file)
        
        try:
            from utils.crypto import CryptoManager
            self.crypto = CryptoManager()
        except ImportError:
            self.crypto = None
            self.logger.warning("Crypto manager not available, encryption disabled")
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Reporter initialized: output to {self.output_dir}")
    
    async def generate_reports(self, scan_results, formats: List[str] = None):
        """Generate reports in specified formats"""
        if formats is None:
            formats = self.config.get('formats', ['json'])
        
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Prepare report data
        report_data = self._prepare_report_data(scan_results, scan_id, timestamp)
        
        # Generate each format
        for format_type in formats:
            if format_type == 'json':
                await self._generate_json_report(report_data, scan_id)
            elif format_type == 'html':
                await self._generate_html_report(report_data, scan_id)
            elif format_type == 'txt':
                await self._generate_txt_report(report_data, scan_id)
        
        # Real-time logging if enabled
        if self.config.get('real_time_logging', True):
            self._log_findings_real_time(scan_results)
        
        self.logger.success(f"Reports generated in {self.output_dir}")
    
    def _log_findings_real_time(self, scan_results):
        """Log findings to console and file in real-time"""
        if not scan_results.credentials:
            return
        
        self.logger.section("🔑 Credentials Found")
        
        # Group by type
        by_type = {}
        for cred in scan_results.credentials:
            cred_type = cred.get('type', 'unknown')
            if cred_type not in by_type:
                by_type[cred_type] = []
            by_type[cred_type].append(cred)
        
        # Log each type
        for cred_type, creds in by_type.items():
            self.logger.info(f"🎯 {cred_type.upper()}: {len(creds)} found")
            for cred in creds[:5]:  # Show first 5 of each type
                self.logger.info(f"  📍 {cred.get('url', 'N/A')}")
            
            if len(creds) > 5:
                self.logger.info(f"  ... and {len(creds) - 5} more")
    
    def _prepare_report_data(self, scan_results, scan_id: str, timestamp: str) -> Dict[str, Any]:
        """Prepare comprehensive report data"""
        return {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "scan_info": {
                "target_file": getattr(scan_results, 'target_file', 'N/A'),
                "duration": self._format_duration(time.time() - getattr(scan_results, 'start_time', time.time())),
                "threads": 100,  # Default value
                "proxies_used": 0  # Will be updated by network manager
            },
            "statistics": {
                "urls_processed": scan_results.total_processed,
                "unique_urls": scan_results.unique_urls,
                "validated_urls": scan_results.valid_credentials,
                "success_rate": scan_results.success_rate,
                "total_hits": len(scan_results.credentials)
            },
            "findings": self._organize_findings(scan_results.credentials),
            "validation_results": getattr(scan_results, 'validation_results', []),
            "performance": {
                "avg_response_time": 0,  # Will be calculated
                "cpu_usage": 0.0,
                "memory_usage": 0.0
            }
        }
    
    def _organize_findings(self, credentials: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Organize findings by service type"""
        findings = {
            "aws": [],
            "sendgrid": [],
            "mailgun": [],
            "twilio": [],
            "smtp": [],
            "git": [],
            "kubernetes": [],
            "other": []
        }
        
        for cred in credentials:
            cred_type = cred.get('type', '').lower()
            
            if 'aws' in cred_type:
                findings['aws'].append(self._format_aws_finding(cred))
            elif 'sendgrid' in cred_type:
                findings['sendgrid'].append(self._format_email_finding(cred))
            elif 'mailgun' in cred_type:
                findings['mailgun'].append(self._format_email_finding(cred))
            elif 'twilio' in cred_type:
                findings['twilio'].append(self._format_sms_finding(cred))
            elif 'smtp' in cred_type:
                findings['smtp'].append(self._format_smtp_finding(cred))
            elif 'git' in cred_type:
                findings['git'].append(self._format_git_finding(cred))
            elif 'kubernetes' in cred_type:
                findings['kubernetes'].append(self._format_k8s_finding(cred))
            else:
                findings['other'].append(cred)
        
        return findings
    
    def _format_aws_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format AWS credential finding"""
        return {
            "type": "aws_credentials",
            "access_key": cred['value'] if cred.get('aws_type') == 'access_key' else "REDACTED",
            "status": "UNKNOWN",  # Will be updated by validation
            "permissions": [],
            "source": cred['url'],
            "line": cred.get('line', 0),
            "context": cred.get('context', '')
        }
    
    def _format_email_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format email service finding"""
        return {
            "type": cred['type'],
            "api_key": cred['value'][:20] + "..." if len(cred['value']) > 20 else cred['value'],
            "service": cred.get('service', 'Unknown'),
            "status": "UNKNOWN",
            "source": cred['url'],
            "line": cred.get('line', 0)
        }
    
    def _format_sms_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format SMS service finding"""
        return {
            "type": cred['type'],
            "api_key": cred['value'][:20] + "..." if len(cred['value']) > 20 else cred['value'],
            "service": "Twilio",
            "status": "UNKNOWN",
            "source": cred['url'],
            "line": cred.get('line', 0)
        }
    
    def _format_smtp_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format SMTP finding"""
        return {
            "type": "smtp_credentials",
            "server": "Unknown",
            "username": "Unknown",
            "status": "UNKNOWN",
            "source": cred['url'],
            "line": cred.get('line', 0)
        }
    
    def _format_git_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format Git finding"""
        return {
            "type": "git_exposure",
            "path": cred['url'],
            "files_found": [],
            "secrets_in_history": [],
            "source": cred['url']
        }
    
    def _format_k8s_finding(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        """Format Kubernetes finding"""
        return {
            "type": "kubernetes_secret",
            "namespace": "Unknown",
            "secret_type": cred['type'],
            "status": "UNKNOWN",
            "source": cred['url'],
            "line": cred.get('line', 0)
        }
    
    async def _generate_json_report(self, report_data: Dict[str, Any], scan_id: str):
        """Generate JSON report"""
        filename = self.output_dir / f"evyl_report_{scan_id}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report saved: {filename}")
    
    async def _generate_html_report(self, report_data: Dict[str, Any], scan_id: str):
        """Generate HTML report"""
        filename = self.output_dir / f"evyl_report_{scan_id}.html"
        
        html_content = self._create_html_template(report_data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {filename}")
    
    async def _generate_txt_report(self, report_data: Dict[str, Any], scan_id: str):
        """Generate TXT report"""
        filename = self.output_dir / f"evyl_report_{scan_id}.txt"
        
        txt_content = self._create_txt_template(report_data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(txt_content)
        
        self.logger.info(f"TXT report saved: {filename}")
    
    def _create_html_template(self, data: Dict[str, Any]) -> str:
        """Create HTML report template"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Evyl Framework Report - {data['scan_id']}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; flex: 1; }}
        .finding {{ background: #fff; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .aws {{ border-left: 4px solid #ff9500; }}
        .email {{ border-left: 4px solid #3498db; }}
        .git {{ border-left: 4px solid #e74c3c; }}
        .k8s {{ border-left: 4px solid #9b59b6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 Evyl Framework v2.0 Report</h1>
        <p>Scan ID: {data['scan_id']}</p>
        <p>Generated: {data['timestamp']}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>URLs Processed</h3>
            <h2>{data['statistics']['urls_processed']:,}</h2>
        </div>
        <div class="stat-box">
            <h3>Total Hits</h3>
            <h2>{data['statistics']['total_hits']}</h2>
        </div>
        <div class="stat-box">
            <h3>Success Rate</h3>
            <h2>{data['statistics']['success_rate']:.1f}%</h2>
        </div>
    </div>
    
    <h2>🎯 Findings</h2>
    {self._generate_html_findings(data['findings'])}
    
</body>
</html>
        """
    
    def _generate_html_findings(self, findings: Dict[str, List]) -> str:
        """Generate HTML findings section"""
        html = ""
        
        for service, items in findings.items():
            if items:
                html += f"<h3>{service.upper()} Findings ({len(items)})</h3>"
                for item in items:
                    html += f'<div class="finding {service}">'
                    html += f'<strong>Type:</strong> {item.get("type", "Unknown")}<br>'
                    html += f'<strong>Source:</strong> {item.get("source", "Unknown")}<br>'
                    if 'line' in item:
                        html += f'<strong>Line:</strong> {item["line"]}<br>'
                    html += '</div>'
        
        return html
    
    def _create_txt_template(self, data: Dict[str, Any]) -> str:
        """Create TXT report template"""
        txt = f"""
EVYL FRAMEWORK v2.0 REPORT
==========================

Scan ID: {data['scan_id']}
Generated: {data['timestamp']}
Duration: {data['scan_info']['duration']}

STATISTICS
----------
URLs Processed: {data['statistics']['urls_processed']:,}
Unique URLs: {data['statistics']['unique_urls']:,}
Total Hits: {data['statistics']['total_hits']}
Success Rate: {data['statistics']['success_rate']:.1f}%

FINDINGS SUMMARY
----------------
"""
        
        for service, items in data['findings'].items():
            if items:
                txt += f"{service.upper()}: {len(items)} findings\n"
        
        txt += "\nDETAILED FINDINGS\n"
        txt += "================\n"
        
        for service, items in data['findings'].items():
            if items:
                txt += f"\n{service.upper()} FINDINGS:\n"
                txt += "-" * (len(service) + 10) + "\n"
                
                for i, item in enumerate(items, 1):
                    txt += f"{i}. Type: {item.get('type', 'Unknown')}\n"
                    txt += f"   Source: {item.get('source', 'Unknown')}\n"
                    if 'line' in item:
                        txt += f"   Line: {item['line']}\n"
                    txt += "\n"
        
        return txt
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"