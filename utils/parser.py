"""
Multi-format Parser for Evyl Framework

Handles parsing of various file formats for credential extraction.
"""

import json
import yaml
import xml.etree.ElementTree as ET
import configparser
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from utils.logger import Logger

class Parser:
    """Multi-format file parser"""
    
    def __init__(self):
        self.logger = Logger()
    
    def parse_file(self, file_path: str, content: str = None) -> Dict[str, Any]:
        """Parse file based on extension or content"""
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                self.logger.error(f"Failed to read file {file_path}: {e}")
                return {}
        
        file_ext = Path(file_path).suffix.lower()
        
        parsers = {
            '.json': self.parse_json,
            '.yaml': self.parse_yaml,
            '.yml': self.parse_yaml,
            '.xml': self.parse_xml,
            '.ini': self.parse_ini,
            '.conf': self.parse_ini,
            '.config': self.parse_ini,
            '.properties': self.parse_properties,
            '.env': self.parse_env,
            '.toml': self.parse_toml,
        }
        
        parser = parsers.get(file_ext, self.parse_generic)
        
        try:
            return parser(content)
        except Exception as e:
            self.logger.warning(f"Failed to parse {file_path} as {file_ext}: {e}")
            return self.parse_generic(content)
    
    def parse_json(self, content: str) -> Dict[str, Any]:
        """Parse JSON content"""
        try:
            data = json.loads(content)
            return self._flatten_dict(data) if isinstance(data, dict) else {}
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JSON: {e}")
            return {}
    
    def parse_yaml(self, content: str) -> Dict[str, Any]:
        """Parse YAML content"""
        try:
            data = yaml.safe_load(content)
            return self._flatten_dict(data) if isinstance(data, dict) else {}
        except yaml.YAMLError as e:
            self.logger.warning(f"Invalid YAML: {e}")
            return {}
    
    def parse_xml(self, content: str) -> Dict[str, Any]:
        """Parse XML content"""
        try:
            root = ET.fromstring(content)
            return self._xml_to_dict(root)
        except ET.ParseError as e:
            self.logger.warning(f"Invalid XML: {e}")
            return {}
    
    def parse_ini(self, content: str) -> Dict[str, Any]:
        """Parse INI/config content"""
        try:
            config = configparser.ConfigParser()
            config.read_string(content)
            
            result = {}
            for section_name in config.sections():
                section = config[section_name]
                for key, value in section.items():
                    result[f"{section_name}.{key}"] = value
            
            return result
        except configparser.Error as e:
            self.logger.warning(f"Invalid INI: {e}")
            return {}
    
    def parse_properties(self, content: str) -> Dict[str, Any]:
        """Parse Java properties content"""
        result = {}
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('!'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    result[key.strip()] = value.strip()
                elif ':' in line:
                    key, value = line.split(':', 1)
                    result[key.strip()] = value.strip()
        
        return result
    
    def parse_env(self, content: str) -> Dict[str, Any]:
        """Parse environment file content"""
        result = {}
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                
                result[key] = value
        
        return result
    
    def parse_toml(self, content: str) -> Dict[str, Any]:
        """Parse TOML content (basic implementation)"""
        try:
            # Try to import toml library if available
            import toml
            data = toml.loads(content)
            return self._flatten_dict(data) if isinstance(data, dict) else {}
        except ImportError:
            # Fallback to basic parsing
            return self.parse_ini(content)
        except Exception as e:
            self.logger.warning(f"Invalid TOML: {e}")
            return {}
    
    def parse_generic(self, content: str) -> Dict[str, Any]:
        """Generic parser for unknown file types"""
        result = {}
        
        # Look for key-value pairs
        patterns = [
            r'^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.+)$',  # key: value or key = value
            r'^([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$',         # key value
            r'"([^"]+)"\s*[:=]\s*"([^"]+)"',              # "key": "value"
            r"'([^']+)'\s*[:=]\s*'([^']+)'",              # 'key': 'value'
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    key, value = match.groups()
                    result[f"line_{line_num}_{key}"] = value
                    break
        
        return result
    
    def _flatten_dict(self, data: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary"""
        items = []
        
        for key, value in data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            
            if isinstance(value, dict):
                items.extend(self._flatten_dict(value, new_key, sep).items())
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", str(item)))
            else:
                items.append((new_key, str(value)))
        
        return dict(items)
    
    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary"""
        result = {}
        
        # Add attributes
        if element.attrib:
            for key, value in element.attrib.items():
                result[f"@{key}"] = value
        
        # Add text content
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()
        
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                # Convert to list if multiple elements with same tag
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
    
    def extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content"""
        url_pattern = r'https?://[^\s<>"\'`]+|www\.[^\s<>"\'`]+'
        urls = re.findall(url_pattern, content, re.IGNORECASE)
        return list(set(urls))  # Remove duplicates
    
    def extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        return list(set(emails))  # Remove duplicates
    
    def extract_ips(self, content: str) -> List[str]:
        """Extract IP addresses from content"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, content)
        # Filter valid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        return list(set(valid_ips))  # Remove duplicates
    
    def extract_domains(self, content: str) -> List[str]:
        """Extract domain names from content"""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, content)
        return list(set(domains))  # Remove duplicates