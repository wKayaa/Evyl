# Cloud module initialization
"""
Cloud Platform Exploitation Module

Provides comprehensive cloud platform security testing:
- AWS metadata and service exploitation
- GCP service account and metadata exploitation  
- Azure metadata and identity exploitation
"""

from .aws_scanner import AWSScanner
from .gcp_scanner import GCPScanner
from .azure_scanner import AzureScanner

__all__ = ["AWSScanner", "GCPScanner", "AzureScanner"]